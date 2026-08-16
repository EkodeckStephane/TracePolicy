from __future__ import annotations
import os, sys, json, random, time, hashlib, platform
from pathlib import Path
import numpy as np, pandas as pd
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from trace_policy_engine import *
from local_bench import clean_policy, generate_local_trace

ROOT=Path(__file__).resolve().parents[1]
RES=ROOT/'results'/'raw'; RES.mkdir(parents=True,exist_ok=True)
SEEDS=json.load(open(ROOT/'config'/'seeds.json'))['seeds']

def eval_binary(events, policy, drop_rate=0.0, seed=0, engine='reference'):
    rng=random.Random(seed); trace=[]; ys=[]; yp=[]; classes=[]; checks=[]; cands=[]
    idx=StaticIndex(policy) if engine=='index' else None
    inc=IncrementalEvaluator(policy) if engine=='incremental' else None
    for e in events:
        y=int(e.malicious or 0)
        observed=e
        if rng.random()<drop_rate:
            observed=Event.stutter_like(e)
        if engine=='incremental': r=inc.push(observed)
        else:
            trace.append(observed)
            r=reference_eval(trace,policy) if engine=='reference' else idx.eval(trace)
        pred=int(r.alert_class in (VIOLATION,CONFLICT)) # gaps are configuration defects, not malicious events
        ys.append(y); yp.append(pred); classes.append(r.alert_class); checks.append(r.checks); cands.append(r.candidates)
    tn,fp,fn,tp=confusion_matrix(ys,yp,labels=[0,1]).ravel()
    return dict(precision=precision_score(ys,yp,zero_division=0), recall=recall_score(ys,yp,zero_division=0),
                f1=f1_score(ys,yp,zero_division=0), fpr=fp/(fp+tn) if fp+tn else np.nan,
                tp=int(tp),tn=int(tn),fp=int(fp),fn=int(fn), mean_checks=float(np.mean(checks)),mean_candidates=float(np.mean(cands)))

def degrade_policy(policy, frac, seed):
    denies=[r for r in policy.rules if r.effect==DENY]
    k=min(len(denies),int(round(frac*len(denies))))
    rm=set(r.rid for r in random.Random(seed).sample(denies,k)) if k else set()
    return PolicyVersion(policy.pid,100+int(frac*100),tuple(r for r in policy.rules if r.rid not in rm)),tuple(sorted(rm))

def rq1():
    rows=[]; base=clean_policy()
    for seed in SEEDS:
        ev=generate_local_trace(3000,seed,attack_rate=.18)
        for pf in [0,.25,.5,.75]:
            pol,rm=degrade_policy(base,pf,seed)
            for df in [0,.05,.10,.20]:
                m=eval_binary(ev,pol,df,seed+77,'reference')
                rows.append(dict(seed=seed,policy_deletion_fraction=pf,trace_dropout_fraction=df,removed_rules=';'.join(rm),**m))
    pd.DataFrame(rows).to_csv(RES/'rq1_local_detection.csv',index=False)
    return len(rows)

def make_decoy_policy(P,version=1):
    base=list(clean_policy(version).rules)
    n=max(0,P-len(base))
    for i in range(n):
        base.append(Rule(f'Z{i}',1,ALLOW,Selector(f'decoy_action_{i}',f'decoy_resource_{i%17}','user')))
    return PolicyVersion('PERF',version,tuple(base))

def rq4_perf():
    rows=[]; div=[]
    for seed in SEEDS:
        ev=generate_local_trace(500,seed,attack_rate=.15)
        for P in [50,200,500]:
            pol=make_decoy_policy(P)
            idx=StaticIndex(pol); inc=IncrementalEvaluator(pol); tr=[]
            lref=[]; lidx=[]; linc=[]; cands=[]
            for i,e in enumerate(ev):
                tr.append(e)
                t=time.perf_counter_ns(); a=reference_eval(tr,pol); lref.append(time.perf_counter_ns()-t)
                t=time.perf_counter_ns(); b=idx.eval(tr); lidx.append(time.perf_counter_ns()-t)
                t=time.perf_counter_ns(); c=inc.push(e); linc.append(time.perf_counter_ns()-t)
                cands.append(b.candidates)
                if (a.decision,a.alert_class,set(a.applicable),set(a.top))!=(b.decision,b.alert_class,set(b.applicable),set(b.top)):
                    div.append((seed,P,i,'index'))
                if (a.decision,a.alert_class,set(a.applicable),set(a.top))!=(c.decision,c.alert_class,set(c.applicable),set(c.top)):
                    div.append((seed,P,i,'incremental'))
            for name,arr in [('reference',lref),('indexed',lidx),('incremental',linc)]:
                a=np.asarray(arr)/1000.0 # microseconds
                rows.append(dict(seed=seed,P=P,engine=name,n_events=len(ev),mean_us=a.mean(),p50_us=np.percentile(a,50),p95_us=np.percentile(a,95),p99_us=np.percentile(a,99),throughput_eps=1e6/a.mean(),mean_candidate_rules=np.mean(cands) if name!='reference' else P))
    pd.DataFrame(rows).to_csv(RES/'rq4_latency.csv',index=False)
    pd.DataFrame(div,columns=['seed','P','event_index','engine']).to_csv(RES/'oracle_divergences.csv',index=False)
    return len(rows),len(div)

def rq4_updates():
    rows=[]; div=[]
    for seed in SEEDS:
        rng=random.Random(seed); base=make_decoy_policy(500); refpol=base; inc=IncrementalEvaluator(base); tr=[]
        ev=generate_local_trace(600,seed,.15); version=1
        update_ns=[]; eval_ref=[]; eval_inc=[]
        for i,e in enumerate(ev):
            if i>0 and i%100==0:
                version+=1
                # Deterministically add a decoy rule; cannot change current semantics.
                nr=Rule(f'U{version}',2,ALLOW,Selector(f'update_decoy_{version}','u_resource','user'))
                newp=PolicyVersion(base.pid,version,refpol.rules+(nr,))
                refpol=newp
                t=time.perf_counter_ns(); inc.update_policy(newp); update_ns.append(time.perf_counter_ns()-t)
            tr.append(e)
            t=time.perf_counter_ns(); a=reference_eval(tr,refpol); eval_ref.append(time.perf_counter_ns()-t)
            t=time.perf_counter_ns(); b=inc.push(e); eval_inc.append(time.perf_counter_ns()-t)
            if (a.decision,a.alert_class,set(a.applicable),set(a.top))!=(b.decision,b.alert_class,set(b.applicable),set(b.top)):
                div.append((seed,version,i))
        rows.append(dict(seed=seed,updates=len(update_ns),mean_update_us=np.mean(update_ns)/1000 if update_ns else 0,p95_update_us=np.percentile(np.array(update_ns)/1000,95) if update_ns else 0,
                         reference_mean_us=np.mean(eval_ref)/1000,incremental_mean_us=np.mean(eval_inc)/1000))
    pd.DataFrame(rows).to_csv(RES/'rq4_policy_updates.csv',index=False)
    if div:
        pd.DataFrame(div,columns=['seed','version','event_index']).to_csv(RES/'oracle_update_divergences.csv',index=False)
    else:
        pd.DataFrame(columns=['seed','version','event_index']).to_csv(RES/'oracle_update_divergences.csv',index=False)
    return len(rows),len(div)

def predict_defects(pol,domain):
    pred=set();
    for tr in domain:
        c=reference_eval(tr,pol).alert_class
        if c==CONFLICT: pred.add('conflict')
        if c==GAP: pred.add('gap')
    st=bounded_structural_diagnosis(pol,domain)
    if any(x.startswith('M_SHADOW_') for x in st['shadowed']): pred.add('shadowing')
    if any(x.startswith('M_REDUNDANT_') for x in st['redundant']): pred.add('redundancy')
    return pred,st

def rq3():
    rows=[]
    base=clean_policy()
    # Domain contains short prefixes ending in events that exercise all base selectors.
    for seed in SEEDS:
        ev=generate_local_trace(300,seed,.25)
        domain=[]; tr=[]
        for e in ev:
            tr.append(e); domain.append(tuple(tr[-4:]))
        # Force representative events for each rule to avoid stochastic coverage gaps.
        forced=[
            [Event('F1',1,'read','secret','user',{},1,'secret_read')],
            [Event('F2',2,'write','system','user',{},1,'system_write')],
            [Event('F3',3,'exec','system','user',{},1,'system_exec')],
            [Event('F4',4,'read','public','user',{},0,'normal')],
            [Event('F5',5,'write','public','user',{},0,'normal')],
            [Event('F6',6,'connect','service','user',{},0,'normal')],
        ]
        domain.extend(forced)
        cases=[]
        cases.append(('conflict',mutate_conflict(base,'D_SECRET_READ',200+seed%1000)))
        cases.append(('shadowing',mutate_shadowing(base,'D_SECRET_READ',300+seed%1000)))
        cases.append(('redundancy',mutate_redundancy(base,'A_READ_PUBLIC',400+seed%1000)))
        cases.append(('gap',mutate_gap(base,['A_READ_PUBLIC'],500+seed%1000)))
        for truth,pol in cases:
            pred,st=predict_defects(pol,domain)
            rows.append(dict(seed=seed,truth=truth,predicted=';'.join(sorted(pred)),correct=int(truth in pred),false_positive_count=len(pred-{truth}),shadowed=';'.join(st['shadowed']),redundant=';'.join(st['redundant'])))
    pd.DataFrame(rows).to_csv(RES/'rq3_policy_defects.csv',index=False)
    return len(rows)

if __name__=='__main__':
    print('RQ1 rows',rq1())
    print('RQ3 rows',rq3())
    print('RQ4 perf rows/div',rq4_perf())
    print('RQ4 update rows/div',rq4_updates())
