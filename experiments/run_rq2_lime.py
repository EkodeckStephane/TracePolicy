from __future__ import annotations
import sys,time,json,random
from pathlib import Path
import numpy as np,pandas as pd
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src')); sys.path.insert(0,str(ROOT/'vendor'))
import trace_policy_engine as tpe
from local_bench import clean_policy
from lime.lime_tabular import LimeTabularExplainer
RES=ROOT/'results'/'raw'; SEEDS=json.load(open(ROOT/'config'/'seeds.json'))['seeds']
CLASSES=[tpe.NOALERT,tpe.VIOLATION,tpe.CONFLICT,tpe.GAP]

def make_case(kind,seed):
    rng=random.Random(seed); ts=0; benign=[]
    for i in range(3):
        ts+=1; a,rc=rng.choice([('read','public'),('write','public'),('connect','service')]); benign.append(tpe.Event(f'B{seed}_{i}',ts,a,rc,'user',{},0,'normal'))
    if kind=='secret_read': return benign+[tpe.Event(f'A{seed}',4,'read','secret','user',{},1,kind)]
    if kind=='system_write': return benign+[tpe.Event(f'A{seed}',4,'write','system','user',{},1,kind)]
    if kind=='system_exec': return benign+[tpe.Event(f'A{seed}',4,'exec','system','user',{},1,kind)]
    if kind=='scan': return [tpe.Event(f'S{seed}_{i}',i+1,'connect','network','user',{},1,'scan') for i in range(3)]

def unit_info(trace,pol,horizon=4):
    st=max(0,len(trace)-horizon); eps=list(range(st,len(trace))); cur=trace[-1]; rids=[r.rid for r in pol.rules if r.selector.matches(cur)]; units=[f'e:{i}' for i in eps]+[f'r:{r}' for r in rids]; return eps,rids,units

def smallest(trace,pol,ranking):
    s=set()
    for k,u in enumerate(ranking,1):
        s.add(u)
        if tpe.exact_sufficiency_of_selected(trace,pol,s,4): return k,tuple(sorted(s))
    return None,tuple(sorted(s))

def run():
    rows=[]; valsout=[]; pol=clean_policy(); kinds=['secret_read','system_write','system_exec','scan']
    seeds=SEEDS+[2026081501,2026081502]
    for j,seed in enumerate(seeds):
        kind=kinds[j%4]; tr=make_case(kind,seed); y=tpe.reference_eval(tr,pol).alert_class; yi=CLASSES.index(y); ex=tpe.min_explain_bruteforce(tr,pol,4); core={f'e:{i}' for i in ex.event_positions}|{f'r:{r}' for r in ex.rule_ids}; eps,rids,units=unit_info(tr,pol); m=len(units)
        # Enumerated binary masks form the training distribution for LIME, preserving the exact retention domain.
        train=np.array(list(__import__('itertools').product([0,1],repeat=m)),dtype=float)
        def pred(X):
            out=[]
            for bits in np.asarray(X):
                c=tpe._class_under_mask(tr,pol,eps,rids,[int(v>=.5) for v in bits]); out.append([1.0 if c==q else 0.0 for q in CLASSES])
            return np.asarray(out)
        explainer=LimeTabularExplainer(train,mode='classification',feature_names=units,categorical_features=list(range(m)),categorical_names={i:['0','1'] for i in range(m)},class_names=CLASSES,discretize_continuous=False,random_state=seed)
        t=time.perf_counter_ns(); exp=explainer.explain_instance(np.ones(m),pred,labels=(yi,),num_features=m,num_samples=5000); us=(time.perf_counter_ns()-t)/1000
        loc=exp.local_exp.get(yi,[]); weights={units[i]:float(w) for i,w in loc}; ranking=sorted(units,key=lambda u:abs(weights.get(u,0.0)),reverse=True); k,sel=smallest(tr,pol,ranking); sset=set(sel); jac=len(core&sset)/len(core|sset) if core|sset else 1.0
        rows.append(dict(seed=seed,kind=kind,target_class=y,n_units=m,intrinsic_core_size=len(core),lime_sufficient_k=k,lime_selected=';'.join(sel),lime_jaccard_with_core=jac,lime_us=us,lime_local_pred=float(exp.local_pred[0]) if hasattr(exp,'local_pred') else np.nan,lime_score=float(exp.score) if hasattr(exp,'score') else np.nan,core=';'.join(sorted(core)),lime_ranking=';'.join(ranking)))
        for u in units: valsout.append(dict(seed=seed,kind=kind,unit=u,lime_weight=weights.get(u,0.0),in_intrinsic_core=int(u in core)))
    pd.DataFrame(rows).to_csv(RES/'rq2_intrinsic_vs_lime.csv',index=False); pd.DataFrame(valsout).to_csv(RES/'rq2_lime_unit_values.csv',index=False)
    print(pd.DataFrame(rows).groupby('kind')[['intrinsic_core_size','lime_sufficient_k','lime_jaccard_with_core','lime_us','lime_score']].mean().round(3))
if __name__=='__main__': run()
