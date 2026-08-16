from __future__ import annotations
import sys,time,json,random
from pathlib import Path
import numpy as np,pandas as pd, shap
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
import trace_policy_engine as tpe
from local_bench import clean_policy
ROOT=Path(__file__).resolve().parents[1]; RES=ROOT/'results'/'raw'; RES.mkdir(parents=True,exist_ok=True)
SEEDS=json.load(open(ROOT/'config'/'seeds.json'))['seeds']
CLASSES=[tpe.NOALERT,tpe.VIOLATION,tpe.CONFLICT,tpe.GAP]

def make_case(kind,seed):
    rng=random.Random(seed); ts=0
    benign=[]
    for i in range(3):
        ts+=1; a,rc=rng.choice([('read','public'),('write','public'),('connect','service')]); benign.append(tpe.Event(f'B{seed}_{i}',ts,a,rc,'user',{},0,'normal'))
    if kind=='secret_read':
        ts+=1; return benign+[tpe.Event(f'A{seed}',ts,'read','secret','user',{},1,kind)]
    if kind=='system_write':
        ts+=1; return benign+[tpe.Event(f'A{seed}',ts,'write','system','user',{},1,kind)]
    if kind=='system_exec':
        ts+=1; return benign+[tpe.Event(f'A{seed}',ts,'exec','system','user',{},1,kind)]
    if kind=='scan':
        return [tpe.Event(f'S{seed}_{i}',i+1,'connect','network','user',{},1,'scan') for i in range(3)]
    raise ValueError(kind)

def unit_info(trace,pol,horizon=4):
    start=max(0,len(trace)-horizon); eps=list(range(start,len(trace))); cur=trace[-1]
    rids=[r.rid for r in pol.rules if r.selector.matches(cur)]
    units=[f'e:{i}' for i in eps]+[f'r:{r}' for r in rids]
    return eps,rids,units

def model_for(trace,pol,eps,rids):
    m=len(eps)+len(rids)
    def f(X):
        X=np.asarray(X).reshape(-1,m); out=[]
        for bits in X:
            c=tpe._class_under_mask(trace,pol,eps,rids,[int(v>=.5) for v in bits])
            out.append([1.0 if c==q else 0.0 for q in CLASSES])
        return np.asarray(out)
    return f

def smallest_sufficient_by_ranking(trace,pol,units,ranking):
    selected=set()
    for k,u in enumerate(ranking,1):
        selected.add(u)
        ok=tpe.exact_sufficiency_of_selected(trace,pol,selected,horizon=4)
        if ok: return k,tuple(sorted(selected))
    return None,tuple(sorted(selected))

def run():
    pol=clean_policy(); rows=[]; masks=[]
    kinds=['secret_read','system_write','system_exec','scan']
    # 32 controlled alert instances; >30 independent random backgrounds.
    for j,seed in enumerate(SEEDS+[2026081501,2026081502]):
        kind=kinds[j%4]; tr=make_case(kind,seed); factual=tpe.reference_eval(tr,pol)
        assert factual.alert_class==tpe.VIOLATION, (kind,factual.alert_class)
        t=time.perf_counter_ns(); ex=tpe.min_explain_bruteforce(tr,pol,horizon=4); intrinsic_us=(time.perf_counter_ns()-t)/1000
        core_units={f'e:{i}' for i in ex.event_positions}|{f'r:{r}' for r in ex.rule_ids}
        eps,rids,units=unit_info(tr,pol,4); m=len(units); f=model_for(tr,pol,eps,rids); target_idx=CLASSES.index(factual.alert_class)
        background=np.zeros((1,m)); x=np.ones((1,m))
        t=time.perf_counter_ns(); ke=shap.KernelExplainer(f,background); sv=np.asarray(ke.shap_values(x,nsamples=min(2**m,1024),silent=True)); shap_us=(time.perf_counter_ns()-t)/1000
        # shap 0.50 returns (samples, features, outputs)
        vals=sv[0,:,target_idx] if sv.ndim==3 else np.asarray(sv[target_idx])[0]
        ranking=[units[i] for i in np.argsort(-np.abs(vals))]
        k,sel=smallest_sufficient_by_ranking(tr,pol,units,ranking)
        shap_set=set(sel)
        jac=len(core_units&shap_set)/len(core_units|shap_set) if core_units|shap_set else 1.0
        rows.append(dict(seed=seed,kind=kind,target_class=factual.alert_class,n_units=m,intrinsic_core_size=len(core_units),intrinsic_event_units=len(ex.event_positions),intrinsic_rule_units=len(ex.rule_ids),intrinsic_sound=int(tpe.exact_sufficiency_of_selected(tr,pol,core_units,4)),intrinsic_witnesses=len(ex.witnesses),intrinsic_us=intrinsic_us,shap_sufficient_k=k,shap_selected=';'.join(sel),shap_jaccard_with_core=jac,shap_us=shap_us,core=';'.join(sorted(core_units)),shap_ranking=';'.join(ranking)))
        for u,v in zip(units,vals): masks.append(dict(seed=seed,kind=kind,unit=u,shap_target=float(v),in_intrinsic_core=int(u in core_units)))
    pd.DataFrame(rows).to_csv(RES/'rq2_intrinsic_vs_shap.csv',index=False)
    pd.DataFrame(masks).to_csv(RES/'rq2_shap_unit_values.csv',index=False)
    print(pd.DataFrame(rows).groupby('kind')[['intrinsic_core_size','shap_sufficient_k','shap_jaccard_with_core','intrinsic_us','shap_us']].mean().round(3))
if __name__=='__main__': run()
