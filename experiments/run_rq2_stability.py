from __future__ import annotations
import sys,json,random,time,itertools
from pathlib import Path
import numpy as np,pandas as pd, shap
ROOT=Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT/'src')); sys.path.insert(0,str(ROOT/'vendor'))
import trace_policy_engine as tpe
from local_bench import clean_policy
from lime.lime_tabular import LimeTabularExplainer
from run_rq2_lime import make_case,unit_info,smallest,CLASSES
RES=ROOT/'results'/'raw'; SEEDS=json.load(open(ROOT/'config'/'seeds.json'))['seeds']+[2026081501,2026081502]; kinds=['secret_read','system_write','system_exec','scan']

def explain_sets(tr,pol,seed):
    y=tpe.reference_eval(tr,pol).alert_class; yi=CLASSES.index(y); ex=tpe.min_explain_bruteforce(tr,pol,4); core={f'e:{i}' for i in ex.event_positions}|{f'r:{r}' for r in ex.rule_ids}; eps,rids,units=unit_info(tr,pol); m=len(units)
    def pred(X):
        out=[]
        for bits in np.asarray(X).reshape(-1,m):
            c=tpe._class_under_mask(tr,pol,eps,rids,[int(v>=.5) for v in bits]); out.append([1. if c==q else 0. for q in CLASSES])
        return np.asarray(out)
    # SHAP
    sv=np.asarray(shap.KernelExplainer(pred,np.zeros((1,m))).shap_values(np.ones((1,m)),nsamples=min(2**m,1024),silent=True)); vals=sv[0,:,yi]; rank=[units[i] for i in np.argsort(-np.abs(vals))]; _,shsel=smallest(tr,pol,rank)
    # LIME official tagged source 0.2.0.0 vendored unchanged
    train=np.array(list(itertools.product([0,1],repeat=m)),float); le=LimeTabularExplainer(train,mode='classification',feature_names=units,categorical_features=list(range(m)),categorical_names={i:['0','1'] for i in range(m)},class_names=CLASSES,discretize_continuous=False,random_state=seed); exp=le.explain_instance(np.ones(m),pred,labels=(yi,),num_features=m,num_samples=5000); w={units[i]:float(v) for i,v in exp.local_exp[yi]}; rank2=sorted(units,key=lambda u:abs(w.get(u,0)),reverse=True); _,lisel=smallest(tr,pol,rank2)
    # Witness validation
    witness_ok=True
    start=max(0,len(tr)-4); epos=list(range(start,len(tr))); cur=tr[-1]; rr=[r.rid for r in pol.rules if r.selector.matches(cur)]; allunits=[f'e:{i}' for i in epos]+[f'r:{r}' for r in rr]
    for u,maskdict in ex.witnesses.items():
        bits=[maskdict[x] for x in allunits]
        if tpe._class_under_mask(tr,pol,epos,rr,bits)==y: witness_ok=False
    return core,set(shsel),set(lisel),witness_ok

def jac(a,b): return len(a&b)/len(a|b) if a|b else 1.0
rows=[]
for j,seed in enumerate(SEEDS):
    kind=kinds[j%4]; pol=clean_policy(); tr=make_case(kind,seed); c0,s0,l0,w0=explain_sets(tr,pol,seed)
    if kind=='scan':
        pol2=tpe.PolicyVersion(pol.pid,2,tuple(r for r in pol.rules if r.rid!='A_NETWORK_CONNECT')); tr2=tr
        perturb='remove_noncore_allow_rule'
    else:
        tr2=list(tr); tr2[0]=tpe.Event.stutter_like(tr2[0]); pol2=pol; perturb='stutter_noncore_event_0'
    assert tpe.reference_eval(tr2,pol2).alert_class==tpe.reference_eval(tr,pol).alert_class
    c1,s1,l1,w1=explain_sets(tr2,pol2,seed+999)
    rows.append(dict(seed=seed,kind=kind,perturbation=perturb,intrinsic_jaccard=jac(c0,c1),shap_jaccard=jac(s0,s1),lime_jaccard=jac(l0,l1),witness_valid_before=int(w0),witness_valid_after=int(w1)))
pd.DataFrame(rows).to_csv(RES/'rq2_stability_counterfactual.csv',index=False)
print(pd.DataFrame(rows).groupby('kind')[['intrinsic_jaccard','shap_jaccard','lime_jaccard','witness_valid_before','witness_valid_after']].mean().round(3))
