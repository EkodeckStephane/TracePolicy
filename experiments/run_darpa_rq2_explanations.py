from __future__ import annotations
import argparse,sys,time,json
from pathlib import Path
import numpy as np,pandas as pd, shap
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'src'));sys.path.insert(0,str(ROOT/'vendor'))
import trace_policy_engine as tpe
from darpa_adapter import iter_events,load_malicious_ids
from policy_io import load_policy_csv
from lime.lime_tabular import LimeTabularExplainer
CLASSES=[tpe.NOALERT,tpe.VIOLATION,tpe.CONFLICT,tpe.GAP]

def choose(root,pat):return sorted([p for p in root.rglob(pat) if p.is_file() and not p.name.endswith(('.gz','.tgz','.tar.gz'))])
def units(trace,pol):
    eps=[0];rids=[r.rid for r in pol.rules if r.selector.matches(trace[-1])];return eps,rids,[f'e:0']+[f'r:{x}' for x in rids]
def predictor(trace,pol,eps,rids):
    def f(X):
      out=[]
      for bits in np.asarray(X):
        c=tpe._class_under_mask(trace,pol,eps,rids,[int(v>=.5) for v in bits]);out.append([1. if c==q else 0. for q in CLASSES])
      return np.asarray(out)
    return f

def smallest(trace,pol,ranking):
    s=set()
    for k,u in enumerate(ranking,1):
        s.add(u)
        if tpe.exact_sufficiency_of_selected(trace,pol,s,horizon=1):return k,tuple(sorted(s))
    return None,tuple(sorted(s))

def main():
 ap=argparse.ArgumentParser();ap.add_argument('--data-root',default=str(ROOT/'datasets/raw/darpa_e3/cadets'));ap.add_argument('--test-pattern',default='ta1-cadets-e3-official-2.json*');ap.add_argument('--groundtruth',default=str(ROOT/'datasets/seed/cadets_groundtruth_threatrace.txt'));ap.add_argument('--policy',default=str(ROOT/'results/raw/rq5_darpa_policy_rules.csv'));ap.add_argument('--cases',type=int,default=32);args=ap.parse_args()
 pol=load_policy_csv(Path(args.policy));files=choose(Path(args.data_root),args.test_pattern);db=ROOT/'datasets/processed/darpa_cadets_entities.sqlite';gt=load_malicious_ids(Path(args.groundtruth));cases=[]
 for e in iter_events(files,db,gt):
    r=tpe.reference_eval([e],pol)
    if int(e.malicious or 0)==1 and r.alert_class!=tpe.NOALERT:cases.append(e)
    if len(cases)>=args.cases:break
 if len(cases)<args.cases: raise SystemExit(f'Only {len(cases)} true alert cases found; required {args.cases}. Do not substitute false alerts.')
 rows=[];unitrows=[]
 for j,e in enumerate(cases):
    tr=[e];factual=tpe.reference_eval(tr,pol);yi=CLASSES.index(factual.alert_class);t=time.perf_counter_ns();ex=tpe.min_explain_bruteforce(tr,pol,horizon=1,max_units=18);intrinsic_us=(time.perf_counter_ns()-t)/1000;core={f'e:{i}' for i in ex.event_positions}|{f'r:{r}' for r in ex.rule_ids};eps,rids,us=units(tr,pol);m=len(us);f=predictor(tr,pol,eps,rids)
    if m>12: raise SystemExit(f'RQ2 case has {m} units; bounded same-oracle explanation would be intractable. Review policy/index; do not truncate silently.')
    x=np.ones((1,m));bg=np.zeros((1,m));t=time.perf_counter_ns();sv=np.asarray(shap.KernelExplainer(f,bg).shap_values(x,nsamples=min(2**m,1024),silent=True));shap_us=(time.perf_counter_ns()-t)/1000;vals=sv[0,:,yi] if sv.ndim==3 else np.asarray(sv[yi])[0];srank=[us[i] for i in np.argsort(-np.abs(vals))];sk,ssel=smallest(tr,pol,srank)
    train=np.array(list(__import__('itertools').product([0,1],repeat=m)),dtype=float);expl=LimeTabularExplainer(train,mode='classification',feature_names=us,categorical_features=list(range(m)),categorical_names={i:['0','1'] for i in range(m)},class_names=CLASSES,discretize_continuous=False,random_state=20260814+j);t=time.perf_counter_ns();le=expl.explain_instance(np.ones(m),f,labels=(yi,),num_features=m,num_samples=5000);lime_us=(time.perf_counter_ns()-t)/1000;weights={us[i]:float(w) for i,w in le.local_exp.get(yi,[])};lrank=sorted(us,key=lambda u:abs(weights.get(u,0.)),reverse=True);lk,lsel=smallest(tr,pol,lrank)
    ss=set(ssel);ls=set(lsel);jac=lambda a,b:len(a&b)/len(a|b) if a|b else 1.
    rows.append(dict(case=j,event_id=e.eid,truth=e.malicious,alert_class=factual.alert_class,n_units=m,intrinsic_core_size=len(core),intrinsic_us=intrinsic_us,shap_us=shap_us,shap_sufficient_k=sk,shap_jaccard=jac(core,ss),lime_us=lime_us,lime_sufficient_k=lk,lime_jaccard=jac(core,ls),lime_score=float(le.score),core=';'.join(sorted(core))))
    for u,v in zip(us,vals):unitrows.append(dict(case=j,event_id=e.eid,unit=u,shap_value=float(v),lime_weight=weights.get(u,0.),in_core=int(u in core)))
 out=ROOT/'results/raw';pd.DataFrame(rows).to_csv(out/'rq2_darpa_explanations.csv',index=False);pd.DataFrame(unitrows).to_csv(out/'rq2_darpa_unit_values.csv',index=False);print(pd.DataFrame(rows)[['intrinsic_us','shap_us','lime_us','shap_jaccard','lime_jaccard']].describe())
if __name__=='__main__':main()
