from __future__ import annotations
import argparse, sys, time
from pathlib import Path
import numpy as np
import pandas as pd
import shap
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
sys.path.insert(0, str(ROOT / 'vendor'))
import trace_policy_engine as tpe
try:
    from lime.lime_tabular import LimeTabularExplainer
except ModuleNotFoundError:
    LimeTabularExplainer = None
CLASSES=[tpe.NOALERT,tpe.VIOLATION,tpe.CONFLICT,tpe.GAP]
RAW=ROOT/'results'/'raw'; SUMMARY=ROOT/'results'/'summary'; RAW.mkdir(parents=True,exist_ok=True); SUMMARY.mkdir(parents=True,exist_ok=True)
def make_scaling_case(n_units:int):
    if n_units<5: raise ValueError('n_units must be >= 5')
    trace=[tpe.Event('b0',1,'read','public','user',{'marker':-1}),tpe.Event('b1',2,'write','public','user',{'marker':-1}),tpe.Event('b2',3,'connect','service','user',{'marker':-1}),tpe.Event('attack',4,'probe','protected','user',{'marker':0},1,'scaling')]
    sel=tpe.Selector('probe','protected','user'); rules=[tpe.Rule('D_TARGET',100,tpe.DENY,sel)]
    for i in range(n_units-5): rules.append(tpe.Rule(f'A_DISTRACTOR_{i:02d}',10,tpe.ALLOW,sel,tpe.Guard(comparisons=(('marker','==',i+1),))))
    return trace,tpe.PolicyVersion('RQ2_SCALING',1,tuple(rules))
def unit_info(trace,policy,horizon=4):
    start=max(0,len(trace)-horizon); eps=list(range(start,len(trace))); rids=[r.rid for r in policy.rules if r.selector.matches(trace[-1])]; return eps,rids,[f'e:{i}' for i in eps]+[f'r:{r}' for r in rids]
def predictor(trace,policy,eps,rids):
    m=len(eps)+len(rids)
    def f(X):
        out=[]
        for bits in np.asarray(X).reshape(-1,m):
            c=tpe._class_under_mask(trace,policy,eps,rids,[int(v>=.5) for v in bits]); out.append([1.0 if c==q else 0.0 for q in CLASSES])
        return np.asarray(out)
    return f
def run_one(n_units,repeat,lime_samples):
    trace,policy=make_scaling_case(n_units); factual=tpe.reference_eval(trace,policy); eps,rids,units=unit_info(trace,policy); assert len(units)==n_units
    f=predictor(trace,policy,eps,rids); target=CLASSES.index(factual.alert_class); x=np.ones((1,n_units)); bg=np.zeros((1,n_units))
    t0=time.perf_counter_ns(); ex=tpe.min_explain_bruteforce(trace,policy,horizon=4,max_units=18); intrinsic=(time.perf_counter_ns()-t0)/1000
    t0=time.perf_counter_ns(); shap.KernelExplainer(f,bg).shap_values(x,nsamples=min(2**n_units,1024),silent=True); shap_us=(time.perf_counter_ns()-t0)/1000
    lime_us=np.nan
    if LimeTabularExplainer is not None:
        rng=np.random.default_rng(20260816+1000*repeat+n_units); train_rows=min(max(256,8*n_units),2048); train=rng.integers(0,2,size=(train_rows,n_units)).astype(float); train[0,:]=0; train[1,:]=1
        le=LimeTabularExplainer(train,mode='classification',feature_names=units,categorical_features=list(range(n_units)),categorical_names={i:['0','1'] for i in range(n_units)},class_names=CLASSES,discretize_continuous=False,random_state=20260816+repeat)
        t0=time.perf_counter_ns(); le.explain_instance(np.ones(n_units),f,labels=(target,),num_features=n_units,num_samples=lime_samples); lime_us=(time.perf_counter_ns()-t0)/1000
    return {'n_units':n_units,'repeat':repeat,'intrinsic_checks':ex.checks,'intrinsic_core_size':len(ex.event_positions)+len(ex.rule_ids),'intrinsic_us':intrinsic,'shap_us':shap_us,'lime_us':lime_us,'implementation_limit':18}
def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--min-units',type=int,default=5); ap.add_argument('--max-units',type=int,default=18); ap.add_argument('--repeats',type=int,default=3); ap.add_argument('--lime-samples',type=int,default=5000); a=ap.parse_args()
    if a.max_units>18: raise SystemExit('Current exact implementation is intentionally bounded at 18 units.')
    df=pd.DataFrame(run_one(n,r,a.lime_samples) for n in range(a.min_units,a.max_units+1) for r in range(a.repeats)); df.to_csv(RAW/'rq2_scaling.csv',index=False)
    s=df.groupby('n_units',as_index=False).agg(intrinsic_checks=('intrinsic_checks','first'),intrinsic_core_size=('intrinsic_core_size','first'),intrinsic_us_mean=('intrinsic_us','mean'),intrinsic_us_median=('intrinsic_us','median'),shap_us_mean=('shap_us','mean'),shap_us_median=('shap_us','median'),lime_us_mean=('lime_us','mean'),lime_us_median=('lime_us','median')); s.to_csv(SUMMARY/'rq2_scaling_summary.csv',index=False); print(s.to_string(index=False))
if __name__=='__main__': main()
