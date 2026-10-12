"""Retrospective phased scaling, canonical oracle query counts and deadlines.

Uses controlled distractor family only: this is not general-case scalability.
"""
from pathlib import Path
import sys,json,time,argparse,itertools
import numpy as np
import pandas as pd
from importlib.metadata import version
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'src'),str(ROOT/'experiments')]
import trace_policy_engine as tpe
from run_rq2_scaling import make_scaling_case
from run_rq2_local_lab_explanations import smallest_sufficient
from revision_proof import certify_fixed_set
import shap
from lime.lime_tabular import LimeTabularExplainer
CLASSES=[tpe.NOALERT,tpe.VIOLATION,tpe.CONFLICT,tpe.GAP]

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--min-units',type=int,default=5);ap.add_argument('--max-units',type=int,default=18);ap.add_argument('--repeats',type=int,default=3);ap.add_argument('--timeout-s',type=float,default=60);ap.add_argument('--lime-samples',type=int,default=5000);ap.add_argument('--proof-matched',action='store_true');args=ap.parse_args()
    out=ROOT/('results/revision/scaling_proofmatched' if args.proof_matched else 'results/revision/scaling');out.mkdir(parents=True,exist_ok=True);rows=[]
    original=tpe._class_under_mask; clock={'queries':0,'deadline':float('inf')}
    def counted(*a,**kw):
        if time.perf_counter()>clock['deadline']:raise TimeoutError('per-method canonical-oracle deadline exceeded')
        clock['queries']+=1;return original(*a,**kw)
    tpe._class_under_mask=counted
    for m in range(args.min_units,args.max_units+1):
        tr,p=make_scaling_case(m);eps,rids,units=tpe.explanation_unit_info(tr,p,4);target=tpe.reference_eval(tr,p).alert_class;yi=CLASSES.index(target)
        # Compute each class once, not once per output class.
        def pred(X):
            labels=[counted(tr,p,eps,rids,[int(x>=.5) for x in b]) for b in np.asarray(X).reshape(-1,m)]
            return np.asarray([[float(y==c) for c in CLASSES] for y in labels])
        for repeat in range(args.repeats):
            seed=20261011+1000*repeat+m
            for method in ['TracePolicy','KernelSHAP','LIME']:
                np.random.seed(seed);clock.update(queries=0,deadline=time.perf_counter()+args.timeout_s);row=dict(n_units=m,repeat=repeat,seed=seed,method=method,timeout_s=args.timeout_s,policy_version=p.version)
                try:
                    t0=time.perf_counter()
                    if method=='TracePolicy':
                        t1=t2=t0;q1=q2=0;ex=tpe.min_explain_bruteforce(tr,p,4);selected={f'e:{i}' for i in ex.event_positions}|{f'r:{r}' for r in ex.rule_ids}
                    else:
                        if method=='KernelSHAP':explainer=shap.KernelExplainer(pred,np.zeros((1,m)))
                        else:
                            train=np.random.default_rng(seed).integers(0,2,size=(max(256,8*m),m)).astype(float);train[0]=0;train[1]=1
                            explainer=LimeTabularExplainer(train,mode='classification',feature_names=units,categorical_features=list(range(m)),categorical_names={i:['0','1'] for i in range(m)},class_names=CLASSES,discretize_continuous=False,random_state=seed)
                        t1=time.perf_counter();q1=clock['queries']
                        if method=='KernelSHAP':
                            sv=explainer.shap_values(np.ones((1,m)),nsamples=min(2**m,1024),silent=True);weights=np.asarray(sv)[0,:,yi] if not isinstance(sv,list) else np.asarray(sv[yi])[0]
                        else:
                            exp=explainer.explain_instance(np.ones(m),pred,labels=(yi,),num_features=m,num_samples=args.lime_samples);ws=dict(exp.local_exp[yi]);weights=np.asarray([ws.get(i,0) for i in range(m)]);row['local_score']=float(exp.score)
                        t2=time.perf_counter();q2=clock['queries'];rank=[units[i] for i in np.argsort(-np.abs(weights),kind='stable')]
                        _,selected=smallest_sufficient(tr,p,rank,4);selected=set(selected)
                    t3=time.perf_counter();q3=clock['queries']
                    row.update(status='ok',setup_s=t1-t0,attribution_s=t2-t1,selection_certification_s=t3-t2,total_s=t3-t0,setup_queries=q1,attribution_queries=q2-q1,selection_certification_queries=q3-q2,total_queries=q3,selected=sorted(selected),size=len(selected))
                    if args.proof_matched:
                        if method=='TracePolicy':proof=dict(minimal=True,witnesses=ex.witnesses)
                        else:proof=certify_fixed_set(tr,p,selected,4)
                        t4=time.perf_counter();q4=clock['queries']
                        row.update(fixed_set_proof_s=t4-t3 if method!='TracePolicy' else 0.,proof_total_s=t4-t0 if method!='TracePolicy' else t3-t0,fixed_set_proof_queries=q4-q3,proof_total_queries=q4,proof_minimal=proof['minimal'],proof_witness_count=len(proof['witnesses']))
                    # Validation is untimed, and not part of a method's delivered set.
                    clock['deadline']=time.perf_counter()+args.timeout_s
                    suff=tpe.exact_sufficiency_of_selected(tr,p,selected,4)
                    minimal=suff and all(not tpe.exact_sufficiency_of_selected(tr,p,selected-{u},4) for u in selected)
                    row.update(sufficient=bool(suff),minimal=bool(minimal),validation_queries=clock['queries']-(q4 if args.proof_matched else q3))
                except TimeoutError as error:row.update(status='timeout',error=str(error),elapsed_s=time.perf_counter()-t0,queries=clock['queries'])
                except Exception as error:row.update(status='failed',error=repr(error))
                rows.append(row);(out/'scaling.json').write_text(json.dumps(rows,indent=2),encoding='utf-8');print(f'{m} {repeat} {method} {row["status"]}',flush=True)
    tpe._class_under_mask=original
    df=pd.DataFrame(rows);df.to_csv(out/'scaling.csv',index=False)
    good=df[df.status=='ok'];good.groupby(['n_units','method']).agg(runs=('status','size'),total_s_median=('total_s','median'),total_s_min=('total_s','min'),total_s_max=('total_s','max'),total_queries_median=('total_queries','median'),sufficient_rate=('sufficient','mean'),minimal_rate=('minimal','mean')).to_csv(out/'scaling_summary.csv')
    if args.proof_matched:good.groupby(['n_units','method']).agg(runs=('status','size'),proof_total_s_median=('proof_total_s','median'),proof_total_s_min=('proof_total_s','min'),proof_total_s_max=('proof_total_s','max'),proof_total_queries_median=('proof_total_queries','median'),proof_minimal_rate=('proof_minimal','mean')).to_csv(out/'proofmatched_summary.csv')
    (out/'run_manifest.json').write_text(json.dumps(dict(arguments=vars(args),python=sys.version,packages={p:version(p) for p in ['numpy','pandas','scipy','scikit-learn','shap','lime']},case_family='four events; one active deny; false-guard selector-compatible distractor rules',lime_background='seeded uniform binary sample max(256,8*m) rows; force allzero/allone rows',status_counts=df.status.value_counts().to_dict()),indent=2),encoding='utf-8')
if __name__=='__main__':main()
