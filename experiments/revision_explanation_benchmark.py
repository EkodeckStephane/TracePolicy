"""Revision-only exhaustive oracle audit and phased explanation benchmark.

This is a retrospective controlled stress test, not a new held-out confirmation.
Run: python experiments/revision_explanation_benchmark.py --output results/revision
"""
from pathlib import Path
import sys, itertools, time, json, argparse, platform
import numpy as np
from importlib.metadata import version,PackageNotFoundError
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'src'),str(ROOT/'vendor'),str(ROOT/'experiments')]
import trace_policy_engine as tpe
CLASSES=[tpe.NOALERT,tpe.VIOLATION,tpe.CONFLICT,tpe.GAP]

def controlled_cases():
    E=lambda i,a: tpe.Event(str(i),float(i),a,'resource','user')
    R=lambda rid,effect=tpe.DENY,guard=tpe.Guard(),selector=tpe.Selector('act'): tpe.Rule(rid,10,effect,selector,guard)
    cases=[
      ('instant_violation',[E(0,'noise'),E(1,'act')],[R('D')]),
      ('conflict',[E(0,'act')],[R('D'),R('A',tpe.ALLOW)]),
      ('gap',[E(0,'other')],[R('D')]),
      ('temporal_seq',[E(0,'start'),E(1,'noise'),E(2,'act')],[R('SEQ',guard=tpe.Guard(seq_actions=('start','act'),seq_horizon=3))]),
      ('multiple_rules',[E(0,'act')],[R('D1'),R('D2')]),
      ('multiple_events',[E(0,'start'),E(1,'start'),E(2,'act')],[R('SEEN',guard=tpe.Guard(seen_action='start',seen_horizon=3))]),
      ('distractors',[E(0,'noise'),E(1,'noise'),E(2,'act')],[R('D'),R('IRRELEVANT',selector=tpe.Selector('other'))]),
      ('state_fixed_context',[E(0,'start'),E(1,'act')],[R('STATE',guard=tpe.Guard(state_comparisons=(('action_count:start','>=',1),)))]),
      ('count_threshold',[E(0,'start'),E(1,'start'),E(2,'act')],[R('COUNT',guard=tpe.Guard(count_action='start',count_horizon=3,count_threshold=2))]),
    ]
    return [(name,tr,tpe.PolicyVersion(name,1,tuple(rs)),1 if name=='state_fixed_context' else len(tr)) for name,tr,rs in cases]

def independent_table(trace,policy,eps,rids):
    """Construct interventions independently of engine masking/explanation code."""
    units=[f'e:{i}' for i in eps]+[f'r:{r}' for r in rids]
    table={}
    for bits in itertools.product((0,1),repeat=len(units)):
        retained={eps[j] for j in range(len(eps)) if bits[j]}
        masked=[e if i not in eps or i in retained else tpe.Event.stutter_like(e) for i,e in enumerate(trace)]
        retained_rules={rid for j,rid in enumerate(rids) if bits[len(eps)+j]}
        rules=tuple(r for r in policy.rules if r.rid not in rids or r.rid in retained_rules)
        altered=tpe.PolicyVersion(policy.pid,policy.version,rules)
        table[bits]=tpe.reference_eval(masked,altered).alert_class
    return units,table

def sufficient(selected,units,table,target):
    indexes=[units.index(u) for u in selected]
    return all(y==target for mask,y in table.items() if all(mask[i] for i in indexes))

def all_minimal_cores(units,table,target):
    cores=[]
    for k in range(len(units)+1):
        for c in itertools.combinations(units,k):
            c=set(c)
            if not any(s<=c for s in cores) and sufficient(c,units,table,target): cores.append(c)
    return cores

def certify_ranking(rank,units,table,target,checker=None):
    selected=set()
    check=checker or (lambda c: sufficient(c,units,table,target))
    if check(selected): return selected
    for u in rank:
        selected.add(u)
        if check(selected): return selected
    raise ValueError('ranking fails factual-domain sufficiency')

def validate(selected,units,table,target,cores):
    return dict(sufficient=sufficient(selected,units,table,target),
                minimal=any(selected==c for c in cores),size=len(selected),
                selected=sorted(selected),valid_alternative_count=len(cores))

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--output',default='results/revision'); ap.add_argument('--seeds',default='11,23,47'); ap.add_argument('--samples',default='128,512,2048'); ap.add_argument('--kernel-scales',default='0.5,1,1.5'); ap.add_argument('--background-probabilities',default='0.25,0.5'); args=ap.parse_args()
    out=ROOT/args.output; out.mkdir(parents=True,exist_ok=True)
    rows=[]; audits=[]
    try: import shap
    except ImportError: shap=None
    try: from lime.lime_tabular import LimeTabularExplainer
    except ImportError: LimeTabularExplainer=None
    for name,tr,pol,horizon in controlled_cases():
        eps,rids,units=tpe.explanation_unit_info(tr,pol,horizon)
        target=tpe.reference_eval(tr,pol).alert_class
        _,table=independent_table(tr,pol,eps,rids); cores=all_minimal_cores(units,table,target)
        assert table[(1,)*len(units)]==target
        assert all(tpe._class_under_mask(tr,pol,eps,rids,b)==y for b,y in table.items())
        audits.append(dict(case=name,target=target,units=units,all_minimal_cores=[sorted(c) for c in cores],masks=[dict(bits=b,target=y) for b,y in table.items()]))
        start=time.perf_counter(); ex=tpe.min_explain_bruteforce(tr,pol,horizon); elapsed=time.perf_counter()-start
        selected={f'e:{i}' for i in ex.event_positions}|{f'r:{r}' for r in ex.rule_ids}
        row=dict(case=name,method='TracePolicy',status='ok',setup_s=0,attribution_s=0,selection_certification_s=elapsed,total_s=elapsed,**validate(selected,units,table,target,cores)); rows.append(row)
        assert row['sufficient'] and row['minimal']
        for control in ['DeterministicRanking','RandomRanking']:
            for seed in ([0] if control=='DeterministicRanking' else [11,23,47]):
                t0=time.perf_counter(); ranking=units.copy()
                if control=='RandomRanking': np.random.default_rng(seed).shuffle(ranking)
                t1=time.perf_counter()
                selected=certify_ranking(ranking,units,table,target,lambda c:tpe.exact_sufficiency_of_selected(tr,pol,c,horizon))
                t2=time.perf_counter()
                rows.append(dict(case=name,method=control,seed=seed,status='ok',ranking=ranking,setup_s=0,attribution_s=t1-t0,selection_certification_s=t2-t1,total_s=t2-t0,**validate(selected,units,table,target,cores)))
        def pred(X):
            labels=[tpe._class_under_mask(tr,pol,eps,rids,[int(v>=.5) for v in b]) for b in np.asarray(X).reshape(-1,len(units))]
            return np.array([[float(y==c) for c in CLASSES] for y in labels])
        yi=CLASSES.index(target); m=len(units); train=np.array(list(table),float)
        for method in ['KernelSHAP','LIME']:
            configs=[(s,n,w,p) for s in map(int,args.seeds.split(',')) for n in map(int,args.samples.split(',')) for w in map(float,args.kernel_scales.split(',')) for p in map(float,args.background_probabilities.split(','))] if method=='LIME' else [(11,min(2**m,1024),1,.5)]
            for seed,n,width_scale,background_probability in configs:
                row=dict(case=name,method=method,seed=seed,num_samples=n,kernel_width_scale=width_scale,background_probability=background_probability)
                if (method=='KernelSHAP' and shap is None) or (method=='LIME' and LimeTabularExplainer is None):
                    rows.append(dict(**row,status='dependency_missing')); continue
                try:
                    np.random.seed(seed); t0=time.perf_counter()
                    if method=='KernelSHAP':
                        explainer=shap.KernelExplainer(pred,np.zeros((1,m)))
                    else:
                        background=train if background_probability==.5 else (np.random.default_rng(seed).random((512,m))<background_probability).astype(float)
                        explainer=LimeTabularExplainer(background,mode='classification',feature_names=units,categorical_features=list(range(m)),categorical_names={i:['0','1'] for i in range(m)},class_names=CLASSES,discretize_continuous=False,random_state=seed,kernel_width=width_scale*np.sqrt(m)*.75)
                    t1=time.perf_counter()
                    if method=='KernelSHAP':
                        sv=explainer.shap_values(np.ones((1,m)),nsamples=n,silent=True)
                        weights=np.asarray(sv)[0,:,yi] if not isinstance(sv,list) else np.asarray(sv[yi])[0]
                    else:
                        exp=explainer.explain_instance(np.ones(m),pred,labels=(yi,),num_features=m,num_samples=n)
                        ws=dict(exp.local_exp[yi]); weights=np.array([ws.get(i,0.) for i in range(m)])
                        row['local_training_score']=float(exp.score)
                    t2=time.perf_counter(); rank=[units[i] for i in np.argsort(-np.abs(weights),kind='stable')]
                    selected=certify_ranking(rank,units,table,target,lambda c:tpe.exact_sufficiency_of_selected(tr,pol,c,horizon)); t3=time.perf_counter()
                    row.update(status='ok',weights=weights.tolist(),ranking=rank,setup_s=t1-t0,attribution_s=t2-t1,selection_certification_s=t3-t2,total_s=t3-t0,**validate(selected,units,table,target,cores))
                    if method=='LIME':
                        # Untimed full-domain validation, not held-out ML generalization.
                        surrogate=float(exp.intercept[yi])+train@weights
                        row['full_domain_surrogate_mse']=float(np.mean((surrogate-pred(train)[:,yi])**2))
                except Exception as error: row.update(status='failed',error=repr(error))
                rows.append(row)
        (out/'benchmark.json').write_text(json.dumps(rows,indent=2),encoding='utf-8')
        (out/'domain_audit.json').write_text(json.dumps(audits,indent=2),encoding='utf-8')
    packages={}
    for package in ['numpy','pandas','scipy','scikit-learn','shap','lime']:
        try: packages[package]=version(package)
        except PackageNotFoundError: packages[package]=None
    (out/'environment.json').write_text(json.dumps(dict(python=sys.version,platform=platform.platform(),shap=getattr(shap,'__version__',None),lime_available=LimeTabularExplainer is not None,packages=packages,arguments=vars(args)),indent=2),encoding='utf-8')
    print(json.dumps(dict(cases=len(audits),rows=len(rows),statuses={s:sum(r['status']==s for r in rows) for s in {r['status'] for r in rows}})))

if __name__=='__main__': main()
