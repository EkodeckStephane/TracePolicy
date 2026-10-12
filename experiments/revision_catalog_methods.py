"""Five-method explanation comparison on an externally frozen case catalog.

No dataset fitting or alert resampling occurs here. Alibi runs in its own env.
Use --methods tracepolicy,kernelshap,lime,ffa in the main environment and
--methods anchors --seeds 11,23,47 in the Alibi environment, same output folder.
"""
from pathlib import Path
import sys,json,time,argparse,hashlib,csv,itertools
from dataclasses import asdict,fields
from importlib.metadata import version,PackageNotFoundError
import numpy as np
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'src'),str(ROOT/'experiments')]
import trace_policy_engine as tpe
from revision_extended_methods import independent_table,minimal_masks_dp,selected_mask,CLASSES
from revision_methods import explain_anchor,ffa_from_cores
from revision_proof import certify_fixed_set

def parse_guard(payload):
    data=dict(payload or {})
    unknown=set(data)-{f.name for f in fields(tpe.Guard)}
    if unknown:raise ValueError('unknown guard fields: '+repr(sorted(unknown)))
    for key in ['comparisons','state_comparisons']:
        if key in data:data[key]=tuple(tuple(c) for c in data[key])
    for key in ['all_of','any_of','none_of']:
        if key in data:data[key]=tuple(parse_guard(g) for g in data[key])
    if 'seq_actions' in data:data['seq_actions']=tuple(data['seq_actions'])
    return tpe.Guard(**data)

def parse_policy(payload):
    if not isinstance(payload['version'],int) or isinstance(payload['version'],bool):raise ValueError('policy version must be an integer')
    if any(not isinstance(r['priority'],int) or isinstance(r['priority'],bool) for r in payload['rules']):raise ValueError('rule priorities must be integers; no silent normalization')
    return tpe.PolicyVersion(payload['pid'],int(payload['version']),tuple(tpe.Rule(r['rid'],int(r['priority']),r['effect'],tpe.Selector(**r.get('selector',{})),parse_guard(r.get('guard'))) for r in payload['rules']),float(payload.get('created_at',0)))

def load_catalog(path):
    raw=json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(raw,dict) or not isinstance(raw.get('cases'),list):raise ValueError('catalog must be object with policy and cases')
    policy=parse_policy(raw['policy']);cases=[]
    actual_policy_hash=hashlib.sha256(json.dumps(asdict(policy),sort_keys=True).encode()).hexdigest()
    if raw.get('policy_content_sha256') and raw['policy_content_sha256']!=actual_policy_hash:raise ValueError('frozen policy content hash mismatch')
    for index,c in enumerate(raw['cases']):
        if c.get('initial_state'):raise ValueError('custom initial state is outside prototype explanation scope')
        trace=[tpe.Event(**e) for e in c['trace']]
        if not trace:raise ValueError('empty external case')
        if c.get('event_id') is not None and c['event_id']!=trace[-1].eid:raise ValueError('catalog event identity differs from current trace event')
        h=int(c['horizon']);eps,rids,units=tpe.explanation_unit_info(trace,policy,h)
        if len(units)>18:raise ValueError('external explanatory domain exceeds exact cap; never truncate silently')
        factual=tpe.reference_eval(trace,policy).alert_class
        if factual==tpe.NOALERT:raise ValueError('catalog contains NoAlert; sampling amendment belongs to frozen producer')
        if c.get('target_class') and c['target_class']!=factual:raise ValueError('catalog factual target mismatch')
        if c.get('units') and c['units']!=units:raise ValueError('catalog declared unit domain mismatch')
        cases.append(dict(case=int(c.get('case',index)),trace=trace,horizon=h,event_id=c.get('event_id',trace[-1].eid),scenario=c.get('scenario',c.get('stratum','external_alert')),target_class=factual,metadata={k:v for k,v in c.items() if k not in ['trace','initial_state','units']}))
    ids=[c['case'] for c in cases]
    if len(ids)!=len(set(ids)):raise ValueError('duplicate case identifiers')
    return raw,policy,cases

def ranked_prefix(trace,policy,horizon,ranking):
    selected=set()
    if tpe.exact_sufficiency_of_selected(trace,policy,selected,horizon):return selected
    for unit in ranking:
        selected.add(unit)
        if tpe.exact_sufficiency_of_selected(trace,policy,selected,horizon):return selected
    raise AssertionError('full-unit prefix does not certify factual class')

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--case-catalog',type=Path,required=True);ap.add_argument('--output',type=Path,required=True)
    ap.add_argument('--methods',default='tracepolicy,kernelshap,lime,ffa');ap.add_argument('--seeds',default='11,23,47');ap.add_argument('--seed-base',type=int,default=20261012);ap.add_argument('--timeout-s',type=float,default=120);ap.add_argument('--lime-samples',type=int,default=5000);ap.add_argument('--shap-samples',type=int,default=1024);args=ap.parse_args()
    methods=args.methods.split(',');allowed={'tracepolicy','kernelshap','lime','ffa','anchors'}
    if set(methods)-allowed:raise ValueError('unknown methods')
    raw,policy,cases=load_catalog(args.case_catalog);out=args.output;out.mkdir(parents=True,exist_ok=True);tables=out/'oracle_tables';tables.mkdir(exist_ok=True)
    # Import libraries before case timing and record cold import once separately.
    libraries={};import_cost={}
    for method in methods:
        started=time.perf_counter()
        if method=='kernelshap':import shap;libraries[method]=shap
        if method=='lime':from lime.lime_tabular import LimeTabularExplainer;libraries[method]=LimeTabularExplainer
        if method=='anchors':from alibi.explainers import AnchorTabular
        import_cost[method]=time.perf_counter()-started
    packages={}
    for package in ['numpy','scipy','scikit-learn','shap','lime','alibi']:
        try:packages[package]=version(package)
        except PackageNotFoundError:packages[package]=None
    manifest=dict(catalog_sha256=hashlib.sha256(args.case_catalog.read_bytes()).hexdigest(),catalog_provenance={k:v for k,v in raw.items() if k!='cases'},policy_sha256=hashlib.sha256(json.dumps(asdict(policy),sort_keys=True).encode()).hexdigest(),case_count=len(cases),arguments={k:str(v) if isinstance(v,Path) else v for k,v in vars(args).items()},packages=packages,python=sys.version,cold_import_s=import_cost,mask_encoding='integer k retains unit i iff k & (1<<i)',oracle_backend='native prediction memoization begins empty per method/case; FFA independent table caches event-mask state; exact prefix/proof calls canonical evaluator',limits='declared external alert sample; domain-relative validity; cached backends/separate environments preclude timing superiority inference')
    for method in methods:(out/f'{method}_manifest.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
    rows={method:[] for method in methods}
    for c in cases:
        tr=c['trace'];h=c['horizon'];case=c['case'];eps,rids,units=tpe.explanation_unit_info(tr,policy,h);m=len(units);target=c['target_class'];yi=CLASSES.index(target)
        base=dict(case=case,event_id=c['event_id'],scenario=c['scenario'],target_class=target,n_units=m,units=units,horizon=h,case_metadata=c['metadata'])
        table_start=time.perf_counter()
        try:
            labels,nqueries=independent_table(tr,policy,eps,rids,table_start+args.timeout_s)
            core_masks,sufficient=minimal_masks_dp(labels==yi,m);enumeration_s=time.perf_counter()-table_start
        except Exception as error:
            for method in methods:
                rows[method].append(dict(**base,method=method,status='timeout' if isinstance(error,TimeoutError) else 'failed',phase='independent_domain_audit',error=repr(error),elapsed_s=time.perf_counter()-table_start))
                (out/f'{method}.json').write_text(json.dumps(rows[method],indent=2),encoding='utf-8')
            continue
        if labels[-1]!=yi:raise AssertionError('all-retained factual identity fails')
        cores=[{u for i,u in enumerate(units) if mask&(1<<i)} for mask in core_masks]
        tablepath=tables/f'case_{case:03d}.npz'
        if tablepath.exists():
            with np.load(tablepath,allow_pickle=False) as old:
                if not np.array_equal(old['labels'],labels) or not np.array_equal(old['units'],np.asarray(units)) or not np.array_equal(old['minimal_core_masks'],np.asarray(core_masks)):raise AssertionError('cross-environment independent oracle/core mismatch')
        else:np.savez_compressed(tablepath,labels=labels,units=np.asarray(units),minimal_core_masks=np.asarray(core_masks,dtype=np.int64),class_names=np.asarray(CLASSES))
        for method in methods:
            method_seeds=list(map(int,args.seeds.split(','))) if method=='anchors' else [args.seed_base+case]
            for seed in method_seeds:
                record=dict(**base,method=method,seed=seed,core_count=len(cores),independent_audit_s=enumeration_s)
                start=time.perf_counter();deadline=start+args.timeout_s;counts={'requests':0,'canonical':0};cache={}
                def predict_labels(X):
                    answer=[]
                    for values in np.asarray(X).reshape(-1,m):
                        if time.perf_counter()>deadline:raise TimeoutError('native oracle callback deadline')
                        mask=tuple(int(v>=.5) for v in values);counts['requests']+=1
                        if mask not in cache:cache[mask]=CLASSES.index(tpe._class_under_mask(tr,policy,eps,rids,mask));counts['canonical']+=1
                        answer.append(cache[mask])
                    return np.asarray(answer,int)
                def predict_scores(X):return np.eye(len(CLASSES))[predict_labels(X)]
                try:
                    np.random.seed(seed)
                    if method=='tracepolicy':
                        ex=tpe.min_explain_bruteforce(tr,policy,h);selected={f'e:{i}' for i in ex.event_positions}|{f'r:{r}' for r in ex.rule_ids}
                        end=time.perf_counter();record.update(setup_s=0,attribution_s=0,selection_certification_s=end-start,fixed_set_proof_s=0,total_s=end-start,proof=dict(sufficient=True,minimal=True,witnesses=ex.witnesses,checks=ex.checks),intrinsic_queries=ex.checks)
                    elif method=='ffa':
                        weights=ffa_from_cores(cores,units);ranking=[units[i] for i in np.argsort(-weights,kind='stable')];attr_end=time.perf_counter();selected=set();sm=0
                        if not sufficient[0]:
                            for unit in ranking:
                                selected.add(unit);sm|=1<<units.index(unit)
                                if sufficient[sm]:break
                        select_end=time.perf_counter();proof=certify_fixed_set(tr,policy,selected,h);end=time.perf_counter()
                        record.update(enumeration_s=enumeration_s,enumeration_queries=nqueries,weights=weights.tolist(),ranking=ranking,all_minimal_cores=[sorted(core) for core in cores],attribution_s=attr_end-start,selection_certification_s=select_end-attr_end,fixed_set_proof_s=end-select_end,total_s=enumeration_s+end-start,proof=proof)
                    elif method=='anchors':
                        if m>16:raise ValueError('native complete-domain Anchor population exceeds16 units; unsupported, no truncation')
                        native=explain_anchor(predict_labels,units,seed,.95);native_end=time.perf_counter();selected=set(native['selected']);proof=certify_fixed_set(tr,policy,selected,h);end=time.perf_counter()
                        record.update(native=native,native_s=native_end-start,fixed_set_proof_s=end-native_end,total_s=end-start,proof=proof)
                    else:
                        if method=='kernelshap':explainer=libraries[method].KernelExplainer(predict_scores,np.zeros((1,m)))
                        else:
                            background=np.array(list(itertools.product((0,1),repeat=m)),float)
                            explainer=libraries[method](background,mode='classification',feature_names=units,categorical_features=list(range(m)),categorical_names={i:['removed','retained'] for i in range(m)},class_names=CLASSES,discretize_continuous=False,random_state=seed)
                        setup_end=time.perf_counter()
                        if method=='kernelshap':
                            value=explainer.shap_values(np.ones((1,m)),nsamples=min(2**m,args.shap_samples),silent=True);weights=np.asarray(value)[0,:,yi] if not isinstance(value,list) else np.asarray(value[yi])[0]
                        else:
                            explanation=explainer.explain_instance(np.ones(m),predict_scores,labels=(yi,),num_features=m,num_samples=args.lime_samples);w=dict(explanation.local_exp[yi]);weights=np.asarray([w.get(i,0.) for i in range(m)]);record['local_score']=float(explanation.score)
                        attr_end=time.perf_counter();ranking=[units[i] for i in np.argsort(-np.abs(weights),kind='stable')];selected=ranked_prefix(tr,policy,h,ranking);select_end=time.perf_counter();proof=certify_fixed_set(tr,policy,selected,h);end=time.perf_counter()
                        record.update(setup_s=setup_end-start,attribution_s=attr_end-setup_end,selection_certification_s=select_end-attr_end,fixed_set_proof_s=end-select_end,total_s=end-start,weights=weights.tolist(),ranking=ranking,proof=proof)
                    sm=selected_mask(selected,units)
                    record.update(status='ok',selected=sorted(selected),sufficient=bool(sufficient[sm]),minimal=sm in core_masks,oracle_requests=counts['requests'],canonical_queries=counts['canonical'])
                    # Validate every returned proof witness independently.
                    for released,witness in record['proof']['witnesses'].items():
                        if not all(witness[u] for u in selected-{released}):raise AssertionError('invalid retained-unit witness')
                        wm=sum(1<<i for i,u in enumerate(units) if witness[u])
                        if labels[wm]==yi:raise AssertionError('witness does not change alert class')
                except Exception as error:record.update(status='timeout' if isinstance(error,TimeoutError) else 'failed',error=repr(error),elapsed_s=time.perf_counter()-start)
                rows[method].append(record);(out/f'{method}.json').write_text(json.dumps(rows[method],indent=2),encoding='utf-8')
        print(f'case {case}: completed {",".join(methods)}',flush=True)
    for method,data in rows.items():
        columns=sorted({k for row in data for k in row})
        with (out/f'{method}.csv').open('w',newline='',encoding='utf-8') as stream:
            writer=csv.DictWriter(stream,fieldnames=columns);writer.writeheader();writer.writerows({k:json.dumps(v) if isinstance(v,(dict,list)) else v for k,v in row.items()} for row in data)
        summary=dict(cases=len(cases),rows=len(data),statuses={s:sum(r['status']==s for r in data) for s in {r['status'] for r in data}},sufficient=sum(bool(r.get('sufficient')) for r in data),minimal=sum(bool(r.get('minimal')) for r in data))
        (out/f'{method}_summary.json').write_text(json.dumps(summary,indent=2),encoding='utf-8');print(method,json.dumps(summary))
if __name__=='__main__':main()
