"""Extend native Anchors and exact FFA adaptation to the same 120 Docker strata.

This retrospective campaign loads frozen selections; it does not resample cases.
No SHAP import is needed in the separate Alibi/NumPy environment.
Truth mask integer k retains unit i iff k & (1 << i). Tables are saved as npz.
"""
from pathlib import Path,PureWindowsPath
import sys,json,time,hashlib,csv,argparse,platform
from importlib.metadata import version,PackageNotFoundError
from dataclasses import asdict
import numpy as np
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'src'),str(ROOT/'experiments')]
import trace_policy_engine as tpe
from local_lab_adapter import load_gateway_events,lab_policy
from revision_methods import explain_anchor,ffa_from_cores
from revision_proof import certify_fixed_set
CLASSES=[tpe.NOALERT,tpe.VIOLATION,tpe.CONFLICT,tpe.GAP]

def minimal_masks_dp(target_matches,n_units):
    """All minimal positive-retention explanations, O(m 2**m), no 3**m loop."""
    matches=np.asarray(target_matches,dtype=bool)
    if matches.shape!=(1<<n_units,):raise ValueError('complete truth table required')
    bad=~matches.copy()
    for bit in range(n_units):
        blocks=bad.reshape(-1,2,1<<bit)
        blocks[:,0,:]|=blocks[:,1,:]
    sufficient=~bad
    minimal=sufficient.copy()
    masks=np.arange(1<<n_units,dtype=np.int64)
    for bit in range(n_units):
        has=(masks&(1<<bit))!=0
        minimal[has]&=~sufficient[masks[has]^(1<<bit)]
    return np.flatnonzero(minimal).tolist(),sufficient

def independent_table(trace,policy,eps,rids,deadline=float('inf')):
    """Independent intervention construction, using only canonical decision eval.

    State is cached once per event mask; it never depends on enabled rule units.
    This optimization is part of the timed FFA enumeration, not a free oracle.
    """
    ne=len(eps);nr=len(rids);labels=np.empty(1<<(ne+nr),dtype=np.uint8)
    other_events=set(range(len(trace)))-set(eps)
    fixed_rules={r.rid for r in policy.rules}-set(rids)
    rule_sets=[fixed_rules|{rids[j] for j in range(nr) if k&(1<<j)} for k in range(1<<nr)]
    queries=0
    for emask in range(1<<ne):
        keep=other_events|{eps[j] for j in range(ne) if emask&(1<<j)}
        masked=[e if i in keep else tpe.Event.stutter_like(e) for i,e in enumerate(trace)]
        state=tpe.derive_state(masked)
        for rmask,enabled in enumerate(rule_sets):
            if time.perf_counter()>deadline:raise TimeoutError('independent table deadline')
            labels[emask|(rmask<<ne)]=CLASSES.index(tpe.reference_eval(masked,policy,enabled=enabled,state=state).alert_class)
            queries+=1
    return labels,queries

def selected_mask(selected,units):
    if set(selected)-set(units):raise ValueError('selected units outside shared domain')
    return sum(1<<i for i,u in enumerate(units) if u in selected)

def load_frozen_cases(manifest,lab):
    p=lab_policy();cases=[];checked={};inputs={}
    for old_path,digest in manifest['input_sha256'].items():
        path=lab/PureWindowsPath(old_path).name
        if not path.exists():raise FileNotFoundError(path)
        actual=hashlib.sha256(path.read_bytes()).hexdigest()
        if actual!=digest:raise ValueError(f'input hash mismatch: {path.name}')
        inputs[str(path.resolve())]=actual
    policy_hash=hashlib.sha256(json.dumps(asdict(p),sort_keys=True).encode()).hexdigest()
    if policy_hash!=manifest['policy_sha256']:raise ValueError('frozen policy differs')
    for row in manifest['strata']:
        if row['status']!='selected':continue
        seed=row['seed']
        if seed not in checked:
            truth={r['sid']:{'label':int(r['label']),'scenario':r['scenario']} for r in csv.DictReader((lab/f'truth_{seed}.csv').open(newline=''))}
            checked[seed]=load_gateway_events(lab/f'access_{seed}.jsonl',truth)
        events=checked[seed];i=row['event_index'];e=events[i]
        if e.eid!=row['event_id'] or e.attack_type!=row['scenario']:raise ValueError('frozen case identity mismatch')
        h=manifest['arguments']['horizon'];trace=events[max(0,i-h+1):i+1]
        cases.append(dict(workload_seed=seed,event_index=i,event_id=e.eid,scenario=row['scenario'],trace=trace,horizon=h))
    # Original pipeline orders scenarios alphabetically then workloads ascending.
    cases.sort(key=lambda c:(c['scenario'],c['workload_seed']))
    if len(cases)!=120 or len({c['workload_seed'] for c in cases})!=30:raise ValueError('expected exact 120/30 workload coverage')
    return p,cases,inputs

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--method',choices=['anchors','ffa'],required=True)
    ap.add_argument('--lab-dir',type=Path,default=ROOT/'local_lab/results');ap.add_argument('--manifest',type=Path,default=ROOT/'results/revision/local_lab_proofmatched/run_manifest.json')
    ap.add_argument('--seeds',default='11,23,47');ap.add_argument('--timeout-s',type=float,default=120);ap.add_argument('--limit',type=int,default=0);ap.add_argument('--output',type=Path,default=ROOT/'results/revision/extended_methods');args=ap.parse_args()
    out=args.output;out.mkdir(parents=True,exist_ok=True);table_dir=out/'oracle_tables';table_dir.mkdir(exist_ok=True)
    manifest=json.loads(args.manifest.read_text());policy,cases,inputs=load_frozen_cases(manifest,args.lab_dir)
    if args.limit:cases=cases[:args.limit]
    catalog=[dict(case=i,**{k:v for k,v in c.items() if k!='trace'},trace=[asdict(e) for e in c['trace']],policy_id=policy.pid,policy_version=policy.version) for i,c in enumerate(cases)]
    (out/'case_catalog.json').write_text(json.dumps(catalog,indent=2),encoding='utf-8')
    reference_rows={int(r['case']):r for r in csv.DictReader((ROOT/'results/revision/local_lab_proofmatched/rq2_local_lab_explanations.csv').open(newline=''))}
    packages={}
    for p in ['numpy','scipy','scikit-learn','alibi','pandas']:
        try:packages[p]=version(p)
        except PackageNotFoundError:packages[p]=None
    run_manifest=dict(method=args.method,arguments={k:str(v) if isinstance(v,Path) else v for k,v in vars(args).items()},python=sys.version,platform=platform.platform(),packages=packages,source_manifest_sha256=hashlib.sha256(args.manifest.read_bytes()).hexdigest(),policy_sha256=manifest['policy_sha256'],inputs_sha256=inputs,case_count=len(cases),mask_encoding='integer k retains unit i iff (k & (1<<i)) != 0',comparison_scope='same retrospective frozen 120 Docker strata; separate NumPy environments, no pooled timing superiority claim',native_cold_import='Alibi imported lazily: first outer native_s includes module import/population construction; native.total_native_us excludes those two steps',oracle_memoization='empty canonical cache per native explanation; requests and unique canonical calls separately recorded')
    (out/f'{args.method}_manifest.json').write_text(json.dumps(run_manifest,indent=2),encoding='utf-8')
    rows=[]
    for case_id,c in enumerate(cases):
        trace=c['trace'];h=c['horizon'];eps,rids,units=tpe.explanation_unit_info(trace,policy,h);m=len(units);target=tpe.reference_eval(trace,policy).alert_class;yi=CLASSES.index(target)
        ref=reference_rows[case_id]
        if int(ref['seed'])!=c['workload_seed'] or ref['event_id']!=c['event_id'] or int(ref['n_units'])!=m:raise ValueError('case domain differs from matched comparison')
        base={k:v for k,v in c.items() if k not in ['trace','horizon']};base.update(case=case_id,n_units=m,units=units,target_class=target,horizon=h)
        t0=time.perf_counter();deadline=t0+args.timeout_s
        try:
            labels,enum_queries=independent_table(trace,policy,eps,rids,deadline)
            if labels[-1]!=yi:raise AssertionError('all-retained mask differs from factual')
            core_masks,suff_table=minimal_masks_dp(labels==yi,m);cores=[{u for i,u in enumerate(units) if mask&(1<<i)} for mask in core_masks]
            enum_end=time.perf_counter();enumeration_s=enum_end-t0
            table_path=table_dir/f'case_{case_id:03d}.npz'
            if table_path.exists():
                with np.load(table_path,allow_pickle=False) as previous:
                    if not np.array_equal(previous['labels'],labels) or not np.array_equal(previous['units'],np.asarray(units)) or not np.array_equal(previous['minimal_core_masks'],np.asarray(core_masks,dtype=np.int64)):
                        raise AssertionError('cross-environment independent domain/core audit differs')
            else:np.savez_compressed(table_path,labels=labels,units=np.asarray(units),minimal_core_masks=np.asarray(core_masks,dtype=np.int64),class_names=np.asarray(CLASSES))
        except Exception as error:
            rows.append(dict(**base,method=args.method,status='timeout' if isinstance(error,TimeoutError) else 'failed',phase='independent_enumeration',error=repr(error)))
            (out/f'{args.method}.json').write_text(json.dumps(rows,indent=2),encoding='utf-8');continue
        if args.method=='ffa':
            try:
                ta=time.perf_counter();weights=ffa_from_cores(cores,units);rank=[units[i] for i in np.argsort(-weights,kind='stable')];tb=time.perf_counter()
                selected=set();prefix_mask=0
                if not suff_table[0]:
                    for u in rank:
                        selected.add(u);prefix_mask|=1<<units.index(u)
                        if suff_table[prefix_mask]:break
                tc=time.perf_counter();proof=certify_fixed_set(trace,policy,selected,h);td=time.perf_counter()
                rows.append(dict(**base,method='exact_FFA_definition_adaptation',status='ok',enumeration_s=enumeration_s,enumeration_queries=enum_queries,attribution_s=tb-ta,selection_s=tc-tb,fixed_set_proof_s=td-tc,total_s=enumeration_s+td-ta,weights=weights.tolist(),ranking=rank,selected=sorted(selected),core_count=len(cores),all_minimal_cores=[sorted(s) for s in cores],sufficient=bool(suff_table[selected_mask(selected,units)]),minimal=selected_mask(selected,units) in core_masks,proof=proof))
            except Exception as error:rows.append(dict(**base,method='exact_FFA_definition_adaptation',status='failed',error=repr(error)))
        else:
            for seed in map(int,args.seeds.split(',')):
                started=time.perf_counter();deadline=started+args.timeout_s;queries={'requests':0,'canonical':0};cache={}
                def predictor(X):
                    results=[]
                    for row in np.asarray(X).reshape(-1,m):
                        if time.perf_counter()>deadline:raise TimeoutError('native Anchor oracle deadline')
                        mask=tuple(int(x>=.5) for x in row);queries['requests']+=1
                        # Exact deterministic oracle memoization; no truth-table lookup.
                        # Cache starts empty per native explanation, cost included.
                        if mask not in cache:
                            cache[mask]=CLASSES.index(tpe._class_under_mask(trace,policy,eps,rids,mask));queries['canonical']+=1
                        results.append(cache[mask])
                    return np.asarray(results,dtype=int)
                try:
                    native=explain_anchor(predictor,units,seed,threshold=.95)
                    native_end=time.perf_counter();selected=set(native['selected']);proof=certify_fixed_set(trace,policy,selected,h);proof_end=time.perf_counter();sm=selected_mask(selected,units)
                    rows.append(dict(**base,method='alibi_AnchorTabular',seed=seed,status='ok',native=native,native_s=native_end-started,fixed_set_proof_s=proof_end-native_end,total_s=proof_end-started,first_native_call_includes_cold_import=case_id==0 and seed==int(args.seeds.split(',')[0]),independent_audit_s=enumeration_s,independent_audit_queries=enum_queries,oracle_requests=queries['requests'],canonical_queries=queries['canonical'],memoization='empty per-explanation canonical oracle cache; no precomputed truth table supplied',selected=sorted(selected),core_count=len(cores),sufficient=bool(suff_table[sm]),minimal=sm in core_masks,proof=proof))
                except Exception as error:rows.append(dict(**base,method='alibi_AnchorTabular',seed=seed,status='timeout' if isinstance(error,TimeoutError) else 'failed',elapsed_s=time.perf_counter()-started,error=repr(error),oracle_requests=queries['requests'],canonical_queries=queries['canonical']))
        (out/f'{args.method}.json').write_text(json.dumps(rows,indent=2),encoding='utf-8')
        if (case_id+1)%10==0 or args.limit:print(f'{args.method}: completed {case_id+1}/{len(cases)} cases; rows={len(rows)}',flush=True)
    # pandas absent in some minimal environments: CSV emitted using stdlib.
    columns=sorted({k for row in rows for k in row})
    with (out/f'{args.method}.csv').open('w',newline='',encoding='utf-8') as stream:
        writer=csv.DictWriter(stream,fieldnames=columns);writer.writeheader()
        writer.writerows({k:json.dumps(v) if isinstance(v,(list,dict)) else v for k,v in row.items()} for row in rows)
    summary=dict(cases=len(cases),rows=len(rows),statuses={s:sum(r['status']==s for r in rows) for s in {r['status'] for r in rows}},sufficient=sum(bool(r.get('sufficient')) for r in rows),minimal=sum(bool(r.get('minimal')) for r in rows),workloads=len({c['workload_seed'] for c in cases}))
    (out/f'{args.method}_summary.json').write_text(json.dumps(summary,indent=2),encoding='utf-8');print(json.dumps(summary))
if __name__=='__main__':main()
