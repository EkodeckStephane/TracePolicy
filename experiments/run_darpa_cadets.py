from __future__ import annotations
import argparse,csv,gzip,json,sys,time,hashlib
from pathlib import Path
from collections import Counter
import pandas as pd
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'src'))
from trace_policy_engine import *
from darpa_adapter import build_entity_index,iter_events,learn_whitelist_policy,load_malicious_ids
from metrics import binary_metrics
from policy_io import save_policy_csv

def choose_files(root:Path, pattern:str):
    fs=[p for p in root.rglob(pattern) if p.is_file() and not p.name.endswith(('.tar.gz','.tgz','.gz'))]
    return sorted(fs)

def write_policy(pol,path):
    rows=[]
    for r in pol.rules:
        rows.append({'rid':r.rid,'priority':r.priority,'effect':r.effect,'action':r.selector.action,'resource_class':r.selector.resource_class,'subject_class':r.selector.subject_class,'guard':repr(r.guard)})
    pd.DataFrame(rows).to_csv(path,index=False)

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--data-root',default=str(ROOT/'datasets'/'raw'/'darpa_e3'/'cadets'));ap.add_argument('--groundtruth',default=str(ROOT/'datasets'/'seed'/'cadets_groundtruth_threatrace.txt'))
    ap.add_argument('--train-pattern',default='ta1-cadets-e3-official.json*');ap.add_argument('--test-pattern',default='ta1-cadets-e3-official-2.json*');ap.add_argument('--min-support',type=int,default=20);ap.add_argument('--max-allow-rules',type=int,default=500);ap.add_argument('--repetitions',type=int,default=30);ap.add_argument('--max-test-events',type=int,default=0);args=ap.parse_args()
    droot=Path(args.data_root); out=ROOT/'results'/'raw';out.mkdir(parents=True,exist_ok=True); logs=ROOT/'results'/'logs';logs.mkdir(parents=True,exist_ok=True)
    train=choose_files(droot,args.train_pattern); test=choose_files(droot,args.test_pattern)
    if not train:
        # Fallback only if exact MAGIC-convention segment is absent: use the first official archive member and report it.
        train=[p for p in choose_files(droot,'ta1-cadets-e3-official.json*') if '-2.json' not in p.name]
        train=train[:1]
    if not train or not test:
        raise SystemExit(f'Missing extracted DARPA CADETS JSON files. train={len(train)} test={len(test)}. See datasets/DATASETS.md')
    entity_db=ROOT/'datasets'/'processed'/'darpa_cadets_entities.sqlite'
    build_entity_index(sorted(set(train+test)),entity_db,logs/'darpa_entity_index.json')
    gt=load_malicious_ids(Path(args.groundtruth))
    # Policy construction uses TRAINING labels only: malicious-linked training events are excluded from the benign whitelist.
    # Test labels are not consumed by policy construction or parameter selection.
    train_normal=(e for e in iter_events(train,entity_db,gt) if int(e.malicious or 0)==0)
    pol,counts=learn_whitelist_policy(train_normal,args.min_support,1,args.max_allow_rules)
    save_policy_csv(pol,out/'rq5_darpa_policy_rules.csv')
    (logs/'darpa_selected_files.json').write_text(json.dumps({'train':[str(x) for x in train],'test':[str(x) for x in test]},indent=2))
    rows=[]; first_predictions=out/'rq5_darpa_predictions_first_run.csv.gz'
    max_events=args.max_test_events or None
    for rep in range(args.repetitions):
        inc=IncrementalEvaluator(pol); y=[];yp=[]; lat=[]; n=0
        predwriter=None; fh=None
        if rep==0:
            fh=gzip.open(first_predictions,'wt',newline='');predwriter=csv.writer(fh);predwriter.writerow(['event_id','ts','truth','pred','attack_type','alert_class','top','action','resource_class','subject_uuid','object_uuid'])
        try:
            for e in iter_events(test,entity_db,gt,max_events=max_events):
                t=time.perf_counter_ns();r=inc.push(e);lat.append((time.perf_counter_ns()-t)/1000)
                p=int(r.alert_class in (VIOLATION,CONFLICT)); yy=int(e.malicious or 0);y.append(yy);yp.append(p);n+=1
                if predwriter:
                    predwriter.writerow([e.eid,e.ts,yy,p,e.attack_type,r.alert_class,';'.join(r.top),e.action,e.resource_class,e.attrs.get('subject_uuid',''),e.attrs.get('object_uuid','')])
        finally:
            if fh: fh.close()
        m=binary_metrics(y,yp);m.update(repetition=rep,n=n,mean_us=sum(lat)/len(lat),p50_us=float(pd.Series(lat).quantile(.50)),p95_us=float(pd.Series(lat).quantile(.95)),p99_us=float(pd.Series(lat).quantile(.99)),policy_version=pol.version,policy_rules=len(pol.rules),train_files=len(train),test_files=len(test));rows.append(m)
        print('DARPA rep',rep,m)
    pd.DataFrame(rows).to_csv(out/'rq5_darpa_cadets_metrics.csv',index=False)
if __name__=='__main__':main()
