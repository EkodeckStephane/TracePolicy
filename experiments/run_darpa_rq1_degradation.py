from __future__ import annotations
import argparse, json, random, sys
from pathlib import Path
import pandas as pd
ROOT=Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT/'src'))
from trace_policy_engine import *
from darpa_adapter import build_entity_index,iter_events,load_malicious_ids
from policy_io import load_policy_csv
from metrics import binary_metrics

def choose(root,pat): return sorted([p for p in root.rglob(pat) if p.is_file() and not p.name.endswith(('.gz','.tgz','.tar.gz'))])

def stable_stratified_sample(events, benign_cap=50000, malicious_cap=10000, seed=20260814):
    # Fixed reservoir sample. Used only for degradation sensitivity; full-dataset metrics are RQ5.
    rng=random.Random(seed); b=[];m=[]; nb=nm=0
    for e in events:
        target=m if int(e.malicious or 0) else b; cap=malicious_cap if int(e.malicious or 0) else benign_cap
        if int(e.malicious or 0): nm+=1; seen=nm
        else: nb+=1; seen=nb
        if len(target)<cap: target.append(e)
        else:
            j=rng.randrange(seen)
            if j<cap: target[j]=e
    out=b+m; rng.shuffle(out); return out,{'benign_seen':nb,'malicious_seen':nm,'benign_sampled':len(b),'malicious_sampled':len(m)}

def relax_policy(pol,fraction,seed):
    if fraction<=0:return pol
    rng=random.Random(seed); allow=[r for r in pol.rules if r.effect==ALLOW]
    k=round(len(allow)*fraction); chosen={r.rid for r in rng.sample(allow,min(k,len(allow)))}
    nr=[]
    for r in pol.rules:
        if r.rid in chosen:
            # Controlled over-generalisation: preserve action but wildcard resource/subject.
            nr.append(Rule(r.rid,r.priority,r.effect,Selector(r.selector.action,'*','*'),r.guard))
        else:nr.append(r)
    return PolicyVersion(pol.pid,pol.version+1,tuple(nr))

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--data-root',default=str(ROOT/'datasets/raw/darpa_e3/cadets'));ap.add_argument('--test-pattern',default='ta1-cadets-e3-official-2.json*');ap.add_argument('--groundtruth',default=str(ROOT/'datasets/seed/cadets_groundtruth_threatrace.txt'));ap.add_argument('--policy',default=str(ROOT/'results/raw/rq5_darpa_policy_rules.csv'));args=ap.parse_args()
    files=choose(Path(args.data_root),args.test_pattern); policy=load_policy_csv(Path(args.policy)); gt=load_malicious_ids(Path(args.groundtruth)); db=ROOT/'datasets/processed/darpa_cadets_entities.sqlite'
    if not files or not db.exists(): raise SystemExit('Run run_darpa_cadets.py first; extracted test files/entity DB are required.')
    sample,meta=stable_stratified_sample(iter_events(files,db,gt)); (ROOT/'results/logs').mkdir(parents=True,exist_ok=True); (ROOT/'results/logs/darpa_rq1_sample.json').write_text(json.dumps(meta,indent=2))
    rows=[]; seeds=json.load(open(ROOT/'config/seeds.json'))['seeds']; relax_levels=[0,.1,.25,.5]; drop_levels=[0,.05,.1,.2]
    for seed in seeds:
      for relax in relax_levels:
        p=relax_policy(policy,relax,seed); idx=StaticIndex(p); rng=random.Random(seed*1009+int(relax*1000))
        for drop in drop_levels:
          y=[];yp=[]
          for e in sample:
            yy=int(e.malicious or 0); y.append(yy)
            if rng.random()<drop: yp.append(0); continue  # unobserved event => no alert
            r=idx.eval([e]); yp.append(int(r.alert_class in (VIOLATION,CONFLICT,GAP)))
          mm=binary_metrics(y,yp);mm.update(seed=seed,policy_relaxation_fraction=relax,trace_dropout_fraction=drop,n=len(y));rows.append(mm)
    out=ROOT/'results/raw/rq1_darpa_degradation.csv';pd.DataFrame(rows).to_csv(out,index=False);print(pd.DataFrame(rows).groupby(['policy_relaxation_fraction','trace_dropout_fraction'])[['recall','fpr','f1']].mean())
if __name__=='__main__':main()
