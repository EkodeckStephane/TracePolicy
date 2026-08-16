from __future__ import annotations
import argparse,sys,time,json,random
from pathlib import Path
import pandas as pd
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'src'))
from trace_policy_engine import *
from darpa_adapter import iter_events,load_malicious_ids
from policy_io import load_policy_csv

def choose(root,pat):return sorted([p for p in root.rglob(pat) if p.is_file() and not p.name.endswith(('.gz','.tgz','.tar.gz'))])
def policy_size(base,P,mode):
    # Performance stress policy over real DARPA events. Keep a small fixed semantic core
    # and fill to P with semantically-false decoys so the two index regimes differ only
    # in candidate selectivity, not in decisions.
    allows=[r for r in base.rules if r.effect==ALLOW][:min(10,max(0,P-1))]
    fallback=next(r for r in base.rules if r.rid=='D_DARPA_UNSEEN_SELECTOR')
    core=list(allows)+[fallback]
    i=0
    while len(core)<P:
      if mode=='selective': sel=Selector(f'__NO_ACTION_{i}__',f'__NO_RESOURCE_{i}__','__NO_SUBJECT__')
      else: sel=Selector('*','*','*')
      g=Guard(comparisons=(('action','==',f'__IMPOSSIBLE_{i}__'),))
      core.append(Rule(f'DECOY_{mode}_{i}',-100,ALLOW,sel,g));i+=1
    return PolicyVersion(f'{base.pid}_{mode}_{P}',1,tuple(core[:P]))

def eval_timed(events,pol,engine):
    lats=[];div=0;cands=[]
    idx=StaticIndex(pol);inc=IncrementalEvaluator(pol)
    for e in events:
      tr=[e];ref=reference_eval(tr,pol)
      t=time.perf_counter_ns()
      if engine=='reference':r=reference_eval(tr,pol)
      elif engine=='indexed':r=idx.eval(tr)
      else:r=inc.push(e)
      lats.append((time.perf_counter_ns()-t)/1000);cands.append(r.candidates)
      if (r.decision,r.alert_class,r.top)!=(ref.decision,ref.alert_class,ref.top):div+=1
    s=pd.Series(lats);return dict(mean_us=s.mean(),p50_us=s.quantile(.5),p95_us=s.quantile(.95),p99_us=s.quantile(.99),throughput_eps=1e6/s.mean(),mean_candidates=sum(cands)/len(cands),divergences=div)

def main():
 ap=argparse.ArgumentParser();ap.add_argument('--data-root',default=str(ROOT/'datasets/raw/darpa_e3/cadets'));ap.add_argument('--test-pattern',default='ta1-cadets-e3-official-2.json*');ap.add_argument('--groundtruth',default=str(ROOT/'datasets/seed/cadets_groundtruth_threatrace.txt'));ap.add_argument('--policy',default=str(ROOT/'results/raw/rq5_darpa_policy_rules.csv'));ap.add_argument('--events',type=int,default=10000);args=ap.parse_args()
 base=load_policy_csv(Path(args.policy));files=choose(Path(args.data_root),args.test_pattern);db=ROOT/'datasets/processed/darpa_cadets_entities.sqlite';gt=load_malicious_ids(Path(args.groundtruth));events=list(iter_events(files,db,gt,max_events=args.events));seeds=json.load(open(ROOT/'config/seeds.json'))['seeds'];rows=[]
 for mode in ('selective','collision'):
  for P in (50,200,500):
   pol=policy_size(base,P,mode)
   for seed in seeds:
    # fixed event set, deterministic cyclic offset to model independent ordering without changing membership
    k=seed%len(events);ev=events[k:]+events[:k]
    for eng in ('reference','indexed','incremental'):
      m=eval_timed(ev,pol,eng);m.update(seed=seed,mode=mode,P=P,engine=eng,n=len(ev));rows.append(m)
 out=ROOT/'results/raw/rq4_darpa_latency.csv';pd.DataFrame(rows).to_csv(out,index=False)
 if pd.DataFrame(rows).divergences.sum()!=0: raise SystemExit('Semantic divergence detected. Phase 5 must fail.')
 print(pd.DataFrame(rows).groupby(['mode','P','engine'])[['mean_us','mean_candidates','divergences']].mean())
if __name__=='__main__':main()
