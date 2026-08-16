from __future__ import annotations
import argparse,csv,json,sys,time
from pathlib import Path
import pandas as pd
ROOT=Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT/'src'))
from trace_policy_engine import IncrementalEvaluator, VIOLATION, CONFLICT
from local_lab_adapter import load_gateway_events, lab_policy
from metrics import binary_metrics
from episode_metrics import episode_binary_metrics

def load_truth(p):
    return {r['sid']:{'label':int(r['label']),'scenario':r['scenario']} for r in csv.DictReader(open(p,newline=''))}

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--lab-dir',default=str(ROOT/'local_lab'/'results')); ap.add_argument('--out',default=str(ROOT/'results'/'raw'/'rq5_local_lab_tracepolicy.csv')); args=ap.parse_args()
    lab=Path(args.lab_dir); rows=[]; preds=[]
    for truthp in sorted(lab.glob('truth_*.csv')):
        seed=int(truthp.stem.split('_')[-1]); access=lab/f'access_{seed}.jsonl'
        if not access.exists(): raise FileNotFoundError(access)
        truth=load_truth(truthp); events=load_gateway_events(access,truth); inc=IncrementalEvaluator(lab_policy())
        y=[]; yp=[]; lat=[]
        for e in events:
            t=time.perf_counter_ns(); r=inc.push(e); lat.append((time.perf_counter_ns()-t)/1000)
            p=int(r.alert_class in (VIOLATION,CONFLICT)); y.append(int(e.malicious or 0)); yp.append(p)
            preds.append({'seed':seed,'sid':e.eid,'truth':int(e.malicious or 0),'scenario':e.attack_type,'pred':p,'alert_class':r.alert_class,'top':';'.join(r.top),'latency_us':lat[-1]})
        pred_sids={p['sid'] for p in preds if p['seed']==seed and p['pred']==1}; trrows=list(csv.DictReader(open(truthp,newline=''))); em=episode_binary_metrics(trrows,pred_sids);m=binary_metrics(y,yp);m.update({f'episode_{k}':v for k,v in em.items()});m.update(seed=seed,n=len(y),mean_us=sum(lat)/len(lat),policy_version=1); rows.append(m)
    Path(args.out).parent.mkdir(parents=True,exist_ok=True); pd.DataFrame(rows).to_csv(args.out,index=False)
    pd.DataFrame(preds).to_csv(Path(args.out).with_name('rq5_local_lab_tracepolicy_predictions.csv'),index=False)
    print(pd.DataFrame(rows).describe().to_string())
if __name__=='__main__': main()
