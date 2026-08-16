from __future__ import annotations
import argparse,csv,json,re
from pathlib import Path
from urllib.parse import urlparse,parse_qs
import pandas as pd
import sys
ROOT=Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT/'src'))
from metrics import binary_metrics
from episode_metrics import episode_binary_metrics

def truth_rows(p): return list(csv.DictReader(open(p,newline='')))
def sid_from_url(u):
    try: return (parse_qs(urlparse(u).query).get('sid') or [''])[0]
    except Exception: return ''
def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--lab-dir',default=str(ROOT/'local_lab'/'results')); ap.add_argument('--out-root',default=str(ROOT/'results'/'raw')); args=ap.parse_args()
    lab=Path(args.lab_dir); out=Path(args.out_root); out.mkdir(parents=True,exist_ok=True); rows=[]; alerts=[]
    for truthp in sorted(lab.glob('truth_*.csv')):
        seed=int(truthp.stem.split('_')[-1]); eve=lab/f'suricata_{seed}'/'eve.json'
        if not eve.exists(): raise FileNotFoundError(eve)
        pred=set()
        for line in eve.read_text(errors='replace').splitlines():
            try:r=json.loads(line)
            except:continue
            if r.get('event_type')!='alert': continue
            h=r.get('http') or {}; u=h.get('url') or h.get('hostname','')
            sid=sid_from_url(u)
            if sid: pred.add(sid)
            alerts.append({'seed':seed,'sid':sid,'signature_id':(r.get('alert') or {}).get('signature_id'),'signature':(r.get('alert') or {}).get('signature'),'timestamp':r.get('timestamp'),'url':u})
        tr=truth_rows(truthp); y=[int(x['label']) for x in tr]; yp=[int(x['sid'] in pred) for x in tr]
        em=episode_binary_metrics(tr,pred);rows.append({'seed':seed,'n':len(y),**binary_metrics(y,yp),'alerts':len(pred),**{f'episode_{k}':v for k,v in em.items()}})
    pd.DataFrame(rows).to_csv(out/'rq5_local_lab_suricata.csv',index=False); pd.DataFrame(alerts).to_csv(out/'rq5_local_lab_suricata_alerts.csv',index=False)
    print(pd.DataFrame(rows).describe().to_string())
if __name__=='__main__':main()
