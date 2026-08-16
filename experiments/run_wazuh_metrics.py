from __future__ import annotations
import argparse,csv,re,subprocess,sys
from pathlib import Path
import pandas as pd
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'src'))
from metrics import binary_metrics
from episode_metrics import episode_binary_metrics

def parse_output(text):
 pred=set();details=[]
 chunks=re.split(r'(?=\*\*Phase 1:)',text)
 for c in chunks:
  if '**Phase 3:' not in c:continue
  sm=re.search(r"\bsid:\s*'?([^'\s]+)'?",c);rm=re.search(r"\*\*Phase 3:.*?\bid:\s*'?(\d+)'?",c,re.S);lm=re.search(r"\blevel:\s*'?(\d+)'?",c)
  if sm and rm and int(lm.group(1) if lm else 0)>0:
   sid=sm.group(1);pred.add(sid);details.append((sid,rm.group(1),int(lm.group(1) if lm else 0)))
 return pred,details

def main():
 ap=argparse.ArgumentParser();ap.add_argument('--lab-dir',default=str(ROOT/'local_lab/results'));ap.add_argument('--image',default='wazuh/wazuh-manager:4.14.7');ap.add_argument('--out-root',default=str(ROOT/'results/raw'));args=ap.parse_args();lab=Path(args.lab_dir);out=Path(args.out_root);out.mkdir(parents=True,exist_ok=True);rules=ROOT/'docker/wazuh/local_rules.xml';rows=[];det=[]
 for truthp in sorted(lab.glob('truth_*.csv')):
  seed=int(truthp.stem.split('_')[-1]);access=lab/f'access_{seed}.jsonl';tr=list(csv.DictReader(open(truthp,newline='')));name=f'projecta-wazuh-logtest-{seed}'
  subprocess.run(['docker','rm','-f',name],check=False,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
  cp=subprocess.run(['docker','create','-i','--name',name,'--entrypoint','/var/ossec/bin/wazuh-logtest',args.image],text=True,capture_output=True)
  if cp.returncode!=0:raise RuntimeError(cp.stderr)
  subprocess.run(['docker','cp',rules,f'{name}:/var/ossec/etc/rules/local_rules.xml'],check=True)
  cp=subprocess.run(['docker','start','-ai',name],input=access.read_text(),text=True,capture_output=True)
  (lab/f'wazuh_{seed}.stdout.txt').write_text(cp.stdout);(lab/f'wazuh_{seed}.stderr.txt').write_text(cp.stderr);subprocess.run(['docker','rm','-f',name],check=False,stdout=subprocess.DEVNULL)
  if cp.returncode!=0:raise RuntimeError(f'Wazuh logtest failed seed {seed}: {cp.stderr[-3000:]}')
  pred,dd=parse_output(cp.stdout);y=[int(x['label']) for x in tr];yp=[int(x['sid'] in pred) for x in tr];em=episode_binary_metrics(tr,pred);rows.append({'seed':seed,'n':len(y),**binary_metrics(y,yp),'alerts':len(pred),**{f'episode_{k}':v for k,v in em.items()}});det.extend({'seed':seed,'sid':a,'rule_id':b,'level':c} for a,b,c in dd)
 pd.DataFrame(rows).to_csv(out/'rq5_local_lab_wazuh.csv',index=False);pd.DataFrame(det).to_csv(out/'rq5_local_lab_wazuh_alerts.csv',index=False);print(pd.DataFrame(rows).describe().to_string())
if __name__=='__main__':main()
