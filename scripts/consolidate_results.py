#!/usr/bin/env python3
from __future__ import annotations
import hashlib,json,os,shutil,sys,zipfile,platform
from pathlib import Path
import pandas as pd
ROOT=Path(__file__).resolve().parents[1];RAW=ROOT/'results/raw';LOG=ROOT/'results/logs';SUM=ROOT/'results/summary';STAT=ROOT/'results/statistics';FIG=ROOT/'figures/pgfplots'
for p in (SUM,STAT,FIG,LOG):p.mkdir(parents=True,exist_ok=True)
SEEDS=json.load(open(ROOT/'config/seeds.json'))['seeds'];N=len(SEEDS)
def sha(p):
 h=hashlib.sha256()
 with open(p,'rb') as f:
  for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
 return h.hexdigest()
def csvrows(name):
 p=RAW/name
 if not p.exists() or p.stat().st_size==0:return None
 return len(pd.read_csv(p))
def check_empty_csv(name):
 p=RAW/name
 return p.exists() and len(pd.read_csv(p))==0

def main():
 checks=[]
 def ck(key,ok,evidence):checks.append({'id':key,'status':'PASS' if ok else 'FAIL','evidence':str(evidence)})
 # Mandatory controlled and external runs.
 ck('RQ1_CONTROLLED_480',csvrows('rq1_local_detection.csv')==480,csvrows('rq1_local_detection.csv'))
 ck('RQ2_SHAP_32',csvrows('rq2_intrinsic_vs_shap.csv')==32,csvrows('rq2_intrinsic_vs_shap.csv'))
 ck('RQ2_LIME_32',csvrows('rq2_intrinsic_vs_lime.csv')==32,csvrows('rq2_intrinsic_vs_lime.csv'))
 ck('RQ3_120',csvrows('rq3_policy_defects.csv')==120,csvrows('rq3_policy_defects.csv'))
 ck('RQ4_LOCAL_270',csvrows('rq4_latency.csv')==270,csvrows('rq4_latency.csv'))
 ck('ORACLE_LOCAL_ZERO',check_empty_csv('oracle_divergences.csv') and check_empty_csv('oracle_update_divergences.csv'),'zero-row divergence files')
 for n in ['rq5_local_lab_tracepolicy.csv','rq5_local_lab_suricata.csv','rq5_local_lab_wazuh.csv','rq5_rf_test_metrics_30seeds.csv','rq5_if_test_metrics_30seeds.csv','rq5_darpa_cadets_metrics.csv']:
  ck(n.upper(),csvrows(n)==N,csvrows(n))
 ck('DARPA_RQ1_480',csvrows('rq1_darpa_degradation.csv')==N*16,csvrows('rq1_darpa_degradation.csv'))
 ck('DARPA_RQ2_32',csvrows('rq2_darpa_explanations.csv')==32,csvrows('rq2_darpa_explanations.csv'))
 ck('DARPA_RQ4_540',csvrows('rq4_darpa_latency.csv')==N*2*3*3,csvrows('rq4_darpa_latency.csv'))
 if (RAW/'rq4_darpa_latency.csv').exists(): ck('ORACLE_DARPA_ZERO',int(pd.read_csv(RAW/'rq4_darpa_latency.csv').divergences.sum())==0,'sum(divergences)=0')
 else:ck('ORACLE_DARPA_ZERO',False,'missing')
 lab=ROOT/'local_lab/results';ck('LOCAL_LAB_TRUTH_30',len(list(lab.glob('truth_*.csv')))==N,len(list(lab.glob('truth_*.csv'))));ck('LOCAL_LAB_PCAP_30',len(list(lab.glob('pcap_*.pcap')))==N,len(list(lab.glob('pcap_*.pcap'))));ck('LOCAL_LAB_ACCESS_30',len(list(lab.glob('access_*.jsonl')))==N,len(list(lab.glob('access_*.jsonl'))))
 ck('DATASET_MANIFEST',(LOG/'dataset_manifest.json').exists(),LOG/'dataset_manifest.json');ck('DARPA_OFFICIAL_GT_PDF',(ROOT/'datasets/raw/darpa_e3/ground_truth/tc_ground_truth_report_e3_update.pdf').exists(),ROOT/'datasets/raw/darpa_e3/ground_truth/tc_ground_truth_report_e3_update.pdf');ck('PREFLIGHT_MANIFEST',(LOG/'preflight.json').exists(),LOG/'preflight.json')
 # Frozen configuration hashes.
 frozen=[ROOT/'formal/L5_Phase4_Formal_Specification.tex',ROOT/'src/trace_policy_engine.py',ROOT/'docker/suricata/local.rules',ROOT/'docker/wazuh/local_rules.xml',ROOT/'config/experiment.json',ROOT/'config/seeds.json']
 for p in frozen:ck('HASH_'+p.name,p.exists(),sha(p) if p.exists() else 'missing')
 status='PASS' if all(x['status']=='PASS' for x in checks) else 'FAIL'
 pd.DataFrame(checks).to_csv(ROOT/'PHASE5_COMPLETION_CHECKLIST.csv',index=False)
 md=['# Phase 5 completion checklist','',f'**PHASE5_GATE={status}**','', '| ID | Status | Evidence |','|---|---|---|']+[f"| {x['id']} | **{x['status']}** | {x['evidence']} |" for x in checks]
 if status!='PASS':md+=['','**R4 remains active. Do not draft Phase 6.**']
 else:md+=['','All machine-checkable mandatory items in this execution kit are present. This does not itself certify scientific acceptance; return the result ZIP for independent Phase-5 audit before Phase 6.']
 (ROOT/'PHASE5_COMPLETION_CHECKLIST.md').write_text('\n'.join(md))
 # Summaries derived only from raw CSVs.
 for n in ['rq5_local_lab_tracepolicy.csv','rq5_local_lab_suricata.csv','rq5_local_lab_wazuh.csv','rq5_darpa_cadets_metrics.csv','rq5_rf_test_metrics_30seeds.csv','rq5_if_test_metrics_30seeds.csv','rq4_darpa_latency.csv','rq1_darpa_degradation.csv','rq2_darpa_explanations.csv']:
  p=RAW/n
  if p.exists():
   df=pd.read_csv(p);df.describe(include='all').transpose().to_csv(SUM/(p.stem+'_describe.csv'))
 # PGFPlots data are raw-derived tables, never hand-entered values.
 if (RAW/'rq4_darpa_latency.csv').exists():pd.read_csv(RAW/'rq4_darpa_latency.csv').groupby(['mode','P','engine'],as_index=False)[['mean_us','p95_us','p99_us','throughput_eps','mean_candidates']].mean().to_csv(FIG/'darpa_rq4_latency.csv',index=False)
 if all((RAW/x).exists() for x in ['rq5_local_lab_tracepolicy.csv','rq5_local_lab_suricata.csv','rq5_local_lab_wazuh.csv']):
  rr=[]
  for method,n in [('TracePolicy','rq5_local_lab_tracepolicy.csv'),('Suricata','rq5_local_lab_suricata.csv'),('Wazuh','rq5_local_lab_wazuh.csv')]:
   d=pd.read_csv(RAW/n);rr.append({'method':method,**{m:float(d[m].mean()) for m in ['precision','recall','f1','fpr']}})
  pd.DataFrame(rr).to_csv(FIG/'local_lab_baselines.csv',index=False)
 # Manifest: include code/config/results plus dataset hashes, but do not duplicate huge DARPA files into return ZIP.
 lines=[]
 for p in sorted(ROOT.rglob('*')):
  if p.is_file() and '__pycache__' not in p.parts and '.pytest_cache' not in p.parts and p.name not in {'RETURN_MANIFEST_SHA256.txt'}:
   if 'datasets/raw/darpa_e3/cadets' in str(p).replace('\\','/') and p.suffix not in {'.json','.txt'}: continue
   try:lines.append(f'{sha(p)}  {p.relative_to(ROOT)}  {p.stat().st_size}')
   except:pass
 (ROOT/'RETURN_MANIFEST_SHA256.txt').write_text('\n'.join(lines)+'\n')
 # Return ZIP includes all results/code/frozen configs/local pcaps but excludes multi-GB DARPA raw datasets and seed source datasets.
 zpath=ROOT/f'Project_A_Phase5_RESULTS_{status}.zip'
 exclude_prefix=['datasets/raw/darpa_e3/cadets','datasets/seed','vendor','__pycache__','.pytest_cache']
 with zipfile.ZipFile(zpath,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=6) as z:
  for p in sorted(ROOT.rglob('*')):
   if not p.is_file() or p==zpath:continue
   rel=str(p.relative_to(ROOT)).replace('\\','/')
   if any(rel.startswith(x) for x in exclude_prefix):continue
   z.write(p,rel)
 print('PHASE5_GATE='+status);print('RETURN_ZIP='+str(zpath))
 if status!='PASS':raise SystemExit(3)
if __name__=='__main__':main()
