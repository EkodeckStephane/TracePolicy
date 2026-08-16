#!/usr/bin/env python3
from pathlib import Path
import pandas as pd,hashlib,json,sys,re
ROOT=Path(__file__).resolve().parents[1];RAW=ROOT/'results/raw';LOG=ROOT/'results/logs';STAT=ROOT/'results/statistics'
checks=[]
def ck(k,ok,e):checks.append({'id':k,'status':'PASS' if ok else 'FAIL','evidence':str(e)})
def rows(name):
    p=RAW/name
    try:return len(pd.read_csv(p))
    except:return -1

# Current publication protocol hash verification.
bad=0
for line in (ROOT/'FROZEN_PUBLICATION_SHA256.txt').read_text().splitlines():
    if not line.strip():continue
    exp,rel=line.split(None,1);p=ROOT/rel.strip()
    if not p.exists() or hashlib.sha256(p.read_bytes()).hexdigest()!=exp:bad+=1
ck('PUBLICATION_PROTOCOL',bad==0,f'mismatches={bad}')

# Original mandatory artifacts.
for name,n in [
 ('rq1_local_detection.csv',480),('rq2_intrinsic_vs_shap.csv',32),('rq2_intrinsic_vs_lime.csv',32),
 ('rq3_policy_defects.csv',120),('rq4_latency.csv',270),
 ('rq5_local_lab_tracepolicy.csv',30),('rq5_local_lab_suricata.csv',30),
 ('rq5_rf_test_metrics_30seeds.csv',30),('rq5_if_test_metrics_30seeds.csv',30),
 ('rq5_darpa_cadets_metrics.csv',30),('rq1_darpa_degradation.csv',480),
 ('rq2_darpa_explanations.csv',32),('rq4_darpa_latency.csv',540)]:
    ck('ROWS_'+name,rows(name)==n,rows(name))

# Corrected Wazuh validity, not mere row count.
w=RAW/'rq5_local_lab_wazuh.csv'; wa=RAW/'rq5_local_lab_wazuh_alerts.csv'
if w.exists():
    wd=pd.read_csv(w)
    ck('WAZUH_30',len(wd)==30,len(wd))
    ck('WAZUH_PHASE1_ALL',len(wd)==30 and (wd.phase1_blocks>=wd.n).all(),wd.phase1_blocks.min() if 'phase1_blocks' in wd else 'missing-column')
    ck('WAZUH_PHASE3_ALL',len(wd)==30 and (wd.phase3_blocks>0).all(),wd.phase3_blocks.min() if 'phase3_blocks' in wd else 'missing-column')
    ck('WAZUH_ALERTS_NONZERO',len(wd)==30 and (wd.alerts>0).all(),wd.alerts.min() if 'alerts' in wd else 'missing-column')
else:
    for k in ['WAZUH_30','WAZUH_PHASE1_ALL','WAZUH_PHASE3_ALL','WAZUH_ALERTS_NONZERO']:ck(k,False,'missing')
ck('WAZUH_ALERT_CSV_NONEMPTY',wa.exists() and wa.stat().st_size>20,wa.stat().st_size if wa.exists() else 'missing')
wlogs=LOG/'wazuh_v2'
errs=0;p1=0;p3=0
if wlogs.exists():
    for p in wlogs.glob('wazuh_*.stderr.txt'):errs+=p.read_text(errors='replace').count('error when connecting with wazuh-analysisd')
    for p in wlogs.glob('wazuh_*.stdout.txt'):
        t=p.read_text(errors='replace');p1+=t.count('**Phase 1:');p3+=t.count('**Phase 3:')
ck('WAZUH_ZERO_CONNECTION_ERRORS',errs==0,errs);ck('WAZUH_VALID_OUTPUT_BLOCKS',p1>=9000 and p3>0,f'phase1={p1},phase3={p3}')

# DARPA unit correction + statistics.
ck('DARPA_ENTITY_METRIC',rows('rq5_darpa_entity_metrics_v2.csv')==1,rows('rq5_darpa_entity_metrics_v2.csv'))
ck('DARPA_UNIT_NOTE',(LOG/'darpa_groundtruth_unit_v2.json').exists(),LOG/'darpa_groundtruth_unit_v2.json')
for p in [STAT/'paired_tests_v2.csv',STAT/'bootstrap_ci_v2.csv',STAT/'darpa_detection_point_estimate_v2.csv']:
    ck('STAT_'+p.name,p.exists() and p.stat().st_size>50,p.stat().st_size if p.exists() else 'missing')

# Equivalence.
for name in ['oracle_divergences.csv','oracle_update_divergences.csv']:
    p=RAW/name
    ok=p.exists() and len(pd.read_csv(p))==0
    ck('ZERO_'+name,ok,'zero rows' if ok else 'nonzero/missing')
d4=RAW/'rq4_darpa_latency.csv'
ck('DARPA_ORACLE_ZERO',d4.exists() and int(pd.read_csv(d4).divergences.sum())==0,
   int(pd.read_csv(d4).divergences.sum()) if d4.exists() else 'missing')

df=pd.DataFrame(checks);status='PASS' if (df.status=='PASS').all() else 'FAIL'
df.to_csv(ROOT/'PHASE5_CORRECTIVE_GATE_V2.csv',index=False)
lines=['# Phase 5 corrective gate v2','',f'**CORRECTIVE_GATE_V2={status}**','',
       '| ID | Status | Evidence |','|---|---|---|']
lines += [f"| {r.id} | **{r.status}** | {str(r.evidence).replace('|','/')} |" for r in df.itertuples()]
if status!='PASS':lines+=['','**R4 remains active.**']
else:lines+=['','Machine corrective gate passed. Independent scientific re-audit is still required before Phase 6.']
(ROOT/'PHASE5_CORRECTIVE_GATE_V2.md').write_text('\n'.join(lines))
print('CORRECTIVE_GATE_V2='+status)
if status!='PASS':raise SystemExit(4)
