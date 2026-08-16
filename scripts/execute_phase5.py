#!/usr/bin/env python3
from __future__ import annotations
import subprocess,sys,time,json,traceback
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];LOG=ROOT/'results/logs';LOG.mkdir(parents=True,exist_ok=True)
STEPS=[
 ('preflight',['scripts/preflight.py']),
 ('collect_datasets',['scripts/collect_datasets.py']),
 ('darpa_groundtruth_crosscheck',['scripts/audit_darpa_groundtruth.py']),
 ('semantic_tests',['-m','pytest','-q']),
 ('rq1_rq3_rq4_controlled',['experiments/run_local_core.py']),
 ('rq2_shap_controlled',['experiments/run_rq2_explanations.py']),
 ('rq2_lime_controlled',['experiments/run_rq2_lime.py']),
 ('rq2_stability_controlled',['experiments/run_rq2_stability.py']),
 ('real_local_lab_capture',['scripts/run_local_lab.py']),
 ('real_local_tracepolicy',['experiments/run_local_lab_tracepolicy.py']),
 ('real_suricata',['scripts/run_suricata.py']),
 ('real_wazuh',['scripts/run_wazuh.py']),
 ('toniot',['experiments/run_toniot_local.py']),
 ('darpa_full_rq5',['experiments/run_darpa_cadets.py']),
 ('darpa_rq1_degradation',['experiments/run_darpa_rq1_degradation.py']),
 ('darpa_rq2_explanations',['experiments/run_darpa_rq2_explanations.py']),
 ('darpa_rq4_performance',['experiments/run_darpa_rq4_perf.py']),
 ('consolidate',['scripts/consolidate_results.py']),
]
def main():
 journal=[]
 for name,args in STEPS:
  t=time.time();cmd=[sys.executable,*args];print('\n===',name,'===\n+',' '.join(cmd),flush=True)
  cp=subprocess.run(cmd,cwd=ROOT,text=True,capture_output=True)
  rec={'step':name,'cmd':cmd,'start_epoch':t,'duration_s':time.time()-t,'returncode':cp.returncode,'stdout_tail':cp.stdout[-12000:],'stderr_tail':cp.stderr[-12000:]};journal.append(rec);(LOG/'execution_journal.json').write_text(json.dumps(journal,indent=2))
  print(cp.stdout[-4000:]);
  if cp.stderr:print(cp.stderr[-4000:],file=sys.stderr)
  if cp.returncode!=0:
   (LOG/'PIPELINE_STOPPED_AT.txt').write_text(f'{name}\nreturncode={cp.returncode}\n')
   raise SystemExit(f'Execution stopped at {name}. Failure was preserved in results/logs/execution_journal.json; do not skip or fake this step.')
 print('\nAll execution steps completed. See PHASE5_COMPLETION_CHECKLIST.md and results package.')
if __name__=='__main__':main()
