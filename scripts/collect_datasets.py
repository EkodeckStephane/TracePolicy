#!/usr/bin/env python3
from __future__ import annotations
import argparse,hashlib,os,subprocess,sys,tarfile,json,shutil
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
DARPA=ROOT/'datasets/raw/darpa_e3/cadets'; TON=ROOT/'datasets/seed/Train_Test_IoT_Modbus.csv'; GT=ROOT/'datasets/seed/cadets_groundtruth_threatrace.txt'
EXPECTED_TON='78345a857244e671b0c255ca65aac619049632448fc5aa736f1cea255f308cbb'
EXPECTED_GT='19b367eec60d96c3b3063117fabac7a41eeaf226159c3c0668fd400363716f60'
ARCHIVES=['ta1-cadets-e3-official.json.tar.gz','ta1-cadets-e3-official-2.json.tar.gz']
GT_PDF=ROOT/'datasets/raw/darpa_e3/ground_truth/tc_ground_truth_report_e3_update.pdf'

def sha(p):
 h=hashlib.sha256();
 with open(p,'rb') as f:
  for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
 return h.hexdigest()
def download(url,dest):
 dest.parent.mkdir(parents=True,exist_ok=True)
 # gdown handles Google Drive share URLs; curl handles direct HTTPS.
 if 'drive.google.com' in url:
  subprocess.run(['gdown','--fuzzy',url,'-O',str(dest)],check=True)
 else:
  subprocess.run(['curl','-fL','--retry','4','--retry-delay','5','-o',str(dest),url],check=True)
def safe_extract(tar,dest):
 dest=dest.resolve()
 for m in tar.getmembers():
  p=(dest/m.name).resolve()
  if not str(p).startswith(str(dest)):raise RuntimeError('unsafe tar member '+m.name)
 tar.extractall(dest)
def main():
 DARPA.mkdir(parents=True,exist_ok=True); manifest={'toniot':{},'threatrace_groundtruth':{},'darpa_archives':[]}
 if sha(TON)!=EXPECTED_TON:raise SystemExit('Included TON_IoT seed hash mismatch; aborting.')
 if sha(GT)!=EXPECTED_GT:raise SystemExit('Included ThreaTrace CADETS UUID mapping hash mismatch; aborting.')
 manifest['toniot']={'file':str(TON.relative_to(ROOT)),'sha256':sha(TON),'source':'UNSW TON_IoT project; seed copy frozen in kit'}
 manifest['threatrace_groundtruth']={'file':str(GT.relative_to(ROOT)),'sha256':sha(GT),'source':'threaTrace derived CADETS UUID mapping; NOT labelled as official DARPA ground truth'}
 envmap={'ta1-cadets-e3-official.json.tar.gz':'DARPA_CADETS_TRAIN_URL','ta1-cadets-e3-official-2.json.tar.gz':'DARPA_CADETS_TEST_URL'}
 missing=[]
 # Official DARPA E3 ground-truth report is retained separately from the derived ThreaTrace UUID mapping.
 if not GT_PDF.exists():
  u=os.environ.get('DARPA_E3_GT_PDF_URL','').strip()
  if u: download(u,GT_PDF)
  else: missing.append(str(GT_PDF.relative_to(ROOT)))
 if GT_PDF.exists(): manifest['official_darpa_groundtruth']={'file':str(GT_PDF.relative_to(ROOT)),'size':GT_PDF.stat().st_size,'sha256':sha(GT_PDF),'source':'Official DARPA Transparent Computing E3 ground truth report'}
 for name in ARCHIVES:
  p=DARPA/name
  if not p.exists():
   url=os.environ.get(envmap[name],'').strip()
   if url:
    print('Downloading',name,'from user-supplied official URL');download(url,p)
   else:missing.append(name);continue
  if p.stat().st_size<1024:raise SystemExit(f'{name} is implausibly small; aborting.')
  manifest['darpa_archives'].append({'file':str(p.relative_to(ROOT)),'size':p.stat().st_size,'sha256':sha(p)})
 if missing:
  print('\nDARPA E3 CADETS raw archives are mandatory and were not found:')
  for x in missing: print('  -',x)
  print('\nUse the official DARPA Transparent Computing E3 Google Drive linked from README-E3.md.')
  print('Place the exact archives above into:',DARPA)
  print('OR set DARPA_CADETS_TRAIN_URL, DARPA_CADETS_TEST_URL, and DARPA_E3_GT_PDF_URL to direct/share URLs for those exact official files.')
  print('Do not substitute mirrors or 100k subsets for the final run.')
  (ROOT/'results/logs').mkdir(parents=True,exist_ok=True);(ROOT/'results/logs/dataset_collection_status.json').write_text(json.dumps({'status':'BLOCKED_MISSING_DARPA','missing':missing},indent=2))
  raise SystemExit(2)
 # Extract without deleting intermediate segments; CDM entity definitions may be needed by later events.
 for name in ARCHIVES:
  marker=DARPA/(name+'.extracted.ok')
  if not marker.exists():
   print('Extracting',name)
   with tarfile.open(DARPA/name,'r:gz') as t:safe_extract(t,DARPA)
   marker.write_text('extracted\n')
 json_files=[p for p in DARPA.rglob('ta1-cadets-e3-official*.json*') if p.is_file() and not p.name.endswith(('.tar.gz','.gz','.tgz'))]
 if not json_files: raise SystemExit('Extraction completed but no expected CADETS JSON segments found.')
 manifest['extracted_files']=[{'file':str(p.relative_to(ROOT)),'size':p.stat().st_size,'sha256':sha(p)} for p in sorted(json_files)]
 (ROOT/'results/logs').mkdir(parents=True,exist_ok=True);(ROOT/'results/logs/dataset_manifest.json').write_text(json.dumps(manifest,indent=2))
 print('Dataset collection validation: OK; extracted files:',len(json_files))
if __name__=='__main__':main()
