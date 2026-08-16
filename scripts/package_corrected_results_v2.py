#!/usr/bin/env python3
from pathlib import Path
import zipfile,hashlib,pandas as pd,os
ROOT=Path(__file__).resolve().parents[1]
gate=ROOT/'PHASE5_CORRECTIVE_GATE_V2.csv'
if not gate.exists() or not (pd.read_csv(gate).status=='PASS').all():
    status='FAIL'
else: status='PASS'
# Two distinct manifests: entire workspace vs files included in return ZIP.
def sha(p):
    h=hashlib.sha256()
    with open(p,'rb') as f:
        for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
    return h.hexdigest()
ws=[]
for p in sorted(ROOT.rglob('*')):
    if p.is_file() and '__pycache__' not in p.parts and '.pytest_cache' not in p.parts and not p.name.endswith('.zip'):
        try:ws.append(f'{sha(p)}  {p.relative_to(ROOT)}  {p.stat().st_size}')
        except:pass
(ROOT/'WORKSPACE_MANIFEST_SHA256_V2.txt').write_text('\n'.join(ws)+'\n')
zpath=ROOT/f'Project_A_Phase5_RESULTS_CORRECTED_V2{"_FAIL" if status!="PASS" else ""}.zip'
exclude=('datasets/raw/darpa_e3/cadets/','datasets/seed/','vendor/','.external/','results/invalid_prepatch_wazuh/')
included=[]
with zipfile.ZipFile(zpath,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=6) as z:
    for p in sorted(ROOT.rglob('*')):
        if not p.is_file() or p==zpath or p.name.endswith('.zip'):continue
        rel=str(p.relative_to(ROOT)).replace('\\','/')
        if any(rel.startswith(x) for x in exclude):continue
        z.write(p,rel);included.append(f'{sha(p)}  {rel}  {p.stat().st_size}')
(ROOT/'RETURN_ZIP_MANIFEST_SHA256_V2.txt').write_text('\n'.join(included)+'\n')
# Reopen and add the return manifest itself.
with zipfile.ZipFile(zpath,'a',compression=zipfile.ZIP_DEFLATED,compresslevel=6) as z:
    z.write(ROOT/'RETURN_ZIP_MANIFEST_SHA256_V2.txt','RETURN_ZIP_MANIFEST_SHA256_V2.txt')
print(zpath)
