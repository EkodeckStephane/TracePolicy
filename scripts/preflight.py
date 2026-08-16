#!/usr/bin/env python3
from __future__ import annotations
import json,platform,shutil,subprocess,sys,os
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];LOG=ROOT/'results/logs';LOG.mkdir(parents=True,exist_ok=True)
CFG=json.load(open(ROOT/'config/experiment.json'))
def capture(cmd):
 p=subprocess.run(cmd,text=True,capture_output=True);return {'cmd':cmd,'returncode':p.returncode,'stdout':p.stdout,'stderr':p.stderr}
def main():
 # Verify the frozen scientific protocol before contacting datasets or running baselines.
 manifest=ROOT/'FROZEN_PUBLICATION_SHA256.txt'
 for line in manifest.read_text().splitlines():
  expected,rel=line.split(None,1); fp=ROOT/rel.strip(); import hashlib
  got=hashlib.sha256(fp.read_bytes()).hexdigest() if fp.exists() else 'MISSING'
  if got!=expected: raise SystemExit(f'Publication protocol hash mismatch: {rel.strip()} expected={expected} got={got}. Document a protocol deviation instead of continuing.')
 info={'platform':platform.platform(),'python':sys.version,'disk_free_bytes':shutil.disk_usage(ROOT).free,'docker':capture(['docker','version']),'compose':capture(['docker','compose','version'])}
 if info['docker']['returncode']!=0:raise SystemExit('Docker daemon is not reachable from the execution environment. If using the runner, mount /var/run/docker.sock; otherwise run scripts from the host.')
 if info['compose']['returncode']!=0:raise SystemExit('docker compose plugin is required.')
 if info['disk_free_bytes']<50*1024**3:print('WARNING: less than 50 GiB free. DARPA E3 extraction may require substantially more space; monitor disk usage.')
 for image in [CFG['suricata_image'],CFG['wazuh_image']]:
  print('Pulling pinned image',image);subprocess.run(['docker','pull',image],check=True)
  info.setdefault('images',{})[image]=capture(['docker','image','inspect',image])
 (LOG/'preflight.json').write_text(json.dumps(info,indent=2))
 print('Preflight OK')
if __name__=='__main__':main()
