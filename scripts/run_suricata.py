#!/usr/bin/env python3
from __future__ import annotations
import json,subprocess,shutil,sys,uuid
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];LAB=ROOT/'local_lab/results';CFG=json.load(open(ROOT/'config/experiment.json'));SEEDS=json.load(open(ROOT/'config/seeds.json'))['seeds'];image=CFG['suricata_image']
def run(cmd,**kw):print('+',' '.join(map(str,cmd)));return subprocess.run(list(map(str,cmd)),check=True,**kw)
def main():
 for seed in SEEDS:
  p=LAB/f'pcap_{seed}.pcap';od=LAB/f'suricata_{seed}';name=f'projecta-suricata-{seed}'
  if not p.exists():raise FileNotFoundError(p)
  if od.exists():shutil.rmtree(od)
  od.mkdir(parents=True)
  subprocess.run(['docker','rm','-f',name],check=False,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
  run(['docker','create','--name',name,image,'-r','/input.pcap','-S','/local.rules','-l','/var/log/suricata','-k','none'])
  run(['docker','exec',name,'mkdir','-p','/data/out']) if False else None
  # docker cp can copy files into a stopped created container.
  run(['docker','cp',p,f'{name}:/input.pcap']);run(['docker','cp',ROOT/'docker/suricata/local.rules',f'{name}:/local.rules'])
  cp=subprocess.run(['docker','start','-a',name],text=True,capture_output=True)
  (od/'container.stdout.txt').write_text(cp.stdout);(od/'container.stderr.txt').write_text(cp.stderr)
  if cp.returncode!=0:raise RuntimeError(f'Suricata failed seed {seed}: {cp.stderr[-3000:]}')
  run(['docker','cp',f'{name}:/var/log/suricata/.',od]);subprocess.run(['docker','rm','-f',name],check=False,stdout=subprocess.DEVNULL)
  if not (od/'eve.json').exists():raise RuntimeError(f'Suricata eve.json missing seed {seed}')
 subprocess.run([sys.executable,str(ROOT/'experiments/run_suricata_metrics.py')],check=True)
if __name__=='__main__':main()
