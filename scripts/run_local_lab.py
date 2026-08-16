#!/usr/bin/env python3
from __future__ import annotations
import json,subprocess,time,sys,shutil
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]; LAB=ROOT/'local_lab/results'; LAB.mkdir(parents=True,exist_ok=True)
CFG=json.load(open(ROOT/'config/experiment.json')); SEEDS=json.load(open(ROOT/'config/seeds.json'))['seeds']; n=CFG['local_lab_requests_per_seed']
def run(cmd,**kw):
 print('+',' '.join(map(str,cmd)));return subprocess.run(list(map(str,cmd)),check=True,**kw)
def main():
 run(['docker','compose','-f',ROOT/'docker-compose.local-lab.yml','build'])
 for seed in SEEDS:
  # Isolate each repetition: a clean container and clean log.
  subprocess.run(['docker','compose','-f',str(ROOT/'docker-compose.local-lab.yml'),'down','--remove-orphans'],check=False)
  run(['docker','compose','-f',ROOT/'docker-compose.local-lab.yml','up','-d','gateway']);time.sleep(1.5)
  # Clean the named volume after the fresh gateway exists.
  run(['docker','exec','projecta-gateway','sh','-c','rm -f /data/access.jsonl /data/capture.pcap /data/truth_*.csv'])
  # Capture inside the actual target container.
  run(['docker','exec','-d','projecta-gateway','sh','-c','rm -f /data/capture.pcap; tcpdump -U -i eth0 -w /data/capture.pcap tcp port 8080'])
  time.sleep(.5)
  run(['docker','compose','-f',ROOT/'docker-compose.local-lab.yml','run','--rm','driver','--seed',seed,'--out',f'/results/truth_{seed}.csv','--n',n])
  time.sleep(.5);subprocess.run(['docker','exec','projecta-gateway','pkill','-INT','tcpdump'],check=False);time.sleep(.5)
  # Copy from Docker named volume through the gateway container into the outer runner's /work bind mount.
  for remote,local in [(f'/data/access.jsonl',LAB/f'access_{seed}.jsonl'),(f'/data/capture.pcap',LAB/f'pcap_{seed}.pcap'),(f'/data/truth_{seed}.csv',LAB/f'truth_{seed}.csv')]:
   run(['docker','cp',f'projecta-gateway:{remote}',local])
   if not Path(local).exists() or Path(local).stat().st_size==0: raise RuntimeError(f'missing/empty local-lab artifact {local}')
 subprocess.run(['docker','compose','-f',str(ROOT/'docker-compose.local-lab.yml'),'down','--remove-orphans'],check=False)
 print('Local lab complete:',len(SEEDS),'independent repetitions')
if __name__=='__main__':main()
