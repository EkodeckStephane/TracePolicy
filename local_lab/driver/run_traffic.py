#!/usr/bin/env python3
import argparse, csv, random, time, uuid, urllib.request, urllib.error
from pathlib import Path

BENIGN=[('/public','benign_public'),('/status','benign_status'),('/login?ok=1','benign_login')]
ATTACK=[('/admin/secret','admin_probe'),('/%2e%2e/%2e%2e/etc/passwd','path_traversal'),('/cmd?x=id','command_probe')]

def send(base,path,sid):
    sep='&' if '?' in path else '?'; url=base+path+sep+'sid='+sid
    req=urllib.request.Request(url,headers={'User-Agent':'ProjectA-Lab/1.0','X-Scenario-ID':sid})
    try:
        with urllib.request.urlopen(req,timeout=5) as r: return r.status
    except urllib.error.HTTPError as e: return e.code

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--seed',type=int,required=True); ap.add_argument('--base',default='http://gateway:8080')
    ap.add_argument('--out',required=True); ap.add_argument('--n',type=int,default=300); args=ap.parse_args()
    rng=random.Random(args.seed); rows=[]
    def new_uuid(): return str(uuid.UUID(int=rng.getrandbits(128)))
    # Include temporal brute-force episodes among independent requests.
    i=0
    while i<args.n:
        if rng.random()<0.18:
            typ=rng.choice(['single','bruteforce'])
            if typ=='bruteforce':
                episode_id=new_uuid()
                for _ in range(min(5,args.n-i)):
                    sid=new_uuid(); t=time.time(); st=send(args.base,'/login?ok=0',sid)
                    rows.append((sid,t,1,'bruteforce',st,episode_id)); i+=1; time.sleep(rng.uniform(.002,.015))
                continue
            path,label=rng.choice(ATTACK); y=1
        else:
            path,label=rng.choice(BENIGN); y=0
        sid=new_uuid(); t=time.time(); st=send(args.base,path,sid); rows.append((sid,t,y,label,st,sid)); i+=1
        time.sleep(rng.uniform(.002,.015))
    p=Path(args.out); p.parent.mkdir(parents=True,exist_ok=True)
    with p.open('w',newline='') as f:
        w=csv.writer(f); w.writerow(['sid','sent_ts','label','scenario','http_status','episode_id']); w.writerows(rows)
if __name__=='__main__': main()
