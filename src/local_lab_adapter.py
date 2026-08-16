from __future__ import annotations
import json
from pathlib import Path
from trace_policy_engine import *

def classify_resource(path,status):
    p=(path or '').lower()
    if p.startswith('/admin'): return 'admin_sensitive'
    if 'etc/passwd' in p or '..' in p: return 'path_traversal'
    if p.startswith('/cmd'): return 'command_probe'
    if p.startswith('/login') and int(status)==401: return 'auth_fail'
    if p.startswith('/login'): return 'auth'
    if p.startswith('/public'): return 'public'
    if p.startswith('/status'): return 'status'
    return 'other'

def load_gateway_events(path:Path, truth:dict):
    out=[]
    for i,line in enumerate(path.read_text(errors='replace').splitlines()):
        if not line.strip(): continue
        r=json.loads(line); sid=r.get('sid',''); y=int(truth.get(sid,{}).get('label',0)); typ=truth.get(sid,{}).get('scenario','unknown')
        rc=classify_resource(r.get('path',''),r.get('status',0))
        out.append(Event(sid or f'lab{i}',float(r.get('ts',i)),'http_request',rc,'remote_client',
                         {'path':r.get('path',''),'status':int(r.get('status',0)),'sid':sid},y,typ))
    return out

def lab_policy(version=1):
    return PolicyVersion('LOCAL_HTTP_GATEWAY',version,(
        Rule('D_ADMIN',100,DENY,Selector('http_request','admin_sensitive','remote_client')),
        Rule('D_TRAVERSAL',100,DENY,Selector('http_request','path_traversal','remote_client')),
        Rule('D_COMMAND',100,DENY,Selector('http_request','command_probe','remote_client')),
        Rule('D_BRUTEFORCE',100,DENY,Selector('http_request','auth_fail','remote_client'),
             Guard(count_action='http_request',count_resource='auth_fail',count_horizon=5,count_op='>=',count_threshold=4)),
        Rule('A_AUTH_FAIL_SINGLE',10,ALLOW,Selector('http_request','auth_fail','remote_client')),
        Rule('A_AUTH',10,ALLOW,Selector('http_request','auth','remote_client')),
        Rule('A_PUBLIC',10,ALLOW,Selector('http_request','public','remote_client')),
        Rule('A_STATUS',10,ALLOW,Selector('http_request','status','remote_client')),
    ))
