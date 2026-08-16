from __future__ import annotations
import random, time
from trace_policy_engine import *

def clean_policy(version=1):
    return PolicyVersion('LOCAL',version,(
        Rule('D_SECRET_READ',100,DENY,Selector('read','secret','user')),
        Rule('D_SYSTEM_WRITE',100,DENY,Selector('write','system','user')),
        Rule('D_SYSTEM_EXEC',100,DENY,Selector('exec','system','user')),
        Rule('D_SCAN',100,DENY,Selector('connect','network','user'),Guard(count_action='connect',count_resource='network',count_horizon=4,count_op='>=',count_threshold=3)),
        Rule('A_READ_PUBLIC',10,ALLOW,Selector('read','public','user')),
        Rule('A_WRITE_PUBLIC',10,ALLOW,Selector('write','public','user')),
        Rule('A_CONNECT_SERVICE',10,ALLOW,Selector('connect','service','user')),
        Rule('A_NETWORK_CONNECT',10,ALLOW,Selector('connect','network','user')),
        Rule('A_ADMIN',50,ALLOW,Selector('*','*','admin')),
    ))

def generate_local_trace(n=5000,seed=0,attack_rate=.18):
    rng=random.Random(seed); events=[]; ts=0.0; scan_stage=0
    for i in range(n):
        ts += rng.uniform(.01,.2)
        is_attack = rng.random()<attack_rate
        if is_attack:
            typ=rng.choice(['secret_read','system_write','system_exec','scan'])
            if typ=='secret_read': a,rc='read','secret'
            elif typ=='system_write': a,rc='write','system'
            elif typ=='system_exec': a,rc='exec','system'
            else: a,rc='connect','network'
            events.append(Event(f'L{i}',ts,a,rc,'user',{},1,typ))
        else:
            a,rc=rng.choice([('read','public'),('write','public'),('connect','service')])
            events.append(Event(f'L{i}',ts,a,rc,'user',{},0,'normal'))
    return events

def mark_policy_ground_truth(trace,policy):
    # For RQ1, ground truth is generated attack intent, independent of policy output.
    return [int(e.malicious or 0) for e in trace]
