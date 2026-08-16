from __future__ import annotations
from collections import defaultdict
from metrics import binary_metrics

def episode_binary_metrics(truth_rows, pred_sids):
    ep={}
    for r in truth_rows:
        eid=r.get('episode_id') or r['sid']
        x=ep.setdefault(eid,{'truth':0,'pred':0})
        x['truth']=max(x['truth'],int(r['label']))
        x['pred']=max(x['pred'],int(r['sid'] in pred_sids))
    return binary_metrics([x['truth'] for x in ep.values()],[x['pred'] for x in ep.values()])
