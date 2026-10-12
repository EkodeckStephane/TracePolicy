"""Validate observed revision outputs against saved exhaustive mask tables."""
from pathlib import Path
import json
import numpy as np
import sys
import hashlib
import itertools

ROOT=Path(__file__).resolve().parents[1]

def verify_saved_tables(folder,expected):
    loaded={};counts={};witnesses=0
    for method,nrows in expected:
        rows=json.loads((folder/f'{method}.json').read_text(encoding='utf8'))
        assert len(rows)==nrows
        for row in rows:
            assert row['status']=='ok' and row['sufficient'] and row['minimal']
            case=row['case']
            if case not in loaded:
                with np.load(folder/f'oracle_tables/case_{case:03d}.npz',allow_pickle=False) as t:
                    loaded[case]={k:t[k].copy() for k in t.files}
            t=loaded[case];units=t['units'].tolist()
            assert units==row['units']
            target=t['class_names'].tolist().index(row['target_class'])
            selected=set(row['selected']);assert selected<=set(units)
            mask=sum(1<<i for i,u in enumerate(units) if u in selected)
            assert mask in t['minimal_core_masks']
            all_masks=np.arange(len(t['labels']))
            assert len(all_masks)==2**len(units)
            assert np.all(t['labels'][(all_masks&mask)==mask]==target)
            proof=row['proof'];assert proof['sufficient'] and proof['minimal']
            assert set(proof['witnesses'])==selected
            for removed,assignment in proof['witnesses'].items():
                assert set(assignment)==set(units) and assignment[removed]==0
                assert all(assignment[u]==1 for u in selected-{removed})
                assert all(v in [0,1] for v in assignment.values())
                wm=sum(1<<i for i,u in enumerate(units) if assignment[u])
                assert int(t['labels'][wm])!=target
                witnesses+=1
        counts[method]=len(rows)
    return dict(outputs=counts,cases=len(loaded),independently_checked_witnesses=witnesses)


def verify_live():
    import trace_policy_engine as tpe
    from revision_distributed_lab import lab_policies
    artifact=json.loads((ROOT/'results/revision/distributed_live_crossos_proofs.json').read_text())
    cohort=ROOT/'results/revision/distributed_live_crossos_corrected'
    def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
    for name,digest in artifact['cohort_sha256'].items():assert sha(cohort/name)==digest
    assert sha(cohort/'source_snapshot/code/src/trace_policy_engine.py')==artifact['engine_snapshot_sha256']
    policies=lab_policies();witnesses=0
    for row in artifact['proofs']:
        folder=cohort/row['run_id']
        for name,digest in row['source_sha256'].items():assert sha(folder/name)==digest
        observations=[]
        for source in ('A','B'):observations+=json.loads((folder/f'{source}.json').read_text())['observations']
        observations.sort(key=lambda o:(o['event']['ts'],o['event']['eid']))
        assert [o['event'] for o in observations]==row['trace']
        tr=[tpe.Event(**e) for e in row['trace']];policy=policies[2]
        for i,(observation,decision) in enumerate(zip(observations,row['decisions'])):
            assert tpe.reference_eval(tr[:i+1],policies[observation['policy_version']]).alert_class==decision['reference']==decision['incremental']
        units=[f'e:{i}' for i in range(len(tr))]+[f'r:{r.rid}' for r in policy.rules]
        selected=set(row['selected']);table={}
        for mask in itertools.product((0,1),repeat=len(units)):
            altered=[e if mask[i] else tpe.Event.stutter_like(e) for i,e in enumerate(tr)]
            retained=tuple(r for j,r in enumerate(policy.rules) if mask[len(tr)+j])
            table[mask]=tpe.reference_eval(altered,tpe.PolicyVersion(policy.pid,policy.version,retained)).alert_class
        assert all(v==tpe.VIOLATION for k,v in table.items() if all(k[units.index(u)] for u in selected))
        proof=row['explanation'];assert set(proof['witnesses'])==selected
        for released,w in proof['witnesses'].items():
            assert set(w)==set(units) and not w[released]
            assert all(w[u] for u in selected-{released})
            assert table[tuple(w[u] for u in units)]!=tpe.VIOLATION
            witnesses+=1
    assert len(artifact['proofs'])==15 and witnesses==60
    return dict(complete_live_proofs=15,independently_checked_witnesses=witnesses)


def main():
    sys.path[:0]=[str(ROOT/'src'),str(ROOT/'experiments')]
    from revision_extended_methods import load_frozen_cases
    manifest=json.loads((ROOT/'results/revision/local_lab_proofmatched/run_manifest.json').read_text(encoding='utf8'))
    _,cases,input_hashes=load_frozen_cases(manifest,ROOT/'local_lab/results')
    assert len(cases)==120 and len(input_hashes)==60
    docker=verify_saved_tables(ROOT/'results/revision/extended_methods',[('anchors',360),('ffa',120)])
    temporal={}
    for name in ('earliest_alerts','temporal_delta'):
        temporal[name]=verify_saved_tables(ROOT/'results/revision/theia_chronological_methods'/name,[(m,96 if m=='anchors' else 32) for m in ('tracepolicy','kernelshap','lime','ffa','anchors')])
    assert sum(sum(v['outputs'].values()) for v in temporal.values())==448
    assert sum(v['independently_checked_witnesses'] for v in temporal.values())==896
    print(json.dumps(dict(docker=docker,input_hashes=len(input_hashes),chronological=temporal,live=verify_live())))

if __name__=='__main__':main()
