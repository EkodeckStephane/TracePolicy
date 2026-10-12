"""Validate observed revision outputs against saved exhaustive mask tables."""
from pathlib import Path
import json
import numpy as np
import sys

ROOT=Path(__file__).resolve().parents[1]

def main():
    sys.path[:0]=[str(ROOT/'src'),str(ROOT/'experiments')]
    from revision_extended_methods import load_frozen_cases
    manifest=json.loads((ROOT/'results/revision/local_lab_proofmatched/run_manifest.json').read_text(encoding='utf8'))
    _,cases,input_hashes=load_frozen_cases(manifest,ROOT/'local_lab/results')
    assert len(cases)==120 and len(input_hashes)==60
    folder=ROOT/'results/revision/extended_methods'
    loaded={}
    counts={}
    witnesses=0
    for method,expected in [('anchors',360),('ffa',120)]:
        rows=json.loads((folder/f'{method}.json').read_text(encoding='utf8'))
        assert len(rows)==expected
        for row in rows:
            assert row['status']=='ok' and row['sufficient'] and row['minimal']
            case=row['case']
            if case not in loaded:
                with np.load(folder/f'oracle_tables/case_{case:03d}.npz',allow_pickle=False) as t:
                    loaded[case]={k:t[k].copy() for k in t.files}
            t=loaded[case];units=t['units'].tolist()
            assert units==row['units']
            classes=t['class_names'].tolist();target=classes.index(row['target_class'])
            selected=set(row['selected'])
            mask=sum(1<<i for i,u in enumerate(units) if u in selected)
            assert mask in t['minimal_core_masks']
            all_masks=np.arange(len(t['labels']))
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
    print(json.dumps(dict(outputs=counts,cases=len(loaded),input_hashes=len(input_hashes),independently_checked_witnesses=witnesses)))

if __name__=='__main__':main()
