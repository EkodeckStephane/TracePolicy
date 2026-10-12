"""Summarize frozen chronological cohorts without treating overlap as replication."""
from pathlib import Path
import argparse,json,statistics,hashlib
from collections import Counter
import numpy as np

def summarize(root):
    output={}; ids={}; actors=set()
    for cohort in ('earliest_alerts','temporal_delta'):
        folder=root/cohort
        methods={m:json.loads((folder/f'{m}.json').read_text()) for m in ('tracepolicy','kernelshap','lime','ffa','anchors')}
        tp={r['case']:r for r in methods['tracepolicy']}
        ids[cohort]={r['event_id'] for r in tp.values()}
        actors.update(r['case_metadata']['metadata']['source_process'] for r in tp.values())
        data={'cases':len(tp),'unique_events':len(ids[cohort]),'methods':{}}
        data['unit_counts']=dict(Counter(r['n_units'] for r in tp.values()))
        data['exact_core_counts']=dict(Counter(r['core_count'] for r in tp.values()))
        data['tp_selected_sets']=dict(Counter('|'.join(r['selected']) for r in tp.values()))
        for method,rows in methods.items():
            ok=[r for r in rows if r['status']=='ok']
            jaccard=[]
            for row in ok:
                a=set(row['selected']);b=set(tp[row['case']]['selected'])
                jaccard.append(len(a&b)/len(a|b) if a|b else 1.)
                with np.load(folder/'oracle_tables'/f"case_{row['case']:03d}.npz",allow_pickle=False) as table:
                    units=table['units'].tolist();labels=table['labels'];cores=table['minimal_core_masks'].tolist()
                    sm=sum(1<<i for i,u in enumerate(units) if u in a)
                    assert row['minimal']==(sm in cores)
                    assert len(labels)==2**len(units)
                    factual=labels[-1]
                    # Independent exhaustive sufficiency, including each returned witness.
                    suff=all(labels[k]==factual for k in range(len(labels)) if k&sm==sm)
                    assert row['sufficient']==suff
                    for released,witness in row['proof']['witnesses'].items():
                        assert not witness[released]
                        assert all(witness[u] for u in a-{released})
                        wm=sum(1<<i for i,u in enumerate(units) if witness[u])
                        assert labels[wm]!=factual
            data['methods'][method]={
                'rows':len(rows),'statuses':dict(Counter(r['status'] for r in rows)),
                'sufficient':sum(bool(r.get('sufficient')) for r in rows),
                'minimal':sum(bool(r.get('minimal')) for r in rows),
                'selected_sizes':dict(Counter(len(r['selected']) for r in ok)),
                'median_total_ms':statistics.median(r['total_s'] for r in ok)*1000 if ok else None,
                'mean_total_ms':statistics.mean(r['total_s'] for r in ok)*1000 if ok else None,
                'mean_jaccard_to_tp':statistics.mean(jaccard) if jaccard else None,
                'seeds':sorted({r['seed'] for r in rows}),
            }
        output[cohort]=data
    output['dependence']={'catalog_cases':sum(len(v) for v in ids.values()),'unique_current_events':len(set.union(*ids.values())), 'overlapping_current_events':len(set.intersection(*ids.values())),'unique_processes':len(actors)}
    output['interpretation']=[
        'Two conditional, deterministic earliest-alert cohorts; overlap and shared actors preclude treating 64 cases as independent observations.',
        'All minimal-core tables describe full shared event-stutter/rule-disable domains, not correctness inferred from Jaccard.',
        'Positive-retention cores need not contain predecessors whose absence of an expected pattern caused fallback denial.',
        'FFA is an exact complete-core membership adaptation with cached state enumeration included in its total; no timing superiority inference.',
        'Anchors native sets are unchanged and independently certified; three seeds are repeated explanations of each case, not new alerts.',
        'The frozen positive EXECUTE-to-CONNECT diagnostic had zero test instances and is excluded without retuning.'
    ]
    (root/'comparative_summary.json').write_text(json.dumps(output,indent=2),encoding='utf-8')
    return output

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--root',type=Path,required=True)
    args=parser.parse_args();print(json.dumps(summarize(args.root),indent=2))
