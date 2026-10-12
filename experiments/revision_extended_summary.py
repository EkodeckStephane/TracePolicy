"""Evidence-only summary and provenance annotations; does not change measurements."""
from pathlib import Path
import json,csv,statistics,collections
ROOT=Path(__file__).resolve().parents[1]

def main():
    folder=ROOT/'results/revision/extended_methods'
    refs={int(r['case']):set(r['core'].split(';')) for r in csv.DictReader((ROOT/'results/revision/local_lab_proofmatched/rq2_local_lab_explanations.csv').open())}
    jac=lambda a,b:len(a&b)/len(a|b) if a|b else 1.
    rows_by_method={method:json.loads((folder/f'{method}.json').read_text()) for method in ['anchors','ffa']}
    anchor_manifest=json.loads((folder/'anchors_manifest.json').read_text())
    anchor_manifest.update(native_cold_import='Alibi imported lazily: first outer native_s includes module import and population construction; native.total_native_us excludes both',oracle_memoization='empty canonical cache per native explanation; no independent truth table used for native prediction',timing_comparison='separate NumPy environment; no superiority claim against other methods')
    (folder/'anchors_manifest.json').write_text(json.dumps(anchor_manifest,indent=2),encoding='utf-8')
    first_seed=int(anchor_manifest['arguments']['seeds'].split(',')[0])
    for row in rows_by_method['anchors']:
        row['first_native_call_includes_cold_import']=row['case']==0 and row.get('seed')==first_seed
    ffa_manifest=json.loads((folder/'ffa_manifest.json').read_text())
    ffa_manifest.update(enumeration_backend='independent canonical table, state replay cached per event mask, complete all-core superset DP O(m*2^m)',timing_comparison='includes full-table enumeration and complete-core construction; different cached backend and richer output than single-core methods, no superiority inference')
    (folder/'ffa_manifest.json').write_text(json.dumps(ffa_manifest,indent=2),encoding='utf-8')
    combined=[]
    for method,rows in rows_by_method.items():
        for row in rows:
            if row['status']=='ok':row['jaccard_with_intrinsic']=jac(set(row['selected']),refs[row['case']])
        (folder/f'{method}.json').write_text(json.dumps(rows,indent=2),encoding='utf-8')
        fields=sorted({k for row in rows for k in row})
        with (folder/f'{method}.csv').open('w',newline='',encoding='utf-8') as stream:
            writer=csv.DictWriter(stream,fieldnames=fields);writer.writeheader();writer.writerows({k:json.dumps(v) if isinstance(v,(dict,list)) else v for k,v in row.items()} for row in rows)
        for scenario in sorted({r['scenario'] for r in rows}):
            sub=[r for r in rows if r['scenario']==scenario];good=[r for r in sub if r['status']=='ok']
            combined.append(dict(method=method,scenario=scenario,runs=len(sub),ok=len(good),sufficient=sum(bool(r.get('sufficient')) for r in sub),minimal=sum(bool(r.get('minimal')) for r in sub),jaccard_mean=statistics.mean(r['jaccard_with_intrinsic'] for r in good) if good else None,total_s_median=statistics.median(r['total_s'] for r in good) if good else None,selected_size_min=min(len(r['selected']) for r in good) if good else None,selected_size_max=max(len(r['selected']) for r in good) if good else None))
    core_counts=collections.Counter(r['core_count'] for r in rows_by_method['ffa'] if r['status']=='ok')
    (folder/'comparative_summary.json').write_text(json.dumps(dict(by_scenario=combined,complete_core_count_distribution=dict(core_counts),limitations=['retrospective true-positive Docker strata only','native Anchors canonical-cache backend and separate NumPy environment','FFA full-core cached-state enumeration is a definition adaptation, not the published anytime implementation','no analyst utility or timing superiority inferred']),indent=2),encoding='utf-8')
    print(json.dumps(dict(rows=sum(len(r) for r in rows_by_method.values()),complete_core_count_distribution=dict(core_counts))))
if __name__=='__main__':main()
