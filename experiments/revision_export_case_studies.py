"""Export verified controlled attribution counterexamples without rerunning methods."""
from pathlib import Path
import json,sys
from dataclasses import asdict
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'src'),str(ROOT/'experiments')]
import trace_policy_engine as tpe
from revision_explanation_benchmark import controlled_cases,independent_table,all_minimal_cores,sufficient

def main():
    folder=ROOT/'results/revision'; rows=json.loads((folder/'benchmark.json').read_text()); cases={name:(tr,p,h) for name,tr,p,h in controlled_cases()}
    exports=[]
    for row in rows:
        if row['method']!='LIME' or row['status']!='ok' or row['minimal']:continue
        tr,p,h=cases[row['case']]; eps,rids,units=tpe.explanation_unit_info(tr,p,h)
        _,table=independent_table(tr,p,eps,rids);target=tpe.reference_eval(tr,p).alert_class
        cores=all_minimal_cores(units,table,target);ex=tpe.min_explain_bruteforce(tr,p,h)
        selected=set(row['selected']); deletions=[]
        for u in sorted(selected):
            candidate=selected-{u}; witnesses=[dict(zip(units,mask)) for mask,y in table.items() if all(mask[units.index(v)] for v in candidate) and y!=target]
            deletions.append(dict(released_unit=u,still_sufficient=sufficient(candidate,units,table,target),counterexample_mask=witnesses[0] if witnesses else None))
        exports.append(dict(measured_lime_row=row,trace=[asdict(e) for e in tr],policy=asdict(p),horizon=h,units=units,all_minimal_cores=[sorted(c) for c in cores],intrinsic_witnesses=ex.witnesses,deletion_checks=deletions))
    (folder/'lime_nonminimal_case_studies.json').write_text(json.dumps(exports,indent=2),encoding='utf-8');print(f'Exported {len(exports)} measured LIME counterexample(s)')
if __name__=='__main__':main()
