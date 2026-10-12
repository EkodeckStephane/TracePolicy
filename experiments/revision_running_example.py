from pathlib import Path
import sys,json
ROOT=Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT/'src'))
import trace_policy_engine as tpe
from local_lab_adapter import lab_policy

def main():
    rows=[]; p=lab_policy()
    for name,n,resource in [('bruteforce',4,'auth_fail'),('admin',1,'admin_sensitive')]:
        tr=[tpe.Event(f'{name}:{i}',i,'http_request',resource,'remote_client') for i in range(n)]
        ex=tpe.min_explain_bruteforce(tr,p,5)
        units={f'e:{i}' for i in ex.event_positions}|{f'r:{r}' for r in ex.rule_ids}
        rows.append(dict(case=name,target=ex.target_class,core=sorted(units),witnesses=ex.witnesses,unit_count=ex.unit_count,
                         release_event_with_rules_factual=[tpe.reference_eval([e if i!=j else tpe.Event.stutter_like(e) for i,e in enumerate(tr)],p).alert_class for j in range(n)]))
    out=ROOT/'results/revision/running_example.json'; out.parent.mkdir(parents=True,exist_ok=True);out.write_text(json.dumps(rows,indent=2),encoding='utf-8');print(out)
if __name__=='__main__':main()
