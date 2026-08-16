from __future__ import annotations
from pathlib import Path
import pandas as pd
from trace_policy_engine import Rule,Selector,Guard,PolicyVersion

def save_policy_csv(policy: PolicyVersion, path: Path):
    rows=[]
    for r in policy.rules:
        # DARPA learned policies currently use the empty guard or explicit fallback guard.
        rows.append({
            'pid':policy.pid,'version':policy.version,'rid':r.rid,'priority':r.priority,'effect':r.effect,
            'action':r.selector.action,'resource_class':r.selector.resource_class,'subject_class':r.selector.subject_class,
            'fallback_nonstutter':int(r.rid=='D_DARPA_UNSEEN_SELECTOR')
        })
    Path(path).parent.mkdir(parents=True,exist_ok=True)
    pd.DataFrame(rows).to_csv(path,index=False)

def load_policy_csv(path: Path) -> PolicyVersion:
    df=pd.read_csv(path)
    rules=[]
    for x in df.itertuples(index=False):
        g=Guard(comparisons=(('action','!=','__STUTTER__'),)) if int(getattr(x,'fallback_nonstutter',0)) else Guard()
        rules.append(Rule(str(x.rid),int(x.priority),str(x.effect),Selector(str(x.action),str(x.resource_class),str(x.subject_class)),g))
    return PolicyVersion(str(df.iloc[0].pid),int(df.iloc[0].version),tuple(rules))
