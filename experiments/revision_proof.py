"""Exact proof object for a fixed selected set; never prune or repair that set."""
from itertools import product
import trace_policy_engine as tpe

def certify_fixed_set(trace,policy,selected,horizon=4,max_units=18):
    eps,rids,units=tpe.explanation_unit_info(trace,policy,horizon)
    if len(units)>max_units: raise RuntimeError('proof object unit bound exceeded')
    selected=set(selected)
    if selected-set(units):raise ValueError('selected unit outside proof domain')
    y=tpe.reference_eval(trace,policy).alert_class;checks=0
    def counterexample(core):
        nonlocal checks
        free=[i for i,u in enumerate(units) if u not in core]
        for assignment in product((0,1),repeat=len(free)):
            mask=[int(u in core) for u in units]
            for i,value in zip(free,assignment):mask[i]=value
            checks+=1
            if tpe._class_under_mask(trace,policy,eps,rids,mask)!=y:return dict(zip(units,mask))
        return None
    suff_counterexample=counterexample(selected)
    if suff_counterexample is not None:return dict(sufficient=False,minimal=False,witnesses={},sufficiency_counterexample=suff_counterexample,checks=checks)
    witnesses={};redundant=[]
    for unit in sorted(selected):
        witness=counterexample(selected-{unit})
        if witness is None:redundant.append(unit)
        else:witnesses[unit]=witness
    return dict(sufficient=True,minimal=not redundant,witnesses=witnesses,redundant_units=redundant,checks=checks,target=y)
