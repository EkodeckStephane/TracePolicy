import sys
from pathlib import Path
import itertools
import pytest
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'src'),str(ROOT/'experiments')]
import trace_policy_engine as tpe
from revision_explanation_benchmark import controlled_cases, independent_table, all_minimal_cores, sufficient
from revision_proof import certify_fixed_set

@pytest.mark.parametrize('name,tr,policy,horizon',controlled_cases())
def test_independent_interventions_and_all_valid_cores(name,tr,policy,horizon):
    eps,rids,units=tpe.explanation_unit_info(tr,policy,horizon)
    _,table=independent_table(tr,policy,eps,rids)
    target=tpe.reference_eval(tr,policy).alert_class
    assert table[(1,)*len(units)]==target
    for mask,y in table.items():
        assert tpe._class_under_mask(tr,policy,eps,rids,mask)==y
    cores=all_minimal_cores(units,table,target)
    ex=tpe.min_explain_bruteforce(tr,policy,horizon)
    selected={f'e:{i}' for i in ex.event_positions}|{f'r:{r}' for r in ex.rule_ids}
    assert selected in cores
    for u,witness in ex.witnesses.items():
        assert all(witness[v] for v in selected-{u})
        assert table[tuple(witness[v] for v in units)] != target
    if name.startswith('multiple_'): assert len(cores)>1

def test_stutter_identity_and_wildcard_neutralization():
    e=tpe.Event('e',0,'act','resource','user')
    s=tpe.derive_state([e]); neutral=tpe.Event.stutter_like(e)
    assert tpe.transition(s,neutral)==s
    assert tpe.transition(s,neutral).values==s.values
    assert not tpe.Selector().matches(neutral)
    assert not tpe.Guard(seen_action='*',seen_horizon=1).eval([neutral])
    assert not tpe.Guard(seq_actions=('*',),seq_horizon=1).eval([neutral])

def test_selector_reduced_domain_matches_full_for_every_mask():
    for _,tr,policy,horizon in controlled_cases():
        eps,rids,units=tpe.explanation_unit_info(tr,policy,horizon,True)
        for mask in itertools.product((0,1),repeat=len(units)):
            full_rids=[r.rid for r in policy.rules]
            full_mask=list(mask[:len(eps)])+[mask[len(eps)+rids.index(r)] if r in rids else 1 for r in full_rids]
            assert tpe._class_under_mask(tr,policy,eps,rids,mask)==tpe._class_under_mask(tr,policy,eps,full_rids,full_mask)

def test_unknown_selected_units_are_rejected():
    _,tr,p,h=controlled_cases()[0]
    with pytest.raises(ValueError): tpe.exact_sufficiency_of_selected(tr,p,{'r:nonexistent'},h)

def test_sufficient_prefix_can_be_nonminimal():
    name,tr,p,h=next(c for c in controlled_cases() if c[0]=='distractors')
    eps,rids,units=tpe.explanation_unit_info(tr,p,h)
    _,table=independent_table(tr,p,eps,rids); target=tpe.reference_eval(tr,p).alert_class
    selected={'e:0','e:2','r:D'}
    assert sufficient(selected,units,table,target)
    assert selected not in all_minimal_cores(units,table,target)
    proof=certify_fixed_set(tr,p,selected,h)
    assert proof['sufficient'] and not proof['minimal']
    assert proof['redundant_units']==['e:0']

@pytest.mark.parametrize('name,tr,policy,horizon',controlled_cases())
def test_fixed_set_proof_witnesses_independently(name,tr,policy,horizon):
    eps,rids,units=tpe.explanation_unit_info(tr,policy,horizon)
    _,table=independent_table(tr,policy,eps,rids);target=tpe.reference_eval(tr,policy).alert_class
    core=all_minimal_cores(units,table,target)[0];proof=certify_fixed_set(tr,policy,core,horizon)
    assert proof['sufficient'] and proof['minimal']
    assert set(proof['witnesses'])==core
    for unit,w in proof['witnesses'].items():
        assert all(w[u] for u in core-{unit})
        assert table[tuple(w[u] for u in units)]!=target

def update_fixture():
    old=tpe.PolicyVersion('update',1,(tpe.Rule('A',0,tpe.ALLOW,tpe.Selector()),))
    new=tpe.PolicyVersion('update',2,old.rules+(tpe.Rule('D',10,tpe.DENY,tpe.Selector('connect'),tpe.Guard(seq_actions=('read','exec','connect'),seq_horizon=3)),))
    trace=[tpe.Event(str(i),i,a,'resource','user') for i,a in enumerate(['read','exec','connect'])]
    return old,new,trace

def test_history_expanding_update_rejection_is_atomic():
    old,new,tr=update_fixture();inc=tpe.IncrementalEvaluator(old)
    inc.push(tr[0]);inc.push(tr[1])
    before=(inc.policy,inc.index,list(inc.trace),dict(inc.state.values),list(inc.version_history),inc.retention_horizon,inc.discarded_positions)
    assert inc.discarded_positions==1
    with pytest.raises(ValueError,match='history was discarded'):inc.update_policy(new)
    assert (inc.policy,inc.index,list(inc.trace),dict(inc.state.values),list(inc.version_history),inc.retention_horizon,inc.discarded_positions)==before
    assert inc.push(tr[2]).alert_class==tpe.reference_eval(tr,old).alert_class
    assert tpe.reference_eval(tr,new).alert_class==tpe.VIOLATION

@pytest.mark.parametrize('retention,push_before_update',[(3,2),(None,1)])
def test_history_expanding_update_with_sufficient_history(retention,push_before_update):
    old,new,tr=update_fixture();inc=tpe.IncrementalEvaluator(old,retention_horizon=retention)
    for e in tr[:push_before_update]:inc.push(e)
    inc.update_policy(new)
    for i in range(push_before_update,len(tr)):
        assert inc.push(tr[i]).alert_class==tpe.reference_eval(tr[:i+1],new).alert_class
    assert inc.version_history==[1,2]
    assert inc.discarded_positions==0
