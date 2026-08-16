import sys, random
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from trace_policy_engine import *


def ev(i,a='read',r='public',s='user',**attrs):
    return Event(str(i),float(i),a,r,s,attrs)


def test_allow_deny_conflict_gap_and_priority():
    e=ev(1)
    allow=Rule('A',10,ALLOW,Selector('read','public','user'))
    deny_low=Rule('DL',1,DENY,Selector('read','public','user'))
    deny_same=Rule('DS',10,DENY,Selector('read','public','user'))
    p=PolicyVersion('p',1,(allow,deny_low))
    assert reference_eval([e],p).alert_class==NOALERT
    p2=PolicyVersion('p',2,(allow,deny_same))
    assert reference_eval([e],p2).alert_class==CONFLICT
    p3=PolicyVersion('p',3,(deny_same,))
    assert reference_eval([e],p3).alert_class==VIOLATION
    p4=PolicyVersion('p',4,())
    assert reference_eval([e],p4).alert_class==GAP


def test_state_seen_count_seq_and_boolean_guards():
    tr=[ev(1,'connect','network'),ev(2,'read','public'),ev(3,'connect','network')]
    st=derive_state(tr)
    g=Guard(
        state_comparisons=(('event_count','>=',3),),
        seen_action='read',seen_horizon=3,
        count_action='connect',count_resource='network',count_horizon=3,count_op='>=',count_threshold=2,
        seq_actions=('connect','read','connect'),seq_horizon=3,
        all_of=(Guard(comparisons=(('resource_class','==','network'),)),),
        none_of=(Guard(comparisons=(('subject_class','==','admin'),)),)
    )
    assert g.eval(tr,st)


def test_index_equivalence_randomized():
    rules=[]
    acts=['read','write','exec']; rs=['public','secret','system']; ss=['user','admin']
    k=0
    for a in acts:
        for r in rs:
            for s in ss:
                rules.append(Rule(f'R{k}',10 if k%3 else 20,DENY if k%4==0 else ALLOW,Selector(a,r,s)))
                k+=1
    rules.append(Rule('DEFAULT',0,DENY,Selector('*','*','*')))
    p=PolicyVersion('p',1,tuple(rules)); idx=StaticIndex(p)
    rng=random.Random(7); tr=[]
    for i in range(300):
        e=ev(i,rng.choice(acts),rng.choice(rs),rng.choice(ss)); tr.append(e)
        a=reference_eval(tr,p); b=idx.eval(tr)
        assert (a.decision,a.alert_class,set(a.applicable),set(a.top))==(b.decision,b.alert_class,set(b.applicable),set(b.top))


def test_incremental_equivalence_and_version_binding():
    p1=PolicyVersion('p',1,(Rule('A',10,ALLOW,Selector('read','public','user')),Rule('D',0,DENY,Selector('*','*','*'))))
    p2=PolicyVersion('p',2,p1.rules+(Rule('X',20,DENY,Selector('write','system','user')),))
    inc=IncrementalEvaluator(p1); tr=[]
    for i,e in enumerate([ev(1),ev(2,'write','public'),ev(3,'write','system')]):
        if i==2: inc.update_policy(p2); p=p2
        else: p=p1
        tr.append(e); a=reference_eval(tr,p); b=inc.push(e)
        assert (a.alert_class,a.top)==(b.alert_class,b.top)
        assert b.policy_version==p.version
    try:
        inc.update_policy(p1)
        assert False, 'rollback should fail'
    except ValueError:
        pass


def test_minimal_explanation_soundness_and_witnesses():
    p=PolicyVersion('p',1,(
        Rule('D',100,DENY,Selector('read','secret','user')),
        Rule('A',10,ALLOW,Selector('read','public','user')),
    ))
    tr=[ev(1,'read','public'),ev(2,'read','secret')]
    ex=min_explain_bruteforce(tr,p,horizon=2)
    selected={f'e:{i}' for i in ex.event_positions}|{f'r:{r}' for r in ex.rule_ids}
    assert exact_sufficiency_of_selected(tr,p,selected,horizon=2) is True
    assert ex.target_class==VIOLATION
    assert len(ex.witnesses)==len(selected)
    assert ex.policy_version==1


def test_policy_defect_diagnosis():
    base=PolicyVersion('p',1,(Rule('A',10,ALLOW,Selector('read','public','user')),))
    conflict=mutate_conflict(base,'A',2)
    assert reference_eval([ev(1)],conflict).alert_class==CONFLICT
    domain=[[ev(1)],[ev(2,'write','system')]]
    red=mutate_redundancy(base,'A',2)
    out=bounded_structural_diagnosis(red,domain)
    assert any(x.startswith('M_REDUNDANT_') for x in out['redundant'])
