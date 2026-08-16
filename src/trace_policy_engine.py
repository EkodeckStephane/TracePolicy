from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Dict, List, Tuple, Optional, Sequence, Set
from collections import defaultdict
from itertools import product

ALLOW='ALLOW'; DENY='DENY'
NOALERT='NoAlert'; VIOLATION='Violation'; CONFLICT='Conflict'; GAP='Gap'

@dataclass(frozen=True)
class Event:
    eid: str
    ts: float
    action: str
    resource_class: str
    subject_class: str
    attrs: Dict[str, Any] = field(default_factory=dict, compare=False, hash=False)
    malicious: Optional[int] = None
    attack_type: Optional[str] = None

    @staticmethod
    def stutter_like(e: 'Event') -> 'Event':
        return Event(eid=f'stutter:{e.eid}', ts=e.ts, action='__STUTTER__',
                     resource_class='__STUTTER__', subject_class='__STUTTER__', attrs={})

@dataclass(frozen=True)
class SystemState:
    """Finite deterministic state used by state atoms in the Phase-4 semantics."""
    values: Dict[str, Any] = field(default_factory=dict, compare=False, hash=False)


def transition(state: SystemState, event: Event) -> SystemState:
    """Deterministic default transition δ."""
    v = dict(state.values)
    v['event_count'] = int(v.get('event_count', 0)) + 1
    v[f'action_count:{event.action}'] = int(v.get(f'action_count:{event.action}', 0)) + 1
    v[f'resource_count:{event.resource_class}'] = int(v.get(f'resource_count:{event.resource_class}', 0)) + 1
    v['last_action'] = event.action
    v['last_resource_class'] = event.resource_class
    return SystemState(v)


def derive_state(trace: Sequence[Event], initial: Optional[SystemState]=None) -> SystemState:
    s = initial or SystemState()
    for e in trace:
        s = transition(s, e)
    return s

@dataclass(frozen=True)
class Selector:
    action: str='*'
    resource_class: str='*'
    subject_class: str='*'

    def matches(self, e: Event) -> bool:
        return ((self.action=='*' or self.action==e.action) and
                (self.resource_class=='*' or self.resource_class==e.resource_class) and
                (self.subject_class=='*' or self.subject_class==e.subject_class))

@dataclass(frozen=True)
class Guard:
    comparisons: Tuple[Tuple[str,str,Any], ...] = ()
    state_comparisons: Tuple[Tuple[str,str,Any], ...] = ()
    seen_action: Optional[str] = None
    seen_resource: Optional[str] = None
    seen_horizon: int = 0
    count_action: Optional[str] = None
    count_resource: Optional[str] = None
    count_horizon: int = 0
    count_op: Optional[str] = None
    count_threshold: Optional[int] = None
    seq_actions: Tuple[str, ...] = ()
    seq_horizon: int = 0
    all_of: Tuple['Guard', ...] = ()
    any_of: Tuple['Guard', ...] = ()
    none_of: Tuple['Guard', ...] = ()

    def _cmp(self, x, op, y) -> bool:
        if op=='==': return x==y
        if op=='!=': return x!=y
        if op=='>': return x>y
        if op=='>=': return x>=y
        if op=='<': return x<y
        if op=='<=': return x<=y
        if op=='in': return x in y
        if op=='notin': return x not in y
        if op=='startswith': return isinstance(x,str) and x.startswith(str(y))
        if op=='endswith': return isinstance(x,str) and x.endswith(str(y))
        if op=='contains': return y in x
        raise ValueError(f'unsupported decidable comparison operator: {op}')

    def _event_value(self, e: Event, key: str):
        if key=='action': return e.action
        if key=='resource_class': return e.resource_class
        if key=='subject_class': return e.subject_class
        if key=='ts': return e.ts
        return e.attrs.get(key)

    def eval(self, trace: Sequence[Event], state: Optional[SystemState]=None) -> bool:
        if not trace: return False
        e=trace[-1]; state=state or derive_state(trace)
        for key,op,val in self.comparisons:
            try:
                if not self._cmp(self._event_value(e,key),op,val): return False
            except (TypeError, KeyError): return False
        for key,op,val in self.state_comparisons:
            try:
                if not self._cmp(state.values.get(key),op,val): return False
            except (TypeError, KeyError): return False
        if self.seen_action is not None:
            h=max(1,int(self.seen_horizon)); window=trace[-h:]
            if not any((self.seen_action=='*' or z.action==self.seen_action) and
                       (self.seen_resource is None or self.seen_resource=='*' or z.resource_class==self.seen_resource)
                       for z in window): return False
        if self.count_action is not None:
            h=max(1,int(self.count_horizon)); window=trace[-h:]
            c=sum(1 for z in window if (self.count_action=='*' or z.action==self.count_action)
                  and (self.count_resource is None or self.count_resource=='*' or z.resource_class==self.count_resource))
            if not self._cmp(c,self.count_op or '>=',self.count_threshold if self.count_threshold is not None else 0): return False
        if self.seq_actions:
            h=max(len(self.seq_actions),int(self.seq_horizon or len(self.seq_actions)),len(self.seq_actions)); acts=[z.action for z in trace[-h:]]; pos=0
            for a in acts:
                want=self.seq_actions[pos]
                if want=='*' or a==want:
                    pos+=1
                    if pos==len(self.seq_actions): break
            if pos!=len(self.seq_actions): return False
        if any(not g.eval(trace,state) for g in self.all_of): return False
        if self.any_of and not any(g.eval(trace,state) for g in self.any_of): return False
        if any(g.eval(trace,state) for g in self.none_of): return False
        return True

@dataclass(frozen=True)
class Rule:
    rid: str
    priority: int
    effect: str
    selector: Selector
    guard: Guard=Guard()
    def __post_init__(self):
        if self.effect not in (ALLOW,DENY): raise ValueError(f'invalid effect: {self.effect}')

@dataclass(frozen=True)
class PolicyVersion:
    pid: str
    version: int
    rules: Tuple[Rule,...]
    created_at: float = 0.0
    def __post_init__(self):
        ids=[r.rid for r in self.rules]
        if len(ids)!=len(set(ids)): raise ValueError('rule identifiers must be unique within one policy version')

@dataclass
class EvalResult:
    decision: str
    alert_class: str
    applicable: Tuple[str,...]
    top: Tuple[str,...]
    checks: int
    candidates: int
    policy_version: int


def classify_from_rules(trace: Sequence[Event], rules: Sequence[Rule], state: Optional[SystemState]=None, policy_version:int=0) -> EvalResult:
    app=[]; checks=0; state=state or derive_state(trace)
    for r in rules:
        checks+=1
        if trace and r.selector.matches(trace[-1]) and r.guard.eval(trace,state): app.append(r)
    if not app: return EvalResult(DENY,GAP,(),(),checks,len(rules),policy_version)
    p=max(r.priority for r in app); top=[r for r in app if r.priority==p]; eff={r.effect for r in top}
    if eff=={ALLOW}: d,c=ALLOW,NOALERT
    elif eff=={DENY}: d,c=DENY,VIOLATION
    else: d,c=DENY,CONFLICT
    return EvalResult(d,c,tuple(r.rid for r in app),tuple(r.rid for r in top),checks,len(rules),policy_version)


def reference_eval(trace: Sequence[Event], policy: PolicyVersion, enabled: Optional[Set[str]]=None, state: Optional[SystemState]=None) -> EvalResult:
    rules=policy.rules if enabled is None else tuple(r for r in policy.rules if r.rid in enabled)
    return classify_from_rules(trace,rules,state=state,policy_version=policy.version)

class StaticIndex:
    def __init__(self, policy: PolicyVersion):
        self.policy=policy; self.buckets=defaultdict(list)
        for r in policy.rules: self.buckets[(r.selector.action,r.selector.resource_class,r.selector.subject_class)].append(r)
    def candidates(self,e: Event, enabled: Optional[Set[str]]=None) -> List[Rule]:
        vals=[(e.action,'*'),(e.resource_class,'*'),(e.subject_class,'*')]; out=[]; seen=set()
        for a,r,s in product(*vals):
            for rule in self.buckets.get((a,r,s),()):
                if rule.rid not in seen and (enabled is None or rule.rid in enabled): seen.add(rule.rid); out.append(rule)
        return out
    def eval(self,trace: Sequence[Event], enabled: Optional[Set[str]]=None, state: Optional[SystemState]=None) -> EvalResult:
        if not trace: return EvalResult(DENY,GAP,(),(),0,0,self.policy.version)
        cand=self.candidates(trace[-1],enabled); res=classify_from_rules(trace,cand,state=state,policy_version=self.policy.version); res.candidates=len(cand); return res

def _guard_horizon(g: Guard) -> int:
    h=1
    if g.seen_action is not None: h=max(h,int(g.seen_horizon or 1))
    if g.count_action is not None: h=max(h,int(g.count_horizon or 1))
    if g.seq_actions: h=max(h,int(g.seq_horizon or len(g.seq_actions)),len(g.seq_actions))
    for z in g.all_of+g.any_of+g.none_of: h=max(h,_guard_horizon(z))
    return h

def policy_monitor_horizon(policy: PolicyVersion) -> int: return max([1]+[_guard_horizon(r.guard) for r in policy.rules])

class IncrementalEvaluator:
    def __init__(self, policy: PolicyVersion, initial_state: Optional[SystemState]=None, retention_horizon: Optional[int]=None):
        self.policy=policy; self.index=StaticIndex(policy); self.retention_horizon=max(int(retention_horizon or policy_monitor_horizon(policy)),policy_monitor_horizon(policy)); self.trace=[]; self.state=initial_state or SystemState(); self.version_history=[policy.version]
    def update_policy(self, policy: PolicyVersion):
        if policy.version<=self.policy.version: raise ValueError('policy updates must create a strictly newer immutable version')
        self.policy=policy; self.index=StaticIndex(policy); self.retention_horizon=max(self.retention_horizon,policy_monitor_horizon(policy)); self.version_history.append(policy.version)
    def push(self,e:Event)->EvalResult:
        self.trace.append(e)
        if len(self.trace)>self.retention_horizon: del self.trace[:-self.retention_horizon]
        self.state=transition(self.state,e); return self.index.eval(self.trace,state=self.state)

@dataclass
class Explanation:
    target_class: str
    event_positions: Tuple[int,...]
    rule_ids: Tuple[str,...]
    witnesses: Dict[str, Dict[str,int]]
    unit_count: int
    checks: int
    policy_version: int


def _neutralized_trace(trace: Sequence[Event], keep_event_positions:Set[int]) -> List[Event]:
    return [e if i in keep_event_positions else Event.stutter_like(e) for i,e in enumerate(trace)]

def _class_under_mask(trace: Sequence[Event], policy: PolicyVersion, event_positions: Sequence[int], rule_ids: Sequence[str], bits: Sequence[int]) -> str:
    ne=len(event_positions); keep_e={event_positions[i] for i in range(ne) if bits[i]}; keep_r={rule_ids[j] for j in range(len(rule_ids)) if bits[ne+j]}; t=_neutralized_trace(trace,keep_e)
    return reference_eval(t,policy,enabled=keep_r,state=derive_state(t)).alert_class


def min_explain_bruteforce(trace: Sequence[Event], policy: PolicyVersion, horizon:int=4, relevant_only:bool=True, max_units:int=18) -> Explanation:
    """Exact bounded retention-abductive explainer.

    Sufficiency/minimality checks enumerate every assignment of the currently
    free explanatory units. The extraction therefore has worst-case time
    O(m * 2**m * T_eval), where m is the explanatory-unit count and T_eval is
    one canonical policy evaluation. `max_units=18` is an explicit prototype
    safety bound; callers must use a different exact backend for larger universes.
    """
    factual=reference_eval(trace,policy); y=factual.alert_class
    if y==NOALERT: raise ValueError('Explanation requested for NoAlert')
    start=max(0,len(trace)-horizon); event_positions=list(range(start,len(trace)))
    if relevant_only:
        cur=trace[-1]; rset=[r.rid for r in policy.rules if r.selector.matches(cur)]
        for rid in factual.applicable:
            if rid not in rset: rset.append(rid)
        rule_ids=rset
    else: rule_ids=[r.rid for r in policy.rules]
    units=[f'e:{i}' for i in event_positions]+[f'r:{r}' for r in rule_ids]; n=len(units); checks=0
    if n>max_units: raise RuntimeError(f'bounded brute-force explainer unit limit exceeded: {n}>{max_units}')
    def suff(core_idx:Set[int]):
        nonlocal checks
        free=[i for i in range(n) if i not in core_idx]
        for vals in product([0,1],repeat=len(free)):
            bits=[1 if i in core_idx else 0 for i in range(n)]
            for i,v in zip(free,vals): bits[i]=v
            checks+=1
            if _class_under_mask(trace,policy,event_positions,rule_ids,bits)!=y: return False,bits
        return True,None
    core=set(range(n))
    for i in range(n):
        if i not in core: continue
        ok,_=suff(core-{i})
        if ok: core.remove(i)
    witnesses={}
    for i in sorted(core):
        ok,bits=suff(core-{i})
        if ok: raise AssertionError('minimality failure')
        witnesses[units[i]]={units[j]:int(bits[j]) for j in range(n)}
    ok,_=suff(core)
    if not ok: raise AssertionError('soundness failure')
    ep=tuple(event_positions[i] for i in range(len(event_positions)) if i in core); off=len(event_positions); rr=tuple(rule_ids[j] for j in range(len(rule_ids)) if off+j in core)
    return Explanation(y,ep,rr,witnesses,n,checks,policy.version)


def exact_sufficiency_of_selected(trace: Sequence[Event], policy: PolicyVersion, selected_units:Set[str], horizon:int=4, max_units:int=18):
    factual=reference_eval(trace,policy); y=factual.alert_class; start=max(0,len(trace)-horizon); event_positions=list(range(start,len(trace))); cur=trace[-1]
    rule_ids=[r.rid for r in policy.rules if r.selector.matches(cur)]; units=[f'e:{i}' for i in event_positions]+[f'r:{r}' for r in rule_ids]; core={i for i,u in enumerate(units) if u in selected_units}; n=len(units)
    if n>max_units: return None
    free=[i for i in range(n) if i not in core]
    for vals in product([0,1],repeat=len(free)):
        bits=[1 if i in core else 0 for i in range(n)]
        for i,v in zip(free,vals): bits[i]=v
        if _class_under_mask(trace,policy,event_positions,rule_ids,bits)!=y: return False
    return True

def runtime_diagnosis(res:EvalResult)->str:
    if res.alert_class in (CONFLICT,GAP): return 'PolicyDefectContribution'
    if res.alert_class==VIOLATION: return 'OperationalViolation'
    return 'NoAlert'

def bounded_structural_diagnosis(policy:PolicyVersion, domain_traces:Sequence[Sequence[Event]]):
    rules=list(policy.rules); shadowed=[]; redundant=[]
    for r in rules:
        applicable_cases=[]; ever_top=False
        for tr in domain_traces:
            if not tr: continue
            st=derive_state(tr)
            if r.selector.matches(tr[-1]) and r.guard.eval(tr,st):
                applicable_cases.append(tr); res=reference_eval(tr,policy,state=st)
                if r.rid in res.top: ever_top=True
        if applicable_cases and not ever_top: shadowed.append(r.rid)
        p2=PolicyVersion(policy.pid,policy.version,tuple(x for x in rules if x.rid!=r.rid),policy.created_at)
        if all(reference_eval(tr,policy).alert_class==reference_eval(tr,p2).alert_class for tr in domain_traces if tr): redundant.append(r.rid)
    return {'shadowed':tuple(sorted(shadowed)),'redundant':tuple(sorted(redundant))}

def mutate_conflict(policy:PolicyVersion, target_rid:str, new_version:int)->PolicyVersion:
    r=next(x for x in policy.rules if x.rid==target_rid); opp=DENY if r.effect==ALLOW else ALLOW; nr=Rule(rid=f'M_CONFLICT_{target_rid}',priority=r.priority,effect=opp,selector=r.selector,guard=r.guard); return PolicyVersion(policy.pid,new_version,policy.rules+(nr,))
def mutate_shadowing(policy:PolicyVersion,target_rid:str,new_version:int)->PolicyVersion:
    r=next(x for x in policy.rules if x.rid==target_rid); nr=Rule(rid=f'M_SHADOW_{target_rid}',priority=r.priority-100,effect=r.effect,selector=r.selector,guard=r.guard); return PolicyVersion(policy.pid,new_version,policy.rules+(nr,))
def mutate_redundancy(policy:PolicyVersion,target_rid:str,new_version:int)->PolicyVersion:
    r=next(x for x in policy.rules if x.rid==target_rid); nr=Rule(rid=f'M_REDUNDANT_{target_rid}',priority=r.priority,effect=r.effect,selector=r.selector,guard=r.guard); return PolicyVersion(policy.pid,new_version,policy.rules+(nr,))
def mutate_gap(policy:PolicyVersion,target_rids:Sequence[str],new_version:int)->PolicyVersion:
    rm=set(target_rids); return PolicyVersion(policy.pid,new_version,tuple(r for r in policy.rules if r.rid not in rm))
