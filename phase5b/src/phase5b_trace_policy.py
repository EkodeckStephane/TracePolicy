from __future__ import annotations
from dataclasses import dataclass
from collections import Counter, defaultdict, deque
from typing import Dict, Iterable, Tuple, Sequence, Set, List, Mapping, Any

from trace_policy_engine import (
    Event, Rule, Selector, Guard, PolicyVersion,
    ALLOW, DENY, NOALERT, VIOLATION, CONFLICT,
)

SelectorKey = Tuple[str, str, str]
SeqKey = Tuple[SelectorKey, Tuple[str, ...]]

# Fixed a-priori security semantics. This list MUST NOT be changed after test inspection.
SENSITIVE_NETWORK_ACTIONS = frozenset({'connect', 'sendto', 'sendmsg', 'write'})
SENSITIVE_PROCESS_ACTIONS = frozenset({'modify_process', 'change_principal'})
SENSITIVE_FILE_MUTATIONS = frozenset({'write', 'unlink', 'rename', 'truncate', 'link', 'modify_file_attributes'})
SENSITIVE_FILE_CLASSES = frozenset({'file:etc', 'file:sbin', 'file:usr', 'file:root_other'})


def selector_key(e: Event) -> SelectorKey:
    return (e.action, e.resource_class, e.subject_class)


def subject_key(e: Event) -> str:
    u=str(e.attrs.get('subject_uuid', '') or '').upper()
    return u if u else f'__NO_SUBJECT__:{e.eid}'


def is_sensitive_selector(sel: SelectorKey) -> bool:
    a, r, _ = sel
    if a in SENSITIVE_PROCESS_ACTIONS:
        return True
    if r == 'network' and a in SENSITIVE_NETWORK_ACTIONS:
        return True
    if r in SENSITIVE_FILE_CLASSES and a in SENSITIVE_FILE_MUTATIONS:
        return True
    return False


@dataclass(frozen=True)
class P1Config:
    sequence_length: int
    min_sequence_support: int
    max_sequences_per_selector: int
    extra_validation_alert_budget: float = 0.005

    def as_dict(self) -> Dict[str, Any]:
        return {
            'sequence_length': int(self.sequence_length),
            'min_sequence_support': int(self.min_sequence_support),
            'max_sequences_per_selector': int(self.max_sequences_per_selector),
            'extra_validation_alert_budget': float(self.extra_validation_alert_budget),
        }


@dataclass
class TrainingProfile:
    selector_counts: Counter
    # sequence_counts[k][(selector, action-sequence)] = count
    sequence_counts: Dict[int, Counter]
    training_events: int
    excluded_malicious_link_events: int


@dataclass(frozen=True)
class FrozenP1:
    p0_selectors: frozenset[SelectorKey]
    sensitive_selectors: frozenset[SelectorKey]
    allowed_sequences: frozenset[SeqKey]
    config: P1Config
    min_current_support: int
    max_current_rules: int
    pid: str = 'DARPA_CADETS_TRACE_AWARE'
    version: int = 2

    @property
    def rule_count(self) -> int:
        # P1 = trace allow + sensitive deny + current-context allow + fallback deny.
        return len(self.allowed_sequences) + len(self.sensitive_selectors) + len(self.p0_selectors) + 1


def learn_training_profile(
    events: Iterable[Event],
    sequence_lengths: Sequence[int] = (2, 3, 4),
    exclude_malicious_link: bool = True,
) -> TrainingProfile:
    seq_lengths = tuple(sorted(set(int(k) for k in sequence_lengths)))
    max_k = max(seq_lengths)
    selectors = Counter()
    seq_counts = {k: Counter() for k in seq_lengths}
    histories: Dict[str, deque] = defaultdict(lambda: deque(maxlen=max_k - 1))
    total = 0
    excluded = 0

    for e in events:
        total += 1
        sk = subject_key(e)
        hist = histories[sk]
        # Preserve temporal context even if the event is excluded from the benign policy counts.
        if exclude_malicious_link and int(e.malicious or 0) == 1:
            excluded += 1
            # Do not let a ground-truth-linked training event contaminate benign sequence support.
            # Clear the local history so later benign sequences cannot bridge across the excluded event.
            hist.clear()
            continue

        sel = selector_key(e)
        selectors[sel] += 1
        if is_sensitive_selector(sel):
            prev = list(hist)
            for k in seq_lengths:
                if len(prev) >= k - 1:
                    seq = tuple(prev[-(k - 1):] + [e.action])
                    seq_counts[k][(sel, seq)] += 1
        hist.append(e.action)

    return TrainingProfile(selectors, seq_counts, total, excluded)


def select_p0_selectors(profile: TrainingProfile, min_current_support: int = 20, max_current_rules: int = 500) -> frozenset[SelectorKey]:
    rows = [(sel, c) for sel, c in profile.selector_counts.items() if c >= min_current_support]
    rows.sort(key=lambda z: (-z[1], z[0]))
    return frozenset(sel for sel, _ in rows[:max_current_rules])


def build_allowed_sequences(profile: TrainingProfile, p0_selectors: Set[SelectorKey], cfg: P1Config) -> frozenset[SeqKey]:
    counts = profile.sequence_counts[int(cfg.sequence_length)]
    by_selector: Dict[SelectorKey, List[Tuple[Tuple[str, ...], int]]] = defaultdict(list)
    for (sel, seq), c in counts.items():
        if sel in p0_selectors and is_sensitive_selector(sel) and c >= int(cfg.min_sequence_support):
            by_selector[sel].append((seq, c))

    keep: Set[SeqKey] = set()
    for sel, vals in by_selector.items():
        vals.sort(key=lambda z: (-z[1], z[0]))
        for seq, _ in vals[: int(cfg.max_sequences_per_selector)]:
            keep.add((sel, seq))
    return frozenset(keep)


def freeze_p1(profile: TrainingProfile, cfg: P1Config, min_current_support: int = 20, max_current_rules: int = 500) -> FrozenP1:
    p0 = select_p0_selectors(profile, min_current_support, max_current_rules)
    sens = frozenset(sel for sel in p0 if is_sensitive_selector(sel))
    seqs = build_allowed_sequences(profile, set(p0), cfg)
    return FrozenP1(p0, sens, seqs, cfg, min_current_support, max_current_rules)


class DirectSubjectPolicyEvaluator:
    """Semantics-preserving compiled evaluator for P0/P1.

    P0:
      - known current selector -> ALLOW
      - otherwise -> DENY (unseen selector)

    P1:
      - same P0 current-selector coverage;
      - sensitive known selectors require a benign train-observed same-subject action sequence;
      - non-sensitive known selectors remain allowed;
      - unseen selectors remain denied.

    This is equivalent to compile_p1_policy() for one subject-local trace, and the
    patch test suite checks that equivalence on synthetic traces.
    """

    def __init__(self, p1: FrozenP1):
        self.p1 = p1
        self.histories: Dict[str, deque] = defaultdict(lambda: deque(maxlen=max(1, p1.config.sequence_length - 1)))

    def reset(self):
        self.histories.clear()

    def classify(self, e: Event) -> Tuple[bool, str, bool, bool, Tuple[str, ...]]:
        """Return (alert, reason, current_covered, trace_covered, sequence)."""
        sel = selector_key(e)
        current_covered = sel in self.p1.p0_selectors
        sk = subject_key(e)
        hist = self.histories[sk]
        seq: Tuple[str, ...] = ()
        if len(hist) >= self.p1.config.sequence_length - 1:
            seq = tuple(list(hist)[-(self.p1.config.sequence_length - 1):] + [e.action])

        if not current_covered:
            alert, reason, trace_covered = True, 'unseen_current_selector', False
        elif sel in self.p1.sensitive_selectors:
            trace_covered = bool(seq and (sel, seq) in self.p1.allowed_sequences)
            alert = not trace_covered
            reason = 'known_sensitive_trace' if trace_covered else 'unknown_sensitive_trace'
        else:
            alert, reason, trace_covered = False, 'known_nonsensitive_context', True

        hist.append(e.action)
        return alert, reason, current_covered, trace_covered, seq


class DirectP0Evaluator:
    def __init__(self, p0_selectors: Set[SelectorKey]):
        self.p0 = frozenset(p0_selectors)
    def classify(self, e: Event) -> Tuple[bool, str]:
        ok = selector_key(e) in self.p0
        return (not ok, 'known_current_selector' if ok else 'unseen_current_selector')


def compile_p0_policy(p0_selectors: Set[SelectorKey], version: int = 1) -> PolicyVersion:
    rules = []
    for i, (a, r, s) in enumerate(sorted(p0_selectors)):
        rules.append(Rule(f'A_P0_{i:04d}', 10, ALLOW, Selector(a, r, s)))
    rules.append(Rule('D_P0_UNSEEN_SELECTOR', 0, DENY, Selector('*', '*', '*'), Guard(comparisons=(('action', '!=', '__STUTTER__'),))))
    return PolicyVersion('DARPA_CADETS_P0_5B', version, tuple(rules))


def compile_p1_policy(p1: FrozenP1) -> PolicyVersion:
    rules: List[Rule] = []
    # Priority 30: known benign subject-local traces can authorize a sensitive event.
    for i, (sel, seq) in enumerate(sorted(p1.allowed_sequences)):
        a, r, s = sel
        rules.append(Rule(
            f'A_P1_TRACE_{i:05d}', 30, ALLOW, Selector(a, r, s),
            Guard(seq_actions=tuple(seq), seq_horizon=len(seq)),
        ))
    # Priority 20: absent an applicable trace authorization, sensitive event is denied.
    for i, (a, r, s) in enumerate(sorted(p1.sensitive_selectors)):
        rules.append(Rule(f'D_P1_SENSITIVE_{i:04d}', 20, DENY, Selector(a, r, s)))
    # Priority 10: ordinary current contexts retain P0 allow semantics.
    for i, (a, r, s) in enumerate(sorted(p1.p0_selectors)):
        rules.append(Rule(f'A_P1_CONTEXT_{i:04d}', 10, ALLOW, Selector(a, r, s)))
    # Priority 0: unknown current context remains denied.
    rules.append(Rule('D_P1_UNSEEN_SELECTOR', 0, DENY, Selector('*', '*', '*'), Guard(comparisons=(('action', '!=', '__STUTTER__'),))))
    return PolicyVersion(p1.pid, p1.version, tuple(rules))


def frozen_to_jsonable(p1: FrozenP1) -> Dict[str, Any]:
    return {
        'pid': p1.pid,
        'version': p1.version,
        'config': p1.config.as_dict(),
        'min_current_support': p1.min_current_support,
        'max_current_rules': p1.max_current_rules,
        'p0_selectors': [list(x) for x in sorted(p1.p0_selectors)],
        'sensitive_selectors': [list(x) for x in sorted(p1.sensitive_selectors)],
        'allowed_sequences': [
            {'selector': list(sel), 'sequence': list(seq)}
            for sel, seq in sorted(p1.allowed_sequences)
        ],
        'rule_count': p1.rule_count,
    }


def frozen_from_jsonable(d: Mapping[str, Any]) -> FrozenP1:
    cfgd = d['config']
    cfg = P1Config(
        int(cfgd['sequence_length']), int(cfgd['min_sequence_support']),
        int(cfgd['max_sequences_per_selector']), float(cfgd.get('extra_validation_alert_budget', 0.005))
    )
    return FrozenP1(
        frozenset(tuple(x) for x in d['p0_selectors']),
        frozenset(tuple(x) for x in d['sensitive_selectors']),
        frozenset((tuple(x['selector']), tuple(x['sequence'])) for x in d['allowed_sequences']),
        cfg, int(d['min_current_support']), int(d['max_current_rules']),
        str(d.get('pid', 'DARPA_CADETS_TRACE_AWARE')), int(d.get('version', 2)),
    )
