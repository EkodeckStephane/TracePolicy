"""Exhaustively compare the engine with a small independently coded semantics.

The oracle below reads model objects (rules, selectors, guard syntax) but does not
call production guard, transition, classification, masking, or explanation code.
It covers all traces of length one or two over an eight-event alphabet, eight
length-three temporal traces, 48 rule forms, policies with at most two rules,
and every event/rule retention mask.
"""
from __future__ import annotations

import itertools
import json
import sys
from dataclasses import asdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
import trace_policy_engine as engine


def atom_value(event, key):
    if key == "action": return event.action
    if key == "resource_class": return event.resource_class
    if key == "subject_class": return event.subject_class
    if key == "ts": return event.ts
    return event.attrs.get(key)


def compare(left, op, right):
    if op == "==": return left == right
    if op == "!=": return left != right
    if op == ">": return left > right
    if op == ">=": return left >= right
    if op == "<": return left < right
    if op == "<=": return left <= right
    if op == "in": return left in right
    if op == "notin": return left not in right
    if op == "startswith": return isinstance(left, str) and left.startswith(str(right))
    if op == "endswith": return isinstance(left, str) and left.endswith(str(right))
    if op == "contains": return right in left
    raise AssertionError(f"unmodeled operator: {op}")


def independent_state(trace):
    state = {}
    for event in trace:
        if event.action == "__STUTTER__":
            continue
        state["event_count"] = state.get("event_count", 0) + 1
        ak = f"action_count:{event.action}"
        rk = f"resource_count:{event.resource_class}"
        state[ak] = state.get(ak, 0) + 1
        state[rk] = state.get(rk, 0) + 1
        state["last_action"] = event.action
        state["last_resource_class"] = event.resource_class
    return state


def independent_stutter(event):
    return engine.Event(eid=f"stutter:{event.eid}", ts=event.ts,
                        action="__STUTTER__", resource_class="__STUTTER__",
                        subject_class="__STUTTER__", attrs={})


def independent_guard(guard, trace, state):
    if not trace or trace[-1].action == "__STUTTER__":
        return False
    current = trace[-1]
    for key, op, value in guard.comparisons:
        try:
            if not compare(atom_value(current, key), op, value): return False
        except (TypeError, KeyError):
            return False
    for key, op, value in guard.state_comparisons:
        try:
            if not compare(state.get(key), op, value): return False
        except (TypeError, KeyError):
            return False
    if guard.seen_action is not None:
        h = max(1, int(guard.seen_horizon))
        if not any(e.action != "__STUTTER__"
                   and (guard.seen_action == "*" or e.action == guard.seen_action)
                   and (guard.seen_resource in (None, "*") or e.resource_class == guard.seen_resource)
                   for e in trace[-h:]):
            return False
    if guard.count_action is not None:
        h = max(1, int(guard.count_horizon))
        count = sum(e.action != "__STUTTER__"
                    and (guard.count_action == "*" or e.action == guard.count_action)
                    and (guard.count_resource in (None, "*") or e.resource_class == guard.count_resource)
                    for e in trace[-h:])
        try:
            if not compare(count, guard.count_op or ">=", 0 if guard.count_threshold is None else guard.count_threshold):
                return False
        except (TypeError, KeyError):
            return False
    if guard.seq_actions:
        h = max(len(guard.seq_actions), int(guard.seq_horizon or len(guard.seq_actions)))
        pos = 0
        for event in trace[-h:]:
            if event.action == "__STUTTER__":
                continue
            wanted = guard.seq_actions[pos]
            if wanted == "*" or event.action == wanted:
                pos += 1
                if pos == len(guard.seq_actions): break
        if pos != len(guard.seq_actions): return False
    if any(not independent_guard(g, trace, state) for g in guard.all_of): return False
    if guard.any_of and not any(independent_guard(g, trace, state) for g in guard.any_of): return False
    if any(independent_guard(g, trace, state) for g in guard.none_of): return False
    return True


def independent_class(trace, rules, state=None):
    state = independent_state(trace) if state is None else state
    if not trace:
        return engine.GAP, set(), set()
    current = trace[-1]
    applicable = []
    for rule in rules:
        selector = rule.selector
        selected = (current.action != "__STUTTER__"
                    and (selector.action == "*" or selector.action == current.action)
                    and (selector.resource_class == "*" or selector.resource_class == current.resource_class)
                    and (selector.subject_class == "*" or selector.subject_class == current.subject_class))
        if selected and independent_guard(rule.guard, trace, state):
            applicable.append(rule)
    if not applicable:
        return engine.GAP, set(), set()
    priority = max(rule.priority for rule in applicable)
    top = [rule for rule in applicable if rule.priority == priority]
    effects = {rule.effect for rule in top}
    if effects == {engine.ALLOW}: category = engine.NOALERT
    elif effects == {engine.DENY}: category = engine.VIOLATION
    else: category = engine.CONFLICT
    return category, {r.rid for r in applicable}, {r.rid for r in top}


def guard_forms():
    return [
        engine.Guard(),
        engine.Guard(comparisons=(("action", "==", "A"),)),
        engine.Guard(state_comparisons=(("event_count", ">=", 2),)),
        engine.Guard(seen_action="A", seen_horizon=2),
        engine.Guard(count_action="A", count_horizon=2, count_op=">=", count_threshold=2),
        engine.Guard(seq_actions=("A", "B"), seq_horizon=2),
        engine.Guard(any_of=(engine.Guard(comparisons=(("action", "==", "B"),)),
                             engine.Guard(seen_action="A", seen_horizon=2))),
        engine.Guard(all_of=(engine.Guard(comparisons=(("action", "==", "A"),)),
                             engine.Guard(seen_action="B", seen_horizon=2))),
        engine.Guard(none_of=(engine.Guard(comparisons=(("action", "==", "A"),)),)),
        engine.Guard(seen_action="*", seen_resource="Y", seen_horizon=2),
        engine.Guard(count_action="*", count_resource="X", count_horizon=2,
                     count_op=">=", count_threshold=1),
        engine.Guard(seq_actions=("A", "*", "B"), seq_horizon=3),
    ]


def rule_forms():
    selectors = [engine.Selector(), engine.Selector("A"), engine.Selector("B"),
                 engine.Selector(resource_class="X")]
    effects_priorities = [(engine.DENY, 0), (engine.ALLOW, 0),
                          (engine.DENY, 1), (engine.ALLOW, 1)]
    out = []
    for gi, guard in enumerate(guard_forms()):
        for vi, (selector, (effect, priority)) in enumerate(zip(selectors, effects_priorities)):
            out.append(engine.Rule(f"r{gi}_{vi}", priority, effect, selector, guard))
    return out


def policy_forms():
    forms = rule_forms()
    yield engine.PolicyVersion("empty", 1, ())
    for i, rule in enumerate(forms):
        yield engine.PolicyVersion(f"single-{i}", 1, (rule,))
    for i, left in enumerate(forms):
        for right in forms[i + 1:]:
            yield engine.PolicyVersion(f"pair-{left.rid}-{right.rid}", 1, (left, right))


def traces():
    alphabet = [engine.Event(f"{a}-{r}-{s}", 1.0, a, r, s)
                for a, r, s in itertools.product(("A", "B"), ("X", "Y"), ("U", "V"))]
    for n in (1, 2):
        for row in itertools.product(alphabet, repeat=n):
            yield list(row)
    for actions in itertools.product(("A", "B"), repeat=3):
        yield [engine.Event(f"tri-{i}-{action}", float(i), action, ("X", "Y", "X")[i], "U")
               for i, action in enumerate(actions)]


def main():
    counts = {"policy_trace_pairs": 0, "retention_masks": 0, "alerts_certified": 0,
              "index_comparisons": 0, "incremental_prefix_comparisons": 0,
              "selector_reduction_masks": 0}
    h = 2
    for policy in policy_forms():
        idx = engine.StaticIndex(policy)
        for trace in traces():
            counts["policy_trace_pairs"] += 1
            expected, expected_app, expected_top = independent_class(trace, policy.rules)
            reference = engine.reference_eval(trace, policy)
            assert reference.alert_class == expected
            assert set(reference.applicable) == expected_app
            assert set(reference.top) == expected_top
            indexed = idx.eval(trace)
            assert indexed.alert_class == expected
            assert set(indexed.applicable) == expected_app
            assert set(indexed.top) == expected_top
            counts["index_comparisons"] += 1

            eps, rids, units = engine.explanation_unit_info(trace, policy, h)
            table = {}
            for bits in itertools.product((0, 1), repeat=len(units)):
                kept_positions = {eps[j] for j in range(len(eps)) if bits[j]}
                masked = [e if i not in eps or i in kept_positions else independent_stutter(e)
                          for i, e in enumerate(trace)]
                enabled = {rid for j, rid in enumerate(rids) if bits[len(eps) + j]}
                kept_rules = [r for r in policy.rules if r.rid in enabled]
                oracle_class, _, _ = independent_class(masked, kept_rules)
                observed = engine._class_under_mask(trace, policy, eps, rids, bits)
                assert observed == oracle_class
                table[bits] = oracle_class
                counts["retention_masks"] += 1

            reduced_eps, reduced_rids, reduced_units = engine.explanation_unit_info(
                trace, policy, h, relevant_only=True)
            assert reduced_eps == eps
            for reduced_bits in itertools.product((0, 1), repeat=len(reduced_units)):
                kept_positions = {eps[j] for j in range(len(eps)) if reduced_bits[j]}
                reduced_trace = [e if i not in eps or i in kept_positions else independent_stutter(e)
                                 for i, e in enumerate(trace)]
                retained_relevant = {rid for j, rid in enumerate(reduced_rids)
                                     if reduced_bits[len(eps) + j]}
                active_ids = (set(r.rid for r in policy.rules) - set(reduced_rids)) | retained_relevant
                expected_reduced, _, _ = independent_class(
                    reduced_trace, [r for r in policy.rules if r.rid in active_ids])
                actual_reduced = engine._class_under_mask(
                    trace, policy, reduced_eps, reduced_rids, reduced_bits)
                assert actual_reduced == expected_reduced
                counts["selector_reduction_masks"] += 1

            if expected != engine.NOALERT:
                explanation = engine.min_explain_bruteforce(trace, policy, horizon=h)
                chosen = {f"e:{i}" for i in explanation.event_positions}
                chosen |= {f"r:{rid}" for rid in explanation.rule_ids}
                unit_index = {u: i for i, u in enumerate(units)}
                def sufficient(core):
                    return all(category == expected for bits, category in table.items()
                               if all(bits[unit_index[u]] == 1 for u in core))
                assert sufficient(chosen)
                for u in chosen:
                    assert not sufficient(chosen - {u})
                    witness = explanation.witnesses[u]
                    assert set(witness) == set(units)
                    assert all(witness[v] == 1 for v in chosen - {u})
                    witness_bits = tuple(int(witness[v]) for v in units)
                    assert table[witness_bits] != expected
                counts["alerts_certified"] += 1

            inc = engine.IncrementalEvaluator(policy, retention_horizon=h)
            prefix = []
            for event in trace:
                prefix.append(event)
                got = inc.push(event)
                want, want_app, want_top = independent_class(prefix, policy.rules)
                assert got.alert_class == want
                assert set(got.applicable) == want_app
                assert set(got.top) == want_top
                counts["incremental_prefix_comparisons"] += 1

    result = {"schema_version": 2, "horizon": h, "rule_forms": len(rule_forms()),
              "policies": sum(1 for _ in policy_forms()), "traces": sum(1 for _ in traces()),
              "counts": counts,
              "oracle": "separate transition/guard/selector/priority implementation; no production evaluator calls",
              "scope": "empty initial state; full length-one/two trace cube over two actions, resources, and subjects; eight length-three temporal traces; policies with at most two rules; all event/rule retention assignments"}
    out = ROOT / "audit" / "independent_semantics_modelcheck_2026-11-26.json"
    out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
