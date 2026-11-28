"""Exhaustively verify a parametric event/rule composability family.

For n independent guarded-deny alternatives, compare every event-only/rule-only
minimal-core union with the complete joint intervention table. This is a
bounded semantic characterization of the implemented policy evaluator, not an
independent security-workload evaluation.
"""
from __future__ import annotations

import itertools
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "experiments")]

import trace_policy_engine as tpe
from revision_explanation_benchmark import (
    all_minimal_cores,
    independent_table,
    sufficient,
)

OUT = ROOT / "results" / "revision" / "composability_family_v1" / "summary.json"


def verify_family(branches: int) -> dict:
    if branches < 2:
        raise ValueError("the crossed-union family requires at least two branches")

    trace = [
        tpe.Event(f"A{i}", float(i), f"A{i}", "resource", "user")
        for i in range(branches)
    ]
    trace.append(tpe.Event("B", float(branches), "B", "resource", "user"))
    rules = tuple(
        tpe.Rule(
            f"R{i}",
            10,
            tpe.DENY,
            tpe.Selector("B"),
            tpe.Guard(seen_action=f"A{i}", seen_horizon=branches + 1),
        )
        for i in range(branches)
    )
    policy = tpe.PolicyVersion(f"OR_BRANCH_{branches}", 1, rules)
    event_positions = list(range(branches + 1))
    rule_ids = [rule.rid for rule in rules]
    target = tpe.reference_eval(trace, policy).alert_class
    assert target == tpe.VIOLATION

    event_units, event_table = independent_table(trace, policy, event_positions, [])
    rule_units, rule_table = independent_table(trace, policy, [], rule_ids)
    joint_units, joint_table = independent_table(
        trace, policy, event_positions, rule_ids
    )

    # Confirm the evaluator's full truth table against the closed-form policy.
    for bits, observed in joint_table.items():
        event_retained = dict(zip(event_positions, bits[: len(event_positions)]))
        rule_retained = dict(zip(rule_ids, bits[len(event_positions) :]))
        formula = bool(
            event_retained[branches]
            and any(
                event_retained[i] and rule_retained[f"R{i}"]
                for i in range(branches)
            )
        )
        assert (observed == target) == formula, (branches, bits, observed, formula)

    event_cores = all_minimal_cores(event_units, event_table, target)
    rule_cores = all_minimal_cores(rule_units, rule_table, target)
    joint_cores = all_minimal_cores(joint_units, joint_table, target)

    expected_event_cores = {
        frozenset((f"e:{i}", f"e:{branches}")) for i in range(branches)
    }
    expected_rule_cores = {
        frozenset((f"r:R{i}",)) for i in range(branches)
    }
    expected_joint_cores = {
        frozenset((f"e:{i}", f"e:{branches}", f"r:R{i}"))
        for i in range(branches)
    }
    assert set(map(frozenset, event_cores)) == expected_event_cores
    assert set(map(frozenset, rule_cores)) == expected_rule_cores
    assert set(map(frozenset, joint_cores)) == expected_joint_cores

    pair_results = []
    for event_core, rule_core in itertools.product(event_cores, rule_cores):
        union = set(event_core) | set(rule_core)
        is_sufficient = sufficient(union, joint_units, joint_table, target)
        selected_rule = next(
            i for i in range(branches) if f"r:R{i}" in rule_core
        )
        matched_branch = f"e:{selected_rule}" in event_core
        assert is_sufficient == matched_branch
        pair_results.append(is_sufficient)

    assert sum(pair_results) == branches
    total_pairs = branches * branches
    return {
        "branches": branches,
        "explanatory_units": 2 * branches + 1,
        "joint_assignments_checked": 1 << (2 * branches + 1),
        "event_only_minimal_cores": len(event_cores),
        "rule_only_minimal_cores": len(rule_cores),
        "joint_minimal_cores": len(joint_cores),
        "separated_core_unions_checked": total_pairs,
        "sufficient_unions": sum(pair_results),
        "insufficient_crossed_unions": total_pairs - sum(pair_results),
        "crossed_union_failure_rate": (total_pairs - branches) / total_pairs,
        "all_matching_unions_are_joint_minimal": True,
        "all_crossed_unions_have_a_joint_counterexample": True,
    }


def main() -> None:
    rows = [verify_family(branches) for branches in range(2, 6)]
    result = {
        "protocol": "exhaustive finite retention masks; fixed event sequence and policy family",
        "policy_class": "equal-priority guarded-deny alternatives with one shared current event",
        "closed_form_target_indicator": "x_B AND OR_i(x_Ai AND r_i)",
        "results": rows,
        "interpretation": (
            "Within this restricted class, only branch-matched event/rule core "
            "unions are sufficient. The failure rate rises as 1 - 1/n. This is "
            "a semantic instance of monotone-DNF explanation structure; it does "
            "not estimate frequency or diagnostic utility in operational data."
        ),
        "limitations": [
            "Constructed family; no empirical prevalence claim.",
            "Uses the project reference evaluator and independent mask-table enumerator, not a second policy implementation.",
            "The Boolean characterization is adjacent to generic AXp and monotone-DNF theory; novelty remains unestablished.",
        ],
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
