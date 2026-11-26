"""Four-way E-only/R-only/naive-union/E+R ablation.

Runs on the frozen retrospective Docker selection and controlled fixtures.
The two separate core families are generated independently, then every
cross-product union is checked in the joint intervention domain.
"""
from __future__ import annotations

import hashlib
import itertools
import json
from pathlib import Path

import revision_joint_ablation as base
import trace_policy_engine as tpe

ROOT = base.ROOT
OUT = ROOT / "results" / "revision" / "joint_union_ablation_v1"


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def assess_union(factual, selected, units, table, independent_sufficiency):
    """Check a selected set in the complete E+R domain and its deletion-minimality."""
    sufficient = independent_sufficiency(selected, units, table, factual)
    if not sufficient:
        counterexample = None
        selected_indexes = [units.index(u) for u in selected]
        for bits, result in table.items():
            if result != factual and all(bits[i] for i in selected_indexes):
                counterexample = {"assignment": dict(zip(units, bits)),
                                  "resulting_class": result,
                                  "target_class": factual}
                break
        if counterexample is None:
            raise AssertionError("failed sufficiency check lacked counterexample assignment")
        return {"sufficient": sufficient, "inclusion_minimal": False,
                "deletion_checks": 0, "counterexample": counterexample}
    deletion_checks = 0
    minimal = True
    for unit in sorted(selected):
        deletion_checks += 1
        if independent_sufficiency(selected - {unit}, units, table, factual):
            minimal = False
    return {"sufficient": True, "inclusion_minimal": minimal,
            "deletion_checks": deletion_checks}


def analyze_case(case_id, source, trace, policy, horizon, metadata=None):
    fact = tpe.reference_eval(trace, policy).alert_class
    base_result = base.analyze(case_id, source, trace, policy, horizon=horizon)
    event = base_result["E-only"]
    rules = base_result["R-only"]
    joint = base_result["E+R"]
    if fact != base_result["factual"]:
        raise AssertionError("oracle result changed during paired evaluation")

    from revision_explanation_benchmark import independent_table, sufficient
    eps, rids, _ = tpe.explanation_unit_info(trace, policy, horizon=horizon)
    joint_units, joint_table = independent_table(trace, policy, eps, rids)
    unions = []
    exact_joint_cores = {frozenset(core) for core in joint["minimal_cores"]}
    for ecore, rcore in itertools.product(event["minimal_cores"], rules["minimal_cores"]):
        candidate = frozenset(ecore) | frozenset(rcore)
        checked = assess_union(fact, set(candidate), joint_units, joint_table, sufficient)
        unions.append({"event_core": ecore, "rule_core": rcore,
                       "union": sorted(candidate), **checked,
                       "equals_joint_minimal_core": candidate in exact_joint_cores})

    return {"case_id": case_id, "source": source, "factual": fact,
            **(metadata or {}), "horizon": horizon,
            "event_core_count": len(event["minimal_cores"]),
            "rule_core_count": len(rules["minimal_cores"]),
            "joint_core_count": len(joint["minimal_cores"]),
            "unions": unions,
            "all_unions_sufficient": bool(unions) and all(x["sufficient"] is True for x in unions),
            "some_union_sufficient": any(x["sufficient"] is True for x in unions),
            "any_union_is_joint_minimal": any(x["equals_joint_minimal_core"] for x in unions),
            "sufficient_but_not_minimal_union_count": sum(
                x["sufficient"] is True and not x["inclusion_minimal"] for x in unions)}


def composability_counterexample():
    """Small semantic witness: two alternative event-rule denial paths."""
    ev = lambda eid, ts, action: tpe.Event(eid, ts, action, "resource", "user")
    trace = [ev("eA", 1.0, "A"), ev("eC", 2.0, "C"), ev("eB", 3.0, "B")]
    policy = tpe.PolicyVersion("JOINT_COMPOSABILITY_WITNESS", 1, (
        tpe.Rule("DENY_AFTER_A", 10, tpe.DENY, tpe.Selector("B"),
                 tpe.Guard(seen_action="A", seen_horizon=3)),
        tpe.Rule("DENY_AFTER_C", 10, tpe.DENY, tpe.Selector("B"),
                 tpe.Guard(seen_action="C", seen_horizon=3)),
    ))
    row = analyze_case("constructed-composability-counterexample", "constructed_semantic_witness",
                       trace, policy, 3,
                       {"purpose": "falsify universal claim that every separate-core union is jointly sufficient"})
    # Verify exact families against the independently enumerating baseline routine.
    base_result = base.analyze("witness", "constructed_semantic_witness", trace, policy, horizon=3)
    from revision_explanation_benchmark import independent_table, all_minimal_cores
    eps, rids, _ = tpe.explanation_unit_info(trace, policy, horizon=3)
    joint_units, joint_table = independent_table(trace, policy, eps, rids)
    for bits, result in joint_table.items():
        assignment = dict(zip(joint_units, bits))
        formula = (assignment["e:2"] and
                   ((assignment["e:0"] and assignment["r:DENY_AFTER_A"]) or
                    (assignment["e:1"] and assignment["r:DENY_AFTER_C"])))
        expected = tpe.VIOLATION if formula else tpe.GAP
        if result != expected:
            raise AssertionError(f"closed-form witness disagrees at {assignment}: {result} != {expected}")
    witness_target = base_result["factual"]
    for mode_eps, mode_rids, mode in ((eps, [], "E-only"), ([], rids, "R-only"), (eps, rids, "E+R")):
        units, table = independent_table(trace, policy, mode_eps, mode_rids)
        independent_cores = {tuple(sorted(c)) for c in all_minimal_cores(
            units, table, witness_target
        )}
        engine_cores = {tuple(sorted(c)) for c in base_result[mode]["minimal_cores"]}
        if independent_cores != engine_cores:
            raise AssertionError(f"independent mask-table disagreement for {mode}: {independent_cores} != {engine_cores}")
    expected_e = {tuple(c) for c in base_result["E-only"]["minimal_cores"]}
    expected_r = {tuple(c) for c in base_result["R-only"]["minimal_cores"]}
    if expected_e != {("e:0", "e:2"), ("e:1", "e:2")}:
        raise AssertionError(f"unexpected E-only cores: {expected_e}")
    if expected_r != {("r:DENY_AFTER_A",), ("r:DENY_AFTER_C",)}:
        raise AssertionError(f"unexpected R-only cores: {expected_r}")
    if row["all_unions_sufficient"] or not row["some_union_sufficient"]:
        raise AssertionError(f"witness did not demonstrate selective composability: {row}")
    return row


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    policy, by_scenario, selection = base.collect_frozen_strata(base.LAB, 5, 20261011)
    rows = []
    for scenario, items in sorted(by_scenario.items()):
        for seed, event_index, trace, event in items:
            rows.append(analyze_case(
                f"docker-{len(rows)}", "frozen_docker_alert", trace, policy, 5,
                {"scenario": scenario, "seed": seed, "event_index": event_index,
                 "event_id": event.eid}))

    from revision_explanation_benchmark import controlled_cases
    for name, trace, fixture_policy, horizon in controlled_cases():
        rows.append(analyze_case(f"fixture-{name}", "controlled_fixture",
                                 trace, fixture_policy, horizon, {"scenario": name}))
    rows.append(composability_counterexample())

    if sum(r["source"] == "frozen_docker_alert" for r in rows) != 120:
        raise AssertionError("the frozen Docker selection must contain 120 cases")

    summaries = {}
    for source in ("frozen_docker_alert", "controlled_fixture", "constructed_semantic_witness"):
        group = [r for r in rows if r["source"] == source]
        all_unions = [u for r in group for u in r["unions"]]
        summaries[source] = {
            "cases": len(group),
            "cases_with_separate_core_families": sum(
                r["event_core_count"] > 0 and r["rule_core_count"] > 0 for r in group),
            "cases_all_unions_sufficient": sum(r["all_unions_sufficient"] for r in group),
            "cases_some_union_sufficient": sum(r["some_union_sufficient"] for r in group),
            "cases_any_union_is_joint_minimal": sum(r["any_union_is_joint_minimal"] for r in group),
            "union_candidates": len(all_unions),
            "sufficient_unions": sum(u["sufficient"] is True for u in all_unions),
            "insufficient_unions": sum(u["sufficient"] is False for u in all_unions),
            "sufficient_but_nonminimal_unions": sum(
                u["sufficient"] is True and not u["inclusion_minimal"] for u in all_unions),
            "undefined_unions": sum(u["sufficient"] is None for u in all_unions),
        }
    result_path = OUT / "case_results.json"
    summary_path = OUT / "summary.json"
    result_path.write_text(json.dumps(rows, indent=2), encoding="utf-8", newline="\n")
    summary_path.write_text(json.dumps({
        "classification": "retrospective workload analysis plus a constructed semantic falsification witness",
        "selection_seed": 20261011,
        "semantics": "all cross-products of event-only and rule-only inclusion-minimal cores; each union tested under the full joint E+R intervention domain",
        "oracle": "trace_policy_engine.reference_eval",
        "groups": summaries,
        "interpretation_limit": "Observed workload-specific composability; no independent generalization or analyst utility claim.",
    }, indent=2), encoding="utf-8", newline="\n")
    manifest = {
        "input_sha256": selection["input_sha256"],
        "selection_manifest": selection,
        "generator_script": str(Path(__file__).name),
        "generator_sha256": sha256(Path(__file__)),
        "base_script_sha256": sha256(Path(base.__file__)),
        "joint_semantics": "retention intervention over complete declared event horizon and all policy rules",
        "outputs_sha256": {result_path.name: sha256(result_path), summary_path.name: sha256(summary_path)},
        "limitations": ["retrospective sample", "constructed semantic witness is not empirical prevalence evidence", "no external confirmation", "no human analyst study"],
    }
    (OUT / "protocol_manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8", newline="\n")
    print(json.dumps(summaries, indent=2))


if __name__ == "__main__":
    main()
