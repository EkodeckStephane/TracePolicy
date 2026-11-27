"""Retrospective paired policy-version benchmark on frozen Docker traces.

The three update operations are fixed in source before scanning the frozen
corpus. Every five-event window is evaluated under both versions. One
deterministic differing-decision window per operation receives exact
single-version explanation analysis. This is a descriptive benchmark, not an
independent holdout or a differential-explanation algorithm.
"""
from __future__ import annotations

import csv
import hashlib
import json
import sys
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "experiments"))
import trace_policy_engine as tpe
from local_lab_adapter import lab_policy, load_gateway_events
from revision_joint_ablation import analyze, sha256
from revision_explanation_benchmark import all_minimal_cores, independent_table

LAB = ROOT / "local_lab" / "results"
OUTPUT = ROOT / "results" / "revision" / "policy_evolution_pairs_v1"
HORIZON = 5


def updated_policy(base, operation: str):
    rules = list(base.rules)
    changed = []
    if operation in {"tighten_bruteforce_threshold", "relax_bruteforce_threshold"}:
        old = 4
        new = 3 if operation.startswith("tighten") else 5
        rules = [replace(r, guard=replace(r.guard, count_threshold=new))
                 if r.rid == "D_BRUTEFORCE" else r for r in rules]
        changed = [{"rule_id": "D_BRUTEFORCE", "field": "count_threshold",
                    "before": old, "after": new}]
    elif operation == "remove_admin_deny_rule":
        rules = [r for r in rules if r.rid != "D_ADMIN"]
        changed = [{"rule_id": "D_ADMIN", "field": "presence",
                    "before": "present", "after": "removed"}]
    else:
        raise ValueError(operation)
    return tpe.PolicyVersion(base.pid, base.version + 1, tuple(rules)), changed


def main() -> None:
    OUTPUT.mkdir(parents=True, exist_ok=True)
    base = lab_policy()
    operations = ("tighten_bruteforce_threshold", "relax_bruteforce_threshold",
                  "remove_admin_deny_rule")
    candidates = {op: [] for op in operations}
    inputs = {}
    for truth_path in sorted(LAB.glob("truth_*.csv")):
        seed = int(truth_path.stem.split("_")[-1])
        access_path = LAB / f"access_{seed}.jsonl"
        if not access_path.exists():
            raise FileNotFoundError(access_path)
        inputs[truth_path.name] = sha256(truth_path)
        inputs[access_path.name] = sha256(access_path)
        with truth_path.open(newline="", encoding="utf-8") as stream:
            truth = {r["sid"]: {"label": int(r["label"]), "scenario": r["scenario"]}
                     for r in csv.DictReader(stream)}
        events = load_gateway_events(access_path, truth)
        variants = {op: updated_policy(base, op) for op in operations}
        for i, event in enumerate(events):
            trace = events[max(0, i-HORIZON+1):i+1]
            before = tpe.reference_eval(trace, base).alert_class
            for op, (new_policy, change) in variants.items():
                after = tpe.reference_eval(trace, new_policy).alert_class
                if before != after:
                    candidates[op].append({"seed": seed, "event_index": i,
                        "event_id": event.eid, "trace": trace,
                        "before": before, "after": after,
                        "new_policy": new_policy, "change": change})

    rows = []
    for op in operations:
        eligible = candidates[op]
        if not eligible:
            rows.append({"operation": op, "differing_window_count": 0,
                         "selected_pair": None})
            continue
        item = eligible[0]  # deterministic first occurrence in sorted frozen inputs
        if item["before"] == item["after"]:
            raise AssertionError("selected version pair does not change the decision")
        old_exp = analyze(f"{op}-v1", "frozen_policy_version_pair", item["trace"], base,
                          horizon=HORIZON)
        new_exp = analyze(f"{op}-v2", "frozen_policy_version_pair", item["trace"],
                          item["new_policy"], horizon=HORIZON)
        old_cores = {tuple(x) for x in old_exp["E+R"]["minimal_cores"]}
        new_cores = {tuple(x) for x in new_exp["E+R"]["minimal_cores"]}
        independently_verified = True
        for policy, result, expected_cores in (
            (base, old_exp, old_cores), (item["new_policy"], new_exp, new_cores)):
            eps, rids, _ = tpe.explanation_unit_info(item["trace"], policy, horizon=HORIZON)
            units, table = independent_table(item["trace"], policy, eps, rids)
            independent = {tuple(sorted(c)) for c in all_minimal_cores(
                units, table, result["factual"])}
            if independent != expected_cores:
                independently_verified = False
                raise AssertionError(f"independent minimal-core mismatch for {op}: {independent} != {expected_cores}")
        rows.append({
            "operation": op, "differing_window_count": len(eligible),
            "changed_rule_fields": item["change"], "seed": item["seed"],
            "event_index": item["event_index"], "event_id": item["event_id"],
            "horizon": HORIZON, "decision_before": item["before"],
            "decision_after": item["after"],
            "decision_pair_differs": item["before"] != item["after"],
            "minimal_core_families_independently_verified": independently_verified,
            "old_version_joint_minimal_cores": sorted([list(x) for x in old_cores]),
            "new_version_joint_minimal_cores": sorted([list(x) for x in new_cores]),
            "core_family_intersection": sorted([list(x) for x in old_cores & new_cores]),
            "core_family_symmetric_difference": sorted([list(x) for x in old_cores ^ new_cores]),
            "classification": "retrospective paired replay; not a differential explanation",
        })

    result = OUTPUT / "paired_results.json"
    result.write_text(json.dumps(rows, indent=2), encoding="utf-8", newline="\n")
    summary = {"operations": len(operations),
               "operations_with_decision_change": sum(x["differing_window_count"] > 0 for x in rows),
               "differing_windows_by_operation": {x["operation"]: x["differing_window_count"] for x in rows},
               "selected_pairs_have_different_decisions": sum(bool(x.get("decision_pair_differs")) for x in rows),
               "interpretation_limit": "Retrospective updates on one frozen local-lab policy and corpus; results do not establish policy-update prevalence, external generalization, or analyst utility."}
    summary_path = OUTPUT / "summary.json"
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8", newline="\n")
    manifest = {"input_sha256": inputs, "policy": "local_lab_adapter.lab_policy(version=1)",
        "update_operations": list(operations), "window_horizon": HORIZON,
        "candidate_rule": "all five-event suffix windows from all frozen workload streams; no attack-label filtering",
        "selection": "first differing-decision window in sorted workload files and event order",
        "oracle": "trace_policy_engine.reference_eval",
        "explanation_generator": "revision_joint_ablation.analyze",
        "classification": "retrospective paired replay; single-version cores only",
        "output_sha256": {"paired_results.json": sha256(result), "summary.json": sha256(summary_path)},
        "script_sha256": sha256(Path(__file__))}
    (OUTPUT / "protocol_manifest.json").write_text(json.dumps(manifest, indent=2),
        encoding="utf-8", newline="\n")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
