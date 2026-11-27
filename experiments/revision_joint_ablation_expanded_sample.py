"""Expanded stratified sample of eligible frozen Docker alert cases.

It samples at most two eligible true-positive alerts per workload/scenario
stratum with a fixed seed. It remains retrospective and is not an independent
generalization test. Output is isolated from archived v1.
"""
from __future__ import annotations

import csv
import hashlib
import json
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "experiments"))
import trace_policy_engine as tpe
from local_lab_adapter import lab_policy, load_gateway_events
from revision_joint_ablation import sha256
from revision_union_ablation import analyze_case

LAB = ROOT / "local_lab" / "results"
OUTPUT = ROOT / "results" / "revision" / "joint_ablation_expanded_sample_v1"
SCENARIOS = ("admin_probe", "bruteforce", "command_probe", "path_traversal")
HORIZON = 5
SAMPLE_PER_STRATUM = 2
SELECTION_SEED = 20261127


def main() -> None:
    OUTPUT.mkdir(parents=True, exist_ok=True)
    policy = lab_policy()
    rows = []
    inputs = {}
    strata = []
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
        eligible = {scenario: [] for scenario in SCENARIOS}
        for i, event in enumerate(events):
            if int(event.malicious or 0) != 1 or event.attack_type not in eligible:
                continue
            trace = events[max(0, i-HORIZON+1):i+1]
            target = tpe.reference_eval(trace, policy).alert_class
            if target not in (tpe.VIOLATION, tpe.CONFLICT):
                continue
            eligible[event.attack_type].append((i, event, trace))
        counts = {scenario: len(items) for scenario, items in eligible.items()}
        for scenario, items in eligible.items():
            rng = random.Random(SELECTION_SEED + seed + sum(map(ord, scenario)))
            selected = sorted(rng.sample(items, min(SAMPLE_PER_STRATUM, len(items))), key=lambda x: x[0])
            for i, event, trace in selected:
                rows.append(analyze_case(
                    case_id=f"docker-expanded-{seed}-{scenario}-{i}",
                    source="frozen_docker_alert_expanded_sample", trace=trace, policy=policy,
                    horizon=HORIZON, metadata={"scenario": scenario, "seed": seed,
                                               "event_index": i, "event_id": event.eid,
                                               "eligible_stratum_count": len(items)},
                ))
        for scenario, count in counts.items():
            strata.append({"seed": seed, "scenario": scenario, "eligible_count": count})

    expected = sum(min(SAMPLE_PER_STRATUM, x["eligible_count"]) for x in strata)
    if len(rows) != expected:
        raise AssertionError("sample row count differs from the fixed per-stratum sample size")
    result_path = OUTPUT / "case_results.json"
    result_path.write_text(json.dumps(rows, indent=2), encoding="utf-8", newline="\n")
    summary = {"cases": len(rows), "by_scenario": {},
               "interpretation_limit": "Retrospective stratified sample of eligible positive alerts in this frozen corpus; no external generalization claim."}
    for scenario in SCENARIOS:
        group = [r for r in rows if r["scenario"] == scenario]
        summary["by_scenario"][scenario] = {
            "cases": len(group),
            "union_sufficiency_failures": sum(not r["all_unions_sufficient"] for r in group),
            "cases_with_union_equal_to_joint_core": sum(r["any_union_is_joint_minimal"] for r in group),
        }
    summary_path = OUTPUT / "summary.json"
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8", newline="\n")
    manifest = {
        "corpus": "local_lab/results frozen input files",
        "input_sha256": inputs, "strata": strata,
        "selection": "fixed-seed sample of at most two eligible malicious alerts per workload/scenario stratum",
        "selection_seed": SELECTION_SEED, "sample_per_stratum": SAMPLE_PER_STRATUM,
        "horizon": HORIZON, "policy": "local_lab_adapter.lab_policy(version=1)",
        "decision_oracle": "trace_policy_engine.reference_eval",
        "analysis": "E-only, R-only, union of every pair of separated minimal cores, and exact E+R minimal cores",
        "classification": "retrospective stratified sample; not independent confirmation",
        "output_sha256": {"case_results.json": sha256(result_path), "summary.json": sha256(summary_path)},
        "script_sha256": sha256(Path(__file__)),
    }
    (OUTPUT / "protocol_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8", newline="\n")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
