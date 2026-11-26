"""Paired E-only/R-only/joint explanation-domain ablation.

Retrospective analysis on frozen local-lab examples plus the existing controlled
fixtures. It is not an external generalization test. Outputs use a new directory.
"""
from __future__ import annotations

import hashlib
import itertools
import json
import csv
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "experiments"))

import trace_policy_engine as tpe
from local_lab_adapter import lab_policy, load_gateway_events

LAB = ROOT / "local_lab" / "results"
OUTPUT = ROOT / "results" / "revision" / "joint_ablation_v1"


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def parse_event(d: dict) -> tpe.Event:
    return tpe.Event(
        eid=str(d["eid"]), ts=float(d["ts"]), action=d["action"],
        resource_class=d["resource_class"], subject_class=d["subject_class"],
        attrs=d.get("attrs", {}), malicious=d.get("malicious"),
        attack_type=d.get("attack_type"),
    )


def mode_variables(trace, policy, mode: str, horizon: int):
    eps, rids, _ = tpe.explanation_unit_info(trace, policy, horizon=horizon)
    if mode == "E-only":
        rids = []
    elif mode == "R-only":
        eps = []
    elif mode != "E+R":
        raise ValueError(mode)
    units = [f"e:{i}" for i in eps] + [f"r:{r}" for r in rids]
    return eps, rids, units


def enumerate_minimal_cores(trace, policy, target, eps, rids, units):
    n = len(units)
    outputs = []
    for mask in range(1 << n):
        bits = [(mask >> i) & 1 for i in range(n)]
        outputs.append(tpe._class_under_mask(trace, policy, eps, rids, bits))

    # Superset zeta transform: candidate C is insufficient iff some non-target
    # completion contains C. This computes that predicate in O(n 2^n), then
    # enumerates inclusion-minimal sufficient candidates exactly.
    has_bad_superset = [result != target for result in outputs]
    checks = len(outputs)
    for bit in range(n):
        flag = 1 << bit
        for mask in range(1 << n):
            if not (mask & flag) and has_bad_superset[mask | flag]:
                has_bad_superset[mask] = True
            checks += 1

    cores = []
    for size in range(n + 1):
        for selected in itertools.combinations(range(n), size):
            selected = frozenset(selected)
            if any(core.issubset(selected) for core in cores):
                continue
            mask = sum(1 << i for i in selected)
            checks += 1
            if not has_bad_superset[mask]:
                cores.append(selected)
    core_units = [[units[i] for i in sorted(c)] for c in cores]
    return outputs, core_units, checks


def analyze(case_id, source, trace, policy, meta=None, horizon=5):
    factual = tpe.reference_eval(trace, policy).alert_class
    out = {"case_id": case_id, "source": source, "factual": factual, **(meta or {})}
    for mode in ("E-only", "R-only", "E+R"):
        eps, rids, units = mode_variables(trace, policy, mode, horizon)
        outputs, cores, checks = enumerate_minimal_cores(trace, policy, factual, eps, rids, units)
        expected = 1 << len(units)
        if len(outputs) != expected or outputs[-1] != factual:
            raise AssertionError(f"incomplete/factual domain failure: {case_id} {mode}")
        out[mode] = {
            "horizon": horizon,
            "event_positions": eps,
            "rule_ids": rids,
            "unit_count": len(units),
            "intervention_count": expected,
            "target_preserving_interventions": sum(x == factual for x in outputs),
            "minimal_cores": cores,
            "minimal_core_count": len(cores),
            "checks": checks,
            "all_minimal_cores_jointly_retain_events_and_rules":
                all(any(u.startswith("e:") for u in c) and any(u.startswith("r:") for u in c)
                    for c in cores) if mode == "E+R" and cores else None,
        }
    return out


def make_version_switch():
    ev = tpe.Event("v-switch-event", 1.0, "write", "sensitive", "user")
    trace = [ev]
    v1 = tpe.PolicyVersion("VERSION_SWITCH_CONTROL", 1,
        (tpe.Rule("ALLOW_WRITE_V1", 10, tpe.ALLOW,
                  tpe.Selector("write", "sensitive", "user")),))
    v2 = tpe.PolicyVersion("VERSION_SWITCH_CONTROL", 2,
        (tpe.Rule("DENY_WRITE_V2", 10, tpe.DENY,
                  tpe.Selector("write", "sensitive", "user")),))
    return trace, v1, v2


def collect_frozen_strata(lab_dir: Path, horizon: int, selection_seed: int):
    """Reproduce the frozen one-alert-per-scenario/workload selection without SHAP."""
    expected = ["admin_probe", "bruteforce", "command_probe", "path_traversal"]
    by_scenario = {s: [] for s in expected}
    strata = []
    input_hashes = {}
    policy = lab_policy()
    for truth_path in sorted(lab_dir.glob("truth_*.csv")):
        seed = int(truth_path.stem.split("_")[-1])
        access_path = lab_dir / f"access_{seed}.jsonl"
        if not access_path.exists():
            raise FileNotFoundError(access_path)
        input_hashes[truth_path.name] = sha256(truth_path)
        input_hashes[access_path.name] = sha256(access_path)
        with truth_path.open(newline="", encoding="utf-8") as stream:
            truth = {r["sid"]: {"label": int(r["label"]), "scenario": r["scenario"]}
                     for r in csv.DictReader(stream)}
        events = load_gateway_events(access_path, truth)
        candidates = {s: [] for s in expected}
        for i, event in enumerate(events):
            if int(event.malicious or 0) != 1 or event.attack_type not in candidates:
                continue
            trace = events[max(0, i-horizon+1):i+1]
            if tpe.reference_eval(trace, policy).alert_class in (tpe.VIOLATION, tpe.CONFLICT):
                candidates[event.attack_type].append((seed, i, trace, event))
        rng = random.Random(selection_seed + seed)
        for scenario in expected:
            items = candidates[scenario]
            if items:
                selected = items[rng.randrange(len(items))]
                by_scenario[scenario].append(selected)
                strata.append({"seed": seed, "scenario": scenario,
                               "status": "selected", "eligible_count": len(items),
                               "event_index": selected[1], "event_id": selected[3].eid})
            else:
                strata.append({"seed": seed, "scenario": scenario,
                               "status": "no_eligible_true_positive", "eligible_count": 0})
    manifest = {"input_sha256": input_hashes,
                "selection": "one seeded randomized eligible true-positive alert per scenario/workload",
                "selection_seed": selection_seed, "strata": strata}
    return policy, by_scenario, manifest


def main():
    OUTPUT.mkdir(parents=True, exist_ok=True)
    rows = []
    policy, by_scenario, selection_manifest = collect_frozen_strata(LAB, 5, 20261011)
    case_no = 0
    for scenario in sorted(by_scenario):
        for seed, event_index, trace, event in by_scenario[scenario]:
            rows.append(analyze(
                case_id=f"docker-{case_no}", source="frozen_docker_alert",
                trace=trace, policy=policy,
                meta={"scenario": scenario, "seed": seed,
                      "event_index": event_index, "event_id": event.eid},
            ))
            case_no += 1
    if case_no != 120:
        raise AssertionError(f"expected 120 frozen Docker examples, found {case_no}")

    # Controlled method fixtures; labelled separately from observed Docker cases.
    from revision_explanation_benchmark import controlled_cases
    for name, trace, pol, _horizon in controlled_cases():
        rows.append(analyze(f"fixture-{name}", "controlled_fixture", trace, pol,
                            {"scenario": name}, horizon=_horizon))

    # A paired policy-version switch control: same trace, two immutable versions.
    trace, v1, v2 = make_version_switch()
    rows.append({"case_id": "constructed-version-switch", "source": "constructed_pair",
                 "version_pair": [1, 2],
                 "version_1_decision": tpe.reference_eval(trace, v1).alert_class,
                 "version_2_decision": tpe.reference_eval(trace, v2).alert_class,
                 "version_2_ablation": analyze("v2", "constructed_pair", trace, v2,
                                                horizon=1)})

    # Verify the version-2 control has an irreducible joint event-rule core.
    v2_row = rows[-1]["version_2_ablation"]
    joint = v2_row["E+R"]["minimal_cores"]
    if ["e:0", "r:DENY_WRITE_V2"] not in joint:
        raise AssertionError(f"constructed joint core absent: {joint}")
    if rows[-1]["version_1_decision"] == rows[-1]["version_2_decision"]:
        raise AssertionError("version switch failed to change the decision")

    (OUTPUT / "case_results.json").write_text(json.dumps(rows, indent=2), encoding="utf-8", newline="\n")
    summary = {
        "case_result_records": len(rows),
        "cases_with_direct_mode_ablation": sum("E+R" in r for r in rows),
        "docker_observed_cases": sum(r["source"] == "frozen_docker_alert" for r in rows),
        "controlled_fixtures": sum(r["source"] == "controlled_fixture" for r in rows),
        "constructed_version_pairs": sum(r["source"] == "constructed_pair" for r in rows),
        "by_source": {},
        "interpretation_limit": "Retrospective explanation-domain ablation; not external generalization or analyst utility.",
    }
    for source in ("frozen_docker_alert", "controlled_fixture"):
        source_rows = [r for r in rows if r["source"] == source]
        summary["by_source"][source] = {"cases": len(source_rows), "modes": {}}
        for mode in ("E-only", "R-only", "E+R"):
            group = [r[mode] for r in source_rows]
            sizes = sorted(len(c) for x in group for c in x["minimal_cores"])
            summary["by_source"][source]["modes"][mode] = {
                "cases": len(group),
                "cases_with_any_nonempty_core": sum(any(len(c) > 0 for c in x["minimal_cores"]) for x in group),
                "cases_with_empty_core": sum(any(len(c) == 0 for c in x["minimal_cores"]) for x in group),
                "cases_with_multiple_minimal_cores": sum(x["minimal_core_count"] > 1 for x in group),
                "core_count_total": sum(x["minimal_core_count"] for x in group),
                "minimal_core_sizes": {
                    "min": min(sizes) if sizes else None,
                    "median": (sizes[(len(sizes)-1)//2] + sizes[len(sizes)//2]) / 2 if sizes else None,
                    "max": max(sizes) if sizes else None,
                },
            }
            if mode == "E+R":
                summary["by_source"][source]["modes"][mode]["cases_with_a_core_containing_both_types"] = sum(
                    any(any(u.startswith("e:") for u in c) and any(u.startswith("r:") for u in c)
                        for c in x["minimal_cores"]) for x in group)
    (OUTPUT / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8", newline="\n")
    manifest = {
        "input_directory": str(LAB.relative_to(ROOT)),
        "input_sha256": selection_manifest["input_sha256"],
        "strata": selection_manifest["strata"],
        "policy": "local_lab_adapter.lab_policy(version=1)",
        "horizon": 5,
        "selection_seed": 20261011,
        "modes": ["E-only", "R-only", "E+R"],
        "decision_oracle": "trace_policy_engine.reference_eval",
        "output_files": ["case_results.json", "summary.json"],
        "output_sha256": {name: sha256(OUTPUT / name)
                          for name in ("case_results.json", "summary.json")},
        "script_sha256": sha256(Path(__file__)),
        "classification": "retrospective; not independent confirmation",
    }
    (OUTPUT / "protocol_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8", newline="\n")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
