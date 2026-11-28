"""Compare the frozen 486-configuration LIME analysis with a fresh run."""
from __future__ import annotations

import csv
import hashlib
import json
import math
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results/revision"
OLD = RESULTS / "benchmark.json"
NEW_DIR = RESULTS / "lime_reproduction_2026-11-28"
NEW = NEW_DIR / "benchmark.json"
CASE_STUDY = RESULTS / "lime_nonminimal_case_studies.json"
SUMMARY = RESULTS / "lime_sensitivity_summary.csv"


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def config_key(row: dict) -> tuple:
    return (
        row["case"], int(row["seed"]), int(row["num_samples"]),
        round(float(row["kernel_width_scale"]), 8),
        round(float(row["background_probability"]), 8),
    )


def close(a, b, tol=1e-12) -> bool:
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(close(x, y, tol) for x, y in zip(a, b))
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return math.isclose(float(a), float(b), rel_tol=0.0, abs_tol=tol)
    return a == b


def main() -> None:
    old_rows = json.loads(OLD.read_text(encoding="utf-8"))
    new_rows = json.loads(NEW.read_text(encoding="utf-8"))
    old_lime = {config_key(r): r for r in old_rows if r.get("method") == "LIME"}
    new_lime = {config_key(r): r for r in new_rows if r.get("method") == "LIME"}
    assert len(old_lime) == len(new_lime) == 486
    assert old_lime.keys() == new_lime.keys()

    stable_fields = (
        "status", "sufficient", "minimal", "size", "selected",
        "valid_alternative_count", "ranking", "weights",
        "local_training_score", "full_domain_surrogate_mse",
    )
    mismatches = []
    for key in sorted(old_lime):
        a, b = old_lime[key], new_lime[key]
        for field in stable_fields:
            if not close(a.get(field), b.get(field)):
                mismatches.append({"configuration": key, "field": field,
                                   "old": a.get(field), "new": b.get(field)})
    assert not mismatches, mismatches[:5]
    assert all(row["status"] == "ok" for row in new_lime.values())

    expected_cases = {
        "conflict", "count_threshold", "distractors", "gap",
        "instant_violation", "multiple_events", "multiple_rules",
        "state_fixed_context", "temporal_seq",
    }
    by_case = {}
    for name in expected_cases:
        rows = [r for r in new_lime.values() if r["case"] == name]
        assert len(rows) == 54, (name, len(rows))
        by_case[name] = {
            "runs": len(rows),
            "minimal_rate": sum(bool(r["minimal"]) for r in rows) / len(rows),
            "local_score_min": min(r["local_training_score"] for r in rows),
            "local_score_max": max(r["local_training_score"] for r in rows),
            "full_domain_mse_min": min(r["full_domain_surrogate_mse"] for r in rows),
            "full_domain_mse_max": max(r["full_domain_surrogate_mse"] for r in rows),
        }
    assert {r["case"] for r in new_lime.values()} == expected_cases
    nonminimal = [r for r in new_lime.values() if not r["minimal"]]
    assert len(nonminimal) == 1
    failing = nonminimal[0]
    assert config_key(failing) == ("temporal_seq", 23, 128, 0.5, 0.25)
    assert failing["sufficient"] and failing["size"] == 4

    # Recheck the saved counterexample against the fresh, full intervention table.
    study = json.loads(CASE_STUDY.read_text(encoding="utf-8"))[0]
    assert close(study["measured_lime_row"]["weights"], failing["weights"])
    assert study["measured_lime_row"]["selected"] == failing["selected"]
    assert close(study["measured_lime_row"]["full_domain_surrogate_mse"],
                 failing["full_domain_surrogate_mse"])
    fresh_domains = json.loads((NEW_DIR / "domain_audit.json").read_text(encoding="utf-8"))
    domain = next(row for row in fresh_domains if row["case"] == "temporal_seq")
    assert domain["all_minimal_cores"] == study["all_minimal_cores"]
    target = domain["target"]
    units = domain["units"]
    labels = {tuple(m["bits"]): m["target"] for m in domain["masks"]}
    assert len(labels) == 1 << len(units)
    for check in study["deletion_checks"]:
        kept = set(failing["selected"]) - {check["released_unit"]}
        violating = [bits for bits, label in labels.items()
                     if all(bits[units.index(unit)] == 1 for unit in kept)
                     and label != target]
        assert check["still_sufficient"] == (not violating)
        if check["still_sufficient"]:
            assert check["counterexample_mask"] is None
        else:
            witness = check["counterexample_mask"]
            bits = tuple(int(witness[u]) for u in units)
            assert bits in violating
            assert labels[bits] != target

    # Recompute every plotted summary field from the fresh row-level outputs.
    with SUMMARY.open(newline="", encoding="utf-8") as stream:
        old_summary = {r["case"]: r for r in csv.DictReader(stream)}
    assert old_summary.keys() == expected_cases
    summary_mismatches = []
    for name, calc in by_case.items():
        prior = old_summary[name]
        for field, value in calc.items():
            if field == "runs":
                equal = int(prior[field]) == value
            else:
                equal = close(float(prior[field]), value, tol=1e-10)
            if not equal:
                summary_mismatches.append({"case": name, "field": field,
                                           "recorded": prior[field], "recomputed": value})
    assert not summary_mismatches, summary_mismatches

    output = {
        "decision": "PASS_REPRODUCED_WITHIN_FROZEN_ENVIRONMENT",
        "scope": "same frozen fixtures, implementation, dependencies, and random seeds; fresh output directory",
        "old_and_new_lime_configurations": len(new_lime),
        "statuses": dict(Counter(r["status"] for r in new_lime.values())),
        "runs_per_fixture": 54,
        "nonminimal_count": len(nonminimal),
        "nonminimal_configuration": {
            k: failing[k] for k in ("case", "seed", "num_samples", "kernel_width_scale",
                                    "background_probability", "selected", "size",
                                    "sufficient", "minimal", "local_training_score",
                                    "full_domain_surrogate_mse")
        },
        "all_row_level_stable_fields_match": True,
        "all_nine_csv_summary_rows_recomputed": True,
        "counterexample_deletion_witnesses_rechecked_against_fresh_domain": 4,
        "hashes": {
            "source_script": sha(ROOT / "experiments/revision_explanation_benchmark.py"),
            "historical_benchmark": sha(OLD),
            "fresh_benchmark": sha(NEW),
            "historical_case_study": sha(CASE_STUDY),
            "historical_summary": sha(SUMMARY),
            "fresh_domain_audit": sha(NEW_DIR / "domain_audit.json"),
            "fresh_environment": sha(NEW_DIR / "environment.json"),
        },
        "limitations": [
            "This is exact computational reproduction, not independent implementation replication.",
            "The nine fixtures are controlled and do not establish behavior on independent security instances.",
            "LIME outputs depend on the recorded implementation and environment; wall-clock times are excluded from equality checks.",
        ],
    }
    (ROOT / "audit/lime_sensitivity_reproduction_2026-11-28.json").write_text(
        json.dumps(output, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()

