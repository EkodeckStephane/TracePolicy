"""Independent exhaustive verifier for revision_policy_differential.py."""
from __future__ import annotations

import csv
import hashlib
import itertools
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "experiments")]
import trace_policy_engine as tpe
from local_lab_adapter import lab_policy, load_gateway_events
from revision_policy_evolution import updated_policy

DATA = ROOT / "local_lab" / "results"
RESULT = ROOT / "results" / "revision" / "policy_evolution_differential_v1" / "paired_explanations.json"
OUT = RESULT.parent
OPS = ("tighten_bruteforce_threshold", "relax_bruteforce_threshold", "remove_admin_deny_rule")


def find_representatives():
    base = lab_policy()
    variants = {op: updated_policy(base, op)[0] for op in OPS}
    selected = {}
    for csv_path in sorted(DATA.glob("truth_*.csv")):
        seed = int(csv_path.stem.split("_")[-1])
        access = DATA / f"access_{seed}.jsonl"
        with csv_path.open(newline="", encoding="utf-8") as f:
            labels = {r["sid"]: {"label": int(r["label"]), "scenario": r["scenario"]}
                      for r in csv.DictReader(f)}
        stream = load_gateway_events(access, labels)
        for i, ev in enumerate(stream):
            trace = stream[max(0, i - 4):i + 1]
            old = tpe.reference_eval(trace, base).alert_class
            for op in OPS:
                new = tpe.reference_eval(trace, variants[op]).alert_class
                if old != new and op not in selected:
                    selected[op] = (seed, i, ev.eid, trace, old, new)
    return base, variants, selected


def make_truth_table(trace, old_policy, updated_policy_):
    n = len(trace) + 1
    table = {}
    for assignment in itertools.product((0, 1), repeat=n):
        altered_trace = tuple(
            event if assignment[position] else tpe.Event.stutter_like(event)
            for position, event in enumerate(trace)
        )
        policy_after_edit_intervention = updated_policy_ if assignment[-1] else old_policy
        table[assignment] = (
            tpe.reference_eval(altered_trace, old_policy).alert_class,
            tpe.reference_eval(altered_trace, policy_after_edit_intervention).alert_class,
        )
    return table


def exhaustive_minimal_sets(table, target):
    width = len(next(iter(table)))
    valid = []
    for mask in range(1 << width):
        chosen = {i for i in range(width) if mask & (1 << i)}
        if all(value == target for assignment, value in table.items()
               if all(assignment[i] == 1 for i in chosen)):
            if not any(prior < chosen for prior in valid):
                valid.append(chosen)
    return valid


def main():
    report = json.loads(RESULT.read_text(encoding="utf-8"))
    base, variants, representatives = find_representatives()
    if len(report) != len(OPS) or set(representatives) != set(OPS):
        raise AssertionError("the three expected representative cases are required")
    verified = 0
    for row in report:
        op = row["operation"]
        seed, index, event_id, trace, old, new = representatives[op]
        if (row["seed"], row["event_index"], row["event_id"],
                tuple(row["target_ordered_alert_pair"])) != (seed, index, event_id, (old, new)):
            raise AssertionError(f"representative or factual pair mismatch for {op}")
        table = make_truth_table(trace, base, variants[op])
        target = (old, new)
        computed = exhaustive_minimal_sets(table, target)
        unit_index = {unit: i for i, unit in enumerate(row["units"])}
        stored = [set(unit_index[name] for name in item["core"])
                  for item in row["minimal_paired_explanation_family"]]
        canonical = lambda xs: sorted(tuple(sorted(s)) for s in xs)
        if canonical(computed) != canonical(stored):
            raise AssertionError(f"minimal family mismatch for {op}: {computed} vs {stored}")
        for core_record, core in zip(row["minimal_paired_explanation_family"], stored):
            for unit_name, witness in core_record["deletion_witnesses"].items():
                retained = core - {unit_index[unit_name]}
                bits_by_name = witness["retained_assignment"]
                assignment = tuple(int(bits_by_name[unit]) for unit in row["units"])
                if not all(assignment[i] == 1 for i in retained):
                    raise AssertionError(f"deletion witness fails retained condition for {op}")
                if list(table[assignment]) != witness["resulting_pair"] or table[assignment] == target:
                    raise AssertionError(f"deletion witness is invalid for {op}/{unit_name}")
        verified += 1
    result = {"cases_verified": verified, "all_minimal_families_match": True,
              "all_deletion_witnesses_valid": True,
              "scope": "finite domains of the three selected windows; evaluator and edit constructor are shared"}
    verification_path = OUT / "independent_verification.json"
    verification_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    manifest_path = OUT / "protocol_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["independent_verification_sha256"] = hashlib.sha256(
        verification_path.read_bytes()).hexdigest()
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
                             encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
