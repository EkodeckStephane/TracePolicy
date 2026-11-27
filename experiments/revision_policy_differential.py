"""Exploratory exact paired explanations for fixed policy edits.

The target is the ordered pair of alert classes (old-policy, updated-policy).
Event neutralization is applied identically to both versions. An edit unit is
neutralized by reverting that update in the new version. The script searches
the complete finite event/edit intervention space for inclusion-minimal sets
that preserve the factual ordered pair, and records one deletion witness per
retained unit. This is a pilot formalization, not a novelty claim.
"""
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

LAB = ROOT / "local_lab" / "results"
OUT = ROOT / "results" / "revision" / "policy_evolution_differential_v1"
HORIZON = 5


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def changed_rule_id(operation: str) -> str:
    return "D_ADMIN" if operation == "remove_admin_deny_rule" else "D_BRUTEFORCE"


def core_family(units, table, target):
    """Enumerate every inclusion-minimal sufficient set in the table."""
    cores = []
    for size in range(len(units) + 1):
        for indices in itertools.combinations(range(len(units)), size):
            selected = set(indices)
            sufficient = all(
                value == target
                for bits, value in table.items()
                if all(bits[i] for i in selected)
            )
            if sufficient and not any(c <= selected for c in cores):
                cores.append(selected)
    return cores


def first_counterexample(units, table, target, retained):
    for bits, value in sorted(table.items()):
        if all(bits[i] for i in retained) and value != target:
            return {units[i]: bits[i] for i in range(len(units))}, list(value)
    return None


def paired_table(trace, old_policy, new_policy, operation, edit_unit):
    event_units = [f"e:{i}" for i in range(len(trace))]
    units = event_units + [edit_unit]
    table = {}
    for bits in itertools.product((0, 1), repeat=len(units)):
        masked = [e if bits[i] else tpe.Event.stutter_like(e)
                  for i, e in enumerate(trace)]
        # The final bit controls whether the policy edit is retained. If it is
        # neutralized, the new branch reverts to the old policy.
        right_policy = new_policy if bits[-1] else old_policy
        left = tpe.reference_eval(masked, old_policy).alert_class
        right = tpe.reference_eval(masked, right_policy).alert_class
        table[bits] = (left, right)
    return units, table


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    base = lab_policy()
    operations = (
        "tighten_bruteforce_threshold",
        "relax_bruteforce_threshold",
        "remove_admin_deny_rule",
    )
    candidates = {op: [] for op in operations}
    input_hashes = {}
    for truth_path in sorted(LAB.glob("truth_*.csv")):
        seed = int(truth_path.stem.split("_")[-1])
        access_path = LAB / f"access_{seed}.jsonl"
        if not access_path.exists():
            raise FileNotFoundError(access_path)
        input_hashes[truth_path.name] = sha256(truth_path)
        input_hashes[access_path.name] = sha256(access_path)
        with truth_path.open(newline="", encoding="utf-8") as f:
            truth = {r["sid"]: {"label": int(r["label"]), "scenario": r["scenario"]}
                     for r in csv.DictReader(f)}
        events = load_gateway_events(access_path, truth)
        updated = {op: updated_policy(base, op)[0] for op in operations}
        for i, event in enumerate(events):
            trace = events[max(0, i - HORIZON + 1):i + 1]
            before = tpe.reference_eval(trace, base).alert_class
            for op in operations:
                after = tpe.reference_eval(trace, updated[op]).alert_class
                if before != after:
                    candidates[op].append((seed, i, event.eid, trace, before, after))

    rows = []
    for op in operations:
        if not candidates[op]:
            rows.append({"operation": op, "status": "no_differing_window"})
            continue
        seed, index, event_id, trace, before, after = candidates[op][0]
        new_policy, edit = updated_policy(base, op)
        change = edit[0]
        edit_unit = f"d:{change['rule_id']}.{change['field']}"
        target = (before, after)
        units, table = paired_table(trace, base, new_policy, op, edit_unit)
        observed = table[(1,) * len(units)]
        if observed != target:
            raise AssertionError(f"factual pair mismatch: {observed} != {target}")
        cores = core_family(units, table, target)
        certificates = []
        for core in cores:
            deletion = {}
            for unit_index in sorted(core):
                reduced = core - {unit_index}
                witness = first_counterexample(units, table, target, reduced)
                if witness is None:
                    raise AssertionError("minimality deletion has no counterexample")
                deletion[units[unit_index]] = {
                    "retained_assignment": witness[0],
                    "resulting_pair": witness[1],
                }
            certificates.append({
                "core": [units[i] for i in sorted(core)],
                "size": len(core),
                "deletion_witnesses": deletion,
            })
        rows.append({
            "operation": op,
            "seed": seed,
            "event_index": index,
            "event_id": event_id,
            "horizon": HORIZON,
            "target_ordered_alert_pair": list(target),
            "edit_unit": edit_unit,
            "units": units,
            "intervention_assignments": len(table),
            "minimal_paired_explanation_family": certificates,
            "independent_generation_check": "exhaustively recomputed by experiments/verify_policy_differential.py; same reference evaluator, separate truth-table and powerset enumeration",
            "scope": "representative first-difference windows from the same retrospective Docker corpus; not external validation",
        })

    out_path = OUT / "paired_explanations.json"
    out_path.write_text(json.dumps(rows, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    summary = {
        "operation_count": len(operations),
        "analysed_pairs": sum("minimal_paired_explanation_family" in row for row in rows),
        "target": "exact ordered pair (old-policy alert class, updated-policy alert class)",
        "intervention_semantics": "common stutter neutralization of events in both policy branches; edit neutralization reverts new policy to old policy",
        "all_factual_pairs_confirmed": all(
            row.get("target_ordered_alert_pair") is not None
            and row.get("minimal_paired_explanation_family") for row in rows
        ),
        "scope_warning": "Exploratory pilot on three selected first-difference windows, not an independent benchmark or novelty demonstration.",
    }
    summary_path = OUT / "summary.json"
    summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    manifest = {
        "input_sha256": input_hashes,
        "source_script_sha256": sha256(Path(__file__)),
        "independent_verifier_sha256": sha256(ROOT / "experiments" / "verify_policy_differential.py"),
        "source_update_definition": "experiments/revision_policy_evolution.py::updated_policy",
        "output_sha256": {out_path.name: sha256(out_path), summary_path.name: sha256(summary_path)},
        "update_operations": list(operations),
        "candidate_selection": "first changed-decision suffix window in sorted frozen workload files and event order",
        "policy": "local_lab_adapter.lab_policy(version=1)",
        "horizon": HORIZON,
    }
    (OUT / "protocol_manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
