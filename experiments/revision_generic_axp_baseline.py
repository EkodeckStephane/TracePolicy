"""Independent algorithmic baseline for the frozen paired-explanation pilot.

The evaluator and three factual representative windows are shared with the
existing pilot. The AXp algorithm is different: it builds one hitting-set
constraint from each non-target assignment and enumerates minimal hitting
sets. This checks the generic AXp reduction and complete explanation families;
it is not an independent semantic oracle or a novelty test.
"""
from __future__ import annotations

import hashlib
import itertools
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "experiments")]
from verify_policy_differential import (  # noqa: E402
    RESULT, find_representatives, make_truth_table,
)

OUT = ROOT / "results" / "revision" / "generic_axp_baseline_v1"


def minimal_hitting_sets(constraints: list[frozenset[int]]) -> list[frozenset[int]]:
    """Enumerate all inclusion-minimal hitting sets for finite constraints."""
    if any(not clause for clause in constraints):
        return []
    width = max((max(clause) for clause in constraints if clause), default=-1) + 1
    solutions: list[frozenset[int]] = []
    for size in range(width + 1):
        for indices in itertools.combinations(range(width), size):
            candidate = frozenset(indices)
            if all(candidate & clause for clause in constraints) and not any(
                prior < candidate for prior in solutions
            ):
                solutions.append(candidate)
    return solutions


def generic_axps(table, target):
    # A non-target completion contradicts the target whenever all its zero
    # coordinates are omitted from the retained factual literals. Hence every
    # AXp must hit that zero-coordinate set.
    conflicts = [
        frozenset(i for i, bit in enumerate(assignment) if bit == 0)
        for assignment, output in table.items()
        if output != target
    ]
    return minimal_hitting_sets(conflicts), conflicts


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    report = json.loads(RESULT.read_text(encoding="utf-8"))
    base, variants, representatives = find_representatives()
    rows = []
    for row in report:
        op = row["operation"]
        seed, index, event_id, trace, old, new = representatives[op]
        if (row["seed"], row["event_index"], row["event_id"]) != (seed, index, event_id):
            raise AssertionError(f"frozen representative mismatch for {op}")
        table = make_truth_table(trace, base, variants[op])
        target = (old, new)
        axps, conflicts = generic_axps(table, target)
        units = row["units"]
        stored = {
            frozenset(units.index(name) for name in item["core"])
            for item in row["minimal_paired_explanation_family"]
        }
        if set(axps) != stored:
            raise AssertionError(f"AXp family mismatch for {op}: {axps} != {stored}")
        rows.append({
            "operation": op,
            "factual_pair": list(target),
            "assignments": len(table),
            "non_target_conflicts": len(conflicts),
            "minimal_hitting_sets": [
                [units[i] for i in sorted(axp)] for axp in axps
            ],
            "matches_tracepolicy_complete_family": True,
        })

    output = {
        "cases": rows,
        "all_complete_families_match": True,
        "algorithm": "generic AXp as minimal hitting sets of non-target completion conflicts",
        "limitations": [
            "Shares the frozen reference evaluator, intervention semantics, and representative selection.",
            "This is an algorithmic baseline check, not an independent semantic oracle.",
            "Exact agreement confirms the generic AXp reduction; it does not establish novelty or utility.",
            "No native Margrave execution is included.",
        ],
    }
    result_path = OUT / "generic_axp_results.json"
    result_path.write_text(json.dumps(output, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    manifest = {
        "input_pilot_sha256": sha256(RESULT),
        "script_sha256": sha256(Path(__file__)),
        "source_verifier_sha256": sha256(ROOT / "experiments" / "verify_policy_differential.py"),
        "result_sha256": sha256(result_path),
        "cases": len(rows),
        "output": result_path.relative_to(ROOT).as_posix(),
    }
    (OUT / "protocol_manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    print(json.dumps(output, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
