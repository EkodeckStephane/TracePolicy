"""Verify hashes and internal consistency of the four-way union ablation."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "results" / "revision" / "joint_union_ablation_v1"


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def main() -> None:
    manifest = json.loads((OUT / "protocol_manifest.json").read_text(encoding="utf-8"))
    summary = json.loads((OUT / "summary.json").read_text(encoding="utf-8"))
    rows = json.loads((OUT / "case_results.json").read_text(encoding="utf-8"))

    script = ROOT / "experiments" / manifest["generator_script"]
    assert sha256(script) == manifest["generator_sha256"]
    base_script = ROOT / "experiments" / "revision_joint_ablation.py"
    assert sha256(base_script) == manifest["base_script_sha256"]
    for name, expected in manifest["outputs_sha256"].items():
        assert sha256(OUT / name) == expected, name
    for name, expected in manifest["input_sha256"].items():
        assert sha256(ROOT / "local_lab" / "results" / name) == expected, name

    totals = {}
    for source, group in summary["groups"].items():
        source_rows = [r for r in rows if r["source"] == source]
        assert len(source_rows) == group["cases"], source
        unions = [u for r in source_rows for u in r["unions"]]
        assert len(unions) == group["union_candidates"], source
        assert sum(u["sufficient"] is True for u in unions) == group["sufficient_unions"], source
        assert sum(u["sufficient"] is False for u in unions) == group["insufficient_unions"], source
        for row in source_rows:
            for union in row["unions"]:
                if union["sufficient"]:
                    assert union["counterexample"] is None if "counterexample" in union else True
                    assert union["inclusion_minimal"] or not union["equals_joint_minimal_core"]
                else:
                    witness = union["counterexample"]
                    assert witness and witness["resulting_class"] != witness["target_class"]
                    assert all(witness["assignment"][unit] == 1 for unit in union["union"])
                if union["equals_joint_minimal_core"]:
                    assert union["sufficient"] and union["inclusion_minimal"]
        totals[source] = {"cases": len(source_rows), "unions": len(unions),
                          "sufficient": group["sufficient_unions"],
                          "insufficient": group["insufficient_unions"]}

    witness = summary["groups"]["constructed_semantic_witness"]
    assert witness["union_candidates"] == 4
    assert witness["sufficient_unions"] == 2 and witness["insufficient_unions"] == 2
    print(json.dumps({"verified": True, "groups": totals}, indent=2))


if __name__ == "__main__":
    main()
