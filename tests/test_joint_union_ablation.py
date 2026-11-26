from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "experiments")]

from revision_union_ablation import composability_counterexample


def test_crossed_separate_cores_can_fail_joint_sufficiency():
    result = composability_counterexample()
    assert result["event_core_count"] == 2
    assert result["rule_core_count"] == 2
    assert result["joint_core_count"] == 2
    assert result["all_unions_sufficient"] is False
    assert result["some_union_sufficient"] is True
    assert sum(u["sufficient"] is False for u in result["unions"]) == 2
    assert all(u["counterexample"] for u in result["unions"] if not u["sufficient"])
    assert sum(u["equals_joint_minimal_core"] for u in result["unions"]) == 2
