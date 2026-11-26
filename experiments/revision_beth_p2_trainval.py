"""Train/validation-only BETH temporal policy development.

This program reads only the canonical training and validation CSV files. It
does not open, hash, or inspect the BETH test partition. P2 targets the source
label `sus`; `evil` is reported separately and is not used in rule induction.
"""
from __future__ import annotations

import csv
from collections import Counter, defaultdict
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import sqlite3
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
import trace_policy_engine as tpe

TRAIN = "labelled_training_data.csv"
VALIDATION = "labelled_validation_data.csv"
MAX_ALLOW_ACTIONS = 6
ALLOW_SUPPORT = 20
PAIR_TOTAL_MIN_PER_SPLIT = 5
PAIR_TOTAL_MIN_COMBINED = 20
PAIR_LABEL_MIN = 3
PAIR_PREVALENCE_MIN = 0.20
HORIZON = 2


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def rows(path: Path):
    with path.open("r", newline="", encoding="utf-8-sig") as f:
        for i, row in enumerate(csv.DictReader(f)):
            yield i, row


def metrics(cm: Counter) -> dict:
    tp, fp, fn, tn = (cm[k] for k in ("tp", "fp", "fn", "tn"))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    return {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": precision, "recall": recall,
        "f1": 2 * precision * recall / (precision + recall)
        if precision + recall else 0.0,
        "fpr": fp / (fp + tn) if fp + tn else 0.0,
    }


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    train_path, val_path = args.data_dir / TRAIN, args.data_dir / VALIDATION
    if not train_path.is_file() or not val_path.is_file():
        raise FileNotFoundError("Canonical BETH train and validation CSVs are required")

    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE e(split TEXT, row_id INTEGER, host TEXT, pid TEXT, ts REAL, action TEXT, sus INTEGER, evil INTEGER)")
    split_counts = Counter()
    label_counts = {"train": Counter(), "validation": Counter()}
    action_support = Counter()
    for split, path in (("train", train_path), ("validation", val_path)):
        batch = []
        for row_id, r in rows(path):
            sus, evil = int(r["sus"]), int(r["evil"])
            batch.append((split, row_id, r["hostName"], str(r["processId"]),
                          float(r["timestamp"]), r["eventName"], sus, evil))
            split_counts[split] += 1
            label_counts[split][(sus, evil)] += 1
            if split == "train" and evil == 0:
                action_support[r["eventName"]] += 1
            if len(batch) >= 20000:
                db.executemany("INSERT INTO e VALUES(?,?,?,?,?,?,?,?)", batch)
                batch.clear()
        if batch:
            db.executemany("INSERT INTO e VALUES(?,?,?,?,?,?,?,?)", batch)
    db.execute("CREATE INDEX event_order ON e(split,host,pid,ts,row_id)")

    allowed = [a for a, n in sorted(action_support.items(), key=lambda x: (-x[1], x[0]))
               if n >= ALLOW_SUPPORT][:MAX_ALLOW_ACTIONS]
    pair_counts = {"train": Counter(), "validation": Counter()}
    query = """WITH ordered AS (
      SELECT split,action,sus,
        lag(action) OVER (PARTITION BY split,host,pid ORDER BY ts,row_id) AS prev
      FROM e
    ) SELECT split,prev,action,count(*),sum(sus) FROM ordered
      WHERE prev IS NOT NULL GROUP BY split,prev,action"""
    for split, prev, action, n, n_sus in db.execute(query):
        pair_counts[split][(prev, action)] = (int(n), int(n_sus))

    # Frozen development rule: use a current action already accepted by the
    # training-only P0 baseline; require repeated suspicious examples and an
    # elevated sus fraction in both independent partitions. Validation chooses
    # the rule set, so validation performance is reported as development fit,
    # not as an untouched generalization estimate.
    candidates = []
    all_pairs = set(pair_counts["train"]) & set(pair_counts["validation"])
    for prev, action in all_pairs:
        if action not in allowed:
            continue
        tr_n, tr_s = pair_counts["train"][(prev, action)]
        va_n, va_s = pair_counts["validation"][(prev, action)]
        if (tr_n >= PAIR_TOTAL_MIN_PER_SPLIT
                and va_n >= PAIR_TOTAL_MIN_PER_SPLIT
                and tr_n + va_n >= PAIR_TOTAL_MIN_COMBINED
                and tr_s >= PAIR_LABEL_MIN and va_s >= PAIR_LABEL_MIN
                and tr_s / tr_n >= PAIR_PREVALENCE_MIN
                and va_s / va_n >= PAIR_PREVALENCE_MIN):
            candidates.append({
                "previous_action": prev, "current_action": action,
                "train_total": tr_n, "train_sus": tr_s,
                "train_sus_fraction": tr_s / tr_n,
                "validation_total": va_n, "validation_sus": va_s,
                "validation_sus_fraction": va_s / va_n,
            })
    candidates.sort(key=lambda x: (x["current_action"], x["previous_action"]))

    rules = [tpe.Rule(f"A{i}", 10, tpe.ALLOW,
                      tpe.Selector(a, "host_syscall", "process"))
             for i, a in enumerate(allowed)]
    for i, c in enumerate(candidates):
        rules.append(tpe.Rule(
            f"D_SUS_SEQ{i}", 100, tpe.DENY,
            tpe.Selector(c["current_action"], "host_syscall", "process"),
            tpe.Guard(seq_actions=(c["previous_action"], c["current_action"]),
                      seq_horizon=HORIZON)))
    rules.append(tpe.Rule("D_UNSEEN", 0, tpe.DENY, tpe.Selector()))
    p2 = tpe.PolicyVersion("BETH_P2_SUS_SEQUENCE_DENY", 1, tuple(rules))
    p0 = tpe.PolicyVersion("BETH_P0_TRAIN_ACTION_ALLOWLIST", 1, tuple(
        [tpe.Rule(f"A{i}", 10, tpe.ALLOW,
                 tpe.Selector(a, "host_syscall", "process"))
         for i, a in enumerate(allowed)] +
        [tpe.Rule("D_UNSEEN", 0, tpe.DENY, tpe.Selector())]))

    # Validation replay only; events are sorted actor-locally by source time.
    policies = {"P0": p0, "P2": p2}
    matrices = {lab: {name: Counter() for name in policies}
                for lab in ("sus", "evil")}
    sequence_fires = []
    divergences = 0
    for host, pid in db.execute("SELECT DISTINCT host,pid FROM e WHERE split='validation'"):
        trace = []
        for row_id, ts, action, sus, evil in db.execute(
                "SELECT row_id,ts,action,sus,evil FROM e WHERE split='validation' AND host=? AND pid=? ORDER BY ts,row_id",
                (host, pid)):
            event = tpe.Event(f"beth-val:{host}:{row_id}", ts, action,
                              "host_syscall", "process",
                              {"host_name": host, "process_id": pid})
            trace.append(event)
            if len(trace) > HORIZON:
                trace = trace[-HORIZON:]
            for name, policy in policies.items():
                ref = tpe.reference_eval(trace, policy)
                idx = tpe.StaticIndex(policy).eval(trace)
                if (ref.alert_class, ref.top) != (idx.alert_class, idx.top):
                    divergences += 1
                pred = ref.alert_class in (tpe.VIOLATION, tpe.CONFLICT)
                for lab, truth in (("sus", bool(sus)), ("evil", bool(evil))):
                    if pred and truth: key = "tp"
                    elif pred: key = "fp"
                    elif truth: key = "fn"
                    else: key = "tn"
                    matrices[lab][name][key] += 1
                if name == "P2" and ref.alert_class == tpe.VIOLATION and any(
                        rid.startswith("D_SUS_SEQ") for rid in ref.top):
                    sequence_fires.append({"row_id": row_id, "host": host,
                                           "process_id": pid, "action": action,
                                           "sus": sus, "evil": evil,
                                           "trace": [asdict(e) for e in trace]})
    explanations = []
    for case in sequence_fires:
        trace = [tpe.Event(**e) for e in case["trace"]]
        explanation = tpe.min_explain_bruteforce(trace, p2, horizon=HORIZON,
                                                 max_units=18)
        explanations.append({"row_id": case["row_id"], "sus": case["sus"],
                             "evil": case["evil"],
                             "explanation": asdict(explanation)})

    protocol = {
        "dataset": "BETH canonical training/validation only",
        "training_sha256": digest(train_path),
        "validation_sha256": digest(val_path),
        "test_partition_accessed": False,
        "test_partition_hashed_or_opened": False,
        "objective": "Detect the source label sus using a train/validation-supported same-process predecessor rule; report evil separately and do not infer evil from sus.",
        "label_counts": {s: {str(k): v for k, v in sorted(label_counts[s].items())}
                         for s in label_counts},
        "policy_construction": {
            "base_actions": allowed,
            "base_support_threshold": ALLOW_SUPPORT,
            "candidate_sequence_rule": "DENY current action when immediately preceded by the specified event within the same host/process trace; priority 100 overrides base ALLOW priority 10.",
            "selection_criteria": {
                "current_action_must_be_in_training_base_allowlist": True,
                "minimum_pair_rows_per_split": PAIR_TOTAL_MIN_PER_SPLIT,
                "minimum_pair_rows_combined": PAIR_TOTAL_MIN_COMBINED,
                "minimum_sus_rows_per_split": PAIR_LABEL_MIN,
                "minimum_sus_fraction_each_split": PAIR_PREVALENCE_MIN,
                "sequence_horizon": HORIZON,
                "rule_candidates": "intersection of pairs observed in both training and validation",
            },
            "selected_pairs": candidates,
            "rules": [asdict(r) for r in p2.rules],
            "policy_sha256": hashlib.sha256(json.dumps(
                [asdict(r) for r in p2.rules], sort_keys=True,
                separators=(",", ":")).encode()).hexdigest(),
        },
        "validation_development_metrics": {
            lab: {name: metrics(cm) for name, cm in by_policy.items()}
            for lab, by_policy in matrices.items()},
        "validation_sequence_fires": sequence_fires,
        "validation_sequence_fire_explanations": explanations,
        "reference_index_divergences": divergences,
        "interpretation": "Validation labels were part of policy selection, so the reported validation metrics are development fit, not an untouched estimate. Test labels and predictors were not accessed by this run.",
    }
    args.output.mkdir(parents=True, exist_ok=True)
    protocol["protocol_sha256"] = hashlib.sha256(json.dumps(
        protocol, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    (args.output / "p2_trainval_protocol.json").write_text(
        json.dumps(protocol, indent=2), encoding="utf-8")
    print(json.dumps({
        "selected_pairs": candidates,
        "validation_sus_metrics": protocol["validation_development_metrics"]["sus"],
        "validation_evil_metrics": protocol["validation_development_metrics"]["evil"],
        "sequence_fires": len(sequence_fires),
        "explanations": len(explanations),
        "reference_index_divergences": divergences,
        "test_partition_accessed": False,
    }, indent=2))


if __name__ == "__main__":
    main()
