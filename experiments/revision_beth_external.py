"""Staged BETH external trace-policy evaluation.

The freeze stage reads only canonical training and validation splits plus source
hashes. The evaluation stage reads test predictors but never accesses test labels.
The labels stage is the only stage that joins test labels to frozen predictions.
Raw source files remain in their original directory and are never copied.
"""
from __future__ import annotations

import argparse
import csv
from collections import Counter, defaultdict
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import sqlite3
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
import trace_policy_engine as tpe

TRAIN = "labelled_training_data.csv"
VALIDATION = "labelled_validation_data.csv"
TEST = "labelled_testing_data.csv"
EXPECTED_TEST_SHA256 = "e56aad64df13b9dde7be2d333f1f6b7da7f41596cb9b4105deb0fd051900706b"
MIN_SUPPORT = 20
MAX_ALLOW_ACTIONS = 6
MAX_PREDECESSORS = 3
MAX_EXPLANATION_UNITS = 18
HORIZON = 2


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def json_sha(value) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def write_json(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True), encoding="utf-8")


def csv_rows(path: Path):
    with path.open("r", newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        required = {"timestamp", "processId", "parentProcessId", "processName",
                    "hostName", "eventName", "sus", "evil"}
        missing = required - set(reader.fieldnames or [])
        if missing:
            raise ValueError(f"{path.name}: required columns missing: {sorted(missing)}")
        for row_id, row in enumerate(reader):
            yield row_id, row


def make_event(row_id: int, row: dict) -> tpe.Event:
    # BETH timestamp is host-boot-relative seconds. Histories are partitioned by
    # host and process ID; eventName is preserved as the action token.
    return tpe.Event(
        eid=f"beth:{row.get('hostName','')}:{row_id}",
        ts=float(row["timestamp"]),
        action=row["eventName"],
        resource_class="host_syscall",
        subject_class="process",
        attrs={
            "host_name": row.get("hostName", ""),
            "process_id": str(row["processId"]),
            "parent_process_id": str(row["parentProcessId"]),
            "process_name": row.get("processName", ""),
            "source_row": row_id,
        },
    )


def freeze(data: Path, out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    train_path, val_path, test_path = data / TRAIN, data / VALIDATION, data / TEST
    for p in (train_path, val_path, test_path):
        if not p.is_file():
            raise FileNotFoundError(p)

    train_sha, val_sha = sha256(train_path), sha256(val_path)
    test_sha = sha256(test_path)
    if test_sha != EXPECTED_TEST_SHA256:
        raise ValueError("BETH test file SHA-256 differs from the feasibility-audit snapshot")

    # Label summary is restricted to training and validation. No test rows are
    # parsed in this stage. All non-evil training records define the candidate
    # allowlist, including the source's sus-but-not-evil records.
    action_counts = Counter()
    train_label_counts = Counter()
    train_host_counts = Counter()
    val_label_counts = Counter()
    val_hosts = set()
    ordering_db_path = out / "_beth_train_ordering.sqlite"
    if ordering_db_path.exists():
        ordering_db_path.unlink()
    ordering_db = sqlite3.connect(ordering_db_path)
    ordering_db.execute("CREATE TABLE events(row_id INTEGER, host TEXT, pid TEXT, ts REAL, action TEXT)")
    batch = []
    train_n = 0
    for row_id, row in csv_rows(train_path):
        train_n += 1
        sus, evil = int(row["sus"]), int(row["evil"])
        train_label_counts[(sus, evil)] += 1
        host = row["hostName"]
        train_host_counts[host] += 1
        if evil == 0:
            action = row["eventName"]
            action_counts[action] += 1
            batch.append((row_id, host, str(row["processId"]), float(row["timestamp"]), action))
            if len(batch) >= 20000:
                ordering_db.executemany("INSERT INTO events VALUES(?,?,?,?,?)", batch)
                batch.clear()
    if batch:
        ordering_db.executemany("INSERT INTO events VALUES(?,?,?,?,?)", batch)
    ordering_db.commit()
    ordering_db.execute("CREATE INDEX event_order ON events(host,pid,ts,row_id)")
    pair_counts = Counter()
    query = """WITH ordered AS (
        SELECT action, lag(action) OVER (PARTITION BY host,pid ORDER BY ts,row_id) AS prev
        FROM events
    ) SELECT action,prev,count(*) FROM ordered WHERE prev IS NOT NULL
      GROUP BY action,prev"""
    for action, prev, n in ordering_db.execute(query):
        pair_counts[(action, prev)] = int(n)
    ordering_db.close()
    ordering_db_path.unlink()

    for _, row in csv_rows(val_path):
        val_label_counts[(int(row["sus"]), int(row["evil"]))] += 1
        val_hosts.add(row["hostName"])

    allowed = [a for a, n in sorted(action_counts.items(), key=lambda x: (-x[1], x[0]))
               if n >= MIN_SUPPORT][:MAX_ALLOW_ACTIONS]
    if not allowed:
        raise ValueError("No BETH training actions meet the frozen support threshold")

    predecessors = {}
    for action in allowed:
        choices = [(prev, n) for (cur, prev), n in pair_counts.items()
                   if cur == action and n >= MIN_SUPPORT]
        predecessors[action] = [prev for prev, _ in sorted(choices,
                                                           key=lambda x: (-x[1], x[0]))[:MAX_PREDECESSORS]]

    def fallback():
        return tpe.Rule("D_UNSEEN", 0, tpe.DENY, tpe.Selector())

    p0 = tpe.PolicyVersion("BETH_P0_TRAIN_ACTION_ALLOWLIST", 1, tuple(
        [tpe.Rule(f"A{i}", 10, tpe.ALLOW,
                 tpe.Selector(action, "host_syscall", "process"))
         for i, action in enumerate(allowed)] + [fallback()]))
    p1_rules = []
    for i, action in enumerate(allowed):
        prevs = predecessors[action]
        if not prevs:
            continue
        guard = tpe.Guard(any_of=tuple(
            tpe.Guard(seq_actions=(prev, action), seq_horizon=HORIZON)
            for prev in prevs))
        p1_rules.append(tpe.Rule(f"A_SEQ{i}", 10, tpe.ALLOW,
                                 tpe.Selector(action, "host_syscall", "process"), guard))
    p1 = tpe.PolicyVersion("BETH_P1_TRAIN_SEQUENCE_ALLOWLIST", 1,
                           tuple(p1_rules + [fallback()]))

    protocol = {
        "dataset": "BETH Dataset (Highnam et al., 2021)",
        "source_files": {TRAIN: train_sha, VALIDATION: val_sha, TEST: test_sha},
        "source_path_is_local_external_read_only": True,
        "raw_data_copied": False,
        "test_label_aggregate_seen_during_prior_feasibility_audit": True,
        "test_decision_outcomes_or_explanation_cases_seen_before_freeze": False,
        "test_labels_used_for_policy_or_case_selection": False,
        "splits": {
            "train_rows": train_n,
            "train_hosts": dict(sorted(train_host_counts.items())),
            "validation_rows": sum(val_label_counts.values()),
            "validation_hosts": sorted(val_hosts),
            "test_host_count_from_prior_source_audit": 1,
        },
        "policy_construction": {
            "population": "BETH training rows with evil=0; sus labels retained, not used to rank actions",
            "action": "eventName",
            "stream_partition": "(hostName, processId)",
            "event_order": "per-host/process timestamp ascending; stable file row as tie breaker; train predecessor counts computed by SQL window sort",
            "minimum_action_support": MIN_SUPPORT,
            "maximum_allowed_actions": MAX_ALLOW_ACTIONS,
            "maximum_training_predecessors_per_action": MAX_PREDECESSORS,
            "predecessor_minimum_support": MIN_SUPPORT,
            "validation_role": "descriptive only; no threshold or policy selection",
            "P0": "allow the six highest-support training eventName actions; default DENY otherwise",
            "P1": "allow those actions only after one of their top three supported same-process predecessors; default DENY otherwise",
            "guard_horizon_events": HORIZON,
            "state_atoms": False,
        },
        "evaluation": {
            "test_file": TEST,
            "test_labels_opened_only_in_labels_stage": True,
            "positive_prediction": "Violation or Conflict; default deny fallback makes unknown/sequence-mismatched events violations",
            "explanation_sampling": "earliest 32 P1 alerts and earliest 32 P1-P0 alert-class differences, test labels not consulted",
            "explanation_horizon": HORIZON,
            "exact_unit_cap": MAX_EXPLANATION_UNITS,
        },
        "known_scope_limits": [
            "the canonical test split is one attack-bearing host",
            "the feasibility audit saw aggregate test labels, so this is frozen before scoring but not a fully blind or preregistered test",
            "BETH labels are source-provided event labels, not an independent adjudication of operational IDS alerts",
            "the BETH event vocabulary adapter is a declared mapping from eventName to action",
        ],
        "training_label_counts": {str(k): v for k, v in sorted(train_label_counts.items())},
        "validation_label_counts": {str(k): v for k, v in sorted(val_label_counts.items())},
        "training_action_counts": dict(sorted(action_counts.items())),
        "selected_actions": allowed,
        "selected_predecessors": predecessors,
        "policies": {"P0": asdict(p0), "P1": asdict(p1)},
    }
    protocol["protocol_sha256"] = json_sha(protocol)
    write_json(out / "frozen_protocol.json", protocol)
    print(json.dumps({"stage": "freeze", "protocol_sha256": protocol["protocol_sha256"],
                      "training_rows": train_n, "validation_rows": sum(val_label_counts.values()),
                      "selected_actions": allowed, "selected_predecessors": predecessors,
                      "P0_rules": len(p0.rules), "P1_rules": len(p1.rules),
                      "test_labels_used": False}, indent=2))


def guard_from_dict(g: dict) -> tpe.Guard:
    d = dict(g)
    for k in ("all_of", "any_of", "none_of"):
        d[k] = tuple(guard_from_dict(x) for x in d[k])
    for k in ("comparisons", "state_comparisons"):
        d[k] = tuple(tuple(x) for x in d[k])
    d["seq_actions"] = tuple(d["seq_actions"])
    return tpe.Guard(**d)


def load_policy(d: dict) -> tpe.PolicyVersion:
    return tpe.PolicyVersion(d["pid"], d["version"], tuple(
        tpe.Rule(r["rid"], r["priority"], r["effect"], tpe.Selector(**r["selector"]),
                 guard_from_dict(r["guard"])) for r in d["rules"]), d.get("created_at", 0.0))


def load_frozen(data: Path, out: Path):
    path = out / "frozen_protocol.json"
    if not path.is_file():
        raise FileNotFoundError("Run the freeze stage before this stage")
    frozen = json.loads(path.read_text(encoding="utf-8"))
    if {TRAIN: sha256(data / TRAIN), VALIDATION: sha256(data / VALIDATION),
        TEST: sha256(data / TEST)} != frozen["source_files"]:
        raise ValueError("BETH source files changed after policy freeze")
    protocol_copy = dict(frozen)
    recorded = protocol_copy.pop("protocol_sha256")
    if json_sha(protocol_copy) != recorded:
        raise ValueError("Frozen protocol checksum mismatch")
    return frozen


def evaluate(data: Path, out: Path) -> None:
    frozen = load_frozen(data, out)
    policies = {name: load_policy(frozen["policies"][name]) for name in ("P0", "P1")}
    increments = {name: {} for name in policies}
    histories = defaultdict(list)
    candidates = {"p1_alerts": [], "class_deltas": []}
    predictions = out / "predictions_without_labels.csv"
    divergences = Counter()
    counts = Counter()
    last_timestamp = {}
    start = time.perf_counter()
    with (data / TEST).open("r", newline="", encoding="utf-8-sig") as src, \
         predictions.open("w", newline="", encoding="utf-8") as dst:
        reader = csv.DictReader(src)
        writer = csv.DictWriter(dst, fieldnames=["row_id", "timestamp", "host_name", "process_id",
            "process_name", "event_name", "previous_action", "P0_class", "P0_top", "P1_class", "P1_top"])
        writer.writeheader()
        for row_id, row in enumerate(reader):
            actor = (row.get("hostName", ""), str(row["processId"]))
            event = make_event(row_id, row)
            if actor in last_timestamp and event.ts < last_timestamp[actor]:
                raise ValueError(f"test chronology inversion for actor {actor} at row {row_id}")
            last_timestamp[actor] = event.ts
            hist = histories[actor]
            hist.append(event)
            if len(hist) > HORIZON:
                del hist[:-HORIZON]
            decisions = {}
            for name, policy in policies.items():
                inc = increments[name].get(actor)
                if inc is None:
                    inc = increments[name][actor] = tpe.IncrementalEvaluator(
                        policy, retention_horizon=HORIZON)
                result = inc.push(event)
                ref = tpe.reference_eval(hist, policy)
                indexed = tpe.StaticIndex(policy).eval(hist)
                if (result.alert_class, result.top) != (ref.alert_class, ref.top):
                    divergences[(name, "incremental_vs_reference")] += 1
                if (result.alert_class, result.top) != (indexed.alert_class, indexed.top):
                    divergences[(name, "incremental_vs_indexed")] += 1
                decisions[name] = result
                counts[(name, result.alert_class)] += 1
            p0, p1 = decisions["P0"], decisions["P1"]
            record = {"row_id": row_id, "timestamp": row["timestamp"],
                      "host_name": row.get("hostName", ""), "process_id": row["processId"],
                      "process_name": row.get("processName", ""), "event_name": row["eventName"],
                      "previous_action": hist[-2].action if len(hist) > 1 else "",
                      "P0_class": p0.alert_class, "P0_top": ";".join(p0.top),
                      "P1_class": p1.alert_class, "P1_top": ";".join(p1.top)}
            writer.writerow(record)
            item = {"row_id": row_id, "actor": list(actor), "trace": [asdict(e) for e in hist],
                    "P0": asdict(p0), "P1": asdict(p1)}
            if p1.alert_class in (tpe.VIOLATION, tpe.CONFLICT) and len(candidates["p1_alerts"]) < 32:
                candidates["p1_alerts"].append(item)
            if p0.alert_class != p1.alert_class and len(candidates["class_deltas"]) < 32:
                candidates["class_deltas"].append(item)
            if row_id and row_id % 50000 == 0:
                print(f"scored {row_id:,} unlabeled test rows", flush=True)

    if any(divergences.values()):
        raise AssertionError(f"BETH evaluator disagreement: {dict(divergences)}")

    catalogs = {}
    for group, items in candidates.items():
        cases = []
        for item in items:
            trace = [tpe.Event(**e) for e in item["trace"]]
            for name in ("P0", "P1"):
                factual = item[name]["alert_class"]
                if factual not in (tpe.VIOLATION, tpe.CONFLICT, tpe.GAP):
                    continue
                explanation = tpe.min_explain_bruteforce(
                    trace, policies[name], horizon=HORIZON,
                    max_units=MAX_EXPLANATION_UNITS)
                selected = ({f"e:{i}" for i in explanation.event_positions}
                            | {f"r:{rid}" for rid in explanation.rule_ids})
                sufficient = tpe.exact_sufficiency_of_selected(
                    trace, policies[name], selected, horizon=HORIZON,
                    max_units=MAX_EXPLANATION_UNITS)
                if sufficient is not True:
                    raise AssertionError("independent full-domain sufficiency check failed")
                deletion_checks = {}
                for unit in sorted(selected):
                    remains_sufficient = tpe.exact_sufficiency_of_selected(
                        trace, policies[name], selected - {unit}, horizon=HORIZON,
                        max_units=MAX_EXPLANATION_UNITS)
                    if remains_sufficient is not False:
                        raise AssertionError(f"independent minimality check failed for {unit}")
                    deletion_checks[unit] = "counterexample exists"
                cases.append({"row_id": item["row_id"], "stratum": group, "policy": name,
                    "target_class": explanation.target_class,
                    "trace": item["trace"], "horizon": HORIZON,
                    "unit_count": explanation.unit_count,
                    "event_positions": list(explanation.event_positions),
                    "rule_ids": list(explanation.rule_ids),
                    "witnesses": explanation.witnesses,
                    "checks": explanation.checks,
                    "independent_sufficiency_check": True,
                    "independent_deletion_checks": deletion_checks,
                    "sufficient": True, "inclusion_minimal": True,
                    "source_labels_consulted": False})
        catalogs[group] = cases

    result = {
        "protocol_sha256": frozen["protocol_sha256"],
        "source_sha256": frozen["source_files"],
        "test_rows_scored_without_label_access": sum(counts["P0", c] for c in
            (tpe.NOALERT, tpe.VIOLATION, tpe.CONFLICT, tpe.GAP)),
        "test_predictions_sha256": sha256(predictions),
        "decision_class_counts": {f"{n}:{c}": k for (n, c), k in sorted(counts.items())},
        "reference_index_incremental_divergences": dict(divergences),
        "explanation_catalogs": {k: {"cases": len(v), "file": f"{k}_explanations.json"}
                                  for k, v in catalogs.items()},
        "test_labels_opened": False,
        "elapsed_seconds": time.perf_counter() - start,
    }
    for group, cases in catalogs.items():
        write_json(out / f"{group}_explanations.json", {
            "protocol_sha256": frozen["protocol_sha256"], "sampling": group,
            "cases": cases, "labels_consulted": False})
    write_json(out / "semantic_evaluation.json", result)
    print(json.dumps(result, indent=2))


def metrics(rows, pred_key, truth_key):
    tp = sum(bool(r[pred_key]) and bool(r[truth_key]) for r in rows)
    fp = sum(bool(r[pred_key]) and not bool(r[truth_key]) for r in rows)
    fn = sum(not bool(r[pred_key]) and bool(r[truth_key]) for r in rows)
    tn = sum(not bool(r[pred_key]) and not bool(r[truth_key]) for r in rows)
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": tp / (tp + fp) if tp + fp else 0.0,
            "recall": tp / (tp + fn) if tp + fn else 0.0,
            "f1": 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else 0.0,
            "fpr": fp / (fp + tn) if fp + tn else 0.0}


def score_labels(data: Path, out: Path) -> None:
    frozen = load_frozen(data, out)
    semantic_path = out / "semantic_evaluation.json"
    pred_path = out / "predictions_without_labels.csv"
    if not semantic_path.is_file() or not pred_path.is_file():
        raise FileNotFoundError("Complete evaluate stage before opening test labels")
    semantic = json.loads(semantic_path.read_text(encoding="utf-8"))
    if semantic["protocol_sha256"] != frozen["protocol_sha256"] or semantic["test_labels_opened"]:
        raise ValueError("Semantic evaluation is not bound to this frozen label-free run")
    if sha256(pred_path) != semantic["test_predictions_sha256"]:
        raise ValueError("Prediction file changed after label-free evaluation")

    preds = {}
    with pred_path.open("r", newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            preds[int(r["row_id"])] = r
    counts = Counter()
    labels_by_row = {}
    outcomes = {"evil": {"P0": [], "P1": []}, "sus": {"P0": [], "P1": []}}
    by_action = defaultdict(lambda: {"P0": [], "P1": []})
    with (data / TEST).open("r", newline="", encoding="utf-8-sig") as f:
        for row_id, row in enumerate(csv.DictReader(f)):
            if row_id not in preds:
                raise ValueError(f"Missing frozen prediction for test row {row_id}")
            sus, evil = int(row["sus"]), int(row["evil"])
            counts[(sus, evil)] += 1
            labels_by_row[row_id] = {"sus": sus, "evil": evil}
            p = preds[row_id]
            for name in ("P0", "P1"):
                predicted = p[f"{name}_class"] in (tpe.VIOLATION, tpe.CONFLICT)
                outcomes["evil"][name].append({"pred": predicted, "truth": evil == 1})
                outcomes["sus"][name].append({"pred": predicted, "truth": sus == 1})
                by_action[row["eventName"]][name].append(
                    {"pred": predicted, "truth": evil == 1})

    metrics_out = {label: {name: metrics(rows, "pred", "truth")
                           for name, rows in by_policy.items()}
                   for label, by_policy in outcomes.items()}
    action_metrics = {}
    for action, policy_rows in by_action.items():
        action_metrics[action] = {
            "rows": len(policy_rows["P0"]),
            "evil_rows": sum(bool(r["truth"]) for r in policy_rows["P0"]),
            "evil_prevalence": (sum(bool(r["truth"]) for r in policy_rows["P0"])
                                / len(policy_rows["P0"])),
            "P0_alert_rate": sum(bool(r["pred"]) for r in policy_rows["P0"])
                             / len(policy_rows["P0"]),
            "P1_alert_rate": sum(bool(r["pred"]) for r in policy_rows["P1"])
                             / len(policy_rows["P1"]),
            "P0_evil_confusion": metrics(policy_rows["P0"], "pred", "truth"),
            "P1_evil_confusion": metrics(policy_rows["P1"], "pred", "truth"),
        }
    result = {
        "protocol_sha256": frozen["protocol_sha256"],
        "source_sha256": frozen["source_files"],
        "test_rows": len(preds),
        "test_label_counts": {str(k): v for k, v in sorted(counts.items())},
        "metrics_by_label_unit": metrics_out,
        "metrics_by_event_name_evil": action_metrics,
        "pre_scoring_aggregate_labels_seen": True,
        "labels_used_for_policy_or_explanation_sampling": False,
        "warning": "Single held-out host and attack-heavy test partition; metrics are source-label proxies, not operational IDS prevalence estimates.",
    }
    for group in ("p1_alerts", "class_deltas"):
        cpath = out / f"{group}_explanations.json"
        cat = json.loads(cpath.read_text(encoding="utf-8"))
        for case in cat["cases"]:
            row_id = int(case["row_id"])
            # Record label only after the frozen explanation is complete.
            case["source_label"] = labels_by_row[row_id]
        write_json(cpath, cat)
    write_json(out / "label_metrics.json", result)
    print(json.dumps(result, indent=2))


def verify(data: Path, out: Path) -> None:
    frozen = load_frozen(data, out)
    semantic = json.loads((out / "semantic_evaluation.json").read_text(encoding="utf-8"))
    labels = json.loads((out / "label_metrics.json").read_text(encoding="utf-8"))
    if semantic["protocol_sha256"] != frozen["protocol_sha256"]:
        raise ValueError("Semantic output policy identifier mismatch")
    if semantic["test_labels_opened"]:
        raise ValueError("Label-free evaluation claims test-label access")
    if semantic["reference_index_incremental_divergences"]:
        raise ValueError("Nonzero evaluator divergences")
    if labels["protocol_sha256"] != frozen["protocol_sha256"]:
        raise ValueError("Label metrics policy identifier mismatch")
    for name in ("P0", "P1"):
        n = sum(labels["metrics_by_label_unit"]["evil"][name][k]
                for k in ("tp", "fp", "fn", "tn"))
        if n != labels["test_rows"]:
            raise ValueError(f"{name} confusion matrix does not cover all test rows")
    checked_explanations = {}
    for group in ("p1_alerts", "class_deltas"):
        cat = json.loads((out / f"{group}_explanations.json").read_text(encoding="utf-8"))
        for case in cat["cases"]:
            if not case.get("independent_sufficiency_check"):
                raise ValueError(f"{group}: missing independent sufficiency check")
            n_units = len(case["event_positions"]) + len(case["rule_ids"])
            if len(case.get("independent_deletion_checks", {})) != n_units:
                raise ValueError(f"{group}: incomplete independent deletion checks")
            if "source_label" not in case:
                raise ValueError(f"{group}: case labels were not joined after scoring")
        checked_explanations[group] = len(cat["cases"])
    summary = {"verified": True, "protocol_sha256": frozen["protocol_sha256"],
               "test_rows": labels["test_rows"],
               "reference_index_incremental_divergences": 0,
               "independently_checked_explanations": checked_explanations,
               "confusion_matrices_cover_all_rows": True}
    write_json(out / "verification.json", summary)
    print(json.dumps(summary, indent=2))


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("stage", choices=("freeze", "evaluate", "labels", "verify"))
    p.add_argument("--data-dir", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    {"freeze": freeze, "evaluate": evaluate, "labels": score_labels, "verify": verify}[a.stage](
        a.data_dir, a.output)


if __name__ == "__main__":
    main()
