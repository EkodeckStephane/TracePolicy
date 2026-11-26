"""Staged LID-DS 2021 evaluation for CVE-2020-23839.

The source is the author's outer ZIP containing the official recording ZIPs.
Stages are deliberately separated: freeze reads train/validation only;
evaluate reads test .sc streams only; labels opens test JSON only after frozen
predictions have been hashed. No raw dataset members are written to disk.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import time
import zipfile

SCRIPT_PATH = Path(__file__).resolve()
# Support both the internal `code/experiments` layout and the public
# repository's top-level `experiments` layout.
ROOT = SCRIPT_PATH.parents[2] if SCRIPT_PATH.parent.parent.name == "code" else SCRIPT_PATH.parents[1]
OUTER_DEFAULT = ROOT / "data" / "CVE-2020-23839.zip"
MANIFEST_DEFAULT = ROOT / "results/lidds_cve_2020_23839/archive_manifest.json"
OUT_DEFAULT = ROOT / "results/lidds_cve_2020_23839"
ALERT_BUDGET = 0.01
ALLOWLIST_GRID = (6, 12, 24, 48, 96, 192, 384, 10**9)
PREDECESSOR_GRID = (0, 1, 3, 5)
HORIZON = 2
BENCH_ACTIONS = ("close", "openat", "security_file_open", "fstat", "stat", "access")
BENCH_PREDECESSORS = {
    "access": ("access", "close", "unlink"),
    "close": ("openat", "fstat", "close"),
    "fstat": ("openat", "fstat", "close"),
    "openat": ("security_file_open", "close", "openat"),
    "security_file_open": ("close", "stat", "lstat"),
    "stat": ("close", "stat", "fstat"),
}


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(8 * 1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def json_hash(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


def write_json(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")


def recording_entries(outer: zipfile.ZipFile, split: str):
    result = []
    for info in outer.infolist():
        if not info.filename.lower().endswith(".zip") or info.filename.startswith("__MACOSX/"):
            continue
        parts = PurePosixPath(info.filename).parts
        if split in ("training", "validation") and len(parts) == 3 and parts[:2] == ("CVE-2020-23839", split):
            result.append(info)
        elif split == "test" and len(parts) == 4 and parts[:2] == ("CVE-2020-23839", "test"):
            result.append(info)
    return sorted(result, key=lambda i: i.filename)


def nested_recording(outer: zipfile.ZipFile, info: zipfile.ZipInfo):
    raw = outer.read(info)
    return raw, zipfile.ZipFile(io.BytesIO(raw))


def label_from_metadata(meta: dict) -> str:
    normal = any(c.get("role") == "normal" for c in meta.get("container", []))
    exploit = bool(meta.get("exploit"))
    if normal and exploit:
        return "NORMAL_AND_ATTACK"
    if normal:
        return "NORMAL"
    if exploit:
        return "ATTACK"
    return "IDLE"


def metadata(z: zipfile.ZipFile, info: zipfile.ZipInfo) -> dict:
    stem = PurePosixPath(info.filename).stem
    return json.loads(z.read(stem + ".json").decode("utf-8"))


def syscall_events(z: zipfile.ZipFile, info: zipfile.ZipInfo):
    """Yield (<) events in line order and return data-quality counters."""
    stem = PurePosixPath(info.filename).stem
    counts = Counter()
    previous_ts = None
    line_no = 0
    event_count = 0
    thread_last = {}
    # Matching is diagnostic only: every valid syscall exit is retained once.
    pending = Counter()
    with z.open(stem + ".sc") as stream:
        for raw in stream:
            line_no += 1
            try:
                parts = raw.decode("utf-8").rstrip("\r\n").split(" ", 7)
                if len(parts) < 7:
                    raise ValueError("short line")
                ts, pid, tid = int(parts[0]), int(parts[2]), int(parts[4])
                action, direction = parts[5], parts[6]
                if direction not in (">", "<") or not action:
                    raise ValueError("invalid direction or syscall")
                if previous_ts is not None and ts < previous_ts:
                    counts["timestamp_inversions"] += 1
                if previous_ts == ts:
                    counts["adjacent_timestamp_ties"] += 1
                previous_ts = ts
                key = (pid, tid, action)
                if direction == ">":
                    pending[key] += 1
                    counts["entry_lines"] += 1
                    continue
                counts["exit_lines"] += 1
                event_count += 1
                if pending[key]:
                    pending[key] -= 1
                else:
                    counts["unpaired_exit_lines"] += 1
                actor = (pid, tid)
                prev = thread_last.get(actor)
                thread_last[actor] = action
                yield (action, prev, ts, pid, tid)
            except (UnicodeDecodeError, ValueError, IndexError, OverflowError):
                counts["malformed_lines"] += 1
    counts["unpaired_entry_lines"] = sum(pending.values())
    counts["line_count"] = line_no
    counts["completed_exit_count"] = event_count
    return counts


def scan_recording(outer: zipfile.ZipFile, info: zipfile.ZipInfo, action_counts=None,
                   pair_counts=None, policies=None):
    raw, rec = nested_recording(outer, info)
    stem = PurePosixPath(info.filename).stem
    event_count = 0
    alert_counts = Counter()
    first_alert_ns = {}
    thread_last = {}
    pending = Counter()
    quality = Counter()
    previous_ts = None
    line_count = 0
    with rec.open(stem + ".sc") as stream:
        for raw_line in stream:
            line_count += 1
            try:
                p = raw_line.decode("utf-8").rstrip("\r\n").split(" ", 7)
                if len(p) < 7:
                    raise ValueError
                ts, pid, tid = int(p[0]), int(p[2]), int(p[4])
                action, direction = p[5], p[6]
                if direction not in (">", "<") or not action:
                    raise ValueError
            except (UnicodeDecodeError, ValueError, IndexError, OverflowError):
                quality["malformed_lines"] += 1
                continue
            if previous_ts is not None and ts < previous_ts:
                quality["timestamp_inversions"] += 1
            if previous_ts == ts:
                quality["adjacent_timestamp_ties"] += 1
            previous_ts = ts
            key = (pid, tid, action)
            if direction == ">":
                pending[key] += 1
                quality["entry_lines"] += 1
                continue
            quality["exit_lines"] += 1
            if pending[key]:
                pending[key] -= 1
            else:
                quality["unpaired_exit_lines"] += 1
            event_count += 1
            actor = (pid, tid)
            prev = thread_last.get(actor)
            thread_last[actor] = action
            if action_counts is not None:
                action_counts[action] += 1
            if pair_counts is not None and prev is not None:
                pair_counts[(prev, action)] += 1
            if policies:
                for policy_name, policy in policies.items():
                    allowed = policy["allowed"]
                    if policy["predecessors"] is None:
                        accepted = action in allowed
                    else:
                        accepted = action in allowed and prev in policy["predecessors"].get(action, ())
                    if not accepted:
                        alert_counts[policy_name] += 1
                        first_alert_ns.setdefault(policy_name, ts)
    quality["unpaired_entry_lines"] = sum(pending.values())
    quality["line_count"] = line_count
    quality["completed_exit_count"] = event_count
    return {"recording": stem, "path": info.filename, "bytes": info.file_size,
            "sha256": sha256_bytes(raw), "events": event_count,
            "alert_events": dict(alert_counts), "first_alert_ns": first_alert_ns,
            "quality": dict(quality)}


def policy_for(action_counts: Counter, pair_counts: Counter, n: int, k: int):
    ranked = [a for a, count in sorted(action_counts.items(), key=lambda x: (-x[1], x[0])) if count >= 20]
    allowed = ranked[:n]
    prevs = None
    if k:
        prevs = {}
        for action in allowed:
            candidates = [(prev, count) for (prev, cur), count in pair_counts.items()
                          if cur == action and count >= 20]
            prevs[action] = tuple(prev for prev, _ in sorted(candidates, key=lambda x: (-x[1], x[0]))[:k])
    return {"allowed": tuple(allowed), "predecessors": prevs,
            "n_actions": len(allowed), "k_predecessors": k,
            "rule_count": len(allowed) + sum(len(v) for v in (prevs or {}).values()) + 1}


def scan_split(outer, split, selector=None, action_counts=None, pair_counts=None, policies=None):
    rows = []
    totals = Counter()
    hours = 0.0
    labels = Counter()
    for info in recording_entries(outer, split):
        _, rec = nested_recording(outer, info)
        meta = metadata(rec, info)
        label = label_from_metadata(meta)
        labels[label] += 1
        if selector and label not in selector:
            continue
        row = scan_recording(outer, info, action_counts, pair_counts, policies)
        row["label"] = label
        row["recording_seconds"] = float(meta.get("recording_time", 0) or 0)
        hours += row["recording_seconds"] / 3600
        totals["events"] += row["events"]
        for name, n in row["alert_events"].items():
            totals[f"alerts:{name}"] += n
        for name, n in row["quality"].items():
            totals[f"quality:{name}"] += n
        rows.append(row)
    return rows, {"recordings_by_type": dict(labels), "selected_recordings": len(rows),
                  "events": totals["events"], "recording_hours": hours,
                  "alert_events": {key.split(":", 1)[1]: value for key, value in totals.items() if key.startswith("alerts:")},
                  "quality": {key.split(":", 1)[1]: value for key, value in totals.items() if key.startswith("quality:")}}


def select_operating_points(action_counts, pair_counts, validation_rows):
    total = sum(r["events"] for r in validation_rows)
    if total == 0:
        raise ValueError("No completed syscall exits in NORMAL validation recordings")
    configs = []
    for n in ALLOWLIST_GRID:
        for k in PREDECESSOR_GRID:
            policy = policy_for(action_counts, pair_counts, n, k)
            alert_n = sum(r["alert_events"].get("candidate", 0) for r in validation_rows)
            # Replays below are needed for each candidate; compute from compact per-recording event summaries.
            configs.append((policy, alert_n))
    return configs


def freeze(source: Path, manifest_path: Path, out: Path) -> None:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("status") != "pass" or manifest.get("source_sha256") != sha256_file(source):
        raise ValueError("Source archive does not match the completed integrity manifest")
    start = time.perf_counter()
    action_counts, pair_counts = Counter(), Counter()
    with zipfile.ZipFile(source) as outer:
        train_rows, train_summary = scan_split(outer, "training", {"NORMAL"}, action_counts, pair_counts)
        val_action_counts, val_pair_counts = Counter(), Counter()
        val_rows, val_summary = scan_split(outer, "validation", {"NORMAL"}, val_action_counts, val_pair_counts)
        # Tune on aggregated normal-only validation transitions; no test stream or
        # test JSON is read here.
        configs = []
        val_events = sum(val_action_counts.values())
        val_unpaired_first = val_events - sum(val_pair_counts.values())
        for n in ALLOWLIST_GRID:
            for k in PREDECESSOR_GRID:
                policy = policy_for(action_counts, pair_counts, n, k)
                accepted = sum(count for action, count in val_action_counts.items()
                               if action in policy["allowed"])
                if policy["predecessors"] is not None:
                    accepted = sum(count for (prev, action), count in val_pair_counts.items()
                                   if action in policy["allowed"]
                                   and prev in policy["predecessors"].get(action, ()))
                alerts = val_events - accepted
                events = val_events
                rate = alerts / events if events else 1.0
                configs.append({"n_actions_grid": n, "k_predecessors_grid": k,
                                "policy": policy, "validation_alert_events": alerts,
                                "validation_events": events, "validation_alert_fraction": rate,
                                "validation_accepted_events": accepted,
                                "validation_alert_budget_met": rate <= ALERT_BUDGET})
        p1_configs = [c for c in configs if c["k_predecessors_grid"] > 0]
        feasible = [c for c in p1_configs if c["validation_alert_budget_met"]]
        if not feasible:
            chosen = min(p1_configs, key=lambda c: (c["validation_alert_fraction"], c["policy"]["rule_count"]))
        else:
            chosen = max(feasible, key=lambda c: (c["validation_accepted_events"],
                                                    -c["policy"]["rule_count"],
                                                    -c["n_actions_grid"], -c["k_predecessors_grid"]))
        candidate = chosen["policy"]
        # Separately select the best action-only operating point under the same budget.
        p0_candidates = [c for c in configs if c["k_predecessors_grid"] == 0]
        p0_feasible = [c for c in p0_candidates if c["validation_alert_budget_met"]]
        p0_choice = max(p0_feasible or p0_candidates,
                        key=lambda c: (c["validation_accepted_events"], -c["policy"]["rule_count"], -c["n_actions_grid"]))
        p0, p1 = p0_choice["policy"], candidate
        # Recreate predictions for all policies in one sequential validation pass.
        # BETH comparator is frozen from its earlier training artifact and uses exact action strings only.
        beth_p0 = {"allowed": BENCH_ACTIONS, "predecessors": None}
        beth_p1 = {"allowed": BENCH_ACTIONS, "predecessors": BENCH_PREDECESSORS}
        val_final, val_final_summary = scan_split(outer, "validation", {"NORMAL"},
                                                 policies={"LIDDS_P0": p0, "LIDDS_P1": p1,
                                                           "BETH_P0": beth_p0, "BETH_P1": beth_p1})

    frozen_policies = {
        "LIDDS_P0": {"allowed": list(p0["allowed"]), "predecessors": None,
                      "construction": "Top training-normal syscall names with support >=20; default deny.",
                      "n_actions_grid": p0_choice["n_actions_grid"], "k_predecessors": 0,
                      "validation_alert_fraction": p0_choice["validation_alert_fraction"],
                      "validation_alert_budget_met": p0_choice["validation_alert_budget_met"]},
        "LIDDS_P1": {"allowed": list(p1["allowed"]),
                      "predecessors": {a: list(v) for a, v in (p1["predecessors"] or {}).items()},
                      "construction": "Top training-normal syscalls with support >=20; each allowed action requires one of up to k most frequent supported immediate same-thread predecessors; default deny.",
                      "n_actions_grid": chosen["n_actions_grid"], "k_predecessors": chosen["k_predecessors_grid"],
                      "validation_alert_fraction": chosen["validation_alert_fraction"],
                      "validation_alert_budget_met": chosen["validation_alert_budget_met"]},
        "BETH_P0": {"allowed": list(BENCH_ACTIONS), "predecessors": None,
                     "construction": "Frozen BETH action vocabulary applied unchanged by exact syscall-name match."},
        "BETH_P1": {"allowed": list(BENCH_ACTIONS), "predecessors": {a: list(v) for a, v in BENCH_PREDECESSORS.items()},
                     "construction": "Frozen BETH action and predecessor vocabulary applied unchanged by exact syscall-name match."},
    }
    selected_rule_core = {name: {"allowed": p["allowed"], "predecessors": p["predecessors"]}
                          for name, p in frozen_policies.items()}
    protocol = {
        "dataset": "LID-DS 2021", "scenario": "CVE-2020-23839",
        "source_archive": str(source.resolve()), "source_archive_sha256": manifest["source_sha256"],
        "archive_manifest_sha256": sha256_file(manifest_path),
        "raw_dataset_extracted_or_copied": False,
        "test_json_opened_before_freeze": False,
        "test_category_directory_names_seen_during_structure_audit": ["normal", "normal_and_attack"],
        "test_category_directory_names_used_for_policy_selection": False,
        "training_validation_metadata_summary": {"training": train_summary["recordings_by_type"],
                                                  "validation": val_summary["recordings_by_type"]},
        "training_normal_quality": {"recordings": len(train_rows),
                                    "events": sum(r["events"] for r in train_rows),
                                    "quality": dict(Counter({k: sum(r["quality"].get(k, 0) for r in train_rows)
                                                             for k in set().union(*(r["quality"].keys() for r in train_rows))}))},
        "validation_normal_summary": val_final_summary,
        "policy_design": {
            "action": "syscall name only", "resource_class": "host_syscall", "subject_class": "process",
            "history_partition": "within recording by (process_id, thread_id); original line order; no cross-recording history",
            "event_rows": "completed syscall exits (<), one row per invocation; timestamps retained in nanoseconds",
            "malformed_and_unpaired_lines": "counted and reported; unmatched exits are retained as completed invocations at capture boundaries",
            "training_population": "NORMAL recordings only; IDLE excluded; no attack recording contributes to policy",
            "validation_population": "NORMAL recordings only; IDLE excluded",
            "support_threshold": 20,
            "candidate_allowlist_sizes": list(ALLOWLIST_GRID), "candidate_predecessor_counts": list(PREDECESSOR_GRID),
            "selection": "maximize completed validation events accepted subject to <=1% validation-normal event alert fraction; tie-break on fewer rules, smaller allowlist, then fewer predecessors",
            "alert_budget_fraction": ALERT_BUDGET,
            "calibration_labels": "recording-level NORMAL metadata only; no syscall-level attack labels",
            "exploit_interval_available_in_train_val_metadata": False,
            "split_protocol_note": "Test folder names were visible during central-directory inspection; test JSON metadata and syscall streams were not read before this freeze.",
        },
        "policy_search": [{k: v for k, v in c.items() if k != "policy"} for c in configs],
        "policies": frozen_policies,
        "policy_sha256": json_hash(selected_rule_core),
        "training_action_support": dict(sorted(action_counts.items())),
        "training_pair_support": [{"previous": prev, "current": cur, "support": n}
                                  for (prev, cur), n in sorted(pair_counts.items())],
        "training_recordings": train_rows,
        "validation_recordings": val_final,
        "direct_comparator_mapping": {
            "BETH_P0_P1_action_vocabulary": list(BENCH_ACTIONS),
            "exactly_matched_training_actions": [a for a in BENCH_ACTIONS if a in action_counts],
            "unmatched_beth_actions": [a for a in BENCH_ACTIONS if a not in action_counts],
            "mapping": "identity string match; no semantic translation",
        },
        "runtime_seconds": time.perf_counter() - start,
    }
    protocol["protocol_sha256"] = json_hash(protocol)
    write_json(out / "frozen_protocol.json", protocol)
    print(json.dumps({"protocol_sha256": protocol["protocol_sha256"],
                      "selected_LIDDS_P0": {k: frozen_policies["LIDDS_P0"][k] for k in ("n_actions_grid", "validation_alert_fraction", "validation_alert_budget_met")},
                      "selected_LIDDS_P1": {k: frozen_policies["LIDDS_P1"][k] for k in ("n_actions_grid", "k_predecessors", "validation_alert_fraction", "validation_alert_budget_met")},
                      "test_json_opened": False, "test_events_opened": False,
                      "elapsed_seconds": protocol["runtime_seconds"]}, indent=2))


def load_frozen(out: Path):
    frozen = json.loads((out / "frozen_protocol.json").read_text(encoding="utf-8"))
    actual = frozen.pop("protocol_sha256")
    if json_hash(frozen) != actual:
        raise ValueError("Frozen protocol checksum mismatch")
    frozen["protocol_sha256"] = actual
    return frozen


def evaluate(source: Path, manifest_path: Path, out: Path) -> None:
    frozen = load_frozen(out)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest["source_sha256"] != frozen["source_archive_sha256"] or sha256_file(source) != manifest["source_sha256"]:
        raise ValueError("Dataset source changed after freeze")
    policies = {name: {"allowed": tuple(p["allowed"]),
                       "predecessors": None if p["predecessors"] is None else {k: tuple(v) for k, v in p["predecessors"].items()}}
                for name, p in frozen["policies"].items()}
    start = time.perf_counter()
    test_rows = []
    with zipfile.ZipFile(source) as outer:
        for info in recording_entries(outer, "test"):
            test_rows.append(scan_recording(outer, info, policies=policies))
    payload = {"protocol_sha256": frozen["protocol_sha256"],
               "source_archive_sha256": frozen["source_archive_sha256"],
               "test_json_opened": False, "test_category_names_used": False,
               "predictions": test_rows,
               "summary": {"test_recordings": len(test_rows),
                           "completed_events": sum(r["events"] for r in test_rows),
                           "alerts_by_policy": {name: sum(r["alert_events"].get(name, 0) for r in test_rows)
                                                for name in policies},
                           "recordings_with_alert_by_policy": {name: sum(r["alert_events"].get(name, 0) > 0 for r in test_rows)
                                                                for name in policies},
                           "quality": dict(Counter({k: sum(r["quality"].get(k, 0) for r in test_rows)
                                                    for k in set().union(*(r["quality"].keys() for r in test_rows))}))},
               "runtime_seconds": time.perf_counter() - start}
    payload["predictions_sha256"] = json_hash(test_rows)
    write_json(out / "predictions_without_test_labels.json", payload)
    print(json.dumps({k: payload[k] for k in ("summary", "predictions_sha256", "runtime_seconds")}, indent=2))


def score_labels(source: Path, manifest_path: Path, out: Path) -> None:
    frozen = load_frozen(out)
    payload = json.loads((out / "predictions_without_test_labels.json").read_text(encoding="utf-8"))
    if payload["protocol_sha256"] != frozen["protocol_sha256"] or payload["test_json_opened"]:
        raise ValueError("Label-free predictions do not match the frozen protocol")
    if json_hash(payload["predictions"]) != payload["predictions_sha256"]:
        raise ValueError("Label-free predictions changed after evaluation")
    if sha256_file(source) != frozen["source_archive_sha256"]:
        raise ValueError("Dataset source changed")
    start = time.perf_counter()
    rows = {r["path"]: r for r in payload["predictions"]}
    class_counts = Counter()
    alerts = defaultdict(Counter)
    seconds = Counter()
    recording_rows = []
    with zipfile.ZipFile(source) as outer:
        for info in recording_entries(outer, "test"):
            _, rec = nested_recording(outer, info)
            meta = metadata(rec, info)
            label = label_from_metadata(meta)
            class_counts[label] += 1
            record_seconds = float(meta.get("recording_time", 0) or 0)
            pred = rows[info.filename]
            recording_rows.append({"recording": pred["recording"], "path": info.filename,
                                   "label": label, "recording_seconds": record_seconds,
                                   "exploit_interval_usable": False,
                                   "policy_alerts": pred["alert_events"],
                                   "first_alert_ns": pred["first_alert_ns"]})
            seconds[label] += record_seconds
            for policy, count in pred["alert_events"].items():
                alerts[label][policy] += count
    policy_names = list(payload["summary"]["alerts_by_policy"])
    metrics = {}
    for label in ("NORMAL", "NORMAL_AND_ATTACK", "ATTACK", "IDLE"):
        members = [r for r in recording_rows if r["label"] == label]
        metrics[label] = {
            "recordings": len(members), "recording_hours": seconds[label] / 3600,
            "recordings_with_any_alert": {p: sum(r["policy_alerts"].get(p, 0) > 0 for r in members)
                                           for p in policy_names},
            "recording_alert_coverage": {p: (sum(r["policy_alerts"].get(p, 0) > 0 for r in members) / len(members) if members else None)
                                         for p in policy_names},
            "alert_events": {p: alerts[label][p] for p in policy_names},
            "alerts_per_recording_hour": {p: (alerts[label][p] / (seconds[label] / 3600) if seconds[label] else None)
                                           for p in policy_names},
        }
    result = {
        "protocol_sha256": frozen["protocol_sha256"],
        "source_archive_sha256": frozen["source_archive_sha256"],
        "test_predictions_sha256": payload["predictions_sha256"],
        "test_recording_label_counts": dict(class_counts),
        "metrics_by_recording_label": metrics,
        "test_metadata_keys_scope": "Only opened after prediction hash verification; recording classification used official container role/exploit fields. No event-level labels inferred.",
        "exploit_interval_status": "No unambiguous exploit interval was present in the official recording metadata schema; only recording-level alert coverage is reported.",
        "test_directory_class_names_seen_before_freeze": ["normal", "normal_and_attack"],
        "test_labels_used_for_policy_selection": False,
        "warning": "Controlled scenario recordings are not independent field deployments. Coverage is recording-level; no syscall-level confusion matrix or event recall is computed.",
        "per_recording": recording_rows,
        "runtime_seconds": time.perf_counter() - start,
    }
    write_json(out / "label_metrics.json", result)
    print(json.dumps({"test_recording_label_counts": result["test_recording_label_counts"],
                      "metrics_by_recording_label": metrics,
                      "runtime_seconds": result["runtime_seconds"]}, indent=2))


def verify(source: Path, manifest_path: Path, out: Path) -> None:
    frozen = load_frozen(out)
    prediction = json.loads((out / "predictions_without_test_labels.json").read_text(encoding="utf-8"))
    labels = json.loads((out / "label_metrics.json").read_text(encoding="utf-8"))
    if sha256_file(source) != frozen["source_archive_sha256"]:
        raise ValueError("Source hash mismatch")
    if prediction["protocol_sha256"] != frozen["protocol_sha256"] or prediction["test_json_opened"]:
        raise ValueError("Prediction stage was not label-free or is not tied to frozen protocol")
    if json_hash(prediction["predictions"]) != prediction["predictions_sha256"]:
        raise ValueError("Prediction file hash mismatch")
    if labels["test_predictions_sha256"] != prediction["predictions_sha256"]:
        raise ValueError("Label scoring used different predictions")
    if sum(labels["test_recording_label_counts"].values()) != prediction["summary"]["test_recordings"]:
        raise ValueError("Recording-level label coverage is incomplete")
    report = {"verified": True, "protocol_sha256": frozen["protocol_sha256"],
              "source_archive_sha256": frozen["source_archive_sha256"],
              "test_recordings": prediction["summary"]["test_recordings"],
              "test_completed_events": prediction["summary"]["completed_events"],
              "predictions_hash_matches": True, "test_labels_not_used_for_policy_selection": True,
              "recording_label_counts_cover_test": True}
    write_json(out / "verification.json", report)
    print(json.dumps(report, indent=2))


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("stage", choices=("freeze", "evaluate", "labels", "verify"))
    p.add_argument("--source", type=Path, default=OUTER_DEFAULT)
    p.add_argument("--manifest", type=Path, default=MANIFEST_DEFAULT)
    p.add_argument("--output", type=Path, default=OUT_DEFAULT)
    a = p.parse_args()
    {"freeze": freeze, "evaluate": evaluate, "labels": score_labels, "verify": verify}[a.stage](a.source, a.manifest, a.output)


if __name__ == "__main__":
    main()
