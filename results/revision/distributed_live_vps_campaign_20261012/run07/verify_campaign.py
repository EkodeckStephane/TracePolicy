"""Rebuild the run-07 decision ledger from independent source journals."""
import hashlib
import json
import sys
from pathlib import Path

run_dir = Path(__file__).resolve().parent
candidates = [run_dir, *run_dir.parents]
code = next((candidate for candidate in candidates
             if (candidate / "src" / "revision_distributed.py").is_file()), None)
if code is None:
    project = next((candidate for candidate in candidates
                    if (candidate / "revision_COSE_2026" / "code" / "src" /
                        "revision_distributed.py").is_file()), None)
    if project is None:
        raise FileNotFoundError("cannot locate the TracePolicy code snapshot")
    code = project / "revision_COSE_2026" / "code"
sys.path.insert(0, str(code / "src"))
sys.path.insert(0, str(code / "experiments"))
from revision_distributed import JournalCoordinator  # noqa: E402
from revision_distributed_lab import lab_policies  # noqa: E402
from trace_policy_engine import Event, reference_eval  # noqa: E402

config = json.loads((run_dir / "config.json").read_text(encoding="utf-8"))
source_journals = [json.loads((run_dir / f"source_{source}.json").read_text(encoding="utf-8"))
                   for source in ("A", "B")]
controller = json.loads((run_dir / "controller_result.json").read_text(encoding="utf-8"))
checkpoint_path = run_dir / "checkpoint.json"
policies = lab_policies()
summary = controller["summary"]

observations = [observation for journal in source_journals
                for observation in journal["observations"]]
ordered = sorted(observations,
                 key=lambda item: (item["event"]["ts"], item["event"]["eid"]))
prefixes = {}
replay = []
for observation in ordered:
    event = Event(**observation["event"])
    prefix = prefixes.setdefault(observation["trace_id"], [])
    prefix.append(event)
    decision = reference_eval(prefix, policies[observation["policy_version"]])
    replay.append({"event_id": event.eid, "trace_id": observation["trace_id"],
                   "policy_version": observation["policy_version"],
                   "alert_class": decision.alert_class, "top": list(decision.top)})

restored = JournalCoordinator.restore(checkpoint_path, policies).summary()
arrivals = controller["arrivals"]
max_lateness = max(item["lateness_s"] for item in arrivals)
hostnames = [source["identity"]["hostname"] for source in source_journals]
hostnames.append(controller["process"]["hostname"])
expected_actions = ["read", "exec", "connect"]
actual_actions = [item["event"]["action"] for item in ordered]
checks = {
    "complete": summary["status"] == "complete",
    "all_events_committed": summary["observed"] == summary["committed"] == 3 and summary["pending"] == 0,
    "source_closure": set(summary["closed_sources"]) == {"A", "B"},
    "no_transport_or_sequence_faults": not summary["errors"] and not summary["sequence_gaps"]["A"]
                                          and not summary["sequence_gaps"]["B"]
                                          and not summary["missing_watermarks"]
                                          and summary["duplicate_count"] == 0,
    "distinct_execution_instances": len(set(hostnames)) == 3,
    "expected_event_order": actual_actions == expected_actions,
    "all_deliveries_acknowledged": all(delivery["reply"]["ok"]
        for journal in source_journals for delivery in journal["deliveries"]),
    "all_records_accepted": all(item["status"] == "accepted" for item in arrivals),
    "lateness_within_budget": max_lateness <= config["max_lateness_s"],
    "canonical_replay_matches_controller": replay == summary["decisions"],
    "checkpoint_restore_matches_controller": restored == summary,
    "expected_final_policy_violation": replay[-1]["alert_class"] == "Violation"
        and replay[-1]["top"] == ["DENY_READ_EXEC_CONNECT"],
}
if not all(checks.values()):
    raise SystemExit(json.dumps({"checks": checks, "summary": summary,
                                "replay": replay, "restored": restored}, indent=2))

files = ["config.json", "source_A.json", "source_B.json", "controller_result.json",
         "checkpoint.json"]
manifest = {
    "run_id": config["run_id"],
    "run_type": "three-instance live distributed integration trial; benign constructed workload",
    "topology": {
        "source_A": {"hostname": source_journals[0]["identity"]["hostname"],
                     "platform": source_journals[0]["identity"]["platform"],
                     "role": "Windows workstation source"},
        "source_B": {"hostname": source_journals[1]["identity"]["hostname"],
                     "platform": source_journals[1]["identity"]["platform"],
                     "role": "Ubuntu VPS source"},
        "controller": {"hostname": controller["process"]["hostname"],
                       "platform": controller["process"]["platform"],
                       "role": "Ubuntu Contabo VPS coordinator"},
        "transport": "SSH tunnels to loopback-bound coordinator; no campaign port exposed publicly",
    },
    "workload": "one filesystem fixture read, one child Python execution, one TCP connection; deliberately arranged to exercise the declared temporal deny rule",
    "result": {
        "status": summary["status"], "observed": summary["observed"],
        "committed": summary["committed"], "pending": summary["pending"],
        "duplicates": summary["duplicate_count"], "sequence_gaps": summary["sequence_gaps"],
        "protocol_errors": summary["errors"], "max_arrival_lateness_s": max_lateness,
        "lateness_budget_s": config["max_lateness_s"],
        "decisions": summary["decisions"],
    },
    "verification": checks,
    "implementation": {
        "file": "experiments/revision_distributed_lab.py",
        "sha256": hashlib.sha256((code / "experiments" /
                                  "revision_distributed_lab.py").read_bytes()).hexdigest(),
    },
    "scope_limits": [
        "single ordered run; not an attack-efficacy or P1 temporal external-validation campaign",
        "only explicitly instrumented benign operations were observed",
        "source identity and event clocks are trusted; clock skew was sampled before but not continuously monitored during the run",
        "no production IDS sensors, sustained-load test, arbitrary interhost correlation, adversarial-source test, or provider hypervisor/zone verification",
        "the final violation is the expected result of a deliberately constructed sequence, not an attack label",
    ],
    "sha256": {name: hashlib.sha256((run_dir / name).read_bytes()).hexdigest()
               for name in files},
}
(run_dir / "campaign_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
(run_dir / "canonical_replay.json").write_text(json.dumps(replay, indent=2), encoding="utf-8")
print(json.dumps({"checks": checks, "max_arrival_lateness_s": max_lateness,
                  "event_order": actual_actions, "decisions": replay,
                  "manifest": str(run_dir / "campaign_manifest.json")}, indent=2))
