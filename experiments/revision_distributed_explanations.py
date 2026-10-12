"""Post-analysis of archived complete live runs; never modifies their sources."""
from pathlib import Path
import argparse
from dataclasses import asdict
import hashlib
import itertools
import json
import sys
import time


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--cohort',required=True)
    parser.add_argument('--output',required=True)
    args=parser.parse_args()
    cohort=Path(args.cohort).resolve(); output=Path(args.output).resolve()
    if output.exists():
        raise FileExistsError('preserve earlier derived proof artifacts')
    snapshot=cohort/'source_snapshot'/'code'
    sys.path[:0]=[str(snapshot/'src'),str(snapshot/'experiments')]
    import trace_policy_engine as tpe
    from revision_distributed_lab import lab_policies
    policies=lab_policies()
    results=json.loads((cohort/'results.json').read_text())
    proofs=[]; excluded=[]
    for record in results:
        if record['summary']['status']!='complete':
            excluded.append(record['run_id']); continue
        folder=cohort/record['run_id']
        observations=[]
        inputs=[folder/'config.json',folder/'A.json',folder/'B.json',folder/'checkpoint.json']
        for source in ('A','B'):
            observations.extend(json.loads((folder/(source+'.json')).read_text())['observations'])
        observations.sort(key=lambda o:(o['event']['ts'],o['event']['eid']))
        trace=[tpe.Event(**o['event']) for o in observations]
        replay_start=time.perf_counter()
        incremental=tpe.IncrementalEvaluator(policies[1],retention_horizon=3)
        prefix=[]; decisions=[]
        for observation,event in zip(observations,trace):
            version=observation['policy_version']
            if version!=incremental.policy.version:
                incremental.update_policy(policies[version])
            prefix.append(event)
            reference=tpe.reference_eval(prefix,policies[version]).alert_class
            optimized=incremental.push(event).alert_class
            assert reference==optimized
            decisions.append(dict(event_id=event.eid,policy_version=version,
                                  reference=reference,incremental=optimized))
        replay_seconds=time.perf_counter()-replay_start
        assert [d['reference'] for d in decisions]==[tpe.NOALERT,tpe.NOALERT,tpe.VIOLATION]
        extraction_start=time.perf_counter()
        explanation=tpe.min_explain_bruteforce(trace,policies[2],horizon=3)
        extraction_seconds=time.perf_counter()-extraction_start
        selected={f'e:{i}' for i in explanation.event_positions}|{f'r:{rid}' for rid in explanation.rule_ids}
        expected={'e:0','e:1','e:2','r:DENY_READ_EXEC_CONNECT'}
        assert selected==expected and len(explanation.witnesses)==4
        # Build a separate exhaustive intervention table without engine masking
        # or sufficiency helpers: all three archived event positions and both rules.
        units=[f'e:{i}' for i in range(len(trace))]+[f'r:{r.rid}' for r in policies[2].rules]
        audit_start=time.perf_counter(); table={}
        for mask in itertools.product((0,1),repeat=len(units)):
            altered=[event if mask[i] else tpe.Event.stutter_like(event) for i,event in enumerate(trace)]
            retained=tuple(rule for j,rule in enumerate(policies[2].rules) if mask[len(trace)+j])
            policy=tpe.PolicyVersion(policies[2].pid,2,retained)
            table[mask]=tpe.reference_eval(altered,policy).alert_class
        assert all(value==tpe.VIOLATION for mask,value in table.items()
                   if all(mask[units.index(unit)] for unit in selected))
        witness_checks=[]
        for released,witness in explanation.witnesses.items():
            assert set(witness)==set(units)
            assert all(witness[unit]==1 for unit in selected-{released})
            observed=table[tuple(witness[unit] for unit in units)]
            assert observed!=tpe.VIOLATION
            witness_checks.append(dict(released_unit=released,mask=witness,
                                       observed_class=observed,valid=True))
        proofs.append(dict(run_id=record['run_id'],source_sha256={p.name:digest(p) for p in inputs},
             trace=[asdict(e) for e in trace],decisions=decisions,
             policy_version_history=incremental.version_history,
             retained_horizon=incremental.retention_horizon,
             explanation=asdict(explanation),selected=sorted(selected),
             sufficient=True,minimal=True,witness_checks=witness_checks,
             independent_assignment_count=len(table),
             timings_s=dict(archived_replay=replay_seconds,intrinsic_extraction=extraction_seconds,
                            independent_audit=time.perf_counter()-audit_start)))
    artifact=dict(kind='post_analysis_of_archived_complete_live_prefixes',
        cohort=str(cohort),cohort_sha256={name:digest(cohort/name) for name in ('protocol.json','results.json','summary.json')},
        analysis_sha256=digest(Path(__file__)),
        engine_snapshot_sha256=digest(snapshot/'src'/'trace_policy_engine.py'),
        complete_runs=len(proofs),excluded_incomplete_runs=excluded,
        reference_incremental_comparisons=sum(len(p['decisions']) for p in proofs),
        sufficient_minimal_proofs=len(proofs),verified_witnesses=sum(len(p['witness_checks']) for p in proofs),
        scope='default initial state; archived full prefix; trusted canonical IDs/time/version; offline explanation post-analysis, not online proof delivery',
        proofs=proofs)
    output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text(json.dumps(artifact,indent=2),encoding='utf-8')
    print(json.dumps({k:artifact[k] for k in ('complete_runs','reference_incremental_comparisons','sufficient_minimal_proofs','verified_witnesses')}))


if __name__=='__main__':
    main()
