"""Revision-only adapters and ingestion stress experiment; no baseline result edits."""
from __future__ import annotations

import argparse
import itertools
import json
import sys
import time
from pathlib import Path

import numpy as np


def audit_directory():
    """Resolve evidence in either the author-review or public repository layout."""
    root = Path(__file__).resolve().parents[1]
    public = root/'revision_audit'
    return public if public.exists() else root.parent/'audit'


def explain_anchor(predict_labels, units, seed, threshold=.95, background=None):
    """Run genuine Alibi AnchorTabular on factual retention masks (all ones).

    Default fit population is the complete binary intervention domain, NOT an
    empirical event distribution. Above 16 units an explicit population is required.
    Exact certification/minimization remains the caller's independent operation.
    """
    from alibi.explainers import AnchorTabular
    m = len(units)
    if background is None:
        if m > 16:
            raise ValueError('Explicit background required above 16 binary units')
        background = np.asarray(list(itertools.product((0., 1.), repeat=m)))
    background = np.asarray(background, dtype=float)
    if background.ndim != 2 or background.shape[1] != m or not np.all(np.isin(background, [0, 1])):
        raise ValueError('Background must be binary masks with one column per unit')
    t0 = time.perf_counter_ns()
    explainer = AnchorTabular(predict_labels, list(units),
                             categorical_names={i: ['removed', 'retained'] for i in range(m)},
                             seed=int(seed))
    explainer.fit(np.asarray(background, dtype=float))
    t1 = time.perf_counter_ns()
    exp = explainer.explain(np.ones(m), threshold=threshold, delta=.05, tau=.05,
                            batch_size=100, beam_size=1)
    t2 = time.perf_counter_ns()
    features = [int(i) for i in exp.data['raw']['feature']]
    return dict(selected=[units[i] for i in features], feature_indices=features,
                anchor=exp.data['anchor'], precision=float(np.asarray(exp.data['precision']).item()),
                coverage=float(np.asarray(exp.data['coverage']).item()), threshold=threshold,
                seed=int(seed), init_us=(t1-t0)/1000, explanation_us=(t2-t1)/1000,
                total_native_us=(t2-t0)/1000, implementation='alibi.AnchorTabular',
                background_distribution='uniform_complete_binary_domain' if background.shape[0] == 2**m else 'explicit_population')


def ffa_from_cores(cores, units):
    """Exact FFA definition on a supplied COMPLETE collection of minimal cores.

    This is a finite-domain adaptation, not the SAT-2024 anytime MUS algorithm.
    The caller must enumerate cores independently of a single TracePolicy output.
    """
    cores = [set(core) for core in cores]
    if not cores:
        raise ValueError('FFA requires at least one minimal sufficient core')
    return np.asarray([sum(u in c for c in cores)/len(cores) for u in units])


def replay_experiment(out):
    """Two-source synthetic ingestion test under trusted identities and order keys.

    Full-buffer normalization is intentional: this is NOT bounded-latency distributed
    event ordering. Timestamps are assumed trustworthy and unique here.
    """
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'src'))
    import trace_policy_engine as tpe
    policy = tpe.PolicyVersion('REVISION_TWO_SOURCE', 1, (
        tpe.Rule('D_SEQ', 100, tpe.DENY, tpe.Selector('connect', 'network', 'user'),
                 tpe.Guard(seq_actions=('read', 'exec', 'connect'), seq_horizon=3)),
        tpe.Rule('A_FALLBACK', 10, tpe.ALLOW, tpe.Selector('*', '*', 'user'))))
    canonical = [tpe.Event('hostA:1', 1., 'read', 'public', 'user', {'source': 'hostA'}),
                 tpe.Event('hostB:1', 2., 'exec', 'system', 'user', {'source': 'hostB'}),
                 tpe.Event('hostA:2', 3., 'connect', 'network', 'user', {'source': 'hostA'})]

    def evaluate(events):
        return [{'eid': e.eid, 'class': tpe.reference_eval(events[:i+1], policy).alert_class}
                for i, e in enumerate(events)]

    def normalize(events):
        unique = {}
        for e in events:
            if e.eid in unique and unique[e.eid] != e:
                raise ValueError('Conflicting event identity')
            unique[e.eid] = e
        return sorted(unique.values(), key=lambda e: (e.ts, e.eid))

    ref = evaluate(canonical)
    expected = {r['eid']: r['class'] for r in ref}
    rows = []
    for arrival in itertools.permutations(canonical):
        for duplicated in (False, True):
            events = list(arrival)
            if duplicated:
                events.insert(1, arrival[0])
            raw = evaluate(events)
            normalized = evaluate(normalize(events))
            rows.append(dict(arrival=[e.eid for e in events], duplicated=duplicated,
                             raw_matches_by_identity=all(r['class'] == expected[r['eid']] for r in raw),
                             normalized_matches=normalized == ref, raw=raw, normalized=normalized))
    loss = normalize([canonical[0], canonical[2]])
    payload = dict(policy_id=policy.pid, policy_version=1, kind='synthetic_two_source_ingestion',
                   canonical=ref, cases=rows, n_cases=len(rows),
                   normalized_matches=sum(r['normalized_matches'] for r in rows),
                   raw_matches=sum(r['raw_matches_by_identity'] for r in rows),
                   loss_case=evaluate(loss),
                   limitations=['trusted timestamps and identities', 'full offline buffering',
                                'no bounded-lateness watermark', 'no real multi-host deployment',
                                'loss cannot be repaired by normalization'])
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2), encoding='utf-8')
    return payload


def anchor_benchmark(out):
    """Same real oracle/cases as the audit, in Alibi's separate NumPy<2 environment."""
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import revision_explanation_benchmark as bench
    import trace_policy_engine as tpe
    rows = []
    for name, trace, policy, horizon in bench.controlled_cases():
        eps, rids, units = tpe.explanation_unit_info(trace, policy, horizon)
        target = tpe.reference_eval(trace, policy).alert_class
        _, table = bench.independent_table(trace, policy, eps, rids)
        cores = bench.all_minimal_cores(units, table, target)
        def predict(X):
            return np.array([bench.CLASSES.index(tpe._class_under_mask(trace, policy, eps, rids,
                                [int(v >= .5) for v in bits])) for bits in np.asarray(X).reshape(-1, len(units))])
        for seed in (11, 23, 47):
            row = dict(case=name, seed=seed, method='AnchorTabular')
            try:
                info = explain_anchor(predict, units, seed)
                selected = set(info['selected'])
                t0 = time.perf_counter_ns()
                certified = tpe.exact_sufficiency_of_selected(trace, policy, selected, horizon)
                certification_us = (time.perf_counter_ns()-t0)/1000
                row.update(info, status='ok', exact_certified=bool(certified),
                           certification_us=certification_us,
                           total_certified_us=info['total_native_us']+certification_us,
                           validation=bench.validate(selected, units, table, target, cores))
            except Exception as error:
                row.update(status='failed', error=repr(error))
            rows.append(row)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(json.dumps(rows, indent=2), encoding='utf-8')
    return rows


def ffa_benchmark(out):
    """Record exact definition adaptation including full independent enumeration cost."""
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import revision_explanation_benchmark as bench
    import trace_policy_engine as tpe
    rows = []
    for name, trace, policy, horizon in bench.controlled_cases():
        t0 = time.perf_counter_ns()
        eps, rids, units = tpe.explanation_unit_info(trace, policy, horizon)
        target = tpe.reference_eval(trace, policy).alert_class
        _, table = bench.independent_table(trace, policy, eps, rids)
        cores = bench.all_minimal_cores(units, table, target)
        t1 = time.perf_counter_ns()
        weights = ffa_from_cores(cores, units)
        t2 = time.perf_counter_ns()
        ranking = [units[i] for i in np.argsort(-weights, kind='stable')]
        selected = bench.certify_ranking(ranking, units, table, target,
                   lambda c: tpe.exact_sufficiency_of_selected(trace, policy, c, horizon))
        t3 = time.perf_counter_ns()
        rows.append(dict(case=name, method='Exact_FFA_definition_adaptation', status='ok',
                         units=units, weights=weights.tolist(), n_cores=len(cores),
                         enumeration_us=(t1-t0)/1000, attribution_us=(t2-t1)/1000,
                         selection_certification_us=(t3-t2)/1000, total_us=(t3-t0)/1000,
                         validation=bench.validate(selected, units, table, target, cores)))
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(rows, indent=2), encoding='utf8')
    return rows


def external_static_benchmark(out):
    """Exploratory external STATIC edge projection, not a temporal deployment test."""
    import collections
    import hashlib
    import zipfile
    audit = audit_directory()
    sys.path[:0] = [str(audit), str(Path(__file__).resolve().parents[1]/'src')]
    from extract_magic_arrays import graph_arrays
    import trace_policy_engine as tpe
    archive_path = audit/'magic_theia_graphs.zip'
    protocol = dict(kind='exploratory_external_static_projection',
                    origin='MAGIC derivative THEIA E3 archive',
                    archive_sha256=hashlib.sha256(archive_path.read_bytes()).hexdigest(),
                    train=['train0.pkl', 'train1.pkl'], descriptive_validation=['train2.pkl'],
                    test='test0.pkl', cap_allow_selectors=6, min_support=1,
                    hyperparameter_selection='none', explanation_edge_indexes=list(range(32)),
                    labels='metadata malicious node IDs, incident-edge OR used for prediction aggregation',
                    metadata_schema_and_sample_ids_previously_inspected=True,
                    temporal_claim=False)
    (audit/'external_static_protocol.json').write_text(json.dumps(protocol, indent=2), encoding='utf8')
    archive = zipfile.ZipFile(archive_path)
    def selectors(arrays):
        src, dst, nt, et = arrays
        return np.stack((et, nt[src], nt[dst]), axis=1)
    counts = collections.Counter()
    train_sizes = []
    for member in protocol['train']:
        arrays = graph_arrays(archive.read(member))
        counts.update(map(tuple, selectors(arrays).tolist()))
        train_sizes.append(dict(member=member, nodes=len(arrays[2]), edges=len(arrays[3])))
    allowed = sorted(counts, key=lambda x: (-counts[x], x))[:6]
    rules = [tpe.Rule(f'A{i}',10,tpe.ALLOW,tpe.Selector(f'edge_{a}', f'destination_type_{d}', f'source_type_{s}'))
             for i,(a,s,d) in enumerate(allowed)]
    rules.append(tpe.Rule('D_UNSEEN',0,tpe.DENY,tpe.Selector()))
    policy = tpe.PolicyVersion('MAGIC_THEIA_STATIC_TYPE_WHITELIST',1,tuple(rules))
    freeze = dict(allowed=[list(x) for x in allowed], policy_rules=len(rules),
                  train_sizes=train_sizes, protocol=protocol)
    encoded = json.dumps(freeze, sort_keys=True).encode()
    freeze['frozen_policy_sha256'] = hashlib.sha256(encoded).hexdigest()
    (audit/'external_static_frozen.json').write_text(json.dumps(freeze, indent=2), encoding='utf8')
    # No selection changes after this freeze. Validation is descriptive only.
    val = graph_arrays(archive.read('train2.pkl'))
    val_sel = selectors(val)
    val_alerts = sum(tuple(s) not in allowed for s in val_sel.tolist())
    test = graph_arrays(archive.read('test0.pkl'))
    src, dst, nt, et = test
    test_sel = selectors(test)
    def event(i, s):
        a, nsrc, ndst = map(int,s)
        return tpe.Event(f'THEIA_STATIC_EDGE:{i}',float(i),f'edge_{a}',f'destination_type_{ndst}',f'source_type_{nsrc}')
    outcomes = {}
    for s in sorted(set(map(tuple, test_sel.tolist()))):
        e = event(0,s)
        ref = tpe.reference_eval([e],policy)
        inc = tpe.IncrementalEvaluator(policy).push(e)
        if ref.alert_class != inc.alert_class or ref.top != inc.top:
            raise AssertionError('Static selector evaluator divergence')
        expected = tpe.NOALERT if s in allowed else tpe.VIOLATION
        if ref.alert_class != expected:
            raise AssertionError('Whitelist projection mismatch')
        outcomes[s] = ref.alert_class
    edge_alert = np.array([outcomes[tuple(s)]==tpe.VIOLATION for s in test_sel.tolist()])
    node_pred = np.zeros(len(nt), dtype=bool)
    node_pred[src[edge_alert]] = True
    node_pred[dst[edge_alert]] = True
    meta = json.loads(archive.read('metadata.json'))
    malicious = np.array(meta['malicious'][0],dtype=int)
    if malicious.size and (malicious.min()<0 or malicious.max()>=len(nt)):
        raise ValueError('Malicious indexes outside test graph')
    truth = np.zeros(len(nt),dtype=bool); truth[malicious] = True
    tp = int(np.sum(truth & node_pred)); fp=int(np.sum(~truth & node_pred))
    fn = int(np.sum(truth & ~node_pred)); tn=int(np.sum(~truth & ~node_pred))
    checks = []
    # The engine's public explainer rejects NoAlert. Keep the originally declared
    # first32 edges as decision checks and disclose the label-independent extension
    # to first32 detected alerts for explanation checks; no policy tuning.
    decision_indexes=protocol['explanation_edge_indexes']
    explanation_indexes=np.flatnonzero(edge_alert)[:32].tolist()
    for i in explanation_indexes:
        tr = [event(i,test_sel[i])]
        ex = tpe.min_explain_bruteforce(tr,policy,horizon=1)
        selected={f'e:{j}' for j in ex.event_positions}|{f'r:{rid}' for rid in ex.rule_ids}
        sufficient=tpe.exact_sufficiency_of_selected(tr,policy,selected,1)
        minimal=all(not tpe.exact_sufficiency_of_selected(tr,policy,selected-{u},1) for u in selected)
        if not sufficient or not minimal:
            raise AssertionError('External static explanation certificate failed')
        checks.append(dict(edge_index=i,class_=tpe.reference_eval(tr,policy).alert_class,
                           selected=sorted(selected),sufficient=sufficient,minimal=minimal,
                           witnesses=len(ex.witnesses), witness_assignments=ex.witnesses,
                           units=tpe.explanation_unit_info(tr,policy,1)[2],
                           typed_selector=[int(v) for v in test_sel[i]]))
    result=dict(protocol=protocol, frozen=freeze, validation_edges=len(val_sel),validation_alert_edges=val_alerts,
                test_nodes=len(nt),test_edges=len(et),test_unique_selectors=len(outcomes),
                test_alert_edges=int(edge_alert.sum()),tp=tp,fp=fp,fn=fn,tn=tn,
                precision=tp/(tp+fp) if tp+fp else 0.,recall=tp/(tp+fn) if tp+fn else 0.,
                f1=2*tp/(2*tp+fp+fn) if 2*tp+fp+fn else 0.,explanation_checks=checks,
                originally_declared_edge_decisions=[dict(index=i,alert=bool(edge_alert[i])) for i in decision_indexes],
                explanation_sample_amendment='first32 detected alerts by released edge index; label-independent; amended after NoAlert rejection, no policy change',
                limitations=['static deduplicated edges, no timestamps', 'numeric type abstraction without original action names',
                             'derived node UUID neighborhood labels, not official event truth',
                             'no temporal generalization validated', 'exploratory metadata inspected before freeze'])
    out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(result,indent=2),encoding='utf8')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--anchors', action='store_true')
    parser.add_argument('--ffa', action='store_true')
    parser.add_argument('--external-static', action='store_true')
    parser.add_argument('--out', type=Path, default=audit_directory()/'two_source_replay.json')
    args = parser.parse_args()
    if args.external_static:
        result=external_static_benchmark(args.out)
        print(json.dumps({k:result[k] for k in ('test_nodes','test_edges','precision','recall','f1')}))
    elif args.anchors or args.ffa:
        result = anchor_benchmark(args.out) if args.anchors else ffa_benchmark(args.out)
        print(json.dumps(dict(rows=len(result), ok=sum(r['status']=='ok' for r in result))))
    else:
        result = replay_experiment(args.out)
        print(json.dumps({k: result[k] for k in ('n_cases', 'normalized_matches', 'raw_matches')}))
