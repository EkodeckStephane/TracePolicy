from __future__ import annotations
import argparse, csv, sys, time, json, random, hashlib
from dataclasses import asdict
from importlib.metadata import version
from pathlib import Path
from collections import defaultdict
from itertools import product

import numpy as np
import pandas as pd
import shap

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
sys.path.insert(0, str(ROOT / 'vendor'))

import trace_policy_engine as tpe
from revision_proof import certify_fixed_set
from local_lab_adapter import load_gateway_events, lab_policy
try:
    from lime.lime_tabular import LimeTabularExplainer
except ModuleNotFoundError:
    LimeTabularExplainer = None

CLASSES = [tpe.NOALERT, tpe.VIOLATION, tpe.CONFLICT, tpe.GAP]
RAW = ROOT / 'results' / 'revision' / 'local_lab'
SUMMARY = RAW
RAW.mkdir(parents=True, exist_ok=True)
SUMMARY.mkdir(parents=True, exist_ok=True)


def load_truth(path: Path):
    return {r['sid']: {'label': int(r['label']), 'scenario': r['scenario']}
            for r in csv.DictReader(open(path, newline=''))}


def unit_info(trace, policy, horizon):
    return tpe.explanation_unit_info(trace, policy, horizon)


def predictor(trace, policy, eps, rids):
    m = len(eps) + len(rids)
    def f(X):
        out = []
        for bits in np.asarray(X).reshape(-1, m):
            c = tpe._class_under_mask(trace, policy, eps, rids,
                                      [int(v >= .5) for v in bits])
            out.append([1.0 if c == q else 0.0 for q in CLASSES])
        return np.asarray(out)
    return f


def smallest_sufficient(trace, policy, ranking, horizon):
    selected = set()
    if tpe.exact_sufficiency_of_selected(trace,policy,selected,horizon=horizon):
        return 0, tuple()
    for k, u in enumerate(ranking, 1):
        selected.add(u)
        if tpe.exact_sufficiency_of_selected(trace, policy, selected, horizon=horizon):
            return k, tuple(sorted(selected))
    return None, tuple(sorted(selected))


def collect_cases(lab: Path, per_scenario: int, horizon: int):
    policy = lab_policy()
    by_scenario = defaultdict(list)
    for truthp in sorted(lab.glob('truth_*.csv')):
        seed = int(truthp.stem.split('_')[-1])
        truth = load_truth(truthp)
        access = lab / f'access_{seed}.jsonl'
        events = load_gateway_events(access, truth)
        for i, e in enumerate(events):
            if int(e.malicious or 0) != 1:
                continue
            window = events[max(0, i - horizon + 1): i + 1]
            factual = tpe.reference_eval(window, policy)
            if factual.alert_class not in (tpe.VIOLATION, tpe.CONFLICT):
                continue
            scenario = e.attack_type or 'unknown'
            if len(by_scenario[scenario]) < per_scenario:
                by_scenario[scenario].append((seed, i, window, e))
    return policy, by_scenario


def collect_stratified(lab:Path,horizon:int,selection_seed:int):
    policy=lab_policy(); by_scenario=defaultdict(list); strata=[]; hashes={}
    expected=['admin_probe','bruteforce','command_probe','path_traversal']
    for truthp in sorted(lab.glob('truth_*.csv')):
        seed=int(truthp.stem.split('_')[-1]); access=lab/f'access_{seed}.jsonl'
        for path in [truthp,access]:
            if path.exists(): hashes[str(path.resolve())]=hashlib.sha256(path.read_bytes()).hexdigest()
        if not access.exists():
            strata.extend(dict(seed=seed,scenario=s,status='missing_access_log',eligible_count=0) for s in expected)
            continue
        events=load_gateway_events(access,load_truth(truthp)); candidates=defaultdict(list)
        for i,e in enumerate(events):
            if int(e.malicious or 0)!=1 or e.attack_type not in expected: continue
            window=events[max(0,i-horizon+1):i+1]
            if tpe.reference_eval(window,policy).alert_class in (tpe.VIOLATION,tpe.CONFLICT):
                candidates[e.attack_type].append((seed,i,window,e))
        # Stable source ordering plus fixed RNG, one candidate per workload/scenario.
        rng=random.Random(selection_seed+seed)
        for scenario in expected:
            items=candidates[scenario]
            if items:
                selected=items[rng.randrange(len(items))]; by_scenario[scenario].append(selected)
                strata.append(dict(seed=seed,scenario=scenario,status='selected',eligible_count=len(items),event_index=selected[1],event_id=selected[3].eid))
            else: strata.append(dict(seed=seed,scenario=scenario,status='no_eligible_true_positive',eligible_count=0))
    return policy,by_scenario,dict(strata=strata,input_sha256=hashes)


def main():
    global RAW,SUMMARY
    ap = argparse.ArgumentParser()
    ap.add_argument('--lab-dir', default=str(ROOT / 'local_lab' / 'results'))
    ap.add_argument('--per-scenario', type=int, default=25)
    ap.add_argument('--horizon', type=int, default=5)
    ap.add_argument('--lime-samples', type=int, default=5000)
    ap.add_argument('--quiet',action='store_true')
    ap.add_argument('--selection',choices=['first','stratified'],default='first')
    ap.add_argument('--selection-seed',type=int,default=20261011)
    ap.add_argument('--output',default=None)
    ap.add_argument('--proof-matched',action='store_true')
    args = ap.parse_args()

    if args.output: RAW=ROOT/args.output
    elif args.proof_matched: RAW=ROOT/'results/revision/local_lab_proofmatched'
    elif args.selection=='stratified': RAW=ROOT/'results/revision/local_lab_stratified'
    SUMMARY=RAW; RAW.mkdir(parents=True,exist_ok=True)
    if args.selection=='stratified':
        policy,by_scenario,manifest=collect_stratified(Path(args.lab_dir),args.horizon,args.selection_seed)
    else:
        policy,by_scenario=collect_cases(Path(args.lab_dir),args.per_scenario,args.horizon)
        manifest={}
    policy_json=json.dumps(asdict(policy),sort_keys=True)
    manifest.update(arguments=vars(args),selection_description='one seeded randomized eligible true-positive alert per scenario and available workload' if args.selection=='stratified' else 'first per-scenario eligible alerts in sorted workload order',policy=asdict(policy),policy_sha256=hashlib.sha256(policy_json.encode()).hexdigest(),python=sys.version,packages={p:version(p) for p in ['numpy','pandas','scipy','scikit-learn','shap','lime']})
    (RAW/'run_manifest.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
    expected = {'admin_probe', 'bruteforce', 'command_probe', 'path_traversal'}
    missing = expected - set(by_scenario)
    if missing:
        raise SystemExit(f'Missing true-positive scenarios: {sorted(missing)}')

    rows = []
    detailed=[]
    case_id = 0
    for scenario in sorted(expected):
        cases = by_scenario[scenario]
        if args.selection=='first' and len(cases) < args.per_scenario:
            raise SystemExit(f'Only {len(cases)} cases for {scenario}; required {args.per_scenario}.')
        for seed, event_index, trace, e in (cases[:args.per_scenario] if args.selection=='first' else cases):
            factual = tpe.reference_eval(trace, policy)
            target_idx = CLASSES.index(factual.alert_class)
            t0 = time.perf_counter_ns()
            ex = tpe.min_explain_bruteforce(trace, policy, horizon=args.horizon, max_units=18)
            intrinsic_us = (time.perf_counter_ns() - t0) / 1000.0
            core = {f'e:{i}' for i in ex.event_positions} | {f'r:{r}' for r in ex.rule_ids}
            eps, rids, units = unit_info(trace, policy, args.horizon)
            m = len(units)
            f = predictor(trace, policy, eps, rids)

            x = np.ones((1, m))
            bg = np.zeros((1, m))
            np.random.seed(20261011 + case_id)
            t0 = time.perf_counter_ns()
            sh_explainer=shap.KernelExplainer(f,bg)
            t1=time.perf_counter_ns()
            sv = np.asarray(sh_explainer.shap_values(
                x, nsamples=min(2 ** m, 1024), silent=True))
            t2=time.perf_counter_ns()
            shap_setup_us=(t1-t0)/1000.; shap_us=(t2-t1)/1000.
            vals = sv[0, :, target_idx] if sv.ndim == 3 else np.asarray(sv[target_idx])[0]
            shap_rank = [units[i] for i in np.argsort(-np.abs(vals))]
            shap_k, shap_sel = smallest_sufficient(trace, policy, shap_rank, args.horizon)
            t3=time.perf_counter_ns()
            shap_certification_us=(t3-t2)/1000.; shap_total_us=(t3-t0)/1000.

            lime_us = np.nan
            lime_k = np.nan
            lime_sel = tuple()
            lime_score = np.nan
            lime_setup_us=lime_certification_us=lime_total_us=np.nan
            if LimeTabularExplainer is not None:
                # Full-policy intervention universe: up to 13 binary units.
                # Background construction belongs to setup cost.
                t0=time.perf_counter_ns()
                train = np.array(list(product([0, 1], repeat=m)), dtype=float)
                lime = LimeTabularExplainer(
                    train, mode='classification', feature_names=units,
                    categorical_features=list(range(m)),
                    categorical_names={i: ['0', '1'] for i in range(m)},
                    class_names=CLASSES, discretize_continuous=False,
                    random_state=20260816 + case_id)
                t1 = time.perf_counter_ns()
                le = lime.explain_instance(np.ones(m), f, labels=(target_idx,),
                                           num_features=m, num_samples=args.lime_samples)
                t2=time.perf_counter_ns()
                lime_setup_us=(t1-t0)/1000.; lime_us=(t2-t1)/1000.
                weights = {units[i]: float(w) for i, w in le.local_exp.get(target_idx, [])}
                lime_rank = sorted(units, key=lambda u: abs(weights.get(u, 0.0)), reverse=True)
                lime_k, lime_sel = smallest_sufficient(trace, policy, lime_rank, args.horizon)
                t3=time.perf_counter_ns()
                lime_certification_us=(t3-t2)/1000.; lime_total_us=(t3-t0)/1000.
                lime_score = float(le.score)

            shap_set, lime_set = set(shap_sel), set(lime_sel)
            proof_columns={};shap_proof=lime_proof=None
            if args.proof_matched:
                start=time.perf_counter_ns();shap_proof=certify_fixed_set(trace,policy,shap_set,args.horizon);shap_proof_us=(time.perf_counter_ns()-start)/1000.
                start=time.perf_counter_ns();lime_proof=certify_fixed_set(trace,policy,lime_set,args.horizon) if LimeTabularExplainer is not None else None;lime_proof_us=(time.perf_counter_ns()-start)/1000.
                proof_columns=dict(intrinsic_proof_total_us=intrinsic_us,shap_fixed_set_proof_us=shap_proof_us,shap_proof_total_us=shap_total_us+shap_proof_us,lime_fixed_set_proof_us=lime_proof_us,lime_proof_total_us=lime_total_us+lime_proof_us,shap_proof_checks=shap_proof['checks'],lime_proof_checks=lime_proof['checks'] if lime_proof else None,shap_proof_minimal=int(shap_proof['minimal']),lime_proof_minimal=int(lime_proof['minimal']) if lime_proof else None)
            jac = lambda a, b: len(a & b) / len(a | b) if a | b else 1.0
            def valid(s):
                suff=tpe.exact_sufficiency_of_selected(trace,policy,s,args.horizon)
                mini=suff and all(not tpe.exact_sufficiency_of_selected(trace,policy,s-{u},args.horizon) for u in s)
                return int(bool(suff)),int(bool(mini))
            core_valid,core_minimal=valid(core)
            shap_valid,shap_minimal=valid(shap_set)
            lime_valid,lime_minimal=valid(lime_set) if LimeTabularExplainer is not None else (None,None)
            rows.append({
                **proof_columns,
                'case': case_id, 'seed': seed, 'event_index': event_index,
                'event_id': e.eid, 'scenario': scenario, 'truth': int(e.malicious or 0),
                'target_class': factual.alert_class, 'n_units': m,
                'intrinsic_core_size': len(core), 'intrinsic_checks': ex.checks,
                'intrinsic_us': intrinsic_us,
                'shap_us': shap_us, 'shap_sufficient_k': shap_k,
                'shap_setup_us':shap_setup_us,'shap_selection_certification_us':shap_certification_us,'shap_total_us':shap_total_us,
                'lime_setup_us':lime_setup_us,'lime_selection_certification_us':lime_certification_us,'lime_total_us':lime_total_us,
                'intrinsic_sufficient':core_valid,'intrinsic_minimal':core_minimal,
                'shap_sufficient':shap_valid,'shap_minimal':shap_minimal,'lime_sufficient':lime_valid,'lime_minimal':lime_minimal,
                'shap_selected':';'.join(sorted(shap_set)),'lime_selected':';'.join(sorted(lime_set)),
                'shap_jaccard_with_core': jac(core, shap_set),
                'lime_us': lime_us, 'lime_sufficient_k': lime_k,
                'lime_jaccard_with_core': jac(core, lime_set) if LimeTabularExplainer is not None else np.nan,
                'lime_score': lime_score,
                'core': ';'.join(sorted(core)),
            })
            if not any(d['scenario']==scenario for d in detailed):
                detailed.append(dict(case=case_id,scenario=scenario,seed=seed,event_index=event_index,target=factual.alert_class,trace=[asdict(event) for event in trace],units=units,core=sorted(core),witnesses=ex.witnesses,shap_weights={u:float(w) for u,w in zip(units,vals)},shap_selected=sorted(shap_set),lime_weights=weights if LimeTabularExplainer is not None else None,lime_selected=sorted(lime_set),shap_fixed_set_proof=shap_proof,lime_fixed_set_proof=lime_proof))
            case_id += 1
            if not args.quiet: print(rows[-1], flush=True)
            elif case_id % 25 == 0: print(f'completed {case_id} cases',flush=True)

    df = pd.DataFrame(rows)
    df.to_csv(RAW / 'rq2_local_lab_explanations.csv', index=False)
    (RAW/'detailed_examples.json').write_text(json.dumps(detailed,indent=2),encoding='utf-8')
    summary = (
        df.groupby('scenario', as_index=False)
          .agg(cases=('case', 'size'),
               n_units_mean=('n_units', 'mean'),
               intrinsic_core_size_mean=('intrinsic_core_size', 'mean'),
               intrinsic_us_mean=('intrinsic_us', 'mean'),
               shap_us_mean=('shap_us', 'mean'),
               lime_us_mean=('lime_us', 'mean'),
               shap_jaccard_mean=('shap_jaccard_with_core', 'mean'),
               lime_jaccard_mean=('lime_jaccard_with_core', 'mean'))
    )
    summary.to_csv(SUMMARY / 'rq2_local_lab_explanations_summary.csv', index=False)
    mean_columns=['n_units','intrinsic_core_size','intrinsic_sufficient','intrinsic_minimal','shap_sufficient','shap_minimal','lime_sufficient','lime_minimal','intrinsic_us','shap_setup_us','shap_us','shap_selection_certification_us','shap_total_us','lime_setup_us','lime_us','lime_selection_certification_us','lime_total_us','shap_jaccard_with_core','lime_jaccard_with_core']
    if args.proof_matched:mean_columns+=list(proof_columns)
    df.groupby('scenario')[mean_columns].mean().to_csv(RAW/'corrected_summary.csv')
    print('\n', summary.to_string(index=False))
    print('\nOVERALL\n', df[['n_units','intrinsic_core_size','intrinsic_us','shap_us','lime_us',
                               'shap_jaccard_with_core','lime_jaccard_with_core']].mean().to_string())


if __name__ == '__main__':
    main()
