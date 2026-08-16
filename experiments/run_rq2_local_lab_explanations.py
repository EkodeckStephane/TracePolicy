from __future__ import annotations
import argparse, csv, sys, time
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
from local_lab_adapter import load_gateway_events, lab_policy
try:
    from lime.lime_tabular import LimeTabularExplainer
except ModuleNotFoundError:
    LimeTabularExplainer = None

CLASSES = [tpe.NOALERT, tpe.VIOLATION, tpe.CONFLICT, tpe.GAP]
RAW = ROOT / 'results' / 'raw'
SUMMARY = ROOT / 'results' / 'summary'
RAW.mkdir(parents=True, exist_ok=True)
SUMMARY.mkdir(parents=True, exist_ok=True)


def load_truth(path: Path):
    return {r['sid']: {'label': int(r['label']), 'scenario': r['scenario']}
            for r in csv.DictReader(open(path, newline=''))}


def unit_info(trace, policy, horizon):
    start = max(0, len(trace) - horizon)
    eps = list(range(start, len(trace)))
    current = trace[-1]
    rids = [r.rid for r in policy.rules if r.selector.matches(current)]
    units = [f'e:{i}' for i in eps] + [f'r:{r}' for r in rids]
    return eps, rids, units


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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--lab-dir', default=str(ROOT / 'local_lab' / 'results'))
    ap.add_argument('--per-scenario', type=int, default=25)
    ap.add_argument('--horizon', type=int, default=5)
    ap.add_argument('--lime-samples', type=int, default=5000)
    args = ap.parse_args()

    policy, by_scenario = collect_cases(Path(args.lab_dir), args.per_scenario, args.horizon)
    expected = {'admin_probe', 'bruteforce', 'command_probe', 'path_traversal'}
    missing = expected - set(by_scenario)
    if missing:
        raise SystemExit(f'Missing true-positive scenarios: {sorted(missing)}')

    rows = []
    case_id = 0
    for scenario in sorted(expected):
        cases = by_scenario[scenario]
        if len(cases) < args.per_scenario:
            raise SystemExit(f'Only {len(cases)} cases for {scenario}; required {args.per_scenario}.')
        for seed, event_index, trace, e in cases[:args.per_scenario]:
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
            t0 = time.perf_counter_ns()
            sv = np.asarray(shap.KernelExplainer(f, bg).shap_values(
                x, nsamples=min(2 ** m, 1024), silent=True))
            shap_us = (time.perf_counter_ns() - t0) / 1000.0
            vals = sv[0, :, target_idx] if sv.ndim == 3 else np.asarray(sv[target_idx])[0]
            shap_rank = [units[i] for i in np.argsort(-np.abs(vals))]
            shap_k, shap_sel = smallest_sufficient(trace, policy, shap_rank, args.horizon)

            lime_us = np.nan
            lime_k = np.nan
            lime_sel = tuple()
            lime_score = np.nan
            if LimeTabularExplainer is not None:
                # m <= 7 in the retained local-lab policy, so exact binary enumeration
                # remains small and matches the intervention domain used in the original RQ2.
                train = np.array(list(product([0, 1], repeat=m)), dtype=float)
                lime = LimeTabularExplainer(
                    train, mode='classification', feature_names=units,
                    categorical_features=list(range(m)),
                    categorical_names={i: ['0', '1'] for i in range(m)},
                    class_names=CLASSES, discretize_continuous=False,
                    random_state=20260816 + case_id)
                t0 = time.perf_counter_ns()
                le = lime.explain_instance(np.ones(m), f, labels=(target_idx,),
                                           num_features=m, num_samples=args.lime_samples)
                lime_us = (time.perf_counter_ns() - t0) / 1000.0
                weights = {units[i]: float(w) for i, w in le.local_exp.get(target_idx, [])}
                lime_rank = sorted(units, key=lambda u: abs(weights.get(u, 0.0)), reverse=True)
                lime_k, lime_sel = smallest_sufficient(trace, policy, lime_rank, args.horizon)
                lime_score = float(le.score)

            shap_set, lime_set = set(shap_sel), set(lime_sel)
            jac = lambda a, b: len(a & b) / len(a | b) if a | b else 1.0
            rows.append({
                'case': case_id, 'seed': seed, 'event_index': event_index,
                'event_id': e.eid, 'scenario': scenario, 'truth': int(e.malicious or 0),
                'target_class': factual.alert_class, 'n_units': m,
                'intrinsic_core_size': len(core), 'intrinsic_checks': ex.checks,
                'intrinsic_us': intrinsic_us,
                'shap_us': shap_us, 'shap_sufficient_k': shap_k,
                'shap_jaccard_with_core': jac(core, shap_set),
                'lime_us': lime_us, 'lime_sufficient_k': lime_k,
                'lime_jaccard_with_core': jac(core, lime_set) if LimeTabularExplainer is not None else np.nan,
                'lime_score': lime_score,
                'core': ';'.join(sorted(core)),
            })
            case_id += 1
            print(rows[-1], flush=True)

    df = pd.DataFrame(rows)
    df.to_csv(RAW / 'rq2_local_lab_explanations.csv', index=False)
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
    print('\n', summary.to_string(index=False))
    print('\nOVERALL\n', df[['n_units','intrinsic_core_size','intrinsic_us','shap_us','lime_us',
                               'shap_jaccard_with_core','lime_jaccard_with_core']].mean().to_string())


if __name__ == '__main__':
    main()
