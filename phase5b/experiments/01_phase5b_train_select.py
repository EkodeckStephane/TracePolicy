from __future__ import annotations
import json, gzip, hashlib, sys, time, sqlite3
from pathlib import Path
from collections import defaultdict, deque
import pandas as pd

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from darpa_adapter import build_entity_index, iter_events
from phase5b_trace_policy import (
    P1Config, learn_training_profile, select_p0_selectors, freeze_p1,
    selector_key, subject_key, is_sensitive_selector, frozen_to_jsonable,
    compile_p0_policy, compile_p1_policy,
)


def sha256(p: Path):
    h=hashlib.sha256()
    with open(p,'rb') as f:
        for b in iter(lambda:f.read(1024*1024),b''): h.update(b)
    return h.hexdigest()


def load_cfg():
    return json.loads((ROOT/'config/phase5b.json').read_text())


def exact_files(data_root: Path, names):
    out=[]
    for name in names:
        p=data_root/name
        if not p.exists():
            raise SystemExit(f'Missing required extracted CADETS member: {p}')
        if p.name.endswith('.ok') or '.tar.gz' in p.name:
            raise SystemExit(f'Invalid dataset member selected: {p}')
        out.append(p)
    return out


def policy_rows(policy):
    rows=[]
    for r in policy.rules:
        rows.append({
            'pid':policy.pid,'version':policy.version,'rid':r.rid,'priority':r.priority,
            'effect':r.effect,'action':r.selector.action,'resource_class':r.selector.resource_class,
            'subject_class':r.selector.subject_class,
            'seq_actions':' > '.join(r.guard.seq_actions) if r.guard.seq_actions else '',
            'seq_horizon':r.guard.seq_horizon,
        })
    return rows


def evaluate_validation(files, entity_db, p0, candidates):
    # No ground-truth mapping is loaded here by design.
    histories=defaultdict(lambda: deque(maxlen=3))
    counts={i:{'alerts':0,'sensitive':0,'sensitive_alerts':0,'trace_covered':0,'events':0,'current_covered':0}
            for i in range(len(candidates))}
    p0_alerts=0; n=0; p0_covered=0
    max_k=max(c.config.sequence_length for c in candidates)
    histories=defaultdict(lambda: deque(maxlen=max_k-1))
    for e in iter_events(files,entity_db,malicious_ids=set()):
        n+=1; sel=selector_key(e); sk=subject_key(e); hist=histories[sk]
        current=sel in p0
        if current:p0_covered+=1
        else:p0_alerts+=1
        for i,c in enumerate(candidates):
            d=counts[i];d['events']+=1;d['current_covered']+=int(current)
            if not current:
                d['alerts']+=1
            elif sel in c.sensitive_selectors:
                d['sensitive']+=1
                k=c.config.sequence_length
                seq=tuple(list(hist)[-(k-1):]+[e.action]) if len(hist)>=k-1 else ()
                ok=bool(seq and (sel,seq) in c.allowed_sequences)
                d['trace_covered']+=int(ok)
                if not ok:
                    d['alerts']+=1;d['sensitive_alerts']+=1
        hist.append(e.action)
        if n%1000000==0: print('validation events',n)
    rows=[]
    p0_rate=p0_alerts/max(1,n)
    for i,c in enumerate(candidates):
        d=counts[i]
        rows.append({
            'candidate_id':i,
            **c.config.as_dict(),
            'rule_count':c.rule_count,
            'trace_allow_rules':len(c.allowed_sequences),
            'sensitive_selectors':len(c.sensitive_selectors),
            'validation_events':n,
            'p0_validation_alert_rate':p0_rate,
            'p0_current_coverage':p0_covered/max(1,n),
            'p1_validation_alert_rate':d['alerts']/max(1,n),
            'extra_alert_rate_vs_p0':(d['alerts']-p0_alerts)/max(1,n),
            'sensitive_events':d['sensitive'],
            'sensitive_trace_coverage':d['trace_covered']/max(1,d['sensitive']),
            'sensitive_alert_rate':d['sensitive_alerts']/max(1,d['sensitive']),
        })
    return pd.DataFrame(rows)


def main():
    cfg=load_cfg();data_root=ROOT/'datasets/raw/darpa_e3/cadets'
    out=ROOT/'results/phase5b';logs=ROOT/'results/logs/phase5b';proc=ROOT/'datasets/processed'
    out.mkdir(parents=True,exist_ok=True);logs.mkdir(parents=True,exist_ok=True);proc.mkdir(parents=True,exist_ok=True)
    freeze_marker=out/'P1_FROZEN_BEFORE_TEST.json'
    if freeze_marker.exists():
        raise SystemExit('P1 freeze marker already exists. Refusing to re-select P1 in a workspace where test may have been opened. Use a clean Phase5B run directory.')

    train=exact_files(data_root,cfg['train_members']); val=exact_files(data_root,cfg['validation_members'])
    test_paths=[str(data_root/x) for x in cfg['test_members']]
    # Ensure selection script never opens test data. It records names only, not hashes or contents.
    for p in map(Path,test_paths):
        if not p.exists(): raise SystemExit(f'Test file missing before freeze (existence check only): {p}')

    train_db=proc/'phase5b_train_entities.sqlite';val_db=proc/'phase5b_validation_entities.sqlite'
    for p in [train_db,val_db]:
        if p.exists(): p.unlink()
    print('Building train-only entity index...')
    build_entity_index(train,train_db,logs/'train_entity_index.json')
    print('Building validation-only entity index...')
    build_entity_index(val,val_db,logs/'validation_entity_index.json')

    # Training may use the pre-existing ThreaTrace mapping only to exclude linked events from benign support counts.
    # This does NOT use test event outcomes or test policy performance.
    gt_path=ROOT/'datasets/seed/cadets_groundtruth_threatrace.txt'
    gt={x.strip().upper() for x in gt_path.read_text(errors='ignore').splitlines() if x.strip()}
    print('Learning Phase5B training profile...')
    profile=learn_training_profile(iter_events(train,train_db,gt),cfg['sequence_lengths'],exclude_malicious_link=True)
    p0=select_p0_selectors(profile,cfg['min_current_support'],cfg['max_current_rules'])

    candidates=[]
    for k in cfg['sequence_lengths']:
        for sup in cfg['min_sequence_support_grid']:
            c=P1Config(int(k),int(sup),int(cfg['max_sequences_per_selector']),float(cfg['primary_extra_alert_budget']))
            candidates.append(freeze_p1(profile,c,cfg['min_current_support'],cfg['max_current_rules']))

    print('Single-pass validation calibration (NO attack labels)...')
    grid=evaluate_validation(val,val_db,p0,candidates)
    grid.to_csv(out/'phase5b_validation_grid.csv',index=False)

    chosen=None;used_budget=None
    for budget in cfg['validation_extra_alert_budget_schedule']:
        feas=grid[grid.extra_alert_rate_vs_p0 <= float(budget)+1e-15].copy()
        if len(feas):
            # Predeclared sensitivity rule: use as much of the allowed validation alert budget as possible.
            # Ties: longer sequence, then fewer trace rules.
            feas=feas.sort_values(['p1_validation_alert_rate','sequence_length','trace_allow_rules'],ascending=[False,False,True])
            chosen=feas.iloc[0];used_budget=float(budget);break
    if chosen is None:
        (out/'PHASE5B_STOP_NO_FEASIBLE_P1.md').write_text(
            '# Phase 5B stop\n\nNo P1 candidate met the predeclared validation alert budgets. Test was not opened.\n')
        raise SystemExit(5)

    idx=int(chosen.candidate_id);selected=candidates[idx]
    # Rebind recorded budget to the actual predeclared budget level used.
    selected=type(selected)(selected.p0_selectors,selected.sensitive_selectors,selected.allowed_sequences,
        P1Config(selected.config.sequence_length,selected.config.min_sequence_support,selected.config.max_sequences_per_selector,used_budget),
        selected.min_current_support,selected.max_current_rules,selected.pid,selected.version)

    artifact=frozen_to_jsonable(selected)
    artifact['selection']={
        'method':'largest validation alert rate not exceeding P0 + predeclared extra-alert budget',
        'validation_labels_used':False,
        'used_extra_alert_budget':used_budget,
        'candidate_id':idx,
        'validation_row':{k:(v.item() if hasattr(v,'item') else v) for k,v in chosen.to_dict().items()},
    }
    artifact['split']={
        'train_members':cfg['train_members'],'validation_members':cfg['validation_members'],'test_members':cfg['test_members'],
        'train_sha256':{p.name:sha256(p) for p in train},
        'validation_sha256':{p.name:sha256(p) for p in val},
        'test_not_opened_during_selection':True,
    }
    artifact_path=out/'phase5b_p1_frozen.json.gz'
    with gzip.open(artifact_path,'wt',encoding='utf-8') as f: json.dump(artifact,f,sort_keys=True)
    artifact_sha=sha256(artifact_path)

    p0pol=compile_p0_policy(set(selected.p0_selectors),1);p1pol=compile_p1_policy(selected)
    pd.DataFrame(policy_rows(p0pol)).to_csv(out/'phase5b_p0_rules.csv',index=False)
    pd.DataFrame(policy_rows(p1pol)).to_csv(out/'phase5b_p1_rules.csv',index=False)

    marker={
        'status':'FROZEN_BEFORE_TEST', 'frozen_policy_file':artifact_path.name,'frozen_policy_sha256':artifact_sha,
        'selected_config':selected.config.as_dict(),'p0_rule_count':len(p0pol.rules),'p1_rule_count':len(p1pol.rules),
        'training_events_seen':profile.training_events,'training_malicious_link_events_excluded':profile.excluded_malicious_link_events,
        'training_unique_current_selectors':len(profile.selector_counts),
        'training_sensitive_sequence_counts':{str(k):len(v) for k,v in profile.sequence_counts.items()},
        'selection_used_test_labels':False,'selection_opened_test_content':False,
        'test_members_names_only':cfg['test_members'], 'created_unix':time.time(),
    }
    freeze_marker.write_text(json.dumps(marker,indent=2,sort_keys=True))
    print(json.dumps(marker,indent=2))
    print('P1 frozen. Only now may experiments/02_phase5b_test_once.py be run.')

if __name__=='__main__': main()
