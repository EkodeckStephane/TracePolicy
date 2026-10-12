import sys,itertools,json,hashlib,csv
from dataclasses import asdict
from pathlib import Path
import numpy as np
import pytest
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'src'),str(ROOT/'experiments')]
from revision_extended_methods import minimal_masks_dp,independent_table,load_frozen_cases
from revision_explanation_benchmark import controlled_cases,all_minimal_cores
import trace_policy_engine as tpe

@pytest.mark.parametrize('name,trace,policy,horizon',controlled_cases())
def test_dp_matches_independent_core_enumeration(name,trace,policy,horizon):
    eps,rids,units=tpe.explanation_unit_info(trace,policy,horizon)
    labels,_=independent_table(trace,policy,eps,rids);target=tpe.reference_eval(trace,policy).alert_class
    table={tuple((k>>i)&1 for i in range(len(units))):[tpe.NOALERT,tpe.VIOLATION,tpe.CONFLICT,tpe.GAP][int(y)] for k,y in enumerate(labels)}
    expected=all_minimal_cores(units,table,target)
    masks,sufficient=minimal_masks_dp(labels==[tpe.NOALERT,tpe.VIOLATION,tpe.CONFLICT,tpe.GAP].index(target),len(units))
    actual=[{units[i] for i in range(len(units)) if mask&(1<<i)} for mask in masks]
    assert {frozenset(c) for c in actual}=={frozenset(c) for c in expected}
    for k in range(1<<len(units)):
        bits=[(k>>i)&1 for i in range(len(units))]
        assert labels[k]==[tpe.NOALERT,tpe.VIOLATION,tpe.CONFLICT,tpe.GAP].index(tpe._class_under_mask(trace,policy,eps,rids,bits))

def test_dp_arbitrary_nonmonotone_truth_functions():
    rng=np.random.default_rng(20261012)
    for n in range(1,7):
        for _ in range(12):
            matches=rng.integers(0,2,size=1<<n).astype(bool);matches[-1]=True
            masks,sufficient=minimal_masks_dp(matches,n)
            expected=[]
            for core in range(1<<n):
                is_sufficient=all(matches[assignment] for assignment in range(1<<n) if assignment&core==core)
                assert bool(sufficient[core])==is_sufficient
                if is_sufficient and all(not sufficient[core^(1<<i)] for i in range(n) if core&(1<<i)):expected.append(core)
            assert masks==expected

def test_dp_rejects_incomplete_truth_table():
    with pytest.raises(ValueError):minimal_masks_dp([True,False,True],2)

def test_dp_empty_core_and_unsatisfiable_target():
    masks,_=minimal_masks_dp(np.ones(16,bool),4);assert masks==[0]
    masks,_=minimal_masks_dp(np.zeros(16,bool),4);assert masks==[]

def test_full_thirteen_unit_threshold_has_four_alternative_cores():
    matches=np.array([bool(k&(1<<4) and k&(1<<8) and sum(bool(k&(1<<i)) for i in range(5))>=4) for k in range(1<<13)])
    masks,_=minimal_masks_dp(matches,13)
    expected=[(1<<4)|(1<<8)|sum(1<<i for i in prior) for prior in itertools.combinations(range(4),3)]
    assert set(masks)==set(expected)

def test_windows_saved_manifest_keys_load_real_files_on_any_host(tmp_path):
    from local_lab_adapter import lab_policy
    hashes={};strata=[]
    for seed in range(30):
        rows=[('admin_probe','/admin/a',403),('command_probe','/cmd/a',403),('path_traversal','/../../etc/passwd',403)]+[('bruteforce','/login',401)]*4
        access=tmp_path/f'access_{seed}.jsonl';truth=tmp_path/f'truth_{seed}.csv'
        access.write_text('\n'.join(json.dumps(dict(sid=f'{seed}-{i}',ts=i,path=path,status=status)) for i,(_,path,status) in enumerate(rows)),encoding='utf-8')
        with truth.open('w',newline='') as stream:
            writer=csv.DictWriter(stream,fieldnames=['sid','label','scenario']);writer.writeheader();writer.writerows(dict(sid=f'{seed}-{i}',label=1,scenario=scenario) for i,(scenario,_,_) in enumerate(rows))
        for path in [access,truth]:hashes['C:\\Original Source\\lab\\'+path.name]=hashlib.sha256(path.read_bytes()).hexdigest()
        for i in [0,1,2,6]:strata.append(dict(seed=seed,status='selected',event_index=i,event_id=f'{seed}-{i}',scenario=rows[i][0]))
    p=lab_policy();manifest=dict(input_sha256=hashes,policy_sha256=hashlib.sha256(json.dumps(asdict(p),sort_keys=True).encode()).hexdigest(),strata=strata,arguments={'horizon':5})
    _,cases,inputs=load_frozen_cases(manifest,tmp_path)
    assert len(cases)==120 and len(inputs)==60
    assert all(tpe.reference_eval(c['trace'],p).alert_class==tpe.VIOLATION for c in cases)
