import sys,json,hashlib
from dataclasses import asdict
from pathlib import Path
import pytest
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'src'),str(ROOT/'experiments')]
import trace_policy_engine as tpe
from revision_catalog_methods import load_catalog,parse_policy
from revision_explanation_benchmark import controlled_cases

def save_catalog(tmp_path,initial=None,target=None,units=None):
    _,tr,p,h=next(c for c in controlled_cases() if c[0]=='temporal_seq')
    payload=dict(schema_version=1,policy=asdict(p),cases=[dict(case=9,trace=[asdict(e) for e in tr],horizon=h,initial_state=initial or {},target_class=target or tpe.VIOLATION)])
    if units is not None:payload['cases'][0]['units']=units
    path=tmp_path/'catalog.json';path.write_text(json.dumps(payload),encoding='utf-8');return path,p,tr

def test_catalog_policy_round_trip_preserves_all_interventions(tmp_path):
    path,p,tr=save_catalog(tmp_path);_,parsed,cases=load_catalog(path)
    assert cases[0]['case']==9
    eps,rids,units=tpe.explanation_unit_info(tr,p,3)
    for k in range(1<<len(units)):
        bits=[(k>>i)&1 for i in range(len(units))]
        assert tpe._class_under_mask(tr,p,eps,rids,bits)==tpe._class_under_mask(cases[0]['trace'],parsed,eps,rids,bits)

@pytest.mark.parametrize('kwargs,match',[(dict(initial={'privileged':True}),'initial state'),(dict(target=tpe.GAP),'target mismatch'),(dict(units=['e:0']),'unit domain mismatch')])
def test_catalog_rejects_unsupported_or_mismatched_factual_instance(tmp_path,kwargs,match):
    path,_,_=save_catalog(tmp_path,**kwargs)
    with pytest.raises(ValueError,match=match):load_catalog(path)

def test_catalog_does_not_silently_accept_noalert(tmp_path):
    path,_,_=save_catalog(tmp_path);raw=json.loads(path.read_text());raw['policy']['rules'][0]['effect']=tpe.ALLOW;raw['cases'][0].pop('target_class');path.write_text(json.dumps(raw))
    with pytest.raises(ValueError,match='NoAlert'):load_catalog(path)

def test_catalog_refuses_mutated_frozen_policy_payload(tmp_path):
    path,p,_=save_catalog(tmp_path);raw=json.loads(path.read_text());raw['policy_content_sha256']=hashlib.sha256(json.dumps(asdict(p),sort_keys=True).encode()).hexdigest();raw['policy']['rules'][0]['priority']+=1;path.write_text(json.dumps(raw))
    with pytest.raises(ValueError,match='policy content hash mismatch'):load_catalog(path)

def test_catalog_rejects_fractional_priorities_instead_of_changing_semantics(tmp_path):
    path,_,_=save_catalog(tmp_path);raw=json.loads(path.read_text());raw['policy']['rules'][0]['priority']=10.5;path.write_text(json.dumps(raw))
    with pytest.raises(ValueError,match='priorities must be integers'):load_catalog(path)

def test_catalog_rejects_wrong_current_event_identity(tmp_path):
    path,_,_=save_catalog(tmp_path);raw=json.loads(path.read_text());raw['cases'][0]['event_id']='wrong-source-event';path.write_text(json.dumps(raw))
    with pytest.raises(ValueError,match='event identity'):load_catalog(path)
