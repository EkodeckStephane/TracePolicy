"""Miniature Parquet fixtures test the adapter only; never external study data."""
import json
from pathlib import Path
import sys
import pytest

pa=pytest.importorskip('pyarrow')
pq=pytest.importorskip('pyarrow.parquet')
pytest.importorskip('duckdb')
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'experiments'))
import revision_temporal_external as temporal

@pytest.fixture
def miniature(tmp_path,monkeypatch):
    data=tmp_path/'fixture';data.mkdir();out=tmp_path/'result'
    base=1522764134000380070
    rows=[]
    def add(ts,action,actor):
        reverse=action in temporal.REVERSED
        rows.append(dict(src_node='file' if reverse else f'p{actor}',src_index_id=10 if reverse else actor,
                         operation=action,dst_node=f'p{actor}' if reverse else 'file',dst_index_id=actor if reverse else 10,
                         event_uuid=f'{len(rows):08X}-0000-0000-0000-000000000010',timestamp_rec=base+ts))
    # Supported train predecessors: A OPEN/READ; B repeated WRITE.
    for i in range(60):
        add(2*i,'EVENT_OPEN' if i%2==0 else 'EVENT_READ',1)
        add(2*i+1,'EVENT_WRITE',2)
    add(799,'EVENT_OPEN',1)
    add(801,'EVENT_READ',1)   # carries A's validation predecessor across cut800
    add(802,'EVENT_WRITE',2)  # B's old training predecessor, not A's recent READ
    add(900,'EVENT_WRITE',1)  # unexpected predecessor READ causes temporal delta
    add(950,'EVENT_READ',1)
    add(1000,'EVENT_WRITE',2)
    # Physical input order deliberately differs from timestamp order.
    pq.write_table(pa.Table.from_pylist(list(reversed(rows))),data/'event_table.parquet')
    procs=[dict(node_uuid=f'{i:08X}-0000-0000-0000-000000000020',hash_id=f'p{i}',path='fixture',cmd='fixture',index_id=i) for i in (1,2)]
    pq.write_table(pa.Table.from_pylist(procs),data/'process_node_table.parquet')
    # Explicit fixture-only hash override; production hardcoded source hashes remain.
    monkeypatch.setattr(temporal,'EXPECTED',{n:temporal.sha(data/n) for n in temporal.EXPECTED})
    return data,out,base

def test_nanosecond_actor_normalization_and_boundary_history(miniature):
    data,out,base=miniature
    temporal.prepare(data,out)
    frozen=json.loads((out/'frozen.json').read_text())
    assert frozen['protocol']['cuts']==[base+600,base+800]
    assert frozen['accepted_rows']==126
    db=temporal.connection(out)
    rows=db.execute('SELECT ts,actor,operation,previous_action,previous_ts FROM chronological WHERE ts>=? ORDER BY ts',[base+800]).fetchall()
    db.close()
    assert rows[0]==(base+801,1,'EVENT_READ','EVENT_OPEN',base+799)
    assert rows[1][1:]==(2,'EVENT_WRITE','EVENT_WRITE',base+119)
    assert rows[2][1:]==(1,'EVENT_WRITE','EVENT_READ',base+801)
    # Distinct1ns training events remain ordered despite float precision limitations.
    assert frozen['protocol']['bounds'][0]==base
    assert not (data/'reapr_edge_labels.parquet').exists()
    temporal.evaluate(data,out)  # succeeds with label files completely absent
    temporal.verify_semantics(data,out)
    verified=json.loads((out/'semantic_verification.json').read_text())
    assert verified['failures']==[]
    db=temporal.connection(out)
    delta=db.execute('SELECT p0,p1 FROM test_decisions WHERE ts=?',[base+900]).fetchone();db.close()
    assert delta==(False,True)

def test_changed_source_hash_rejected_before_database_creation(miniature):
    data,out,_=miniature
    with (data/'event_table.parquet').open('ab') as f:f.write(b'changed')
    with pytest.raises(ValueError,match='Source hash mismatch'):temporal.prepare(data,out)
    assert not (out/'chronology.duckdb').exists()

def test_duplicate_process_identity_rejected(miniature):
    data,out,_=miniature
    table=pq.read_table(data/'process_node_table.parquet')
    pq.write_table(pa.concat_tables([table,table.slice(0,1)]),data/'process_node_table.parquet')
    temporal.EXPECTED['process_node_table.parquet']=temporal.sha(data/'process_node_table.parquet')
    with pytest.raises(ValueError,match='Process identities must be unique'):temporal.prepare(data,out)

def test_duplicate_normalized_original_row_identity_rejected(miniature):
    data,out,_=miniature
    temporal.prepare(data,out)
    db=temporal.connection(out)
    db.execute('INSERT INTO chronological SELECT * FROM chronological LIMIT 1')
    with pytest.raises(ValueError,match='duplicated source row identity'):temporal.normalized_identity_audit(db)
    db.close()

@pytest.mark.parametrize('ids,labels',[
    (['malformed'],['attack']),
    ([None],['attack']),
    (['00000001-0000-0000-0000-000000000020']*2,['attack','contaminated']),
])
def test_node_identity_failures_withhold_metrics(ids,labels):
    db=temporal.duckdb.connect()
    db.register('node_labels',pa.table({'id':pa.array(ids,type=pa.string()),'label':labels}))
    with pytest.raises(ValueError,match='metrics withheld'):temporal.node_label_identity_audit(db)
    db.close()
