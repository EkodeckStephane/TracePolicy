"""Timestamp-preserving THEIA hosted derivative, frozen chronological replay.

Prepare and evaluate do not read labels. The separate labels stage requires the
exact label schema and identity audit before reporting detection metrics.
Data/output paths explicit, compatible with portable release layout.
"""
from __future__ import annotations
import argparse
from collections import Counter
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import sys
import time
import duckdb
import pyarrow.parquet as pq

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
import trace_policy_engine as tpe

EXPECTED={'event_table.parquet':'08c006812b25b56c0e1f1e3fbceac144027fcee43f1adc81cd92491497f570e1',
          'process_node_table.parquet':'69a057f2fce1da35d4f8c22e4ee8b73ce2fd5c14a02689bc123c67d29a08543b'}
LABEL_EXPECTED={'reapr_edge_labels.parquet':'c77aa8a99386043aac42524c12527c9653c508d8d628a6474c380ad5862d80d8',
                'reapr_node_labels.parquet':'4ec8b53b9507f47dc6afb1917ef4fd13ed1dca7007744dcbd97686ed8e54f860'}
REVERSED=('EVENT_EXECUTE','EVENT_LSEEK','EVENT_MMAP','EVENT_OPEN','EVENT_ACCEPT',
          'EVENT_READ','EVENT_RECVFROM','EVENT_RECVMSG','EVENT_READ_SOCKET_PARAMS',
          'EVENT_CHECK_FILE_ATTRIBUTES','READ')
def sha(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for b in iter(lambda:f.read(1048576),b''): h.update(b)
    return h.hexdigest()
def content_sha(x): return hashlib.sha256(json.dumps(x,sort_keys=True).encode()).hexdigest()
def write(path,x): path.write_text(json.dumps(x,indent=2),encoding='utf8')
def q(path): return "'"+str(path.resolve()).replace('\\','/').replace("'","''")+"'"
def connection(out):
    db=duckdb.connect(str(out/'chronology.duckdb'))
    db.execute("SET memory_limit='2GB'")
    db.execute('SET threads=4')
    db.execute('SET temp_directory='+q(out/'duckdb_tmp'))
    return db

def process_identity_audit(db):
    row=db.execute('SELECT count(*),count(distinct index_id),count(distinct hash_id),count(distinct upper(node_uuid)),count(index_id),count(hash_id),count(node_uuid) FROM processes').fetchone()
    audit=dict(zip(['rows','distinct_indexes','distinct_hashes','distinct_uuids','nonnull_indexes','nonnull_hashes','nonnull_uuids'],map(int,row)))
    if any(audit[k]!=audit['rows'] for k in audit if k!='rows'):
        raise ValueError('Process identities must be unique and nonnull; join could duplicate events')
    return audit

def normalized_identity_audit(db):
    n,unique=db.execute('SELECT count(*),count(distinct row_id) FROM chronological').fetchone()
    audit=dict(normalized_rows=int(n),distinct_original_row_ids=int(unique))
    if n!=unique:raise ValueError('Chronological normalization duplicated source row identity')
    return audit

def node_label_identity_audit(db):
    audit={
        'invalid_node_uuid':int(db.execute("SELECT count(*) FROM node_labels WHERE id IS NULL OR NOT regexp_full_match(id,'[0-9A-F]{8}(-[0-9A-F]{4}){3}-[0-9A-F]{12}')").fetchone()[0]),
        'node_keys_multiple_labels':int(db.execute('SELECT count(*) FROM(SELECT id FROM node_labels GROUP BY id HAVING count(distinct label)>1)').fetchone()[0])}
    if audit['invalid_node_uuid'] or audit['node_keys_multiple_labels']:
        raise ValueError('Ambiguous/malformed node labels; metrics withheld')
    return audit

def prepare(data,out):
    out.mkdir(parents=True,exist_ok=True)
    hashes={n:sha(data/n) for n in EXPECTED}
    if hashes!=EXPECTED: raise ValueError('Source hash mismatch')
    db=connection(out)
    event=q(data/'event_table.parquet'); proc=q(data/'process_node_table.parquet')
    rev=','.join("'"+x+"'" for x in REVERSED)
    db.execute(f'CREATE OR REPLACE VIEW raw AS SELECT * FROM read_parquet({event},file_row_number=true)')
    db.execute(f'CREATE OR REPLACE VIEW processes AS SELECT * FROM read_parquet({proc})')
    identity_audit=process_identity_audit(db)
    bounds=db.execute('SELECT min(timestamp_rec),max(timestamp_rec),count(*),count(timestamp_rec) FROM raw').fetchone()
    lo,hi,total,nonnull=map(int,bounds); cut1=lo+(hi-lo)*6//10;cut2=lo+(hi-lo)*8//10
    spec=dict(source='alafage/darpa_tc_e3_theia',revision='690e8889c36429db1f62da22ec7ac06254d76e6a',
              input_sha256=hashes,timestamp_unit='nanoseconds',bounds=[lo,hi],cuts=[cut1,cut2],
              train=f'ts<{cut1}',validation=f'{cut1}<=ts<{cut2}',test=f'ts>={cut2}',
              min_support=20,selector_cap=6,predecessor_cap=3,history='same verified process, consecutive events, carried across partition cuts',
              reverse_operations=list(REVERSED),p2_probe=['EVENT_EXECUTE','EVENT_CONNECT'],
              labels_used_for_policy=False,validation_tuning=False,sampling='earliest32 P1 alerts; earliest32 P1-P0 deltas; earliest32 P2 Seq alerts; no label consultation',
              prior_static_THEIA_inspection=True,total_source_rows=total,missing_timestamp_rows=total-nonnull)
    write(out/'protocol.json',spec)
    print('Normalizing verified actors and computing process-local predecessors',flush=True)
    db.execute(f'''CREATE OR REPLACE TABLE chronological AS
      WITH candidates AS (
        SELECT file_row_number AS row_id,timestamp_rec AS ts,event_uuid,operation,
          CASE WHEN operation IN ({rev}) THEN dst_index_id ELSE src_index_id END AS actor,
          CASE WHEN operation IN ({rev}) THEN dst_node ELSE src_node END AS actor_hash,
          src_index_id,dst_index_id FROM raw WHERE timestamp_rec IS NOT NULL),
      verified AS (SELECT c.* FROM candidates c JOIN processes p ON c.actor=p.index_id AND c.actor_hash=p.hash_id)
      SELECT *,lag(operation) OVER w AS previous_action,lag(ts) OVER w AS previous_ts,
        lag(row_id) OVER w AS previous_row,lag(event_uuid) OVER w AS previous_uuid
      FROM verified WINDOW w AS (PARTITION BY actor ORDER BY ts,row_id)''')
    n=db.execute('select count(*) from chronological').fetchone()[0]
    identity_audit.update(normalized_identity_audit(db))
    write(out/'normalization_identity_audit.json',identity_audit)
    counts=db.execute(f'SELECT operation,count(*) FROM chronological WHERE ts<{cut1} GROUP BY operation HAVING count(*)>=20 ORDER BY count(*) DESC,operation LIMIT6'.replace('LIMIT6','LIMIT 6')).fetchall()
    allowed=[x[0] for x in counts]
    preceding={a:[x[0] for x in db.execute('SELECT previous_action,count(*) FROM chronological WHERE ts<? AND operation=? AND previous_action IS NOT NULL GROUP BY previous_action HAVING count(*)>=20 ORDER BY count(*) DESC,previous_action LIMIT 3',[cut1,a]).fetchall()] for a in allowed}
    def fallback(): return tpe.Rule('D_UNSEEN',0,tpe.DENY,tpe.Selector())
    p0=tpe.PolicyVersion('THEIA_TIME_P0',1,tuple([tpe.Rule(f'A{i}',10,tpe.ALLOW,tpe.Selector(a,'entity','process')) for i,a in enumerate(allowed)]+[fallback()]))
    p1=tpe.PolicyVersion('THEIA_TIME_P1',1,tuple([tpe.Rule(f'A_SEQ{i}',10,tpe.ALLOW,tpe.Selector(a,'entity','process'),tpe.Guard(any_of=tuple(tpe.Guard(seq_actions=(b,a),seq_horizon=2) for b in preceding[a]))) for i,a in enumerate(allowed) if preceding[a]]+[fallback()]))
    p2=tpe.PolicyVersion('THEIA_TIME_P2_DIAGNOSTIC',1,p0.rules+(tpe.Rule('D_EXEC_CONNECT',100,tpe.DENY,tpe.Selector('EVENT_CONNECT','entity','process'),tpe.Guard(seq_actions=('EVENT_EXECUTE','EVENT_CONNECT'),seq_horizon=2)),))
    freeze=dict(protocol=spec,protocol_sha256=content_sha(spec),accepted_rows=n,rejected_actor_or_hash_rows=total-n,
                training_operation_counts=counts,predecessors=preceding,
                policies={p.pid:dict(policy=asdict(p),policy_content_sha256=content_sha(asdict(p))) for p in (p0,p1,p2)},
                splits=[dict(split=s,n=db.execute('SELECT count(*) FROM chronological WHERE '+cond).fetchone()[0]) for s,cond in [('train',f'ts<{cut1}'),('validation',f'ts>={cut1} AND ts<{cut2}'),('test',f'ts>={cut2}')]])
    freeze['policy_manifest_sha256']=content_sha(freeze)
    write(out/'frozen.json',freeze)
    db.close();print('Frozen chronological policies; no labels or test decisions accessed',flush=True)

def policy_load(item):
    def guard(g):
        d=dict(g)
        for k in ('all_of','any_of','none_of'):d[k]=tuple(guard(x) for x in d[k])
        for k in ('comparisons','state_comparisons'):d[k]=tuple(tuple(x) for x in d[k])
        d['seq_actions']=tuple(d['seq_actions']);return tpe.Guard(**d)
    p=item['policy'];pol=tpe.PolicyVersion(p['pid'],p['version'],tuple(tpe.Rule(r['rid'],r['priority'],r['effect'],tpe.Selector(**r['selector']),guard(r['guard'])) for r in p['rules']),p['created_at'])
    if content_sha(asdict(pol))!=item['policy_content_sha256']:raise ValueError('Policy hash mismatch')
    return pol

def evaluate(data,out):
    frozen=json.loads((out/'frozen.json').read_text());spec=frozen['protocol'];cut=spec['cuts'][1]
    if {n:sha(data/n) for n in EXPECTED}!=EXPECTED:raise ValueError('Source input changed')
    db=connection(out)
    allowed=[x[0] for x in frozen['training_operation_counts']]
    db.register('allowed_actions',__import__('pyarrow').table({'operation':allowed}))
    pairs=[(a,b) for a,bs in frozen['predecessors'].items() for b in bs]
    db.register('allowed_pairs',__import__('pyarrow').table({'operation':[a for a,b in pairs],'previous_action':[b for a,b in pairs]}))
    db.execute(f'''CREATE OR REPLACE TABLE test_decisions AS SELECT c.*,
      NOT EXISTS(SELECT1 FROM allowed_actions a WHERE a.operation=c.operation) AS p0,
      NOT EXISTS(SELECT1 FROM allowed_pairs a WHERE a.operation=c.operation AND a.previous_action=c.previous_action) AS p1,
      (NOT EXISTS(SELECT1 FROM allowed_actions a WHERE a.operation=c.operation) OR (c.operation='EVENT_CONNECT' AND c.previous_action='EVENT_EXECUTE')) AS p2
      FROM chronological c WHERE ts>={cut}'''.replace('SELECT1','SELECT 1'))
    result=dict(protocol_sha256=frozen['protocol_sha256'],policy_manifest_sha256=frozen['policy_manifest_sha256'],
                rows=db.execute('select count(*) from test_decisions').fetchone()[0],
                alerts={m:db.execute(f'SELECT count(*) FROM test_decisions WHERE {m}').fetchone()[0] for m in ('p0','p1','p2')},
                temporal_deltas=db.execute('select count(*) from test_decisions where p1<>p0').fetchone()[0],
                diagnostic_seq_fires=db.execute("select count(*) from test_decisions where operation='EVENT_CONNECT' AND previous_action='EVENT_EXECUTE'").fetchone()[0])
    catalogs={}
    for policyid,condition,tag in [('THEIA_TIME_P1','p1','p1_earliest_alerts'),('THEIA_TIME_P1','p1<>p0','p1_temporal_delta'),('THEIA_TIME_P2_DIAGNOSTIC',"operation='EVENT_CONNECT' AND previous_action='EVENT_EXECUTE'",'p2_positive_sequence')]:
        item=frozen['policies'][policyid];policy=policy_load(item)
        rows=db.execute(f'SELECT row_id,ts,event_uuid,operation,actor,previous_action,previous_ts,previous_row,previous_uuid FROM test_decisions WHERE {condition} ORDER BY ts,row_id LIMIT 32').fetchall()
        cases=[]
        for i,(rid,ts,uid,action,actor,pa,pts,prid,puid) in enumerate(rows):
            tr=[]
            if pa is not None:tr.append(tpe.Event(str(puid)+':'+str(prid),pts/1e9,pa,'entity','process',{'process_index':actor,'timestamp_ns':pts,'row_id':prid}))
            tr.append(tpe.Event(str(uid)+':'+str(rid),ts/1e9,action,'entity','process',{'process_index':actor,'timestamp_ns':ts,'row_id':rid}))
            ref=tpe.reference_eval(tr,policy);inc=tpe.IncrementalEvaluator(policy)
            for e in tr:actual=inc.push(e)
            if ref.alert_class!=actual.alert_class or ref.top!=actual.top:raise AssertionError('Evaluator disagreement')
            if ref.alert_class not in (tpe.VIOLATION,tpe.CONFLICT,tpe.GAP):raise AssertionError('Unexpected NoAlert sampled')
            if tag=='p2_positive_sequence' and 'D_EXEC_CONNECT' not in ref.top:raise AssertionError('Sequence probe not active')
            cases.append(dict(case=i,event_id=tr[-1].eid,scenario=tag,alertstratum=tag,target_class=ref.alert_class,
                              trace=[asdict(e) for e in tr],horizon=2,initial_state={},units=tpe.explanation_unit_info(tr,policy,2)[2],
                              metadata={'original_subject_row':rid,'original_timestamp_ns':ts,'source_process':actor,'stream_segment':'exact two consecutive events for this verified process, guard horizon2, no state atoms'}))
        catalog=dict(schema_version=1,policy=asdict(policy),policy_content_sha256=item['policy_content_sha256'],
                     policy_manifest_sha256=frozen['policy_manifest_sha256'],protocol_sha256=frozen['protocol_sha256'],
                     input_sha256=spec['input_sha256'],sampling_description=tag+' earliest32 by true ns timestamp/original row, labels not consulted',cases=cases)
        write(out/(tag+'_catalog.json'),catalog);catalogs[tag]=dict(n=len(cases),path=tag+'_catalog.json')
    result['catalogs']=catalogs
    # Label outcome join is a separate explicit phase after all semantic freeze/checks.
    result['detection_metrics']='withheld until REAPr identity schema is audited'
    write(out/'semantic_result.json',result);db.close();print(json.dumps(result),flush=True)

def label_metrics(data,out):
    if {n:sha(data/n) for n in LABEL_EXPECTED}!=LABEL_EXPECTED:raise ValueError('Label source hash mismatch')
    frozen=json.loads((out/'frozen.json').read_text());db=connection(out)
    db.execute('CREATE OR REPLACE VIEW edge_labels AS SELECT upper(edge_uuid) AS id,vertex_label AS label FROM read_parquet('+q(data/'reapr_edge_labels.parquet')+')')
    db.execute('CREATE OR REPLACE VIEW node_labels AS SELECT upper(uuid) AS id,label FROM read_parquet('+q(data/'reapr_node_labels.parquet')+')')
    audit={}
    audit['edge_label_records']=db.execute('SELECT label,count(*),count(distinct id) FROM edge_labels GROUP BY label').fetchall()
    audit['edge_keys_multiple_labels']=db.execute('SELECT count(*) FROM(SELECT id FROM edge_labels GROUP BY id HAVING count(distinct label)>1)').fetchone()[0]
    audit['invalid_edge_uuid']=db.execute("SELECT count(*) FROM edge_labels WHERE id IS NULL OR NOT regexp_full_match(id,'[0-9A-F]{8}(-[0-9A-F]{4}){3}-[0-9A-F]{12}')").fetchone()[0]
    db.execute("CREATE OR REPLACE TABLE attack_edge_keys AS SELECT DISTINCT id FROM edge_labels WHERE label='attack'")
    audit['attack_edge_keys']=db.execute('SELECT count(*) FROM attack_edge_keys').fetchone()[0]
    audit['attack_edge_keys_matched_whole_chronology']=db.execute('SELECT count(distinct a.id) FROM attack_edge_keys a JOIN chronological c ON a.id=upper(c.event_uuid)').fetchone()[0]
    audit['attack_edge_keys_matched_test']=db.execute('SELECT count(distinct a.id) FROM attack_edge_keys a JOIN test_decisions c ON a.id=upper(c.event_uuid)').fetchone()[0]
    audit['attack_event_rows_in_test']=db.execute('SELECT count(*) FROM test_decisions c WHERE EXISTS(SELECT 1 FROM attack_edge_keys a WHERE a.id=upper(c.event_uuid))').fetchone()[0]
    audit['duplicate_test_event_uuid_rows']=db.execute('SELECT count(*)-count(distinct event_uuid) FROM test_decisions').fetchone()[0]
    audit['contaminated_event_rows_excluded']=db.execute("SELECT count(*) FROM test_decisions c WHERE EXISTS(SELECT 1 FROM edge_labels a WHERE a.id=upper(c.event_uuid) AND a.label='contaminated')").fetchone()[0]
    if audit['invalid_edge_uuid'] or audit['edge_keys_multiple_labels']:raise ValueError('Ambiguous/malformed edge labels; metrics withheld')
    def metrics(tp,fp,fn,tn):
        return dict(tp=tp,fp=fp,fn=fn,tn=tn,precision=tp/(tp+fp) if tp+fp else 0,
                    recall=tp/(tp+fn) if tp+fn else 0,f1=2*tp/(2*tp+fp+fn) if 2*tp+fp+fn else 0,
                    fpr=fp/(fp+tn) if fp+tn else 0)
    event={}
    for model in ('p0','p1','p2'):
        result=db.execute(f'''WITH labeled AS(SELECT {model} AS pred,EXISTS(SELECT 1 FROM attack_edge_keys a WHERE a.id=upper(c.event_uuid)) AS truth FROM test_decisions c WHERE NOT EXISTS(SELECT 1 FROM edge_labels a WHERE a.id=upper(c.event_uuid) AND a.label='contaminated'))
          SELECT count(*) FILTER(WHERE pred AND truth),count(*) FILTER(WHERE pred AND NOT truth),count(*) FILTER(WHERE NOT pred AND truth),count(*) FILTER(WHERE NOT pred AND NOT truth) FROM labeled''').fetchone()
        event[model]=metrics(*map(int,result))
    db.execute('CREATE OR REPLACE VIEW processes AS SELECT * FROM read_parquet('+q(data/'process_node_table.parquet')+')')
    audit['node_label_records']=db.execute('SELECT label,count(*),count(distinct id) FROM node_labels GROUP BY label').fetchall()
    audit.update(node_label_identity_audit(db))
    audit['attack_node_keys']=db.execute("SELECT count(distinct id) FROM node_labels WHERE label='attack'").fetchone()[0]
    audit['attack_node_keys_matched_process_table']=db.execute("SELECT count(distinct n.id) FROM node_labels n JOIN processes p ON n.id=upper(p.node_uuid) WHERE n.label='attack'").fetchone()[0]
    db.execute('CREATE OR REPLACE TABLE test_actor_predictions AS SELECT actor,bool_or(p0) AS p0,bool_or(p1) AS p1,bool_or(p2) AS p2 FROM test_decisions GROUP BY actor')
    audit['test_active_processes']=db.execute('SELECT count(*) FROM test_actor_predictions').fetchone()[0]
    audit['attack_node_keys_active_test']=db.execute("SELECT count(distinct n.id) FROM node_labels n JOIN processes p ON n.id=upper(p.node_uuid) JOIN test_actor_predictions a ON a.actor=p.index_id WHERE n.label='attack'").fetchone()[0]
    audit['contaminated_active_processes_excluded']=db.execute("SELECT count(*) FROM test_actor_predictions a JOIN processes p ON a.actor=p.index_id WHERE EXISTS(SELECT 1 FROM node_labels n WHERE n.id=upper(p.node_uuid) AND n.label='contaminated')").fetchone()[0]
    node={}
    for model in ('p0','p1','p2'):
        values=db.execute(f'''WITH labeled AS(SELECT a.{model} AS pred,EXISTS(SELECT 1 FROM node_labels n WHERE n.id=upper(p.node_uuid) AND n.label='attack') AS truth FROM test_actor_predictions a JOIN processes p ON a.actor=p.index_id WHERE NOT EXISTS(SELECT 1 FROM node_labels n WHERE n.id=upper(p.node_uuid) AND n.label='contaminated'))
          SELECT count(*) FILTER(WHERE pred AND truth),count(*) FILTER(WHERE pred AND NOT truth),count(*) FILTER(WHERE NOT pred AND truth),count(*) FILTER(WHERE NOT pred AND NOT truth) FROM labeled''').fetchone()
        node[model]=metrics(*map(int,values))
    payload=dict(protocol_sha256=frozen['protocol_sha256'],policy_manifest_sha256=frozen['policy_manifest_sha256'],
                 label_sha256=LABEL_EXPECTED,identity_audit=audit,event_uuid_proxy_metrics=event,active_process_node_metrics=node,
                 limitations=['unlisted edge/process treated negative; annotations are derived REAPr, not exhaustive official event truth',
                              'contaminated event/process identities excluded from scoring; missing annotation treated negative',
                              'node metric only verified subject-process actors active during the test period',
                              'no labels used in policy construction; training may contain attacks',
                              'P2 fixed positive sequence had zero test firings; no retuning'])
    write(out/'detection_metrics.json',payload);db.close();print(json.dumps(payload),flush=True)

def verify_semantics(data,out):
    frozen=json.loads((out/'frozen.json').read_text());db=connection(out)
    db.execute('CREATE OR REPLACE VIEW processes AS SELECT * FROM read_parquet('+q(data/'process_node_table.parquet')+')')
    identity_audit=process_identity_audit(db)
    identity_audit.update(normalized_identity_audit(db))
    write(out/'normalization_identity_audit.json',identity_audit)
    patterns=db.execute('SELECT operation,previous_action,p0,p1,p2,count(*) FROM test_decisions GROUP BY operation,previous_action,p0,p1,p2').fetchall()
    failures=[];counts=Counter()
    for action,pa,p0,p1,p2,n in patterns:
        tr=[]
        if pa is not None:tr.append(tpe.Event('previous',1.,pa,'entity','process'))
        tr.append(tpe.Event('current',2.,action,'entity','process'))
        for name,expected in [('THEIA_TIME_P0',p0),('THEIA_TIME_P1',p1),('THEIA_TIME_P2_DIAGNOSTIC',p2)]:
            policy=policy_load(frozen['policies'][name]);ref=tpe.reference_eval(tr,policy);idx=tpe.StaticIndex(policy).eval(tr);inc=tpe.IncrementalEvaluator(policy)
            for e in tr:stream=inc.push(e)
            predicted=ref.alert_class in (tpe.VIOLATION,tpe.CONFLICT)
            if bool(predicted)!=bool(expected) or ref.alert_class!=idx.alert_class or ref.alert_class!=stream.alert_class or ref.top!=idx.top or ref.top!=stream.top:
                failures.append(dict(action=action,previous_action=pa,policy=name,sql_prediction=bool(expected),reference=asdict(ref),indexed=asdict(idx),incremental=asdict(stream)))
            counts[name]+=int(n)
    payload=dict(test_observed_patterns=len(patterns),pattern_weighted_rows=dict(counts),failures=failures,
                 claim='all observed action/predecessor equivalence classes exhaustively compared, not independent evaluation of every repeated row',
                 soundness_scope='only current-action and consecutive-process-action guards, no state atoms; exact class/top through reference,indexed,incremental',
                 protocol_sha256=frozen['protocol_sha256'],policy_manifest_sha256=frozen['policy_manifest_sha256'])
    write(out/'semantic_verification.json',payload);db.close()
    if failures:raise AssertionError('Temporal semantic mismatches')
    print(json.dumps(payload),flush=True)

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('stage',choices=['prepare','evaluate','labels','verify']);p.add_argument('--data-dir',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    {'prepare':prepare,'evaluate':evaluate,'labels':label_metrics,'verify':verify_semantics}[a.stage](a.data_dir,a.output)
