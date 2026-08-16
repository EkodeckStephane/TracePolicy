from __future__ import annotations
import argparse,sys,json,gzip,csv,time,tarfile,io,re,sqlite3
from pathlib import Path
import pandas as pd
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from darpa_adapter import (
    EntityIndex,
    _datum,
    _event_type,
    _properties_map,
    _uuid,
    _unwrap,
    iter_events,
    load_malicious_ids,
    path_bucket,
    resource_class,
)
from policy_io import load_policy_csv
from trace_policy_engine import Event,IncrementalEvaluator,VIOLATION,CONFLICT
from metrics import binary_metrics

def choose_json(root:Path,prefix:str):
    out=[]
    for p in root.iterdir():
        if not p.is_file(): continue
        if not p.name.startswith(prefix): continue
        if '.tar.gz' in p.name or p.name.endswith('.ok'): continue
        # Accept base JSON and numeric split members only.
        tail=p.name[len(prefix):]
        if tail=='' or (tail.startswith('.') and tail[1:].isdigit()):
            out.append(p)
    return sorted(out,key=lambda p:(0 if p.name==prefix else int(p.name.rsplit('.',1)[-1])))

def archive_members(tar_path:Path,prefix:str):
    def order(name):
        base=Path(name).name
        if base==prefix: return 0
        m=re.match(r'^'+re.escape(prefix)+r'\.(\d+)$',base)
        return int(m.group(1)) if m else 10**9
    with tarfile.open(tar_path,'r:gz') as tf:
        members=[m for m in tf.getmembers() if m.isfile() and Path(m.name).name.startswith(prefix)]
        for m in sorted(members,key=lambda x:order(x.name)):
            yield m

def iter_archive_records(archives,prefix):
    for tar_path in archives:
        with tarfile.open(tar_path,'r:gz') as tf:
            members=list(archive_members(tar_path,prefix))
            for m in members:
                fh=tf.extractfile(m)
                if fh is None: continue
                with fh, io.TextIOWrapper(fh,encoding='utf-8',errors='replace') as f:
                    for line in f:
                        try:
                            yield tar_path.name+'!'+m.name,json.loads(line)
                        except Exception:
                            continue

def build_entity_index_from_archives(archives,sqlite_path:Path,log_path:Path):
    sqlite_path.parent.mkdir(parents=True,exist_ok=True)
    for suffix in ('','-wal','-shm'):
        p=Path(str(sqlite_path)+suffix)
        if p.exists(): p.unlink()
    con=sqlite3.connect(sqlite_path)
    con.execute('PRAGMA journal_mode=OFF')
    con.execute('PRAGMA synchronous=OFF')
    con.execute('CREATE TABLE entity(uuid TEXT PRIMARY KEY, type TEXT, path TEXT, meta TEXT)')
    n=0;bad=0;batch=[]
    for prefix,paths in archives:
        for _,rec in iter_archive_records(paths,prefix):
            typ,obj=_datum(rec)
            if not typ or typ=='Event' or not isinstance(obj,dict): continue
            uid=_uuid(obj.get('uuid'))
            if not uid: continue
            path=''
            for key in ('path','name'):
                if key in obj and obj[key] is not None:
                    path=str(_unwrap(obj[key])); break
            props=_properties_map(obj.get('properties',{}))
            if not path:
                path=str(props.get('path') or props.get('name') or props.get('exec') or '')
            meta=json.dumps({k:props.get(k) for k in ('exec','cmdLine','name','path') if k in props},sort_keys=True)
            batch.append((uid,typ,path,meta)); n+=1
            if len(batch)>=10000:
                con.executemany('INSERT OR REPLACE INTO entity(uuid,type,path,meta) VALUES(?,?,?,?)',batch)
                batch.clear()
            if n%100000==0:
                con.commit(); print('entity_records',n)
    if batch:
        con.executemany('INSERT OR REPLACE INTO entity(uuid,type,path,meta) VALUES(?,?,?,?)',batch)
    con.commit(); con.close()
    log_path.write_text(json.dumps({'entity_records_indexed':n,'json_decode_errors':bad,'source':'tar_stream'},indent=2))

def ensure_entity_db(droot:Path,sqlite_path:Path):
    if sqlite_path.exists():
        return {'rebuilt':False,'path':str(sqlite_path)}
    train=droot/'ta1-cadets-e3-official.json.tar.gz'
    test=droot/'ta1-cadets-e3-official-2.json.tar.gz'
    missing=[str(p) for p in (train,test) if not p.exists()]
    if missing:
        raise SystemExit('Missing DARPA archives required to stream-build entity DB: '+', '.join(missing))
    logs=ROOT/'results/logs'; logs.mkdir(parents=True,exist_ok=True)
    build_entity_index_from_archives([
        ('ta1-cadets-e3-official.json',[train]),
        ('ta1-cadets-e3-official-2.json',[test]),
    ],sqlite_path,logs/'darpa_entity_index_v2.json')
    return {'rebuilt':True,'path':str(sqlite_path)}

def iter_events_from_archives(archives,entity_db:Path,malicious_ids):
    idx=EntityIndex(entity_db); mal={x.strip().upper() for x in (malicious_ids or set()) if x.strip()}
    emitted=0
    try:
        for source,rec in iter_archive_records(archives,'ta1-cadets-e3-official-2.json'):
            typ,obj=_datum(rec)
            if typ!='Event' or not isinstance(obj,dict): continue
            su=_uuid(obj.get('subject')); ou=_uuid(obj.get('predicateObject')); o2=_uuid(obj.get('predicateObject2'))
            evu=_uuid(obj.get('uuid')); et=_event_type(obj.get('type'))
            ts=_unwrap(obj.get('timestampNanos'))
            try: ts=float(ts)/1e9
            except Exception: ts=float(emitted)
            otype,opath,ometa=idx.get(ou)
            path=str(_unwrap(obj.get('predicateObjectPath')) or opath or '')
            props=_properties_map(obj.get('properties',{}))
            execv=str(props.get('exec') or '')
            attrs={'subject_uuid':su,'object_uuid':ou,'object2_uuid':o2,'event_uuid':evu,
                   'path':path,'path_bucket':path_bucket(path),'exec':execv,'raw_object_type':otype}
            m=int(bool(mal and ({su,ou,o2,evu} & mal)))
            yield Event(evu or f'{source}:{emitted}',ts,et,resource_class(otype,path),'process',attrs,m,
                        'malicious_entity_link' if m else 'normal')
            emitted+=1
    finally:
        idx.close()

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--data-root',default=str(ROOT/'datasets/raw/darpa_e3/cadets'))
    ap.add_argument('--groundtruth',default=str(ROOT/'datasets/seed/cadets_groundtruth_threatrace.txt'))
    ap.add_argument('--entity-db',default=str(ROOT/'datasets/processed/darpa_cadets_entities.sqlite'))
    ap.add_argument('--policy',default=str(ROOT/'results/raw/rq5_darpa_policy_rules.csv'))
    args=ap.parse_args()

    droot=Path(args.data_root)
    test=choose_json(droot,'ta1-cadets-e3-official-2.json')
    db_info=ensure_entity_db(droot,Path(args.entity_db))
    gt=load_malicious_ids(Path(args.groundtruth))
    policy=load_policy_csv(Path(args.policy))
    inc=IncrementalEvaluator(policy)
    if test:
        event_stream=iter_events(test,Path(args.entity_db),gt)
        test_sources=[str(p) for p in test]
        streamed_from_archives=False
    else:
        archive=droot/'ta1-cadets-e3-official-2.json.tar.gz'
        if not archive.exists(): raise SystemExit('No extracted CADETS E3 test JSON members or test archive found')
        event_stream=iter_events_from_archives([archive],Path(args.entity_db),gt)
        test_sources=[str(archive)]
        streamed_from_archives=True

    present=set(); predicted=set(); first_alert={}
    n_events=0; n_alerts=0
    for e in event_stream:
        nodes={str(e.attrs.get(k,'')).upper() for k in ('subject_uuid','object_uuid','object2_uuid')}
        nodes.discard('')
        present.update(nodes)
        r=inc.push(e); n_events+=1
        if r.alert_class in (VIOLATION,CONFLICT):
            n_alerts+=1
            for u in nodes:
                predicted.add(u)
                first_alert.setdefault(u,e.eid)
        if n_events%1000000==0: print('events',n_events,'present_nodes',len(present),'predicted_nodes',len(predicted))

    truth=gt & present
    y=[];yp=[]; rows=[]
    for u in sorted(present):
        yy=int(u in truth); pp=int(u in predicted)
        y.append(yy);yp.append(pp)
        if yy or pp: rows.append({'uuid':u,'truth':yy,'pred':pp,'first_alert_event':first_alert.get(u,'')})
    m=binary_metrics(y,yp)
    m.update({
        'unit':'entity_node',
        'groundtruth_source':'ThreaTrace-derived CADETS malicious-node UUID mapping',
        'official_darpa_event_groundtruth':False,
        'events_scanned':n_events,
        'alert_events':n_alerts,
        'test_entity_nodes':len(present),
        'truth_positive_nodes_in_test':len(truth),
        'predicted_positive_nodes':len(predicted),
        'policy_version':policy.version,
        'policy_rules':len(policy.rules),
        'streamed_from_archives':streamed_from_archives,
    })
    out=ROOT/'results/raw'; logs=ROOT/'results/logs'; out.mkdir(parents=True,exist_ok=True);logs.mkdir(parents=True,exist_ok=True)
    pd.DataFrame([m]).to_csv(out/'rq5_darpa_entity_metrics_v2.csv',index=False)
    with gzip.open(out/'rq5_darpa_entity_predictions_v2.csv.gz','wt',newline='') as f:
        w=csv.DictWriter(f,fieldnames=['uuid','truth','pred','first_alert_event']);w.writeheader();w.writerows(rows)
    (logs/'darpa_groundtruth_unit_v2.json').write_text(json.dumps({
        'truth_mapping':'ThreaTrace-derived node/entity UUID mapping',
        'mapping_uuid_count':len(gt),
        'mapping_present_in_test_count':len(truth),
        'evaluation_unit':'CDM entity node (subject/predicateObject/predicateObject2)',
        'event_uuid_used_as_node':False,
        'event_level_existing_label':'malicious_entity_link proxy',
        'official_DARPA_report_role':'narrative scenario provenance; not parsed into structured event UUID labels',
        'test_files':test_sources,
        'streamed_from_archives':streamed_from_archives,
        'entity_db':db_info,
    },indent=2))
    print(pd.DataFrame([m]).to_string(index=False))

if __name__=='__main__': main()
