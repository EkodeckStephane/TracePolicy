from __future__ import annotations
import json, sqlite3, hashlib, os, re
from pathlib import Path
from collections import Counter
from typing import Iterable, Iterator, Dict, Any, Optional, Sequence, Tuple, Set
from trace_policy_engine import Event, Rule, Selector, Guard, PolicyVersion, ALLOW, DENY

UUID_SUFFIX='UUID'

def _unwrap(v):
    if isinstance(v, dict) and len(v)==1:
        return next(iter(v.values()))
    return v

def _uuid(v) -> str:
    if v is None: return ''
    v=_unwrap(v)
    if isinstance(v, dict):
        for k,x in v.items():
            if k.endswith(UUID_SUFFIX): return str(x).upper()
    return str(v).upper()

def _datum(record: Dict[str,Any]):
    d=record.get('datum',record)
    if not isinstance(d,dict) or not d: return None,None
    k=next(iter(d.keys())); return k.rsplit('.',1)[-1], d[k]

def _event_type(v):
    x=_unwrap(v)
    return str(x or 'UNKNOWN').replace('EVENT_','').lower()

def path_bucket(path: str) -> str:
    p=(path or '').lower()
    if not p: return 'none'
    for pref,name in [('/etc/','etc'),('/usr/','usr'),('/bin/','bin'),('/sbin/','sbin'),('/home/','home'),('/tmp/','tmp'),('/var/','var'),('/dev/','dev'),('/proc/','proc'),('/opt/','opt')]:
        if p.startswith(pref): return name
    if p.startswith('/'): return 'root_other'
    return 'other'

def resource_class(entity_type: str, path: str='') -> str:
    t=(entity_type or 'unknown').lower()
    if 'fileobject' in t: return f'file:{path_bucket(path)}'
    if 'netflow' in t: return 'network'
    if 'subject' in t: return 'process'
    if 'pipe' in t: return 'pipe'
    if 'registry' in t: return 'registry'
    if 'memory' in t: return 'memory'
    if 'srcsink' in t: return 'ipc'
    return 'other'

def _properties_map(v):
    if not isinstance(v,dict): return {}
    v=_unwrap(v)
    if isinstance(v,dict) and 'map' in v and isinstance(v['map'],dict): return v['map']
    return v if isinstance(v,dict) else {}

def build_entity_index(json_files: Sequence[Path], sqlite_path: Path, error_log: Optional[Path]=None):
    sqlite_path.parent.mkdir(parents=True,exist_ok=True)
    con=sqlite3.connect(sqlite_path)
    con.execute('PRAGMA journal_mode=WAL')
    con.execute('CREATE TABLE IF NOT EXISTS entity(uuid TEXT PRIMARY KEY, type TEXT, path TEXT, meta TEXT)')
    bad=0; n=0
    for fp in json_files:
        with open(fp,'r',encoding='utf-8',errors='replace') as f:
            for ln,line in enumerate(f,1):
                try: rec=json.loads(line)
                except Exception:
                    bad+=1; continue
                typ,obj=_datum(rec)
                if not typ or typ=='Event' or not isinstance(obj,dict): continue
                uid=_uuid(obj.get('uuid'))
                if not uid: continue
                path=str(_unwrap(obj.get('baseObject',{}).get('properties',{})) if False else '')
                # Common path/name fields vary by CDM record type.
                for key in ('path','name'):
                    if key in obj and obj[key] is not None:
                        path=str(_unwrap(obj[key])); break
                props=_properties_map(obj.get('properties',{}))
                if not path:
                    path=str(props.get('path') or props.get('name') or props.get('exec') or '')
                meta=json.dumps({k:props.get(k) for k in ('exec','cmdLine','name','path') if k in props},sort_keys=True)
                con.execute('INSERT OR REPLACE INTO entity(uuid,type,path,meta) VALUES(?,?,?,?)',(uid,typ,path,meta)); n+=1
                if n%100000==0: con.commit()
    con.commit(); con.close()
    if error_log:
        error_log.write_text(json.dumps({'entity_records_indexed':n,'json_decode_errors':bad},indent=2))
    return n,bad

class EntityIndex:
    def __init__(self, sqlite_path: Path):
        self.con=sqlite3.connect(sqlite_path)
        self.cache={}
    def get(self,uid:str):
        uid=(uid or '').upper()
        if uid in self.cache: return self.cache[uid]
        row=self.con.execute('SELECT type,path,meta FROM entity WHERE uuid=?',(uid,)).fetchone()
        out=row if row else ('unknown','','{}')
        if len(self.cache)>100000: self.cache.clear()
        self.cache[uid]=out; return out
    def close(self): self.con.close()

def iter_events(json_files: Sequence[Path], entity_db: Path, malicious_ids: Optional[Set[str]]=None,
                max_events: Optional[int]=None) -> Iterator[Event]:
    idx=EntityIndex(entity_db); mal={x.strip().upper() for x in (malicious_ids or set()) if x.strip()}
    emitted=0
    try:
        for fp in json_files:
            with open(fp,'r',encoding='utf-8',errors='replace') as f:
                for line in f:
                    try: rec=json.loads(line)
                    except Exception: continue
                    typ,obj=_datum(rec)
                    if typ!='Event' or not isinstance(obj,dict): continue
                    su=_uuid(obj.get('subject')); ou=_uuid(obj.get('predicateObject')); o2=_uuid(obj.get('predicateObject2'))
                    evu=_uuid(obj.get('uuid'))
                    et=_event_type(obj.get('type'))
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
                    yield Event(evu or f'{fp.name}:{emitted}',ts,et,resource_class(otype,path),'process',attrs,m,
                                'malicious_entity_link' if m else 'normal')
                    emitted+=1
                    if max_events is not None and emitted>=max_events: return
    finally:
        idx.close()

def selector_key(e: Event):
    return (e.action,e.resource_class,e.subject_class)

def learn_whitelist_policy(training_events: Iterable[Event], min_support:int=20, version:int=1,
                           max_allow_rules:int=500) -> Tuple[PolicyVersion,Counter]:
    counts=Counter(selector_key(e) for e in training_events)
    selected=[(k,c) for k,c in counts.items() if c>=min_support]
    selected.sort(key=lambda z:(-z[1],z[0])); selected=selected[:max_allow_rules]
    rules=[]
    for i,((a,r,s),c) in enumerate(selected):
        rules.append(Rule(f'A_DARPA_{i:04d}',10,ALLOW,Selector(a,r,s)))
    # Explicit fallback DENY makes an unseen selector an operational violation rather than a policy gap.
    rules.append(Rule('D_DARPA_UNSEEN_SELECTOR',0,DENY,Selector('*','*','*'),Guard(comparisons=(('action','!=','__STUTTER__'),))))
    return PolicyVersion('DARPA_CADETS_WHITELIST',version,tuple(rules)),counts

def load_malicious_ids(path: Path) -> Set[str]:
    return {x.strip().upper() for x in path.read_text(errors='ignore').splitlines() if x.strip()}
