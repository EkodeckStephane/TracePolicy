from __future__ import annotations
import json,gzip,hashlib,sys,time,csv
from pathlib import Path
from collections import Counter,defaultdict,deque
import pandas as pd

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from darpa_adapter import build_entity_index,iter_events,load_malicious_ids
from phase5b_trace_policy import (
    frozen_from_jsonable,DirectP0Evaluator,DirectSubjectPolicyEvaluator,
    selector_key,subject_key,compile_p1_policy,
)
from trace_policy_engine import StaticIndex,VIOLATION,CONFLICT


def sha256(p:Path):
    h=hashlib.sha256()
    with open(p,'rb') as f:
        for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
    return h.hexdigest()


def metrics(tp,tn,fp,fn):
    precision=tp/(tp+fp) if tp+fp else 0.0
    recall=tp/(tp+fn) if tp+fn else 0.0
    f1=2*precision*recall/(precision+recall) if precision+recall else 0.0
    fpr=fp/(fp+tn) if fp+tn else 0.0
    den=((tp+fp)*(tp+fn)*(tn+fp)*(tn+fn))**0.5
    mcc=((tp*tn)-(fp*fn))/den if den else 0.0
    return {'precision':precision,'recall':recall,'f1':f1,'fpr':fpr,'mcc':mcc,'tp':tp,'tn':tn,'fp':fp,'fn':fn,'n':tp+tn+fp+fn}


def exact_files(data_root,names):
    out=[]
    for n in names:
        p=data_root/n
        if not p.exists():raise SystemExit(f'Missing test member {p}')
        out.append(p)
    return out


def main():
    cfg=json.loads((ROOT/'config/phase5b.json').read_text())
    out=ROOT/'results/phase5b';logs=ROOT/'results/logs/phase5b';proc=ROOT/'datasets/processed'
    freeze=out/'P1_FROZEN_BEFORE_TEST.json';opened=out/'TEST_OPENED_ONCE.json'
    if not freeze.exists():raise SystemExit('P1 is not frozen. Run 01_phase5b_train_select.py first.')
    if opened.exists():raise SystemExit('Phase5B test has already been opened in this workspace. Refusing a second test pass.')
    marker=json.loads(freeze.read_text());artifact=out/marker['frozen_policy_file']
    if sha256(artifact)!=marker['frozen_policy_sha256']:raise SystemExit('Frozen P1 artifact hash mismatch.')
    with gzip.open(artifact,'rt',encoding='utf-8') as f:p1=frozen_from_jsonable(json.load(f))

    data_root=ROOT/'datasets/raw/darpa_e3/cadets';test=exact_files(data_root,cfg['test_members'])
    # Test content is opened only after the frozen-policy hash was validated.
    opened.write_text(json.dumps({'opened_unix':time.time(),'test_sha256':{p.name:sha256(p) for p in test},'frozen_policy_sha256':marker['frozen_policy_sha256']},indent=2))

    test_db=proc/'phase5b_test_entities.sqlite'
    if test_db.exists():test_db.unlink()
    print('Building test-only entity index after freeze...')
    build_entity_index(test,test_db,logs/'test_entity_index.json')
    gt=load_malicious_ids(ROOT/'datasets/seed/cadets_groundtruth_threatrace.txt')

    p0_eval=DirectP0Evaluator(set(p1.p0_selectors));p1_eval=DirectSubjectPolicyEvaluator(p1)
    p0_pred_nodes=set();p1_pred_nodes=set();present_nodes=set();event_counts={'P0':[0,0,0,0],'P1':[0,0,0,0]}
    # entries are tp,tn,fp,fn at event-proxy level, accumulated later
    reason_truth=Counter();quality=Counter();n=0;p0_ns=0;p1_ns=0

    # Semantic equivalence sample between direct P1 evaluator and compiled generic policy.
    compiled=compile_p1_policy(p1);index=StaticIndex(compiled);sample_hist=defaultdict(lambda:deque(maxlen=max(1,p1.config.sequence_length-1)))
    equivalence_checked=0;equivalence_divergences=0

    def upd(name,y,p):
        arr=event_counts[name]
        if y and p:arr[0]+=1
        elif (not y) and (not p):arr[1]+=1
        elif (not y) and p:arr[2]+=1
        else:arr[3]+=1

    for e in iter_events(test,test_db,gt):
        n+=1;y=int(e.malicious or 0);sel=selector_key(e);sk=subject_key(e)
        nodes={str(e.attrs.get(k,'')).upper() for k in ('subject_uuid','object_uuid','object2_uuid') if e.attrs.get(k,'')}
        present_nodes.update(nodes)
        t0=time.perf_counter_ns();p0,why0=p0_eval.classify(e);p0_ns+=time.perf_counter_ns()-t0
        t1=time.perf_counter_ns();p1a,why1,current_covered,trace_covered,seq=p1_eval.classify(e);p1_ns+=time.perf_counter_ns()-t1
        upd('P0',y,int(p0));upd('P1',y,int(p1a))
        if p0:p0_pred_nodes.update(nodes)
        if p1a:p1_pred_nodes.update(nodes)
        reason_truth[(why1,y)]+=1
        quality[('current_covered',y)]+=int(current_covered)
        quality[('events',y)]+=1
        if sel in p1.sensitive_selectors:
            quality[('sensitive_events',y)]+=1
            quality[('sensitive_trace_covered',y)]+=int(trace_covered)

        # First 20k events: prove direct compiled decision equivalence on subject-local traces.
        if equivalence_checked<20000:
            h=sample_hist[sk];tr=list(h)+[e]
            rr=index.eval(tr)
            generic_alert=rr.alert_class in (VIOLATION,CONFLICT)
            if bool(generic_alert)!=bool(p1a):equivalence_divergences+=1
            h.append(e);equivalence_checked+=1
        if n%1000000==0:print('test events',n,'P0 nodes',len(p0_pred_nodes),'P1 nodes',len(p1_pred_nodes))

    if equivalence_divergences:
        raise RuntimeError(f'P1 compiled/direct semantic divergence: {equivalence_divergences}/{equivalence_checked}')

    truth_nodes=gt & present_nodes
    rows=[]
    for name,pnodes in [('P0',p0_pred_nodes),('P1',p1_pred_nodes)]:
        tp=len(pnodes & truth_nodes);fp=len(pnodes-truth_nodes);fn=len(truth_nodes-pnodes);tn=len(present_nodes-(pnodes|truth_nodes))
        rows.append({'policy':name,'unit':'entity_node','groundtruth':'ThreaTrace-derived malicious-node mapping',**metrics(tp,tn,fp,fn),'predicted_nodes':len(pnodes),'truth_nodes':len(truth_nodes)})
        a=event_counts[name];rows.append({'policy':name,'unit':'malicious_entity_link_event_proxy','groundtruth':'derived malicious-entity-link event proxy',**metrics(a[0],a[1],a[2],a[3]),'predicted_nodes':len(pnodes),'truth_nodes':len(truth_nodes)})
    pd.DataFrame(rows).to_csv(out/'phase5b_p0_p1_test_metrics.csv',index=False)

    # Union-only node file: enough to recompute TP/FP/FN without writing every TN row.
    union=sorted(truth_nodes|p0_pred_nodes|p1_pred_nodes)
    with gzip.open(out/'phase5b_node_predictions.csv.gz','wt',newline='') as f:
        w=csv.writer(f);w.writerow(['uuid','truth','p0_pred','p1_pred'])
        for u in union:w.writerow([u,int(u in truth_nodes),int(u in p0_pred_nodes),int(u in p1_pred_nodes)])

    reason_rows=[]
    for (reason,y),c in sorted(reason_truth.items()):reason_rows.append({'reason':reason,'truth_proxy':y,'count':c})
    pd.DataFrame(reason_rows).to_csv(out/'phase5b_reason_by_truth.csv',index=False)
    qrows=[]
    for y in [0,1]:
        ev=quality[('events',y)];se=quality[('sensitive_events',y)]
        qrows.append({'truth_proxy':y,'events':ev,'current_selector_coverage':quality[('current_covered',y)]/max(1,ev),
                      'sensitive_events':se,'sensitive_trace_coverage':quality[('sensitive_trace_covered',y)]/max(1,se)})
    pd.DataFrame(qrows).to_csv(out/'phase5b_policy_quality_test.csv',index=False)
    summary={'test_events':n,'present_entity_nodes':len(present_nodes),'truth_nodes':len(truth_nodes),
             'p0_predicted_nodes':len(p0_pred_nodes),'p1_predicted_nodes':len(p1_pred_nodes),
             'compiled_direct_equivalence_checked':equivalence_checked,'compiled_direct_divergences':equivalence_divergences,
             'frozen_policy_sha256':marker['frozen_policy_sha256'],'test_opened_once':True,
             'p0_mean_direct_eval_us':p0_ns/max(1,n)/1000.0,'p1_mean_direct_eval_us':p1_ns/max(1,n)/1000.0}
    (logs/'phase5b_test_summary.json').write_text(json.dumps(summary,indent=2))
    print(pd.DataFrame(rows).to_string(index=False))

if __name__=='__main__':main()
