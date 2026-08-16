from __future__ import annotations
import argparse,csv,re,subprocess,sys,shutil,time,json
import xml.etree.ElementTree as ET
from pathlib import Path
import pandas as pd
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from metrics import binary_metrics
from episode_metrics import episode_binary_metrics

ERR_TOKEN='error when connecting with wazuh-analysisd'

def run(cmd, *, input=None, check=True):
    cp=subprocess.run(cmd,input=input,text=True,capture_output=True)
    if check and cp.returncode!=0:
        raise RuntimeError(f"Command failed ({cp.returncode}): {' '.join(cmd)}\nSTDOUT:\n{cp.stdout[-4000:]}\nSTDERR:\n{cp.stderr[-4000:]}")
    return cp

def find_manager(explicit=''):
    if explicit:
        cp=run(['docker','inspect','-f','{{.State.Running}}',explicit])
        if cp.stdout.strip().lower()!='true': raise RuntimeError(f'{explicit} is not running')
        return explicit
    # Prefer the ID recorded by the setup helper.
    marker=ROOT/'results/logs/wazuh_manager_container_v2.txt'
    if marker.exists():
        cid=marker.read_text().strip()
        if cid:
            cp=run(['docker','inspect','-f','{{.State.Running}}',cid],check=False)
            if cp.returncode==0 and cp.stdout.strip().lower()=='true': return cid
    cp=run(['docker','ps','--filter','ancestor=wazuh/wazuh-manager:4.14.7','--format','{{.ID}}'],check=False)
    ids=[x.strip() for x in cp.stdout.splitlines() if x.strip()]
    if not ids:
        raise RuntimeError('No running wazuh/wazuh-manager:4.14.7 container. Run scripts/setup_wazuh_official_v2.sh or .ps1 first.')
    return ids[0]

def parse_output(text):
    pred=set();details=[]; phase1=0; phase3=0
    chunks=re.split(r'(?=\*\*Phase 1:)',text)
    for c in chunks:
        if '**Phase 1:' not in c: continue
        phase1 += 1
        if '**Phase 3:' not in c: continue
        phase3 += 1
        sm=re.search(r"\bsid:\s*'?([^'\s]+)'?",c)
        rm=re.search(r"\*\*Phase 3:.*?\bid:\s*'?(\d+)'?",c,re.S)
        lm=re.search(r"\blevel:\s*'?(\d+)'?",c)
        if sm and rm and int(lm.group(1) if lm else 0)>=10:
            sid=sm.group(1); pred.add(sid)
            details.append((sid,rm.group(1),int(lm.group(1) if lm else 0)))
    return pred,details,phase1,phase3

def analysisd_ready(manager):
    cp=run(['docker','exec',manager,'/var/ossec/bin/wazuh-control','status'],check=False)
    return 'wazuh-analysisd is running' in cp.stdout

def render_wazuh_414_rules(rules, logdir):
    tree=ET.parse(rules)
    root=tree.getroot()
    for rule in root.findall('rule'):
        if rule.attrib.get('id')=='100010':
            rule.attrib['level']='1'
            rule.attrib.pop('noalert',None)
        for child in list(rule):
            if child.tag=='field' and child.attrib.get('name')=='status':
                child.tag='status'
                child.attrib.clear()
    rendered=logdir/'local_rules_wazuh_4_14_7_rendered.xml'
    ET.indent(tree, space='  ')
    tree.write(rendered, encoding='unicode')
    return rendered

def install_rules(manager, rules):
    rendered=render_wazuh_414_rules(rules, ROOT/'results/logs/wazuh_v2')
    run(['docker','cp',str(rendered),f'{manager}:/var/ossec/etc/rules/local_rules.xml'])
    run(['docker','exec',manager,'/var/ossec/bin/wazuh-control','restart'])
    for _ in range(60):
        if analysisd_ready(manager): return
        time.sleep(2)
    raise RuntimeError('wazuh-analysisd did not return after rule installation/restart')

def logtest(manager,text):
    cp=run(['docker','exec','-i',manager,'/var/ossec/bin/wazuh-logtest'],input=text,check=False)
    combined=cp.stdout+'\n'+cp.stderr
    if cp.returncode!=0 or ERR_TOKEN in combined:
        raise RuntimeError(f'Invalid wazuh-logtest execution: rc={cp.returncode}\n{combined[-5000:]}')
    cp.stdout=combined
    return cp

def smoke_test(manager, logdir):
    lines=[
        json.dumps({'sid':'smoke-admin','path':'/admin','status':200}),
        json.dumps({'sid':'smoke-login-1','path':'/login','status':401}),
        json.dumps({'sid':'smoke-login-2','path':'/login','status':401}),
        json.dumps({'sid':'smoke-login-3','path':'/login','status':401}),
        json.dumps({'sid':'smoke-login-4','path':'/login','status':401}),
        json.dumps({'sid':'smoke-login-5','path':'/login','status':401}),
    ]
    cp=logtest(manager,'\n'.join(lines)+'\n')
    (logdir/'wazuh_smoke_v2.stdout.txt').write_text(cp.stdout)
    (logdir/'wazuh_smoke_v2.stderr.txt').write_text(cp.stderr)
    pred,det,p1,p3=parse_output(cp.stdout)
    rule_by_sid={sid:rid for sid,rid,_ in det}
    if p1 < len(lines):
        raise RuntimeError(f'Wazuh smoke processed only {p1}/{len(lines)} Phase-1 events')
    if rule_by_sid.get('smoke-admin')!='100001':
        raise RuntimeError(f'Admin smoke did not trigger frozen rule 100001: {det}')
    if not any(rid=='100014' for _,rid,_ in det):
        raise RuntimeError(f'Brute-force smoke did not trigger frozen rule 100014: {det}')
    return {'phase1':p1,'phase3':p3,'details':det}

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--lab-dir',default=str(ROOT/'local_lab/results'))
    ap.add_argument('--manager',default='')
    ap.add_argument('--out-root',default=str(ROOT/'results/raw'))
    args=ap.parse_args()
    lab=Path(args.lab_dir); out=Path(args.out_root); out.mkdir(parents=True,exist_ok=True)
    logdir=ROOT/'results/logs/wazuh_v2'; logdir.mkdir(parents=True,exist_ok=True)
    invalid=ROOT/'results/invalid_prepatch_wazuh'; invalid.mkdir(parents=True,exist_ok=True)

    # Preserve invalid prior outputs exactly once.
    for p in [out/'rq5_local_lab_wazuh.csv',out/'rq5_local_lab_wazuh_alerts.csv']:
        if p.exists() and not (invalid/p.name).exists(): shutil.copy2(p,invalid/p.name)
    for p in lab.glob('wazuh_*.stdout.txt'):
        q=invalid/p.name
        if not q.exists(): shutil.copy2(p,q)
    for p in lab.glob('wazuh_*.stderr.txt'):
        q=invalid/p.name
        if not q.exists(): shutil.copy2(p,q)

    manager=find_manager(args.manager)
    if not analysisd_ready(manager): raise RuntimeError('wazuh-analysisd is not running')
    rules=ROOT/'docker/wazuh/local_rules.xml'
    install_rules(manager,rules)
    smoke=smoke_test(manager,logdir)
    (logdir/'smoke_result.json').write_text(json.dumps(smoke,indent=2))

    rows=[]; details=[]
    truth_files=sorted(lab.glob('truth_*.csv'))
    if len(truth_files)!=30: raise RuntimeError(f'Expected 30 truth files, found {len(truth_files)}')
    for truthp in truth_files:
        seed=int(truthp.stem.split('_')[-1]); access=lab/f'access_{seed}.jsonl'
        tr=list(csv.DictReader(open(truthp,newline='')))
        lines=[x for x in access.read_text().splitlines() if x.strip()]
        if len(lines)!=len(tr): raise RuntimeError(f'{seed}: access/truth row mismatch')
        cp=logtest(manager,'\n'.join(lines)+'\n')
        (logdir/f'wazuh_{seed}.stdout.txt').write_text(cp.stdout)
        (logdir/f'wazuh_{seed}.stderr.txt').write_text(cp.stderr)
        pred,dd,p1,p3=parse_output(cp.stdout)
        if p1 < len(lines):
            raise RuntimeError(f'{seed}: only {p1}/{len(lines)} valid Phase-1 blocks')
        if p3==0 or not pred:
            raise RuntimeError(f'{seed}: no valid Phase-3 alert; this is execution-invalid for the frozen known-attack workload')
        y=[int(x['label']) for x in tr]; yp=[int(x['sid'] in pred) for x in tr]
        em=episode_binary_metrics(tr,pred)
        rows.append({'seed':seed,'n':len(y),**binary_metrics(y,yp),'alerts':len(pred),
                     'phase1_blocks':p1,'phase3_blocks':p3,
                     **{f'episode_{k}':v for k,v in em.items()}})
        details.extend({'seed':seed,'sid':sid,'rule_id':rid,'level':level} for sid,rid,level in dd)

    df=pd.DataFrame(rows).sort_values('seed')
    if len(df)!=30 or (df.alerts<=0).any(): raise RuntimeError('Corrected Wazuh output failed validity checks')
    df.to_csv(out/'rq5_local_lab_wazuh.csv',index=False)
    pd.DataFrame(details).to_csv(out/'rq5_local_lab_wazuh_alerts.csv',index=False)
    print(df.describe().to_string())

if __name__=='__main__': main()
