"""Live portable TCP laboratory: two operation collectors and a coordinator.

Roles can run on separate hosts/containers. The default `local` role deliberately
reports one host with distinct OS processes, never a real multi-host deployment.
Collectors execute actual operations; transport faults affect their delivery, not
their independently archived factual observations. Sources/clocks are trusted.
"""
from __future__ import annotations
import argparse
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import socket
import socketserver
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from trace_policy_engine import Event, Rule, Selector, Guard, PolicyVersion, ALLOW, DENY, reference_eval
from revision_distributed import Observation, JournalCoordinator, canonical

PROFILES = ('ordered', 'reorder_duplicate', 'missing_record', 'late', 'wrong_version', 'restart')


def build_config(run_id, profile, start_epoch):
    if profile not in PROFILES:
        raise ValueError(profile)
    return dict(run_id=run_id, profile=profile, sources=['A','B'], start_epoch=start_epoch,
            max_lateness_s=.7 if profile=='late' else 1.5,
            schedule=[(0,1),(start_epoch+.12,2)],
            jobs={'A':[dict(action='read',offset_s=.02),dict(action='connect',offset_s=.65)],
                  'B':[dict(action='exec',offset_s=.25)]})


def prepare(args):
    path=Path(args.config)
    if path.exists():
        raise FileExistsError('preserve the existing plan; choose a fresh path')
    path.parent.mkdir(parents=True,exist_ok=True)
    config=build_config(args.run_id,args.profile,time.time()+args.start_delay)
    path.write_text(json.dumps(config,indent=2),encoding='utf-8')
    print(json.dumps(config),flush=True)


def mounted_path(path):
    path=Path(path).resolve()
    if not path.drive:
        return str(path)
    return '/mnt/'+path.drive.rstrip(':').lower()+'/'+path.as_posix()[3:]


def probe(args):
    before=time.time()
    reply=request((args.host,args.port),dict(kind='ping'),retries=2)
    if not reply['ok']:
        raise RuntimeError(reply)
    print(json.dumps(dict(hostname=socket.gethostname(),platform=platform.platform(),
          interpreter=sys.executable,pid=os.getpid(),time_before=before,time_after=time.time(),
          reply=reply)),flush=True)


def lab_policies():
    allow = Rule('ALLOW_OBSERVED', 0, ALLOW, Selector())
    chain = Rule('DENY_READ_EXEC_CONNECT', 100, DENY, Selector('connect'),
                 Guard(seq_actions=('read', 'exec', 'connect'), seq_horizon=3))
    return {1: PolicyVersion('LIVE_DISTRIBUTED_LAB', 1, (allow,)),
            2: PolicyVersion('LIVE_DISTRIBUTED_LAB', 2, (allow, chain))}


def new_coordinator(config):
    return JournalCoordinator(config['sources'], lab_policies(), config['schedule'],
                              config['max_lateness_s'])


def request(endpoint, payload, retries=50):
    host, port = endpoint
    error = None
    for _ in range(retries):
        try:
            with socket.create_connection((host, int(port)), timeout=2) as sock:
                sock.settimeout(3)
                stream = sock.makefile('rwb')
                stream.write((canonical(payload) + '\n').encode()); stream.flush()
                line = stream.readline()
                if not line:
                    raise ConnectionError('coordinator closed before durable acknowledgement')
                return json.loads(line)
        except (OSError, ConnectionError) as exc:
            error = exc
            time.sleep(.05)
    raise RuntimeError(f'coordinator request failed: {error}')


def serve(args):
    config = json.loads(Path(args.config).read_text(encoding='utf-8'))
    checkpoint = Path(args.checkpoint)
    coordinator = (JournalCoordinator.restore(checkpoint, lab_policies())
                   if args.restore else new_coordinator(config))
    mutex = threading.Lock()
    stop = threading.Event()
    arrival_path = checkpoint.with_suffix('.arrivals.jsonl')
    arrivals = ([json.loads(line) for line in arrival_path.read_text(encoding='utf-8').splitlines()]
                if args.restore and arrival_path.exists() else [])

    class Server(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True

    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            line = self.rfile.readline(1_000_000)
            if not line:
                return
            received_at = time.time()
            value = json.loads(line)
            with mutex:
                try:
                    kind = value['kind']
                    if kind == 'record':
                        o = value['observation']
                        result = coordinator.record(Observation(o['source'], o['source_seq'],
                                     o['trace_id'], o['policy_version'], Event(**o['event'])), received_at)
                        entry=dict(event_id=o['event']['eid'], received_at=received_at,
                                   peer=list(self.client_address),
                                   lateness_s=received_at-o['event']['ts'], status=result)
                        arrivals.append(entry)
                        with arrival_path.open('a',encoding='utf-8') as journal:
                            journal.write(canonical(entry)+'\n')
                    elif kind == 'watermark':
                        coordinator.watermark(value['source'], value['event_time'], value['through_seq'])
                        result = 'watermark'
                    elif kind == 'close':
                        coordinator.close(value['source']); result = 'closed'
                    elif kind == 'ping':
                        result = 'connected'
                    elif kind == 'status':
                        result = coordinator.summary()
                    elif kind == 'stop':
                        result = coordinator.summary(); stop.set()
                    else:
                        raise ValueError('unknown protocol message')
                    coordinator.checkpoint(checkpoint)
                    response = dict(ok=True, result=result)
                except Exception as exc:
                    if not coordinator.errors or coordinator.errors[-1] != str(exc):
                        coordinator.errors.append('protocol error: '+str(exc))
                    if value.get('kind')=='record':
                        event=value.get('observation',{}).get('event',{})
                        entry=dict(event_id=event.get('eid'),received_at=received_at,
                                   peer=list(self.client_address),
                                   status='rejected',error=str(exc))
                        if isinstance(event.get('ts'),(int,float)):
                            entry['lateness_s']=received_at-event['ts']
                        arrivals.append(entry)
                        with arrival_path.open('a',encoding='utf-8') as journal:
                            journal.write(canonical(entry)+'\n')
                    coordinator.checkpoint(checkpoint)
                    response = dict(ok=False, error=str(exc), result=coordinator.summary())
                self.wfile.write((canonical(response)+'\n').encode()); self.wfile.flush()

    server = Server((args.bind, args.port), Handler)
    info = dict(host=args.bind, port=server.server_address[1], pid=os.getpid(),
                hostname=socket.gethostname(), platform=platform.platform(), restored=args.restore)
    Path(args.ready).write_text(canonical(info), encoding='utf-8')
    server.timeout = .1
    try:
        while not stop.is_set():
            server.handle_request()
    finally:
        with mutex:
            coordinator.checkpoint(checkpoint)
            Path(args.result).write_text(json.dumps(dict(summary=coordinator.summary(),
                    arrivals=arrivals, process=info), indent=2), encoding='utf-8')
        server.server_close()


def perform(action, endpoint, workdir):
    """Instrument real filesystem, child-process, and network operations."""
    workdir.mkdir(parents=True, exist_ok=True)
    if action == 'read':
        target = workdir / 'fixture.txt'
        target.write_text('bounded live lab input\n', encoding='utf-8')
        value = target.read_bytes()
        return dict(operation='filesystem_read', path=str(target), bytes=len(value),
                    sha256=hashlib.sha256(value).hexdigest())
    if action == 'exec':
        completed = subprocess.run([sys.executable, '-c',
                'import os; print("executed-child", os.getpid())'], capture_output=True,
                text=True, check=True, timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
        return dict(operation='child_process_exec', returncode=completed.returncode,
                    output=completed.stdout.strip(), interpreter=sys.executable)
    if action == 'connect':
        connected = request(endpoint, dict(kind='ping'))
        if not connected['ok']:
            raise RuntimeError(connected)
        return dict(operation='tcp_connect', endpoint=list(endpoint), reply=connected['result'])
    raise ValueError(action)


def collect(args):
    config = json.loads(Path(args.config).read_text(encoding='utf-8'))
    endpoint = (args.host, args.port)
    jobs = config['jobs'][args.source]
    journal = []
    deliveries = []
    delivery_errors = []
    threads = []
    lock = threading.Lock()
    destination = Path(args.journal)
    destination.parent.mkdir(parents=True, exist_ok=True)
    source_identity = dict(hostname=socket.gethostname(), pid=os.getpid(), platform=platform.platform(),
                           interpreter=sys.executable, source=args.source)

    def send_record(o, delay, duplicate=False, drop=False, wrong=False):
        if delay:
            time.sleep(delay)
        if drop:
            with lock:
                deliveries.append(dict(event_id=o.event.eid, transport='intentionally_dropped'))
            return
        value = o.payload()
        if wrong:
            value['policy_version'] = 1
        for index in range(2 if duplicate else 1):
            response = request(endpoint, dict(kind='record', observation=value))
            with lock:
                deliveries.append(dict(event_id=o.event.eid, duplicate=index>0, reply=response))

    def guarded_send(*values):
        try:
            send_record(*values)
        except Exception as exc:
            with lock:
                delivery_errors.append(str(exc))

    for seq, job in enumerate(jobs, 1):
        scheduled = config['start_epoch'] + job['offset_s']
        time.sleep(max(0, scheduled-time.time()))
        before = time.time()
        evidence = perform(job['action'], endpoint, destination.parent / ('work_'+args.source))
        after = time.time()
        version = new_coordinator(config).version_at(after)
        e = Event(f"{config['run_id']}:{args.source}:{seq}", after, job['action'], 'lab_resource',
                  'collector_operation', dict(evidence=evidence, source_identity=source_identity,
                  operation_start=before, operation_end=after))
        o = Observation(args.source, seq, config['run_id'], version, e)
        journal.append(o.payload())
        destination.write_text(json.dumps(dict(identity=source_identity, observations=journal,
                                        deliveries=deliveries), indent=2), encoding='utf-8')
        first_a = args.source == 'A' and seq == 1
        profile = config['profile']
        delay = (.85 if profile == 'reorder_duplicate' and first_a else
                 1.1 if profile == 'late' and first_a else 0)
        thread = threading.Thread(target=guarded_send, args=(o, delay,
                profile == 'reorder_duplicate' and not first_a and args.source == 'A',
                profile == 'missing_record' and first_a,
                profile == 'wrong_version' and args.source == 'A' and seq == 2))
        thread.start(); threads.append(thread)
        request(endpoint, dict(kind='watermark', source=args.source,
                               event_time=after, through_seq=seq))
    for thread in threads:
        thread.join()
    if delivery_errors:
        raise RuntimeError('transport infrastructure failure: '+str(delivery_errors))
    # Terminal time fence is a declaration that this source has no more jobs.
    last = max(x['event']['ts'] for x in journal)
    scheduled_horizon = max((job['offset_s'] for jobs_for_source in config['jobs'].values()
                            for job in jobs_for_source), default=0.0)
    request(endpoint, dict(kind='watermark', source=args.source,
               event_time=max(last+.01, config['start_epoch']+scheduled_horizon+10.0),
               through_seq=len(jobs)))
    request(endpoint, dict(kind='close', source=args.source))
    destination.write_text(json.dumps(dict(identity=source_identity, observations=journal,
                                    deliveries=deliveries), indent=2), encoding='utf-8')


def child(command, log):
    return subprocess.Popen(command, stdout=log, stderr=log,
               creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)


def wait_ready(path, process):
    for _ in range(100):
        if path.exists():
            return json.loads(path.read_text(encoding='utf-8'))
        if process.poll() is not None:
            raise RuntimeError('coordinator exited before readiness')
        time.sleep(.05)
    raise TimeoutError('coordinator startup timeout')


def local(args):
    out = Path(args.output).resolve(); out.mkdir(parents=True, exist_ok=True)
    if (out/'protocol.json').exists():
        raise FileExistsError('output already contains a laboratory cohort; choose a fresh output directory')
    # Execute children from the immutable per-cohort sources, avoiding concurrent
    # workspace edits changing the implementation halfway through the campaign.
    snapshot=out/'source_snapshot'/'code'
    source_files=[Path(__file__).resolve(),ROOT/'src/revision_distributed.py',
                  ROOT/'src/trace_policy_engine.py']
    for original in source_files:
        target=snapshot/original.relative_to(ROOT)
        target.parent.mkdir(parents=True,exist_ok=True)
        shutil.copy2(original,target)
    crossos=args.role=='crossos'
    topology=('Windows_coordinator_and_collector_A_plus_Ubuntu_WSL2_collector_B_on_one_physical_host'
              if crossos else 'one_host_three_distinct_os_processes')
    script = str(snapshot/'experiments'/'revision_distributed_lab.py')
    preflight=None
    if crossos:
        pre=out/'preflight';pre.mkdir()
        config_path=pre/'config.json'
        config_path.write_text(json.dumps(build_config('preflight','ordered',time.time()+60)),encoding='utf-8')
        ready=pre/'ready.json'
        with (pre/'process.log').open('w',encoding='utf-8') as log:
            process=child([sys.executable,script,'serve','--config',str(config_path),
                '--bind','0.0.0.0','--port','0','--ready',str(ready),
                '--checkpoint',str(pre/'checkpoint.json'),'--result',str(pre/'result.json')],log)
            try:
                info=wait_ready(ready,process)
                before=time.time()
                completed=subprocess.run(['wsl.exe','-d',args.distro,'--','python3',mounted_path(script),
                    'probe','--host',args.gateway,'--port',str(info['port'])],capture_output=True,
                    text=True,timeout=20,creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0)
                after=time.time()
                (pre/'probe_stdout.txt').write_text(completed.stdout,encoding='utf-8')
                (pre/'probe_stderr.txt').write_text(completed.stderr,encoding='utf-8')
                if completed.returncode:
                    raise RuntimeError('Windows-WSL TCP preflight failed; no firewall configuration changed: '+completed.stderr)
                preflight=dict(windows=info,wsl=json.loads(completed.stdout),
                        host_probe_start=before,host_probe_end=after,
                        gateway=args.gateway,distro=args.distro,
                        independent_physical_hosts=False,independent_linux_vms=False)
                (pre/'network_environment.json').write_text(json.dumps(preflight,indent=2),encoding='utf-8')
                request(('127.0.0.1',info['port']),dict(kind='stop'));process.wait(timeout=5)
            finally:
                if process.poll() is None:
                    process.terminate();process.wait(timeout=5)
    plan = dict(kind='live_tcp_operation_lab', topology=topology,
                sources=['A','B'], profiles=list(PROFILES), repeats=args.repeats,
                total_runs=len(PROFILES)*args.repeats,
                trust=['source identity','source clock','source sequence','policy schedule'],
                collection_scope='explicitly instrumented read/exec/connect operations; setup and transport excluded',
                workload='benign operations arranged to exercise a declared temporal deny policy',
                implementation_sha256={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest()
                    for p in source_files},
                executable_source_snapshot=str(snapshot),
                expected_incomplete=['missing_record','late','wrong_version'],
                expected_complete=['ordered','reorder_duplicate','restart'],
                clock_synchronization_measured=False, network_faults='controlled send-side injections')
    plan['cross_os_preflight']=preflight
    (out/'protocol.json').write_text(json.dumps(plan,indent=2),encoding='utf-8')
    results = []
    for repeat in range(args.repeats):
        for profile in PROFILES:
            run_id=f'{profile}_{repeat:02d}'; folder=out/run_id; folder.mkdir(exist_ok=True)
            start=time.time()+(2.5 if crossos else 1.0)
            config=build_config(run_id,profile,start)
            config_path=folder/'config.json';config_path.write_text(json.dumps(config,indent=2),encoding='utf-8')
            ready=folder/'ready.json';checkpoint=folder/'checkpoint.json';result=folder/'coordinator.json'
            base=[sys.executable,script,'serve','--config',str(config_path),'--bind',
                    '0.0.0.0' if crossos else '127.0.0.1',
                    '--port','0','--ready',str(ready),'--checkpoint',str(checkpoint),'--result',str(result)]
            processes=[]
            with (folder/'processes.log').open('w',encoding='utf-8') as log:
                server=child(base,log);processes.append(server)
                try:
                    info=wait_ready(ready,server);port=info['port']
                    commands=[]
                    for source in ['A','B']:
                        if crossos and source=='B':
                            command=['wsl.exe','-d',args.distro,'--','python3',mounted_path(script),
                                'collect','--config',mounted_path(config_path),'--source',source,
                                '--host',args.gateway,'--port',str(port),
                                '--journal',mounted_path(folder/(source+'.json'))]
                        else:
                            command=[sys.executable,script,'collect','--config',str(config_path),
                                '--source',source,'--host','127.0.0.1','--port',str(port),
                                '--journal',str(folder/(source+'.json'))]
                        commands.append(command)
                    collectors=[child(command,log) for command in commands]
                    processes.extend(collectors)
                    restarts=[]
                    if profile=='restart':
                        # Kill after durable first-event acknowledgement, before the chain completes.
                        checkpoint_deadline=max(time.time()+2.0,start+2.0)
                        durable_event=False
                        while time.time()<checkpoint_deadline:
                            if checkpoint.exists() and json.loads(checkpoint.read_text())['records']:
                                durable_event=True
                                break
                            time.sleep(.02)
                        if not durable_event:
                            raise TimeoutError('no durable event checkpoint before coordinator restart')
                        server.terminate();server.wait(timeout=5)
                        restarts.append(dict(previous_pid=info['pid'],checkpoint_sha256=
                                            hashlib.sha256(checkpoint.read_bytes()).hexdigest()))
                        ready.unlink()
                        replay=base.copy();replay[replay.index('--port')+1]=str(port);replay.append('--restore')
                        server=child(replay,log);processes.append(server);info=wait_ready(ready,server)
                    for process in collectors:
                        if process.wait(timeout=20)!=0:
                            raise RuntimeError('collector process failed; inspect process log')
                    reply=request(('127.0.0.1',port),dict(kind='stop'))
                    if not reply['ok']:
                        raise RuntimeError(reply)
                    server.wait(timeout=5)
                    observations=[];identities=[]
                    for source in ['A','B']:
                        journal=json.loads((folder/(source+'.json')).read_text(encoding='utf-8'))
                        observations.extend(journal['observations']);identities.append(journal['identity'])
                    prefix=[];canonical_decisions=[]
                    for o in sorted(observations,key=lambda x:(x['event']['ts'],x['event']['eid'])):
                        prefix.append(Event(**o['event']))
                        canonical_decisions.append(dict(event_id=o['event']['eid'],
                            policy_version=o['policy_version'],alert_class=reference_eval(prefix,
                            lab_policies()[o['policy_version']]).alert_class))
                    final=json.loads(result.read_text(encoding='utf-8'))
                    restored=JournalCoordinator.restore(checkpoint,lab_policies()).summary()
                    actual=[{k:d[k] for k in ['event_id','policy_version','alert_class']}
                            for d in final['summary']['decisions']]
                    expected_status='incomplete' if profile in plan['expected_incomplete'] else 'complete'
                    record=dict(run_id=run_id,profile=profile,repeat=repeat,
                            source_processes=identities,coordinator_process=info,restarts=restarts,
                            canonical=canonical_decisions,observed=actual,summary=final['summary'],
                            expected_status=expected_status,
                            status_matches=final['summary']['status']==expected_status,
                            canonical_matches=actual==canonical_decisions,
                            checkpoint_replay_matches=restored==final['summary'],
                            actual_operation_count=len(observations),
                            expected_action_order=['read','exec','connect'],
                            actual_action_order=[e.action for e in prefix],
                            sha256={p.name:hashlib.sha256(p.read_bytes()).hexdigest()
                                   for p in [config_path,folder/'A.json',folder/'B.json',checkpoint]})
                    results.append(record)
                    (out/'results.json').write_text(json.dumps(results,indent=2),encoding='utf-8')
                    print(run_id,record['summary']['status'],record['canonical_matches'],flush=True)
                finally:
                    for process in processes:
                        if process.poll() is None:
                            process.terminate();process.wait(timeout=5)
    summary=dict(protocol=plan,runs=len(results),status_matches=sum(r['status_matches'] for r in results),
            complete_canonical_matches=sum(r['canonical_matches'] for r in results
                                            if r['expected_status']=='complete'),
            expected_complete=sum(r['expected_status']=='complete' for r in results),
            replay_matches=sum(r['checkpoint_replay_matches'] for r in results),
            actual_operations=sum(r['actual_operation_count'] for r in results),
            actual_multi_host=False,actual_cross_os=crossos,
            physical_host_count=1,linux_guest_vm_count=1 if crossos else 0)
    (out/'summary.json').write_text(json.dumps(summary,indent=2),encoding='utf-8')
    print(json.dumps(summary),flush=True)


def main():
    ap=argparse.ArgumentParser();sub=ap.add_subparsers(dest='role',required=True)
    p=sub.add_parser('local');p.add_argument('--output',default=str(ROOT/'results/revision/distributed_live_local'));p.add_argument('--repeats',type=int,default=5)
    p=sub.add_parser('crossos');p.add_argument('--output',default=str(ROOT/'results/revision/distributed_live_crossos'));p.add_argument('--repeats',type=int,default=5);p.add_argument('--distro',default='Ubuntu-24.04-Codex');p.add_argument('--gateway',required=True)
    p=sub.add_parser('probe');p.add_argument('--host',required=True);p.add_argument('--port',type=int,required=True)
    p=sub.add_parser('prepare');p.add_argument('--config',required=True);p.add_argument('--run-id',required=True);p.add_argument('--profile',choices=PROFILES,default='ordered');p.add_argument('--start-delay',type=float,default=20)
    p=sub.add_parser('serve');p.add_argument('--config',required=True);p.add_argument('--bind',default='127.0.0.1');p.add_argument('--port',type=int,default=0);p.add_argument('--ready',required=True);p.add_argument('--checkpoint',required=True);p.add_argument('--result',required=True);p.add_argument('--restore',action='store_true')
    p=sub.add_parser('collect');p.add_argument('--config',required=True);p.add_argument('--source',choices=['A','B'],required=True);p.add_argument('--host',required=True);p.add_argument('--port',type=int,required=True);p.add_argument('--journal',required=True)
    args=ap.parse_args();{'local':local,'crossos':local,'probe':probe,'prepare':prepare,'serve':serve,'collect':collect}[args.role](args)


if __name__=='__main__':main()
