#!/usr/bin/env python3
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs, unquote
from pathlib import Path
import json, time, os

LOG=Path(os.environ.get('GATEWAY_LOG','/data/access.jsonl'))
LOG.parent.mkdir(parents=True,exist_ok=True)

class H(BaseHTTPRequestHandler):
    server_version='ProjectAGateway/1.0'
    def log_message(self,*args): pass
    def do_GET(self): self.handle_req()
    def do_POST(self): self.handle_req()
    def handle_req(self):
        now=time.time(); parsed=urlparse(self.path); q=parse_qs(parsed.query)
        sid=(q.get('sid') or [self.headers.get('X-Scenario-ID','')])[0]
        p=unquote(parsed.path)
        status=200
        if p.startswith('/login') and (q.get('ok') or ['0'])[0] != '1': status=401
        elif p.startswith('/admin'): status=403
        elif 'etc/passwd' in p or p.startswith('/cmd'): status=400
        body=json.dumps({'ok': status<400, 'path':p}).encode()
        self.send_response(status); self.send_header('Content-Type','application/json'); self.send_header('Content-Length',str(len(body))); self.end_headers(); self.wfile.write(body)
        rec={'ts':now,'sid':sid,'method':self.command,'path':p,'raw_path':self.path,
             'status':status,'src_ip':self.client_address[0],'user_agent':self.headers.get('User-Agent','')}
        with LOG.open('a',encoding='utf-8') as f: f.write(json.dumps(rec,sort_keys=True)+'\n')

if __name__=='__main__':
    ThreadingHTTPServer(('0.0.0.0',8080),H).serve_forever()
