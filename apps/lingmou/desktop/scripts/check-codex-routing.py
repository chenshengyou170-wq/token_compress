"""Check actual Codex CLI thread resume against a synthetic local upstream.

Run with the product virtualenv Python. Requires Codex CLI on PATH. A temporary
CODEX_HOME and synthetic API key isolate this check from real login/session data.
No external model request is made. This is not real ChatGPT upstream acceptance.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'src'))

import json,os,shutil,subprocess,tempfile,threading
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from codexscope.desktop_companion import Companion, _source_available

codex_entry = shutil.which('codex')
if not codex_entry:
    raise SystemExit('Install Codex CLI before running this optional check.')
codex_command = [codex_entry]
if sys.platform == 'win32' and Path(codex_entry).suffix.lower() in {'.cmd', '.bat', '.ps1'}:
    npm_entry = Path(codex_entry).parent / 'node_modules/@openai/codex/bin/codex.js'
    node = shutil.which('node')
    if not node or not npm_entry.is_file():
        raise SystemExit('Use the npm Codex CLI installation or put codex.exe on PATH.')
    codex_command = [node, str(npm_entry)]

seen=[]
source_server=''
item={'type':'message','id':'msg_test','role':'assistant','content':[{'type':'output_text','text':'OK','annotations':[]}]}
events=[{'type':'response.created','response':{'id':'resp_test','status':'in_progress','output':[]}},
        {'type':'response.output_item.added','output_index':0,'item':{**item,'content':[]}},
        {'type':'response.output_text.delta','item_id':'msg_test','output_index':0,'content_index':0,'delta':'OK'},
        {'type':'response.output_item.done','output_index':0,'item':item},
        {'type':'response.completed','response':{'id':'resp_test','status':'completed','output':[item],
         'usage':{'input_tokens':10,'output_tokens':1,'total_tokens':11}}}]
wire=''.join('data: '+json.dumps(e)+'\n\n' for e in events).encode()
class Upstream(BaseHTTPRequestHandler):
    def log_message(self,*_): pass
    def do_GET(self):
        if self.headers.get('Upgrade'): self.send_response(426)
        else: self.send_response(404)
        self.end_headers()
    def do_POST(self):
        body=self.rfile.read(int(self.headers.get('Content-Length',0)))
        seen.append({'path':self.path,'authorization':self.headers.get('Authorization'),
                     'relay':self.headers.get('X-Lingmou-Relay-Token'),
                     'source_reader_advertised':_source_available(json.loads(body), source_server)})
        self.send_response(200)
        self.send_header('Content-Type','text/event-stream')
        self.send_header('Content-Length',str(len(wire)))
        self.end_headers()
        self.wfile.write(wire)
server=ThreadingHTTPServer(('127.0.0.1',0),Upstream)
thread=threading.Thread(target=server.serve_forever,daemon=True)
thread.start()
with tempfile.TemporaryDirectory(prefix='lingmou-codex-smoke-') as temporary:
    root=Path(temporary)
    codex_home=root/'codex-home'
    codex_home.mkdir()
    work=root/'workspace'
    work.mkdir()
    target=codex_home/'config.toml'
    original=f'openai_base_url = "http://127.0.0.1:{server.server_port}/v1"\nmodel = "gpt-5.4-mini"\n'
    target.write_text(original)
    companion=Companion(root/'state')
    env={key:value for key,value in os.environ.items() if key in ('PATH','HOME','TMPDIR','SYSTEMROOT','WINDIR','COMSPEC','PATHEXT','APPDATA','LOCALAPPDATA')}
    env.update(CODEX_HOME=str(codex_home),CODEX_API_KEY='synthetic-smoke-api-key',OPENAI_API_KEY='synthetic-smoke-api-key',
               HTTP_PROXY='http://127.0.0.1:1',HTTPS_PROXY='http://127.0.0.1:1',NO_PROXY='127.0.0.1,localhost')
    def execute(arguments):
        result=subprocess.run([*codex_command,'exec',*arguments],cwd=work,env=env,text=True,capture_output=True,timeout=70)
        if result.returncode:
            print(result.stdout[-4000:]); print(result.stderr[-4000:]); raise AssertionError(result.returncode)
        return [json.loads(line) for line in result.stdout.splitlines() if line.startswith('{')]
    try:
        companion.connect(config_path=str(target),auth_kind='existing',mode='off')
        source_server=companion.connection.record['source_server']
        events=execute(['--skip-git-repo-check','--sandbox','read-only','--strict-config','--json','Reply only OK. Do not use tools.'])
        print(json.dumps({'stage':'connected','events':events},ensure_ascii=False))
        thread_id=next(event['thread_id'] for event in events if event['type']=='thread.started')
        rollouts=list(codex_home.glob('sessions/**/rollout-*.jsonl'))
        assert rollouts
        metadata=json.loads(rollouts[0].read_text().splitlines()[0])
        assert metadata['payload']['model_provider']=='openai', metadata
        companion.disconnect()
        assert target.read_text()==original
        resumed=execute(['resume','--skip-git-repo-check','--json',thread_id,'Reply only OK again. Do not use tools.'])
        assert any(e.get('type')=='turn.completed' for e in resumed),resumed
        assert len(seen)==2, seen
        assert seen==[{'path':'/v1/responses','authorization':'Bearer synthetic-smoke-api-key','relay':None,
                       'source_reader_advertised':reader} for reader in (True,False)],seen
        print(json.dumps({'codex_version':subprocess.check_output([*codex_command,'--version'],text=True).strip(),
                          'provider':'openai','resume_after_disconnect':'passed','auth_forwarding':'passed',
                          'source_reader_advertised':'passed',
                          'requests_to_local_mock':len(seen),'real_model_requests':0}))
    finally:
        companion.connection.restore(); companion.stop()
        server.shutdown();server.server_close();thread.join(timeout=3)
