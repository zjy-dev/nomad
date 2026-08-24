"""A1 audit-only fixed-route observing proxy.  It never reads credentials."""
from __future__ import annotations
import hashlib, hmac, http.client, json, re, socket, struct, threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qsl, unquote, urlencode, urlsplit

MAX_FRAME=1024; MAX_FIELD=256; MAX_EVENTS=1000; MAX_SSE=8192
HELLO=1; HOST_CHALLENGE=2; PROXY_RESPONSE=3; VERSION=1
ID=re.compile(r'^[A-Za-z0-9_-]{1,256}$'); HEX64=re.compile(r'^[0-9a-f]{64}$')
class ProxyError(ValueError): pass
class _TestAuthority:
    def __reduce__(self): raise TypeError('nonserializable')
_AUTHORITY=_TestAuthority()
def _issue_test_authority():
    """Private test helper; production has no authority factory."""
    return _AUTHORITY
@dataclass(frozen=True)
class Decision: status:int; reason:str; synthetic:bool=False

def _canonical(parts): return b''.join(len(x).to_bytes(8,'big')+x for x in parts)
def _mac(secret, hello, challenge, role):
    return hmac.new(secret,_canonical([b'nomad-run-binding-v1',role,hello['run_id'].encode(),hello['origin'].encode(),hello['nonce'].encode(),hello['digest'].encode(),challenge]),hashlib.sha256).digest()
def _recv_exact(s,n):
    out=b''
    while len(out)<n:
        x=s.recv(n-len(out))
        if not x: raise ProxyError('frame')
        out+=x
    return out
def _write(s,p):
    if not p or len(p)>MAX_FRAME: raise ProxyError('frame')
    s.sendall(struct.pack('!I',len(p))+p)
def _read(s):
    n=struct.unpack('!I',_recv_exact(s,4))[0]
    if not 0<n<=MAX_FRAME: raise ProxyError('frame')
    p=_recv_exact(s,n)
    if len(p)<2 or p[1]!=VERSION: raise ProxyError('schema')
    fields={}; i=2
    while i<len(p):
        if len(p)-i<3: raise ProxyError('frame')
        tag,l=p[i],struct.unpack('!H',p[i+1:i+3])[0]; i+=3
        if l>MAX_FIELD or len(p)-i<l or tag in fields: raise ProxyError('schema')
        fields[tag]=p[i:i+l]; i+=l
    return p[0],fields
def _exact(frame, kind, tags):
    got,fields=_decode_frame(frame)
    if got!=kind or set(fields)!=set(tags): raise ProxyError('schema')
    return fields
def _decode_frame(frame):
    if len(frame)<2 or frame[1]!=VERSION: raise ProxyError('schema')
    fields={};i=2
    while i<len(frame):
        if len(frame)-i<3: raise ProxyError('frame')
        tag,n=frame[i],struct.unpack('!H',frame[i+1:i+3])[0];i+=3
        if n>MAX_FIELD or len(frame)-i<n or tag in fields: raise ProxyError('schema')
        fields[tag]=frame[i:i+n];i+=n
    return frame[0],fields
def _frame(kind, fields):
    p=bytes([kind,VERSION])
    for tag,value in fields:
        if len(value)>MAX_FIELD: raise ProxyError('field')
        p+=bytes([tag])+struct.pack('!H',len(value))+value
    return p
def proxy_handshake(sock,binding_secret,hello):
    """Rust-compatible proxy side; secret is harness memory, never framed."""
    if not isinstance(binding_secret,bytes) or len(binding_secret)!=32: raise ProxyError('secret')
    _valid_hello(hello); previous_timeout=sock.gettimeout(); succeeded=False
    try:
        sock.settimeout(2)
        _write(sock,_frame(HELLO,[(1,hello['run_id'].encode()),(2,hello['origin'].encode()),(3,hello['nonce'].encode()),(4,hello['digest'].encode())]))
        kind,f=_read(sock)
        if kind!=HOST_CHALLENGE or set(f)!={1,2} or len(f[1])!=32 or len(f[2])!=32 or not hmac.compare_digest(f[2],_mac(binding_secret,hello,f[1],b'host')): raise ProxyError('authentication')
        _write(sock,_frame(PROXY_RESPONSE,[(1,f[1]),(2,hello['digest'].encode()),(3,_mac(binding_secret,hello,f[1],b'proxy'))])); succeeded=True
    except ProxyError:
        try: sock.shutdown(socket.SHUT_RDWR)
        except OSError: pass
        raise
    except (OSError, TimeoutError):
        try: sock.shutdown(socket.SHUT_RDWR)
        except OSError: pass
        raise ProxyError('io') from None
    finally:
        if succeeded:
            try: sock.settimeout(previous_timeout)
            except OSError: pass
def _valid_hello(h):
    if set(h)!={'run_id','origin','nonce','digest'} or not all(isinstance(h[k],str) for k in h): raise ProxyError('schema')
    if not all(HEX64.fullmatch(h[k]) for k in ('run_id','nonce','digest')) or not re.fullmatch(r'http://127\.0\.0\.1:[1-9][0-9]{0,4}',h['origin']): raise ProxyError('validation')
    if int(h['origin'].rsplit(':',1)[1])>65535: raise ProxyError('validation')
class HostRunBinding:
    """Test peer only; never attached to production command authorization."""
    def __init__(self,challenge,secret):
        if len(challenge)!=32 or len(secret)!=32 or not any(challenge) or not any(secret): raise ProxyError('validation')
        self.challenge=bytes(challenge);self.secret=bytearray(secret);self.used=False
    def handshake(self,sock):
        if self.used: raise ProxyError('replay')
        self.used=True; sock.settimeout(2)
        try:
            kind,hello_fields=_read(sock)
            if kind!=HELLO or set(hello_fields)!={1,2,3,4}: raise ProxyError('schema')
            hello={'run_id':hello_fields[1].decode(), 'origin':hello_fields[2].decode(), 'nonce':hello_fields[3].decode(), 'digest':hello_fields[4].decode()}
            _valid_hello(hello); mac=_mac(bytes(self.secret),hello,self.challenge,b'host')
            _write(sock,_frame(HOST_CHALLENGE,[(1,self.challenge),(2,mac)]));kind,response=_read(sock)
            if kind!=PROXY_RESPONSE or set(response)!={1,2,3} or response[1]!=self.challenge or response[2]!=hello['digest'].encode() or len(response[3])!=32 or not hmac.compare_digest(response[3],_mac(bytes(self.secret),hello,self.challenge,b'proxy')): raise ProxyError('authentication')
            return {'run_id':hello['run_id'],'origin':hello['origin'],'digest':hello['digest']}
        finally:
            self.secret[:]=b'\0'*len(self.secret)

class ObservingProxy:
    def __init__(self,upstream_origin,canonical_workspace,run_id):
        p=urlsplit(upstream_origin)
        if p.scheme!='http' or p.hostname!='127.0.0.1' or not p.port or p.username or p.password or p.path or p.query or p.fragment: raise ProxyError('upstream')
        if not HEX64.fullmatch(run_id): raise ProxyError('run_id')
        self.origin=upstream_origin; self.workspace=Path(canonical_workspace).resolve(strict=True); self.run_id=run_id
        self.state='audit_only'; self.session_id=None; self._test=False; self._seen=set(); self._rejected=set(); self._outcome_unknown=set(); self._closed=False; self._server=None; self._events=0; self._diagnostic=None; self._diff_seen=False
    @classmethod
    def _with_test_authority(cls,upstream_origin,canonical_workspace,run_id,authority):
        if authority is not _AUTHORITY: raise ProxyError('test authority')
        x=cls(upstream_origin,canonical_workspace,run_id); x._test=True; x.state='audit_only'; return x
    def start(self):
        if self._server: raise ProxyError('started')
        proxy=self
        class QuietServer(ThreadingHTTPServer):
            daemon_threads=False
            block_on_close=True
            def __init__(self,*args,**kwargs):
                self.handler_threads=set(); self.active_sockets=set(); self._tracking_lock=threading.Lock()
                super().__init__(*args,**kwargs)
            def process_request_thread(self,request,client_address):
                current=threading.current_thread()
                with self._tracking_lock: self.handler_threads.add(current); self.active_sockets.add(request)
                try: super().process_request_thread(request,client_address)
                finally:
                    with self._tracking_lock: self.active_sockets.discard(request); self.handler_threads.discard(current)
            def handle_error(self, request, client_address):
                # Client disconnects during SSE are normal and content-free.
                return
        class Handler(BaseHTTPRequestHandler):
            protocol_version='HTTP/1.1'
            def log_message(self,*_): pass
            def do_GET(self): proxy._serve(self)
            def do_POST(self): proxy._serve(self)
        self._server=QuietServer(('127.0.0.1',0),Handler); self._thread=threading.Thread(target=self._server.serve_forever,daemon=True); self._thread.start(); return self._server.server_address
    def shutdown(self):
        self._closed=True
        if self._server:
            self._server.shutdown()
            with self._server._tracking_lock: sockets=list(self._server.active_sockets); handlers=list(self._server.handler_threads)
            for active in sockets:
                try: active.shutdown(socket.SHUT_RDWR)
                except OSError: pass
                try: active.close()
                except OSError: pass
            self._server.server_close(); self._thread.join(2)
            for handler in handlers: handler.join(2)
            with self._server._tracking_lock: remaining=[thread for thread in self._server.handler_threads if thread.is_alive()]
            if self._thread.is_alive() or remaining: raise ProxyError('shutdown')
    def _serve(self,h):
        try:
            if self._closed: raise ProxyError('closed')
            # BaseHTTPRequestHandler retains headers individually; duplicates are observable.
            names=[k.lower() for k,_ in h.headers.items()]
            hosts=h.headers.get_all('Host',[])
            if len(hosts)!=1 or not hosts[0] or ',' in hosts[0] or any(ord(x)<33 or ord(x)>126 for x in hosts[0]) or any(k=='transfer-encoding' or k.startswith('proxy-') or k=='upgrade' for k in names): raise ProxyError('headers')
            if any(k=='connection' and any(x.strip().lower() not in ('close','keep-alive') for x in h.headers.get_all(k,[])[0].split(',')) for k in names): raise ProxyError('headers')
            parsed=urlsplit(h.path)
            if parsed.scheme or parsed.netloc or '#' in h.path: raise ProxyError('path')
            raw_q=parse_qsl(parsed.query,keep_blank_values=True); q={};
            for k,v in raw_q: q.setdefault(k,[]).append(v)
            cls=h.headers.get_all('Content-Length',[])
            if len(cls)>1 or ('transfer-encoding' in names) or (cls and (not cls[0].isascii() or not cls[0].isdigit())): raise ProxyError('headers')
            length=int(cls[0]) if cls else 0
            route=self._route(h.command,parsed.path); limit=self._limits(parsed.path,h.command)[0] if route else 0
            if length>limit: raise ProxyError('body')
            body=h.rfile.read(length) if length else b''
            if len(body)!=length: raise ProxyError('body')
            if h.command=='POST' and h.headers.get('Content-Type')!='application/json': raise ProxyError('headers')
            d=self.validate(h.command,parsed.path,q,body)
            if d.status!=200: self._respond(h,d.status,{'error':d.reason}); return
            if parsed.path=='/event': self._sse(h,q); return
            prepared = self._prepare_v2(parsed.path,body) if route and route[0]=='v2' and self._test else None
            try: status,headers,payload=self._upstream(h.command,parsed.path,parsed.query,body)
            except Exception:
                if prepared: self._outcome_unknown.add(prepared); self._diagnostic='ERR_OUTCOME_UNKNOWN'
                self._respond(h,502,{'error':'ERR_OUTCOME_UNKNOWN' if prepared else 'upstream'}); return
            if parsed.path=='/session' and status//100==2:
                data=self._json(payload,4096); sid=data.get('id') if isinstance(data,dict) else None
                if not isinstance(sid,str) or not ID.fullmatch(sid): raise ProxyError('upstream schema')
                self.session_created(sid)
            if prepared and status//100==2: self._commit_v2(prepared)
            elif prepared: self._rejected.add(prepared); self._diagnostic='UPSTREAM_REJECTED'
            self._respond(h,status,payload,headers)
        except ProxyError as e: self._respond(h,400 if str(e) in ('headers','path','body','json','schema','query') else 403,{'error':str(e)})
        except Exception: self._respond(h,502,{'error':'upstream'})
    def _respond(self,h,status,payload,headers=None):
        try:
            body=payload if isinstance(payload,bytes) else json.dumps(payload,separators=(',',':')).encode(); h.send_response(status); h.send_header('Content-Type',(headers or {}).get('Content-Type','application/json')); h.send_header('Content-Length',str(len(body))); h.end_headers(); h.wfile.write(body)
        except (BrokenPipeError,ConnectionResetError): return
    def _upstream(self,m,path,q,body):
        p=urlsplit(self.origin); conn=http.client.HTTPConnection(p.hostname,p.port,timeout=1); target=path+('?' + q if q else '')
        conn.request(m,target,body=body,headers={'Content-Type':'application/json','Content-Length':str(len(body))} if body else {})
        r=conn.getresponse(); limit=self._limits(path,m)[1]
        response_headers=r.getheaders(); hs={k.lower():v for k,v in response_headers}; cls=[v for k,v in response_headers if k.lower()=='content-length']
        if len(cls)>1 or ('transfer-encoding' in hs) or (cls and (not cls[0].isascii() or not cls[0].isdigit() or int(cls[0])>limit)): conn.close(); raise ProxyError('upstream body')
        claimed=int(cls[0]) if cls else None; data=r.read(limit+1); conn.close()
        if claimed is not None and len(data)!=claimed: raise ProxyError('upstream body')
        if len(data)>limit: raise ProxyError('upstream body')
        return r.status,{k:v for k,v in response_headers if k.lower() in ('content-type','content-length')},data
    def _sse(self,h,q):
        self._directory(q,True); upstream_query=urlencode({'directory':q['directory'][0]}); p=urlsplit(self.origin); conn=http.client.HTTPConnection(p.hostname,p.port,timeout=1); conn.request('GET','/event?'+upstream_query,headers={}); r=conn.getresponse()
        if r.status//100!=2: raise ProxyError('upstream')
        h.send_response(200); h.send_header('Content-Type','text/event-stream'); h.send_header('Connection','close'); h.end_headers(); h.close_connection=True; self.state='waiting_server_connected'
        try:
            while True:
                line=r.fp.readline(MAX_SSE+1)
                if not line: break
                if len(line)>MAX_SSE or not line.startswith(b'data: ') or not line.endswith(b'\n'): raise ProxyError('malformed sse')
                self.observe_sse(line.rstrip(b'\r\n')); h.wfile.write(line); h.wfile.flush()
        except (ProxyError, BrokenPipeError, ConnectionResetError):
            # Headers are already committed: close the stream rather than
            # attempting a second HTTP response.
            self._diagnostic='SSE_STREAM_INVALID'
        finally: conn.close(); h.close_connection=True
        if self.state!='terminal': self.state='reconnect'
    def reconnect_snapshot(self):
        """Audit-only authoritative refresh; it never reissues a V2 action."""
        if not self.session_id: raise ProxyError('state')
        results=[]; query=urlencode({'directory':self.workspace.as_posix()})
        for path in (f'/session/{self.session_id}', '/question', '/permission', f'/session/{self.session_id}/diff'):
            status,_,body=self._upstream('GET',path,query,b'')
            if status//100!=2: raise ProxyError('upstream')
            results.append(self._json(body,self._limits(path,'GET')[1]))
        return tuple(results)
    def _directory(self,q,needed):
        if 'workspace' in q or set(q)-({'directory'} if needed else set()): raise ProxyError('query')
        if not needed:return
        v=q.get('directory',[])
        if len(v)!=1 or '\x00' in v[0] or '..' in v[0].split('/'): raise ProxyError('query')
        raw=v[0]
        if '%' in raw: raise ProxyError('query') # parse_qsl already decoded once; prohibit residual ambiguity
        try: actual=Path(raw).resolve(strict=True)
        except OSError: raise ProxyError('directory')
        if actual!=self.workspace: raise ProxyError('directory')
    def _limits(self,path,m):
        if m=='GET': return (0,8192)
        if path=='/session': return (16384,4096)
        if path.endswith('/prompt'): return (16384,8192)
        if '/question/' in path:return (16384,4096)
        if '/permission/' in path:return (4096,4096)
        if path.endswith('/interrupt'):return (0,4096)
        return (0,0)
    def validate(self,m,path,q,body=b''):
        if self._closed:return Decision(403,'closed')
        routes=self._route(m,path)
        if not routes:return Decision(403,'route')
        try:self._directory(q,routes[1])
        except ProxyError as e:return Decision(400 if str(e)=='query' else 403,str(e))
        req,_=self._limits(path,m)
        if len(body)>req:return Decision(400,'body')
        if routes[0]=='v2':
            if not self._test:return Decision(403,'BLOCKED_A0_CERTIFICATE_REQUIRED')
            try: self._prepare_v2(path,body)
            except ProxyError as e: return Decision(400 if str(e)=='schema' else 403,str(e),True)
            return Decision(200,'SYNTHETIC_TEST_ONLY',True)
        return Decision(200,'v1')
    def _route(self,m,path):
        if (m,path)==('GET','/global/health'):return ('v1',False)
        if (m,path)==('POST','/session') or (m,path) in {('GET','/event'),('GET','/question'),('GET','/permission')}:return ('v1',True)
        if m=='GET' and re.fullmatch(r'/session/[A-Za-z0-9_-]{1,256}(?:/diff)?',path):return ('v1',True)
        if m=='POST' and re.fullmatch(r'/api/session/[A-Za-z0-9_-]{1,256}/prompt',path):return ('v2',False)
        if m=='POST' and re.fullmatch(r'/api/session/[A-Za-z0-9_-]{1,256}/(?:question|permission)/[A-Za-z0-9_-]{1,256}/reply',path):return ('v2',False)
        if m=='POST' and re.fullmatch(r'/api/session/[A-Za-z0-9_-]{1,256}/interrupt',path):return ('v2',False)
        return None
    def _json(self,b,limit):
        if len(b)>limit:raise ProxyError('body')
        try:return json.loads(b)
        except Exception:raise ProxyError('json')
    def _prepare_v2(self,path,body):
        if self.state not in ('provisioned','question_pending','permission_pending') or not self.session_id or not path.startswith('/api/session/'+self.session_id+'/'):raise ProxyError('state')
        action='interrupt' if path.endswith('/interrupt') else 'question' if '/question/' in path else 'permission' if '/permission/' in path else 'prompt'
        if action in self._seen or action in self._rejected or action in self._outcome_unknown:raise ProxyError('duplicate')
        data={} if not body else self._json(body,self._limits(path,'POST')[0]); ok=(action=='prompt' and self.state=='provisioned' and isinstance(data.get('prompt'),dict) and isinstance(data['prompt'].get('text'),str)) or (action=='question' and self.state=='question_pending' and isinstance(data.get('answers'),list) and all(isinstance(x,list) and all(isinstance(y,str) for y in x) for x in data['answers'])) or (action=='permission' and self.state=='permission_pending' and data=={'reply':'reject'}) or (action=='interrupt' and not data)
        if not ok:raise ProxyError('schema')
        return action
    def _commit_v2(self,action):
        self._seen.add(action); self.state='terminal' if action=='interrupt' else 'provisioned'; self._diagnostic='SYNTHETIC_TEST_ONLY'
    def session_created(self,sid):
        if self.state!='server_connected' or not ID.fullmatch(sid):raise ProxyError('transition')
        self.session_id=sid; self.state='session_created'
    def observe_sse(self,line):
        if self._events>=MAX_EVENTS or len(line)>MAX_SSE or not line.startswith(b'data: '):raise ProxyError('malformed sse')
        try:e=json.loads(line[6:])
        except Exception:raise ProxyError('malformed sse')
        if not isinstance(e,dict) or set(e)!={'id','type','properties'} or not isinstance(e['id'],str) or not isinstance(e['type'],str) or not isinstance(e['properties'],dict):raise ProxyError('malformed sse')
        self._events+=1; t,p=e['type'],e['properties']
        if t=='server.connected' and self.state=='waiting_server_connected':self.state='server_connected'; return
        if not self.session_id or p.get('sessionID')!=self.session_id:return
        if t=='session.created' and self.state=='session_created':self.state='provisioned'
        elif t in ('question.asked','question.v2.asked') and self.state=='provisioned':self.state='question_pending'
        elif t in ('permission.asked','permission.v2.asked') and self.state=='provisioned':self.state='permission_pending'
        elif t=='session.diff':self._diff_seen=True
