import http.client, json, queue, socket, tempfile, threading, time, unittest, urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from testkit.pilot.observing_proxy import *
from testkit.pilot import observing_proxy as proxy_mod
H='a'*64; N='b'*64; D='c'*64
class Up(BaseHTTPRequestHandler):
    requests=[]; malformed=False; status=200; oversized=False; coordinated=False
    sse_queue=None; sse_connected=None
    protocol_version='HTTP/1.1'
    def log_message(self,*a):pass
    def do_GET(self):
        Up.requests.append(self.path)
        if self.path.startswith('/event'):
            self.send_response(200);self.send_header('Content-Type','text/event-stream');self.send_header('Connection','close');self.end_headers()
            first=b'data: {"id":"1","type":"server.connected","properties":{}}\n'
            self.wfile.write(first);self.wfile.flush()
            if Up.coordinated:
                Up.sse_connected.set()
                while True:
                    item=Up.sse_queue.get(timeout=5)
                    if item is None: break
                    self.wfile.write(item);self.wfile.flush()
            else:
                lines=[b'data: {"id":"2","type":"session.created","properties":{"sessionID":"test-session-1"}}\n']
                for x in ([b'data: bad\n'] if Up.malformed else lines):self.wfile.write(x);self.wfile.flush()
            self.close_connection=True
        else:
            body=b'x'*9000 if Up.oversized else b'{}';self.send_response(Up.status);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(body)));self.send_header('Connection','close');self.end_headers();self.wfile.write(body)
    def do_POST(self):
        length=int(self.headers.get('Content-Length','0'));self.rfile.read(length);Up.requests.append(self.path);body=b'x'*9000 if Up.oversized else (b'{"id":"test-session-1"}' if self.path.startswith('/session') else b'{}');self.send_response(Up.status);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(body)));self.send_header('Connection','close');self.end_headers();self.wfile.write(body)
class T(unittest.TestCase):
 def setUp(self):
  Up.requests=[];Up.status=200;Up.oversized=False;Up.malformed=False;Up.coordinated=False;Up.sse_queue=queue.Queue();Up.sse_connected=threading.Event();self.tmp=tempfile.TemporaryDirectory();self.ws=Path(self.tmp.name).resolve();self.u=ThreadingHTTPServer(('127.0.0.1',0),Up);self.upstream_thread=threading.Thread(target=self.u.serve_forever);self.upstream_thread.start();self.origin='http://127.0.0.1:'+str(self.u.server_port);self.p=ObservingProxy(self.origin,self.ws,H);self.t=ObservingProxy._with_test_authority(self.origin,self.ws,H,proxy_mod._issue_test_authority())
 def tearDown(self):self.p.shutdown();self.t.shutdown();self.u.shutdown();self.u.server_close();self.upstream_thread.join(2);self.assertFalse(self.upstream_thread.is_alive());self.tmp.cleanup()
 def q(self):return {'directory':[str(self.ws)]}
 def prep(self):self.t.state='server_connected';self.t.session_created('s');self.t.observe_sse(b'data: {"id":"x","type":"session.created","properties":{"sessionID":"s"}}')
 def post(self,path,body=b'',ctype='application/json'):
  host,port=self.t.start() if not self.t._server else self.t._server.server_address; c=__import__('http.client').client.HTTPConnection(host,port)
  try:c.request('POST',path,body=body,headers={'Content-Type':ctype});r=c.getresponse();status=r.status;r.read();return status
  finally:c.close()
 def get(self,path):
  host,port=self.t.start() if not self.t._server else self.t._server.server_address;c=http.client.HTTPConnection(host,port,timeout=3)
  try:c.request('GET',path);r=c.getresponse();status=r.status;body=r.read();return status,body
  finally:c.close()
 def wait_state(self,state):
  deadline=time.monotonic()+3
  while time.monotonic()<deadline:
   if self.t.state==state:return
   time.sleep(.01)
  self.fail('state did not become '+state+'; current='+self.t.state)
 def test01_prod_blocked(self):self.assertEqual(self.p.validate('POST','/api/session/x/prompt',{},b'{}').reason,'BLOCKED_A0_CERTIFICATE_REQUIRED')
 def test02_health(self):self.assertEqual(self.p.validate('GET','/global/health',{}).status,200)
 def test03_unknown(self):self.assertEqual(self.p.validate('GET','/wat',self.q()).status,403)
 def test04_method(self):self.assertEqual(self.p.validate('POST','/event',self.q()).status,403)
 def test05_query_extra(self):self.assertEqual(self.p.validate('GET','/event',{'directory':[str(self.ws)],'x':['1']}).status,400)
 def test06_workspace(self):self.assertEqual(self.p.validate('GET','/event',{'workspace':[str(self.ws)]}).status,400)
 def test07_duplicate_dir(self):self.assertEqual(self.p.validate('GET','/event',{'directory':['x','y']}).status,400)
 def test08_directory_mismatch(self):self.assertEqual(self.p.validate('GET','/event',{'directory':['/tmp']}).status,403)
 def test09_dotdot(self):self.assertEqual(self.p.validate('GET','/event',{'directory':[str(self.ws/'..')]}).status,400)
 def test10_percent(self):self.assertEqual(self.p.validate('GET','/event',{'directory':['%2fno']}).status,400)
 def test11_body(self):self.assertEqual(self.p.validate('POST','/session',self.q(),b'x'*16385).status,400)
 def test12_out_of_order(self):self.assertEqual(self.t.validate('POST','/api/session/s/prompt',{},b'{"prompt":{"text":"x"}}').status,403)
 def test13_prompt(self):self.prep();self.assertEqual(self.t.validate('POST','/api/session/s/prompt',{},b'{"prompt":{"text":"x"}}').reason,'SYNTHETIC_TEST_ONLY');self.assertEqual(self.t.state,'provisioned')
 def test14_prompt_schema(self):self.prep();self.assertEqual(self.t.validate('POST','/api/session/s/prompt',{},b'{}').status,400)
 def test15_question_prepare_is_side_effect_free(self):self.prep();self.t.observe_sse(b'data: {"id":"x","type":"question.v2.asked","properties":{"sessionID":"s"}}');p=b'{"answers":[["x"]]}';self.assertEqual(self.t.validate('POST','/api/session/s/question/r/reply',{},p).status,200);self.assertEqual(self.t.validate('POST','/api/session/s/question/r/reply',{},p).status,200);self.assertEqual(self.t.state,'question_pending')
 def test26_real_http_v2_commits_only_after_2xx(self):
  self.prep();host,port=self.t.start();c=__import__('http.client').client.HTTPConnection(host,port);c.request('POST','/api/session/s/prompt',body=b'{"prompt":{"text":"x"}}',headers={'Content-Type':'application/json'});r=c.getresponse();self.assertEqual(r.status,200);r.read();c.close();self.assertEqual(self.t.state,'provisioned');self.assertIn('prompt',self.t._seen)
 def test27_question_real_forward_once(self):self.prep();self.t.observe_sse(b'data: {"id":"q","type":"question.asked","properties":{"sessionID":"s"}}');self.assertEqual(self.post('/api/session/s/question/r/reply',b'{"answers":[["x"]]}'),200);self.assertEqual(self.post('/api/session/s/question/r/reply',b'{"answers":[["x"]]}'),403);self.assertEqual(sum('/question/' in x for x in Up.requests),1)
 def test28_permission_real_forward(self):self.prep();self.t.observe_sse(b'data: {"id":"p","type":"permission.asked","properties":{"sessionID":"s"}}');self.assertEqual(self.post('/api/session/s/permission/r/reply',b'{"reply":"reject"}'),200);self.assertIn('permission',self.t._seen)
 def test29_interrupt_real_forward(self):self.prep();self.assertEqual(self.post('/api/session/s/interrupt'),200);self.assertEqual(self.t.state,'terminal')
 def test30_non2xx_is_terminal_rejected(self):
  self.prep();Up.status=500;before=len(Up.requests);self.assertEqual(self.post('/api/session/s/prompt',b'{"prompt":{"text":"x"}}'),500);self.assertIn('prompt',self.t._rejected);self.assertEqual(self.t._diagnostic,'UPSTREAM_REJECTED');self.assertEqual(self.t.state,'provisioned');self.assertNotIn('prompt',self.t._seen);Up.status=200;self.assertEqual(self.post('/api/session/s/prompt',b'{"prompt":{"text":"x"}}'),403);self.assertEqual(len(Up.requests),before+1)
 def test31_ambiguous_locks_action(self):
  self.prep();self.t.origin='http://127.0.0.1:1';self.assertEqual(self.post('/api/session/s/prompt',b'{"prompt":{"text":"x"}}'),502);self.assertIn('prompt',self.t._outcome_unknown);self.assertEqual(self.post('/api/session/s/prompt',b'{"prompt":{"text":"x"}}'),403)
 def test32_bad_content_type(self):self.prep();self.assertEqual(self.post('/api/session/s/prompt',b'{"prompt":{"text":"x"}}','text/plain'),400)
 def test33_response_oversize(self):self.prep();Up.oversized=True;self.assertEqual(self.post('/api/session/s/prompt',b'{"prompt":{"text":"x"}}'),502);self.assertIn('prompt',self.t._outcome_unknown)
 def test34_redirect_is_not_followed(self):self.prep();Up.status=301;self.assertEqual(self.post('/api/session/s/prompt',b'{"prompt":{"text":"x"}}'),301);self.assertNotIn('prompt',self.t._seen)
 def test35_origin_rejects_auth_path(self):
  with self.assertRaises(ProxyError):ObservingProxy('http://x@127.0.0.1:9',self.ws,H)
 def raw(self,wire):
  host,port=self.t.start() if not self.t._server else self.t._server.server_address;s=socket.create_connection((host,port));s.sendall(wire);s.shutdown(socket.SHUT_WR);out=b''
  try:
   while True:
    part=s.recv(4096)
    if not part:break
    out+=part
  finally:s.close()
  return out
 def test36_transfer_encoding_rejected_before_upstream(self):
  self.prep();before=len(Up.requests);out=self.raw(b'POST /api/session/s/prompt HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n');self.assertIn(b' 400 ',out);self.assertEqual(len(Up.requests),before)
 def test37_duplicate_content_length_rejected_before_upstream(self):
  self.prep();before=len(Up.requests);out=self.raw(b'POST /api/session/s/prompt HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}');self.assertIn(b' 400 ',out);self.assertEqual(len(Up.requests),before)
 def test38_short_request_body_rejected(self):
  self.prep();before=len(Up.requests);out=self.raw(b'POST /api/session/s/prompt HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{}');self.assertIn(b' 400 ',out);self.assertEqual(len(Up.requests),before)
 def test39_host_malformed_rejected(self):
  self.prep();out=self.raw(b'POST /api/session/s/prompt HTTP/1.1\r\nHost: x, y\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}');self.assertIn(b' 400 ',out)
 def test40_exact_full_v2_forward_counts(self):
  self.prep();self.assertEqual(self.post('/api/session/s/prompt',b'{"prompt":{"text":"x"}}'),200);self.t._seen.clear();self.t.observe_sse(b'data: {"id":"q","type":"question.asked","properties":{"sessionID":"s"}}');self.assertEqual(self.post('/api/session/s/question/r/reply',b'{"answers":[["x"]]}'),200);self.t.observe_sse(b'data: {"id":"p","type":"permission.asked","properties":{"sessionID":"s"}}');self.assertEqual(self.post('/api/session/s/permission/r/reply',b'{"reply":"reject"}'),200);self.assertEqual(self.post('/api/session/s/interrupt'),200);self.assertEqual(len([x for x in Up.requests if x.startswith('/api/session/s/')]),4)
 def test41_sse_server_connected_transition(self):self.t.state='waiting_server_connected';self.t.observe_sse(b'data: {"id":"a","type":"server.connected","properties":{}}');self.assertEqual(self.t.state,'server_connected')
 def test42_sse_session_created_correlates(self):self.t.state='server_connected';self.t.session_created('s');self.t.observe_sse(b'data: {"id":"a","type":"session.created","properties":{"sessionID":"s"}}');self.assertEqual(self.t.state,'provisioned')
 def test43_sse_cross_session_ignored(self):self.prep();self.t.observe_sse(b'data: {"id":"a","type":"question.asked","properties":{"sessionID":"other"}}');self.assertEqual(self.t.state,'provisioned')
 def test44_sse_question_transition(self):self.prep();self.t.observe_sse(b'data: {"id":"a","type":"question.v2.asked","properties":{"sessionID":"s"}}');self.assertEqual(self.t.state,'question_pending')
 def test45_sse_permission_transition(self):self.prep();self.t.observe_sse(b'data: {"id":"a","type":"permission.v2.asked","properties":{"sessionID":"s"}}');self.assertEqual(self.t.state,'permission_pending')
 def test46_sse_diff_tracked(self):self.prep();self.t.observe_sse(b'data: {"id":"a","type":"session.diff","properties":{"sessionID":"s"}}');self.assertTrue(self.t._diff_seen)
 def test47_sse_nondata_rejected(self):
  with self.assertRaises(ProxyError):self.t.observe_sse(b'event: nope')
 def test48_sse_oversized_rejected(self):
  with self.assertRaises(ProxyError):self.t.observe_sse(b'data: '+b'x'*8193)
 def test49_reconnect_snapshot_exact_gets(self):
  self.prep();self.t.reconnect_snapshot();encoded=urllib.parse.urlencode({'directory':self.ws.as_posix()});self.assertEqual(Up.requests[-4:],[ '/session/s?'+encoded,'/question?'+encoded,'/permission?'+encoded,'/session/s/diff?'+encoded])
 def test50_second_start_refused(self):self.t.start();self.assertRaises(ProxyError,self.t.start)
 def test51_real_socket_full_sse_and_http_flow(self):
  Up.coordinated=True;host,port=self.t.start();directory=urllib.parse.urlencode({'directory':self.ws.as_posix()});received=[]
  def sse_client():
   c=http.client.HTTPConnection(host,port,timeout=5)
   try:
    c.request('GET','/event?'+directory);r=c.getresponse();self.assertEqual(r.status,200)
    while True:
     line=r.fp.readline()
     if not line:break
     received.append(line)
   finally:c.close()
  client=threading.Thread(target=sse_client);client.start();self.assertTrue(Up.sse_connected.wait(3));self.wait_state('server_connected')
  self.assertEqual(self.post('/session?'+directory,b'{}'),200);self.assertEqual(self.t.session_id,'test-session-1')
  frames=[
   b'data: {"id":"2","type":"session.created","properties":{"sessionID":"test-session-1"}}\n',
   b'data: {"id":"3","type":"question.v2.asked","properties":{"sessionID":"test-session-1"}}\n',
   b'data: {"id":"4","type":"session.diff","properties":{"sessionID":"test-session-1"}}\n',
   b'data: {"id":"5","type":"permission.v2.asked","properties":{"sessionID":"test-session-1"}}\n',
  ]
  Up.sse_queue.put(frames[0]);self.wait_state('provisioned');self.assertEqual(self.get('/session/test-session-1?'+directory)[0],200)
  self.assertEqual(self.post('/api/session/test-session-1/prompt',b'{"prompt":{"text":"x"}}'),200)
  Up.sse_queue.put(frames[1]);self.wait_state('question_pending');self.assertEqual(self.get('/question?'+directory)[0],200);self.assertEqual(self.post('/api/session/test-session-1/question/q/reply',b'{"answers":[["x"]]}'),200)
  Up.sse_queue.put(frames[2]);
  deadline=time.monotonic()+3
  while not self.t._diff_seen and time.monotonic()<deadline:time.sleep(.01)
  self.assertTrue(self.t._diff_seen);self.assertEqual(self.get('/session/test-session-1/diff?'+directory)[0],200)
  Up.sse_queue.put(frames[3]);self.wait_state('permission_pending');self.assertEqual(self.get('/permission?'+directory)[0],200);self.assertEqual(self.post('/api/session/test-session-1/permission/p/reply',b'{"reply":"reject"}'),200)
  Up.sse_queue.put(None);client.join(3);self.assertFalse(client.is_alive());self.assertEqual(received[1:],frames);self.assertEqual(self.t.state,'reconnect')
  self.t.reconnect_snapshot();self.assertTrue(all('cursor' not in x.lower() and 'last-event-id' not in x.lower() for x in Up.requests))
 def test52_real_malformed_sse_closes_without_second_response(self):
  Up.malformed=True;host,port=self.t.start();directory=urllib.parse.urlencode({'directory':self.ws.as_posix()});c=http.client.HTTPConnection(host,port,timeout=3)
  try:c.request('GET','/event?'+directory);r=c.getresponse();self.assertEqual(r.status,200);r.read()
  finally:c.close()
  self.assertEqual(self.t._diagnostic,'SSE_STREAM_INVALID');self.assertEqual(self.t.state,'reconnect')
 def test53_shutdown_joins_slow_sse_handler_and_client(self):
  Up.coordinated=True;host,port=self.t.start();directory=urllib.parse.urlencode({'directory':self.ws.as_posix()});finished=threading.Event()
  def slow_client():
   c=http.client.HTTPConnection(host,port,timeout=5)
   try:
    c.request('GET','/event?'+directory);r=c.getresponse();self.assertEqual(r.status,200);r.fp.readline();r.fp.readline()
   except (OSError,http.client.HTTPException):pass
   finally:c.close();finished.set()
  client=threading.Thread(target=slow_client);client.start();self.assertTrue(Up.sse_connected.wait(3));self.wait_state('server_connected')
  self.t.shutdown();client.join(3);self.assertTrue(finished.is_set());self.assertFalse(client.is_alive());self.assertFalse(self.t._thread.is_alive())
  with self.t._server._tracking_lock:self.assertFalse([thread for thread in self.t._server.handler_threads if thread.is_alive()])
  Up.sse_queue.put(None)
 def test16_permission_exact(self):self.prep();self.t.observe_sse(b'data: {"id":"x","type":"permission.asked","properties":{"sessionID":"s"}}');self.assertEqual(self.t.validate('POST','/api/session/s/permission/r/reply',{},b'{"reply":"allow"}').status,400)
 def test17_interrupt(self):self.prep();self.assertEqual(self.t.validate('POST','/api/session/s/interrupt',{},b'').status,200);self.assertEqual(self.t.state,'provisioned')
 def test18_cross_session(self):self.prep();self.assertEqual(self.t.validate('POST','/api/session/no/prompt',{},b'{"prompt":{"text":"x"}}').status,403)
 def test19_sse_bad(self):
  with self.assertRaises(ProxyError):self.t.observe_sse(b'data: nope')
 def test20_sse_limit(self):
  self.t._events=1000
  with self.assertRaises(ProxyError):self.t.observe_sse(b'data: {"id":"x","type":"x","properties":{}}')
 def test21_handshake(self):
  a,b=socket.socketpair();hello={'run_id':H,'origin':'http://127.0.0.1:5555','nonce':N,'digest':D};sec=b'z'*32
  th=threading.Thread(target=lambda:proxy_handshake(a,sec,hello));th.start();k,f=proxy_mod._read(b);self.assertEqual(k,HELLO);ch=b'q'*32;proxy_mod._write(b,proxy_mod._frame(HOST_CHALLENGE,[(1,ch),(2,proxy_mod._mac(sec,hello,ch,b'host'))]));k,f=proxy_mod._read(b);self.assertEqual(k,PROXY_RESPONSE);self.assertTrue(hmac.compare_digest(f[3],proxy_mod._mac(sec,hello,ch,b'proxy')));a.close();b.close();th.join(1)
 def test22_handshake_bad_mac(self):
  a,b=socket.socketpair();hello={'run_id':H,'origin':'http://127.0.0.1:5555','nonce':N,'digest':D};result=[]
  def peer():
   try: proxy_handshake(a,b'z'*32,hello)
   except ProxyError as e: result.append(str(e))
   finally: a.close()
  th=threading.Thread(target=peer);th.start();proxy_mod._read(b);proxy_mod._write(b,proxy_mod._frame(HOST_CHALLENGE,[(1,b'q'*32),(2,b'0'*32)]));b.close();th.join(1);self.assertFalse(th.is_alive());self.assertEqual(result,['authentication'])
 def test23_rust_compatibility_vector(self):
  hello={'run_id':'a'*64,'origin':'http://127.0.0.1:43123','nonce':'b'*64,'digest':'c'*64}; secret=bytes([8])*32; challenge=bytes([7])*32
  self.assertEqual(proxy_mod._mac(secret,hello,challenge,b'host').hex(),'2b887de8a59020a660dc9b420eafeeb3b1a03c8c871c812daf219a9db2778570')
  self.assertEqual(proxy_mod._mac(secret,hello,challenge,b'proxy').hex(),'5b831eb9115a9d9591a93c4ad8552edc0820d43a82e3a1a1d68859f73761d884')
 def test24_http_server(self):
  host,port=self.p.start();import http.client;c=http.client.HTTPConnection(host,port);c.request('GET','/global/health');self.assertEqual(c.getresponse().status,200);c.close()
 def test25_clean_shutdown(self):self.p.start();self.p.shutdown();self.assertTrue(self.p._closed)
 def test54_host_peer_roundtrip_and_zeroize(self):
  a,b=socket.socketpair();hello={'run_id':H,'origin':'http://127.0.0.1:5555','nonce':N,'digest':D};host=proxy_mod.HostRunBinding(b'q'*32,b'z'*32);result=[]
  th=threading.Thread(target=lambda:result.append(host.handshake(b)));th.start();proxy_handshake(a,b'z'*32,hello);th.join(2);a.close();b.close();self.assertEqual(result[0]['run_id'],H);self.assertEqual(bytes(host.secret),b'\0'*32)
 def test55_host_peer_replay_rejected(self):
  host=proxy_mod.HostRunBinding(b'q'*32,b'z'*32);host.used=True;a,b=socket.socketpair()
  try:
   with self.assertRaises(ProxyError):host.handshake(a)
  finally:a.close();b.close()
 def test56_host_peer_bad_proxy_mac_zeroizes(self):
  a,b=socket.socketpair();host=proxy_mod.HostRunBinding(b'q'*32,b'z'*32)
  def bad():
   proxy_mod._write(a,proxy_mod._frame(HELLO,[(1,H.encode()),(2,b'http://127.0.0.1:5555'),(3,N.encode()),(4,D.encode())]));proxy_mod._read(a);proxy_mod._write(a,proxy_mod._frame(PROXY_RESPONSE,[(1,b'q'*32),(2,D.encode()),(3,b'0'*32)]))
  th=threading.Thread(target=bad);th.start()
  with self.assertRaises(ProxyError):host.handshake(b)
  th.join(2);a.close();b.close();self.assertEqual(bytes(host.secret),b'\0'*32)
 def test57_frame_zero_and_truncated_rejected(self):
  a,b=socket.socketpair();a.sendall(b'\0\0\0\0');
  with self.assertRaises(ProxyError):proxy_mod._read(b)
  a.close();b.close()
 def test58_unknown_duplicate_and_version_fields_rejected(self):
  for frame in [bytes([HELLO,VERSION,9,0,1,1]),bytes([HELLO,VERSION,1,0,1,1,1,0,1,2]),bytes([HELLO,2])]:
   with self.assertRaises(ProxyError):proxy_mod._exact(frame,HELLO,[1])
 def test59_second_hmac_vector(self):
  hello={'run_id':'d'*64,'origin':'http://127.0.0.1:43124','nonce':'e'*64,'digest':'f'*64};self.assertEqual(proxy_mod._mac(bytes([1])*32,hello,bytes([2])*32,b'host').hex(),'a26407ada6c859a3fcaee9e59dac4aba92db89b2d7e86775526c71f0dde90c19')
 def test60_test_authority_not_pickleable(self):
  import pickle
  with self.assertRaises(TypeError):pickle.dumps(proxy_mod._issue_test_authority())
 def test61_production_all_v2_blocked(self):
  for path,body in [('/api/session/s/prompt',b'{"prompt":{"text":"x"}}'),('/api/session/s/question/q/reply',b'{"answers":[["x"]]}'),('/api/session/s/permission/p/reply',b'{"reply":"reject"}'),('/api/session/s/interrupt',b'')]:self.assertEqual(self.p.validate('POST',path,{},body).reason,'BLOCKED_A0_CERTIFICATE_REQUIRED')
 def test62_no_capability_or_credential_environment_surface(self):
  text=Path(proxy_mod.__file__).read_text();lower=text.lower();self.assertNotIn('os.environ',text);self.assertNotIn('testkit.iteration3_receipts',lower);self.assertNotIn('capability',lower);self.assertNotIn('lifecycle-certificate.json',lower);self.assertNotIn('open(certificate',lower)
 def test63_proxy_handshake_silent_peer_is_bounded_and_shutdown(self):
  a,b=socket.socketpair();hello={'run_id':H,'origin':'http://127.0.0.1:5555','nonce':N,'digest':D};result=[]
  def peer():
   try:proxy_handshake(a,b'z'*32,hello)
   except ProxyError as error:result.append(str(error))
   finally:a.close()
  started=time.monotonic();thread=threading.Thread(target=peer);thread.start();proxy_mod._read(b);thread.join(3);elapsed=time.monotonic()-started
  try:self.assertFalse(thread.is_alive());self.assertLess(elapsed,3);self.assertEqual(result,['io']);self.assertEqual(b.recv(1),b'')
  finally:b.close()
if __name__=='__main__':unittest.main()
