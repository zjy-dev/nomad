from __future__ import annotations
import base64, hashlib, json, os, socket, subprocess, tempfile, unittest, urllib.error
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from tools.nomad_web import agent_runtime, launcher, state

class Response:
    status=200
    def __init__(self, raw): self.raw=raw
    def __enter__(self): return self
    def __exit__(self,*_): return False
    def read(self,_limit): return self.raw

class OfficialSessionResponse(Response):
    status=200

class ProductHostBootstrapTests(unittest.TestCase):
    @staticmethod
    def cfg(root: Path, home: Path, bundle: Path | None = None) -> SimpleNamespace:
        return SimpleNamespace(
            repo_root=root,
            home=home,
            relay_port=18089,
            gateway_port=14173,
            agent_port=4096,
            bundle_root=bundle,
            _test_host_identity_root=root / "host-identity-root",
        )
    def test_official_readiness_requires_available_safe_session_alias(self):
        safe_alias = "sess-" + "a" * 32
        payload = {
            "schema": "nomad.alpha.readonly.v1",
            "status": "available",
            "session": {"session_id": safe_alias},
            "last_applied_seq": 1,
            "digest": "sha256:" + "b" * 64,
            "events": [],
            "changes": {"status": "unavailable", "files": []},
            "provenance": {},
        }
        raw = json.dumps(payload, separators=(",", ":")).encode()
        with mock.patch.object(launcher._NO_PROXY_OPENER, "open", return_value=OfficialSessionResponse(raw)):
            self.assertEqual(launcher._wait_official_session("http://127.0.0.1:4173/api/alpha/session"), safe_alias)
        payload["session"]["session_id"] = "ses_raw"
        raw = json.dumps(payload, separators=(",", ":")).encode()
        with mock.patch.object(launcher._NO_PROXY_OPENER, "open", return_value=OfficialSessionResponse(raw)), mock.patch.object(launcher.time, "sleep"):
            with self.assertRaisesRegex(RuntimeError, "OFFICIAL_SESSION_NOT_READY"):
                launcher._wait_official_session("http://127.0.0.1:4173/api/alpha/session", timeout=0.0001)
    SESSION={"id":"ses_owned","slug":"s","projectID":"p","directory":"d","title":"t","version":"1.18.16","time":{"created":1,"updated":1}}
    def test_session_create_is_authenticated_post_without_list(self):
        seen=[]
        def open_(request,timeout):
            seen.append(request); return Response(json.dumps(self.SESSION).encode())
        with mock.patch.object(launcher._NO_PROXY_OPENER,"open",side_effect=open_):
            self.assertEqual(launcher._create_run_session("http://127.0.0.1:4096","canary"),"ses_owned")
        self.assertEqual(len(seen),1); self.assertEqual(seen[0].method,"POST"); self.assertEqual(seen[0].full_url,"http://127.0.0.1:4096/session")
        self.assertEqual(seen[0].headers["Authorization"],"Basic "+base64.b64encode(b"opencode:canary").decode())
    def test_invalid_session_is_rejected(self):
        with mock.patch.object(launcher._NO_PROXY_OPENER,"open",return_value=Response(b'{"id":"bad id"}')):
            with self.assertRaisesRegex(RuntimeError,"SESSION_CREATE_INVALID"): launcher._create_run_session("http://127.0.0.1:4096","x")
    def test_initial_prompt_dispatch_uses_exact_reviewed_v2_route_and_redacts_output(self):
        seen=[]
        prompt_text = "ship it"
        prompt_digest = hashlib.sha256(prompt_text.encode("utf-8")).hexdigest()
        payload={
            "data":{
                "admittedSeq":7,
                "delivery":"queue",
                "id":"dispatch_raw",
                "promotedSeq":8,
                "prompt":{"text":"secret prompt should never surface"},
                "sessionID":"ses_raw",
                "timeCreated":1,
            }
        }
        def open_(request,timeout):
            seen.append(request)
            return Response(json.dumps(payload, separators=(",", ":")).encode())
        read_fd, write_fd = os.pipe()
        os.write(write_fd, prompt_text.encode("utf-8"))
        os.close(write_fd)
        with mock.patch.object(launcher._NO_PROXY_OPENER, "open", side_effect=open_):
            result = launcher._dispatch_initial_prompt(
                "http://127.0.0.1:4096", "canary", "ses_raw", read_fd
            )
        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0].method, "POST")
        self.assertEqual(seen[0].full_url, "http://127.0.0.1:4096/api/session/ses_raw/prompt")
        self.assertEqual(
            seen[0].headers["Authorization"],
            "Basic " + base64.b64encode(b"opencode:canary").decode(),
        )
        self.assertEqual(seen[0].data, b'{"prompt":{"text":"ship it"}}')
        self.assertEqual(result["delivery"], "queue")
        self.assertEqual(result["admitted_seq"], 7)
        self.assertEqual(result["promoted_seq"], 8)
        self.assertTrue(result["dispatch_alias"].startswith("dispatch-"))
        self.assertNotIn(prompt_text, json.dumps(result, sort_keys=True))
        self.assertNotIn(prompt_digest, json.dumps(result, sort_keys=True))
        self.assertNotIn("dispatch_raw", json.dumps(result, sort_keys=True))
        self.assertNotIn("ses_raw", json.dumps(result, sort_keys=True))
        with self.assertRaises(OSError):
            os.fstat(read_fd)
    def test_initial_prompt_dispatch_rejects_bad_shape_and_empty_prompt_input(self):
        read_fd, write_fd = os.pipe()
        os.write(write_fd, b"   ")
        os.close(write_fd)
        with self.assertRaisesRegex(RuntimeError, "INITIAL_PROMPT_INVALID"):
            launcher._dispatch_initial_prompt(
                "http://127.0.0.1:4096", "canary", "ses_raw", read_fd
            )
        with self.assertRaises(OSError):
            os.fstat(read_fd)
        read_fd, write_fd = os.pipe()
        os.write(write_fd, b"prompt")
        os.close(write_fd)
        with mock.patch.object(launcher._NO_PROXY_OPENER, "open", return_value=Response(b'{"data":{"id":"x"}}')):
            with self.assertRaisesRegex(RuntimeError, "INITIAL_PROMPT_DISPATCH_INVALID"):
                launcher._dispatch_initial_prompt(
                    "http://127.0.0.1:4096", "canary", "ses_raw", read_fd
                )
    def test_run_foundation_returns_redacted_projection_only(self):
        result = {
            "state": "RUNNING",
            "mode": "official-agent-local",
            "real_agent_enabled": True,
            "bundle_digest": "a" * 64,
            "blocked_on": ["PRODUCTION_DEVICE_IDENTITY"],
            "web_url": "http://127.0.0.1:14173/",
            "agent_origin": "http://127.0.0.1:4096",
            "agent_version": "1.18.16",
            "logs_dir": "/tmp/logs",
            "run_id": "b" * 64,
            "session_alias": "sess-" + "c" * 32,
            "workspace_binding_digest": "d" * 64,
            "identity": {"running": {"run_identity": "e" * 64}},
            "_initial_prompt_dispatch": {
                "schema": "nomad.web-companion.initial-dispatch.v1",
                "status": "accepted",
                "delivery": "queue",
                "dispatch_alias": "dispatch-" + "f" * 32,
                "admitted_seq": 7,
                "promoted_seq": 8,
                "empty_success": False,
            },
            "processes": [{"name": "opencode"}],
        }
        with tempfile.TemporaryDirectory() as temporary:
            config = SimpleNamespace(
                home=Path(temporary) / "home",
                _test_host_identity_root=Path(temporary) / "host-identity-root",
            )
            with mock.patch.object(launcher, "initialize_home"), mock.patch.object(
                launcher, "lifecycle_lock"
            ) as lock, mock.patch.object(
                launcher, "_start_unlocked", return_value=result
            ) as start:
                lock.return_value.__enter__.return_value = True
                lock.return_value.__exit__.return_value = False
                output = launcher.run_foundation(
                    config,
                    provider_name="OPENAI_API_KEY",
                    credential_fd=7,
                    workspace=Path(temporary),
                )
        start.assert_called_once()
        self.assertEqual(output["dispatch"]["dispatch_alias"], "dispatch-" + "f" * 32)
        self.assertNotIn("processes", output)
        self.assertNotIn("_initial_prompt_dispatch", output)
    def test_run_mode_requires_stopped_and_prompt_failure_rolls_back(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary); home=root/"home"; workspace=root/"workspace"; bundle=root/"bundle"; workspace.mkdir(); bundle.mkdir()
            config=self.cfg(root, home, bundle)
            state.initialize_home(config)
            for path in (home/"bin",home/"run",home/"logs"): path.mkdir(parents=True,exist_ok=True)
            state.validate_runtime_dirs(config)
            host={"name":"product-host","pid":11,"process_group":11,"identity":"a"*64,"log":str(home/"logs/host.log")}
            prompt_read, prompt_write = os.pipe()
            os.write(prompt_write, b"prompt")
            os.close(prompt_write)
            agent={"name":"opencode","pid":12,"process_group":12,"identity":"b"*64,"log":str(home/"logs/agent.log"),"origin":"http://127.0.0.1:4096","_server_password":"canary","_workspace_binding_digest":"c"*64,"_initial_prompt_fd":prompt_read}
            stopped=[]
            with mock.patch.object(launcher,"select_bundle_for_start",return_value=bundle), mock.patch.object(launcher,"_selected_bundle_digest",return_value="a"*64), mock.patch.object(launcher,"_require_host_identity_ready"), mock.patch.object(launcher,"_prepare_product_host_socket",return_value=home/"run"/"sockdir"/"product-host.sock"), mock.patch.object(launcher,"_socket_parent_identity",return_value={"parent_dev":1,"parent_ino":2}), mock.patch.object(launcher,"_prepare_device_registry_path",return_value=home/"private"/launcher.DEVICE_REGISTRY_BASENAME), mock.patch.object(launcher,"_prepare_command_journal",return_value=home/"run"/"command.sqlite3"), mock.patch.object(launcher,"_spawn_product_host",return_value=host), mock.patch.object(launcher,"start_run_agent",return_value=agent), mock.patch.object(launcher,"_create_run_session",return_value="ses_raw"), mock.patch.object(launcher,"_bootstrap_host",return_value={"parent_dev":1,"parent_ino":2,"parent_uid":os.geteuid(),"parent_mode":0o700,"socket_dev":3,"socket_ino":4,"socket_uid":os.geteuid(),"socket_mode":0o600}), mock.patch.object(launcher,"_cleanup_product_host_socket"), mock.patch.object(launcher,"_cleanup_gateway_db"), mock.patch.object(launcher,"_cleanup_command_journal"), mock.patch.object(launcher,"_dispatch_initial_prompt",side_effect=RuntimeError("INITIAL_PROMPT_DISPATCH_REJECTED")), mock.patch.object(launcher.processes,"stop",side_effect=lambda item: stopped.append(item["name"]) or True):
                with self.assertRaisesRegex(RuntimeError,"INITIAL_PROMPT_DISPATCH_REJECTED"):
                    launcher._start_unlocked(config,provider_name="OPENAI_API_KEY",credential_fd=7,workspace=workspace,require_stopped=True)
            self.assertEqual(set(stopped),{"opencode","product-host"})
            self.assertFalse(state.state_path(config).exists())
            with self.assertRaises(OSError):
                os.fstat(prompt_read)
    def test_child_run_envelope_parser_accepts_canonical_only_and_returns_prompt(self):
        valid = json.dumps({
            "schema": agent_runtime.RUN_STDIN_SCHEMA,
            "provider_credential": "sk-canary",
            "initial_prompt": "ship it",
        }, sort_keys=True, separators=(",", ":")).encode("utf-8")
        read_fd, write_fd = os.pipe()
        os.write(write_fd, valid)
        os.close(write_fd)
        secret, prompt = agent_runtime._read_run_envelope_fd(read_fd)
        self.assertEqual(secret, "sk-canary")
        self.assertEqual(prompt, b"ship it")
        bad_cases = (
            b'{"schema":"nomad.web-companion.run-stdin.v1","provider_credential":"a","provider_credential":"b","initial_prompt":"x"}',
            json.dumps({
                "provider_credential": "a",
                "schema": agent_runtime.RUN_STDIN_SCHEMA,
                "initial_prompt": "x",
            }, indent=2).encode(),
            json.dumps({
                "schema": agent_runtime.RUN_STDIN_SCHEMA,
                "provider_credential": "a",
                "initial_prompt": "   ",
            }, sort_keys=True, separators=(",", ":")).encode(),
        )
        for payload in bad_cases:
            with self.subTest(payload=payload[:80]):
                read_fd, write_fd = os.pipe()
                os.write(write_fd, payload)
                os.close(write_fd)
                with self.assertRaises(SystemExit) as exited:
                    agent_runtime._read_run_envelope_fd(read_fd)
                self.assertEqual(exited.exception.code, 70)
    def test_prompt_pipe_writer_is_exact_and_closes_fd(self):
        read_fd, write_fd = os.pipe()
        agent_runtime._write_prompt_fd(write_fd, bytearray(b"prompt-bytes"))
        self.assertEqual(os.read(read_fd, 64), b"prompt-bytes")
        self.assertEqual(os.read(read_fd, 1), b"")
        os.close(read_fd)
        with self.assertRaises(OSError):
            os.fstat(write_fd)
    def test_run_mode_bootstraps_host_before_dispatch(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary); home=root/"home"; workspace=root/"workspace"; bundle=root/"bundle"; workspace.mkdir(); bundle.mkdir()
            config=self.cfg(root, home, bundle)
            state.initialize_home(config)
            for path in (home/"bin",home/"run",home/"logs"): path.mkdir(parents=True,exist_ok=True)
            state.validate_runtime_dirs(config)
            host={"name":"product-host","pid":11,"process_group":11,"identity":"a"*64,"log":str(home/"logs/host.log")}
            prompt_read, prompt_write = os.pipe()
            os.write(prompt_write, b"prompt")
            os.close(prompt_write)
            agent={"name":"opencode","pid":12,"process_group":12,"identity":"b"*64,"log":str(home/"logs/agent.log"),"origin":"http://127.0.0.1:4096","_server_password":"canary","_workspace_binding_digest":"c"*64,"_initial_prompt_fd":prompt_read}
            order=[]
            def fake_bootstrap(*_args, **_kwargs):
                order.append("bootstrap")
                return {"parent_dev":1,"parent_ino":2,"parent_uid":os.geteuid(),"parent_mode":0o700,"socket_dev":3,"socket_ino":4,"socket_uid":os.geteuid(),"socket_mode":0o600}
            def fake_dispatch(*_args, **_kwargs):
                order.append("dispatch")
                return {"schema":"nomad.web-companion.initial-dispatch.v1","status":"accepted","delivery":"queue","dispatch_alias":"dispatch-"+"f"*32,"admitted_seq":1,"promoted_seq":None,"empty_success":False}
            with mock.patch.object(launcher,"select_bundle_for_start",return_value=bundle), mock.patch.object(launcher,"_selected_bundle_digest",return_value="a"*64), mock.patch.object(launcher,"_require_host_identity_ready"), mock.patch.object(launcher,"_prepare_product_host_socket",return_value=home/"run"/"sockdir"/"product-host.sock"), mock.patch.object(launcher,"_socket_parent_identity",return_value={"parent_dev":1,"parent_ino":2}), mock.patch.object(launcher,"_prepare_device_registry_path",return_value=home/"private"/launcher.DEVICE_REGISTRY_BASENAME), mock.patch.object(launcher,"_prepare_command_journal",return_value=home/"run"/"command.sqlite3"), mock.patch.object(launcher,"_spawn_product_host",return_value=host), mock.patch.object(launcher,"start_run_agent",return_value=agent), mock.patch.object(launcher,"_create_run_session",return_value="ses_raw"), mock.patch.object(launcher,"_bootstrap_host",side_effect=fake_bootstrap), mock.patch.object(launcher,"_dispatch_initial_prompt",side_effect=fake_dispatch), mock.patch.object(launcher,"_compose_identity",return_value={"running":{"run_identity":"z"*64}}), mock.patch.object(launcher,"write_run_state"), mock.patch.object(launcher.processes,"spawn",return_value={"name":"gateway","pid":13,"process_group":13,"identity":"d"*64,"log":str(home/"logs/gateway.log")}), mock.patch.object(launcher,"_wait"), mock.patch.object(launcher,"_wait_official_session",return_value="sess-"+"e"*32):
                result = launcher._start_unlocked(config,provider_name="OPENAI_API_KEY",credential_fd=7,workspace=workspace,require_stopped=True)
            self.assertEqual(order,["bootstrap","dispatch"])
            self.assertEqual(result["_initial_prompt_dispatch"]["delivery"],"queue")
    def test_bootstrap_import_uses_installed_package_root(self):
        self.assertIn("from nomad_web.agent_runtime import _bootstrap_main", agent_runtime.BOOTSTRAP)
        self.assertNotIn("from tools.nomad_web.agent_runtime import _bootstrap_main", agent_runtime.BOOTSTRAP)
        self.assertEqual(
            agent_runtime._BOOTSTRAP_PACKAGE_ROOT,
            str(Path(agent_runtime.__file__).resolve().parents[1]),
        )
    def test_run_spawn_maps_prompt_fd_and_closes_parent_writer(self):
        with tempfile.TemporaryDirectory() as temporary:
            workspace=Path(temporary); _,_,workspace_fd=agent_runtime._verified_workspace(workspace); input_read,input_write=os.pipe(); os.write(input_write,b"x"); os.close(input_write)
            observed={}
            def spawn(_exe,argv,_env,**kwargs): observed["argv"]=argv; observed["actions"]=kwargs["file_actions"]; return 4242
            try:
                with mock.patch.object(agent_runtime.os,"posix_spawn",side_effect=spawn):
                    pid, prompt_fd = agent_runtime._spawn_with_run_envelope_fd(["/bin/echo","4096"],{},"OPENAI_API_KEY",input_read,"password",workspace_fd)
                self.assertEqual(pid,4242)
                self.assertIsInstance(prompt_fd,int)
                targets=[action[2] for action in observed["actions"] if action[0]==os.POSIX_SPAWN_DUP2]
                self.assertEqual(set(targets),{0,1,2,6,7,8,9})
                self.assertIn("run",observed["argv"])
                self.assertIn("6",observed["argv"])
                os.close(prompt_fd)
            finally:
                os.close(workspace_fd)
    def test_session_extra_field_and_duplicate_are_rejected(self):
        extra={**self.SESSION,"extra":1}
        for raw in (json.dumps(extra).encode(),b'{"id":"a","id":"b"}'):
            with mock.patch.object(launcher._NO_PROXY_OPENER,"open",return_value=Response(raw)):
                with self.assertRaisesRegex(RuntimeError,"SESSION_CREATE_INVALID"): launcher._create_run_session("http://127.0.0.1:4096","x")
    def test_session_invalid_utf8_and_depth_are_rejected(self):
        for raw in (b'\xff', b'['*40+b'0'+b']'*40):
            with mock.patch.object(launcher._NO_PROXY_OPENER,"open",return_value=Response(raw)):
                with self.assertRaisesRegex(RuntimeError,"SESSION_CREATE_INVALID"): launcher._create_run_session("http://127.0.0.1:4096","x")
    def test_proxy_environment_and_bad_origin_never_send_auth(self):
        proxy={name:"http://127.0.0.1:1" for name in ("HTTP_PROXY","http_proxy","HTTPS_PROXY","ALL_PROXY")}
        with mock.patch.dict(launcher.os.environ,proxy,clear=False), mock.patch.object(launcher._NO_PROXY_OPENER,"open") as send:
            for origin in ("https://127.0.0.1:4096","http://user@127.0.0.1:4096","http://localhost:4096","http://127.0.0.1:4096/escape"):
                with self.assertRaisesRegex(RuntimeError,"AGENT_LOOPBACK_URL_INVALID"): launcher._create_run_session(origin,"auth-canary")
            send.assert_not_called()
        self.assertFalse(any(isinstance(handler,launcher.urllib.request.ProxyHandler) and handler.proxies for handler in launcher._NO_PROXY_OPENER.handlers))
    def test_health_proxy_is_disabled_and_schema_exact(self):
        self.assertFalse(any(isinstance(handler,agent_runtime.urllib.request.ProxyHandler) and handler.proxies for handler in agent_runtime._NO_PROXY_OPENER.handlers))
        bad=(b'{"healthy":true,"version":"1.18.16","extra":1}',b'{"healthy":1,"version":"1.18.16"}',b'{"healthy":true,"version":"1.18.16","healthy":true}')
        for raw in bad:
            with mock.patch.object(agent_runtime._NO_PROXY_OPENER,"open",return_value=Response(raw)), mock.patch.object(agent_runtime.time,"sleep"), self.assertRaisesRegex(RuntimeError,"AGENT_HEALTH_TIMEOUT"):
                agent_runtime._wait_health(4096,"auth-canary",timeout=0.0001)
    def test_health_bad_url_rejected_before_open(self):
        with mock.patch.object(agent_runtime._NO_PROXY_OPENER,"open") as send:
            with self.assertRaisesRegex(RuntimeError,"AGENT_LOOPBACK_URL_INVALID"): agent_runtime._validate_loopback_url("http://user@127.0.0.1:4096/global/health",4096,"/global/health")
            send.assert_not_called()
    def test_missing_ack_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            home=Path(temporary)/"home"; home.mkdir(); path=launcher._prepare_product_host_socket(home,"d"*64)
            registry_path = launcher._prepare_device_registry_path(home)
            run_dir=home/"run"; run_dir.mkdir(mode=0o700)
            command_journal=launcher._prepare_command_journal(launcher._make_command_journal_path(run_dir,"d"*64),run_dir)
            parent,child=socket.socketpair(); child.close()
            try:
                with self.assertRaisesRegex(RuntimeError,"HOST_READY_INVALID"):
                    launcher._bootstrap_host(parent,run_id="a"*64,origin="http://127.0.0.1:4096",session_id="s",password="canary",workspace_digest="b"*64,product_host_socket_path=path,device_registry_path=registry_path,agent_pid=4242,agent_process_group=4242,agent_process_identity="c"*64,command_transport_key=base64.b64encode(b"t"*32).decode(),command_authority_key=base64.b64encode(b"a"*32).decode(),command_journal_path=command_journal)
            finally: parent.close(); launcher._cleanup_product_host_socket(path)
    def test_bootstrap_contains_only_fixed_private_socket_capability(self):
        with tempfile.TemporaryDirectory() as temporary:
            home=Path(temporary)/"home"; home.mkdir(); path=launcher._prepare_product_host_socket(home,"d"*64)
            registry_path = launcher._prepare_device_registry_path(home)
            parent,child=socket.socketpair(); observed={}; listener=[]
            command_journal = launcher._prepare_command_journal(
                launcher._make_command_journal_path(home / "run", "d" * 64),
                home / "run",
            ) if False else None
            def peer():
                length=int.from_bytes(child.recv(4),"big"); raw=b""
                while len(raw)<length: raw+=child.recv(length-len(raw))
                observed.update(json.loads(raw)); self.assertEqual(child.recv(1),b"")
                server=socket.socket(socket.AF_UNIX); server.bind(str(path)); os.chmod(path,0o600); listener.append(server)
                parent_info=path.parent.stat(); socket_info=path.stat()
                ready={"schema":launcher.HOST_READY_SCHEMA,"parent_dev":parent_info.st_dev,"parent_ino":parent_info.st_ino,"socket_dev":socket_info.st_dev,"socket_ino":socket_info.st_ino,"snapshot_seq":1}
                encoded=json.dumps(ready,separators=(",",":")).encode(); child.sendall(len(encoded).to_bytes(4,"big")+encoded); child.shutdown(socket.SHUT_WR)
            import threading
            worker=threading.Thread(target=peer); worker.start()
            try:
                run_dir = home / "run"
                run_dir.mkdir(mode=0o700)
                command_journal = launcher._prepare_command_journal(
                    launcher._make_command_journal_path(run_dir, "d" * 64),
                    run_dir,
                )
                identity=launcher._bootstrap_host(parent,run_id="a"*64,origin="http://127.0.0.1:4096",session_id="ses_raw",password="secret",workspace_digest="b"*64,product_host_socket_path=path,device_registry_path=registry_path,agent_pid=4242,agent_process_group=4242,agent_process_identity="c"*64,command_transport_key="A"*44,command_authority_key="B"*44,command_journal_path=command_journal)
            finally:
                parent.close(); child.close(); worker.join()
                if listener: listener[0].close()
                launcher._cleanup_product_host_socket(path,identity)
        self.assertEqual(observed["product_host_socket_path"],str(path))
        self.assertEqual(
            Path(observed["device_registry_path"]),
            launcher._device_registry_path(home),
        )
        self.assertNotIn(observed["run_id"],observed["product_host_socket_path"]); self.assertNotIn(observed["session_id"],observed["product_host_socket_path"])
        self.assertEqual(Path(observed["device_registry_path"]).name, launcher.DEVICE_REGISTRY_BASENAME)
        self.assertEqual(Path(observed["device_registry_path"]).parent.name, launcher.DEVICE_REGISTRY_DIRNAME)
        self.assertNotIn(observed["run_id"], observed["device_registry_path"])
        self.assertNotIn(observed["session_id"], observed["device_registry_path"])
        self.assertEqual((observed["agent_pid"],observed["agent_process_group"],observed["agent_process_identity"]),(4242,4242,"c"*64))
        self.assertEqual(observed["command_transport_key"],"A"*44)
        self.assertEqual(observed["command_authority_key"],"B"*44)
        self.assertEqual(observed["command_journal_path"],str(command_journal))
        self.assertFalse(Path(observed["command_journal_path"]).exists())
    def test_official_gateway_argv_uses_socket_without_relay_token(self):
        source=Path(launcher.__file__).read_text()
        self.assertIn('["--product-host-socket", str(product_host_socket_path)]',source)
        self.assertIn('["--command-key-fd", "11"]',source)
        self.assertIn("command_transport_key = _random_command_key()", source)
        self.assertIn("command_authority_key = _random_command_key()", source)
        self.assertIn('"device_registry_path":str(device_registry_path)', source)
        for option in ("--product-host-socket-parent-dev","--product-host-socket-parent-ino","--product-host-socket-dev","--product-host-socket-ino"): self.assertIn(option,source)
        self.assertIn('"--mode", "official-agent-local" if agent_requested else "foundation-readonly"',source)
        self.assertIn('gateway_env: dict[str, str] = {}',source)
        self.assertNotIn("--command-transport-key", source)
        self.assertNotIn("--command-authority-key", source)
    def test_device_registry_path_is_stable_private_ascii_and_not_run_scoped(self):
        with tempfile.TemporaryDirectory() as temporary:
            home=Path(temporary)/"home"; home.mkdir()
            first=launcher._prepare_device_registry_path(home)
            second=launcher._prepare_device_registry_path(home)
            self.assertEqual(first, second)
            self.assertTrue(first.is_absolute())
            self.assertTrue(os.fspath(first).isascii())
            self.assertEqual(first.name, launcher.DEVICE_REGISTRY_BASENAME)
            self.assertEqual(first.parent.name, launcher.DEVICE_REGISTRY_DIRNAME)
            self.assertEqual(first.parent.stat().st_mode & 0o777, 0o700)
            self.assertFalse(first.exists())
    def test_device_registry_cleanup_removes_only_owned_regular_0600_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            home=Path(temporary)/"home"; home.mkdir()
            path=launcher._prepare_device_registry_path(home)
            for candidate in (path, Path(str(path) + "-wal"), Path(str(path) + "-shm")):
                candidate.write_text("x")
                os.chmod(candidate, 0o600)
            launcher._cleanup_device_registry(path)
            self.assertFalse(path.parent.exists())
    def test_device_registry_cleanup_rejects_untrusted_sidecar_and_preserves_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            home=Path(temporary)/"home"; home.mkdir()
            path=launcher._prepare_device_registry_path(home)
            path.write_text("x"); os.chmod(path, 0o600)
            wal = Path(str(path) + "-wal")
            wal.write_text("wal"); os.chmod(wal, 0o644)
            with self.assertRaisesRegex(RuntimeError, "UNSAFE_DEVICE_REGISTRY"):
                launcher._cleanup_device_registry(path)
            self.assertTrue(path.exists())
            self.assertTrue(wal.exists())
    def test_short_socket_capability_is_private_and_content_free(self):
        with tempfile.TemporaryDirectory() as temporary:
            home=Path(temporary)/("home-"+"x"*140); home.mkdir()
            path=launcher._prepare_product_host_socket(home,"d"*64)
            try:
                self.assertLessEqual(len(os.fsencode(path)),100); self.assertEqual(path.name,"product-host.sock")
                self.assertNotIn(home.name,str(path)); self.assertEqual(path.parent.stat().st_mode & 0o777,0o700)
                other=launcher._prepare_product_host_socket(home,"e"*64)
                self.assertNotEqual(other.parent,path.parent)
                launcher._cleanup_product_host_socket(other)
            finally: launcher._cleanup_product_host_socket(path)
    def test_socket_prepare_rejects_orphan_and_symlink_without_removing_them(self):
        with tempfile.TemporaryDirectory() as temporary:
            home=Path(temporary)/"home"; home.mkdir(); path=launcher._prepare_product_host_socket(home,"d"*64)
            listener=socket.socket(socket.AF_UNIX); listener.bind(str(path)); os.chmod(path,0o600); identity=launcher._socket_identity(path,launcher._socket_parent_identity(path))
            try:
                with self.assertRaisesRegex(RuntimeError,"ALREADY_EXISTS"): launcher._prepare_product_host_socket(home,"d"*64)
                self.assertTrue(path.exists())
            finally: listener.close(); launcher._cleanup_product_host_socket(path,identity)
            path=launcher._product_host_socket_path(home,"e"*64); path.parent.symlink_to(Path(temporary)/"missing",target_is_directory=True)
            try:
                with self.assertRaisesRegex(RuntimeError,"UNSAFE_PRODUCT_HOST_SOCKET_DIRECTORY"): launcher._prepare_product_host_socket(home,"e"*64)
                self.assertTrue(path.parent.is_symlink())
            finally: path.parent.unlink()
    def test_cleanup_rejects_non_socket_leaf_and_preserves_state(self):
        with tempfile.TemporaryDirectory() as temporary:
            home=Path(temporary)/"home"; home.mkdir(); path=launcher._prepare_product_host_socket(home,"d"*64); path.write_text("do-not-delete")
            with self.assertRaisesRegex(RuntimeError,"UNSAFE_PRODUCT_HOST_SOCKET"): launcher._cleanup_product_host_socket(path)
            self.assertEqual(path.read_text(),"do-not-delete"); path.unlink(); path.parent.rmdir()
    def test_cleanup_rejects_same_uid_socket_replacement(self):
        with tempfile.TemporaryDirectory() as temporary:
            home=Path(temporary)/"home"; home.mkdir(); path=launcher._prepare_product_host_socket(home,"d"*64); first=socket.socket(socket.AF_UNIX); first.bind(str(path)); os.chmod(path,0o600)
            identity=launcher._socket_identity(path,launcher._socket_parent_identity(path)); first.close(); path.unlink()
            replacement=socket.socket(socket.AF_UNIX); replacement.bind(str(path)); os.chmod(path,0o600)
            try:
                with self.assertRaisesRegex(RuntimeError,"UNSAFE_PRODUCT_HOST_SOCKET"): launcher._cleanup_product_host_socket(path,identity)
                self.assertTrue(path.exists())
            finally: replacement.close(); path.unlink(); path.parent.rmdir()
    def test_state_schema_rejects_raw_session_or_password(self):
        self.assertNotIn("server_password",state.RUN_KEYS); self.assertNotIn("session_id",state.RUN_KEYS); self.assertIn("session_alias",state.RUN_KEYS); self.assertIn("bundle_digest", state.RUN_KEYS); self.assertIn("bundle_digest", state.REMOTE_RUN_KEYS)
    def test_selected_bundle_digest_is_verified_and_canonical_under_home(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary); home=root/"home"; home.mkdir(); digest="a"*64; bundle=home/"bundles"/digest; bundle.mkdir(parents=True)
            other=root/"other"; other.mkdir()
            config=SimpleNamespace(home=home, _test_host_identity_root=root / "host-identity-root")
            with mock.patch.object(launcher,"verify_bundle",return_value={"bundle_digest":digest}):
                self.assertEqual(launcher._selected_bundle_digest(config,bundle),digest)
                with self.assertRaisesRegex(RuntimeError,"SELECTED_BUNDLE_BINDING_INVALID"):
                    launcher._selected_bundle_digest(config,other)
    def test_binding_values_are_content_free_hashes(self):
        run="a"*64; session="ses_raw"; alias="sess-"+"e"*32; self.assertNotIn(session,alias); self.assertRegex(alias,r"^sess-[0-9a-f]{32}$")
        state_alias=hashlib.sha256(f"state:{run}".encode()).hexdigest(); self.assertNotEqual(state_alias,run); self.assertEqual(len(state_alias),64)
    def test_process_order_contract(self):
        source=Path(launcher.__file__).read_text(); self.assertIn('["opencode", "product-host", "gateway"]',Path(state.__file__).read_text()); self.assertLess(source.index("_spawn_product_host"),source.index("start_agent(",source.index("def _start_unlocked")))
    def test_ack_failure_cleans_host_and_agent_without_state(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary); home=root/"home"; workspace=root/"workspace"; bundle=root/"bundle"; workspace.mkdir(); bundle.mkdir()
            config=self.cfg(root, home, bundle)
            state.initialize_home(config)
            for path in (home/"bin",home/"run",home/"logs"): path.mkdir(parents=True,exist_ok=True)
            state.validate_runtime_dirs(config)
            host={"name":"product-host","pid":11,"process_group":11,"identity":"a"*64,"log":str(home/"logs/host.log")}
            agent={"name":"opencode","pid":12,"process_group":12,"identity":"b"*64,"log":str(home/"logs/agent.log"),"origin":"http://127.0.0.1:4096","_server_password":"canary","_workspace_binding_digest":"c"*64}
            stopped=[]
            with mock.patch.object(launcher,"select_bundle_for_start",return_value=bundle), mock.patch.object(launcher,"_selected_bundle_digest",return_value="a"*64), mock.patch.object(launcher,"_require_host_identity_ready"), mock.patch.object(launcher,"_spawn_product_host",return_value=host), mock.patch.object(launcher,"start_agent",return_value=agent), mock.patch.object(launcher,"_create_run_session",return_value="ses_raw"), mock.patch.object(launcher,"_bootstrap_host",side_effect=RuntimeError("HOST_BOOTSTRAP_ACK_MISSING")), mock.patch.object(launcher.processes,"stop",side_effect=lambda item: stopped.append(item["name"]) or True):
                with self.assertRaisesRegex(RuntimeError,"HOST_BOOTSTRAP_ACK_MISSING"):
                    launcher._start_unlocked(config,provider_name="OPENAI_API_KEY",credential_fd=7,workspace=workspace)
            self.assertEqual(set(stopped),{"opencode","product-host"}); self.assertEqual(len(stopped),2); self.assertFalse(state.state_path(config).exists())

    def test_gateway_fd11_receives_transport_key_and_host_does_not(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary); home=root/"home"; workspace=root/"workspace"; bundle=root/"bundle"; workspace.mkdir(); bundle.mkdir()
            config=self.cfg(root, home, bundle)
            state.initialize_home(config)
            for path in (home/"bin",home/"run",home/"logs"): path.mkdir(parents=True,exist_ok=True)
            state.validate_runtime_dirs(config)
            host={"name":"product-host","pid":11,"process_group":11,"identity":"a"*64,"log":str(home/"logs/host.log")}
            agent={"name":"opencode","pid":12,"process_group":12,"identity":"b"*64,"log":str(home/"logs/agent.log"),"origin":"http://127.0.0.1:4096","_server_password":"canary","_workspace_binding_digest":"c"*64}
            seen = {}
            def fake_bootstrap(_channel, **kwargs):
                seen["bootstrap"] = kwargs
                return {"parent_dev":1,"parent_ino":2,"parent_uid":os.geteuid(),"parent_mode":0o700,"socket_dev":3,"socket_ino":4,"socket_uid":os.geteuid(),"socket_mode":0o600}
            def fake_spawn(name, command, cwd, env, log_path, *, extra_fd_actions=(), close_fds=()):
                seen[name] = {"command": list(command), "extra_fd_actions": list(extra_fd_actions), "close_fds": list(close_fds)}
                if name == "gateway":
                    mapping = dict(extra_fd_actions)
                    self.assertIn(11, mapping.values())
                    source_fd = next(source for source, target in extra_fd_actions if target == 11)
                    raw = os.read(source_fd, 256)
                    seen["gateway_key"] = raw
                    self.assertEqual(os.read(source_fd, 1), b"")
                return {"name":name,"pid":99 if name=="gateway" else 98,"process_group":99 if name=="gateway" else 98,"identity":"d"*64,"log":str(log_path)}
            with mock.patch.object(launcher,"select_bundle_for_start",return_value=bundle), mock.patch.object(launcher,"_selected_bundle_digest",return_value="a"*64), mock.patch.object(launcher,"_require_host_identity_ready"), mock.patch.object(launcher,"_spawn_product_host",return_value=host), mock.patch.object(launcher,"start_agent",return_value=agent), mock.patch.object(launcher,"_create_run_session",return_value="ses_raw"), mock.patch.object(launcher,"_bootstrap_host",side_effect=fake_bootstrap), mock.patch.object(launcher.processes,"spawn",side_effect=fake_spawn), mock.patch.object(launcher,"_wait"), mock.patch.object(launcher,"_wait_official_session",return_value="sess-"+"e"*32) as session_ready, mock.patch.object(launcher.processes,"stop",return_value=True):
                result = launcher._start_unlocked(config,provider_name="OPENAI_API_KEY",credential_fd=7,workspace=workspace)
            self.assertEqual(result["state"],"RUNNING")
            self.assertEqual(result["bundle_digest"], "a" * 64)
            session_ready.assert_called_once_with("http://127.0.0.1:14173/api/alpha/session")
            self.assertEqual(result["session_alias"], "sess-" + "e" * 32)
            self.assertEqual(
                Path(seen["bootstrap"]["device_registry_path"]),
                launcher._device_registry_path(home),
            )
            self.assertEqual(seen["gateway"]["command"][-2:],["--command-key-fd","11"])
            self.assertEqual(len(seen["gateway_key"]), 32)
            self.assertRegex(seen["bootstrap"]["command_transport_key"], r"^[A-Za-z0-9+/=]{44}$")
            self.assertRegex(seen["bootstrap"]["command_authority_key"], r"^[A-Za-z0-9+/=]{44}$")
            self.assertNotEqual(seen["bootstrap"]["command_transport_key"], seen["bootstrap"]["command_authority_key"])
            self.assertEqual(base64.b64encode(seen["gateway_key"]).decode("ascii"), seen["bootstrap"]["command_transport_key"])
            self.assertNotIn("--command-authority-key", " ".join(seen["gateway"]["command"]))

    def test_command_journal_cleanup_removes_only_owned_regular_0600_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            run_dir=root/"run"
            run_dir.mkdir(mode=0o700)
            journal=launcher._prepare_command_journal(
                launcher._make_command_journal_path(run_dir, "d" * 64),
                run_dir,
            )
            for path in (journal, Path(str(journal) + "-wal"), Path(str(journal) + "-shm")):
                path.write_text("x")
                os.chmod(path, 0o600)
            launcher._cleanup_command_journal(journal, run_dir)
            for path in (journal, Path(str(journal) + "-wal"), Path(str(journal) + "-shm")):
                self.assertFalse(path.exists())

    def test_command_journal_cleanup_rejects_non_owned_shape(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            run_dir=root/"run"
            run_dir.mkdir(mode=0o700)
            journal=launcher._prepare_command_journal(
                launcher._make_command_journal_path(run_dir, "d" * 64),
                run_dir,
            )
            journal.write_text("x")
            os.chmod(journal, 0o644)
            with self.assertRaisesRegex(RuntimeError,"UNSAFE_COMMAND_JOURNAL"):
                launcher._cleanup_command_journal(journal, run_dir)
            self.assertTrue(journal.exists())
    def test_workspace_identity_detects_stat_race(self):
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary); observed=path.stat(); raced=type(observed)(tuple(observed))
            with mock.patch.object(Path,"stat",return_value=raced):
                # A real descriptor fstat still binds the opened directory; changing the pathname observation must fail.
                with mock.patch.object(os,"fstat",return_value=SimpleNamespace(st_mode=observed.st_mode,st_uid=os.getuid(),st_dev=observed.st_dev,st_ino=observed.st_ino+1)):
                    with self.assertRaisesRegex(RuntimeError,"UNSAFE_AGENT_DIRECTORY"): agent_runtime._verified_workspace(path)
    def test_workspace_fd_survives_path_replacement_and_binds_original_inode(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary); workspace=root/"workspace"; workspace.mkdir(); original=workspace.stat(); resolved,digest,descriptor=agent_runtime._verified_workspace(workspace)
            moved=root/"moved"; workspace.rename(moved); workspace.mkdir()
            try:
                observed=os.fstat(descriptor); self.assertEqual((observed.st_dev,observed.st_ino),(original.st_dev,original.st_ino)); self.assertNotEqual(observed.st_ino,workspace.stat().st_ino)
                self.assertEqual(digest,hashlib.sha256(f"{resolved}:{original.st_dev}:{original.st_ino}".encode()).hexdigest())
            finally: os.close(descriptor)
    def test_agent_spawn_maps_only_fixed_capability_fds(self):
        with tempfile.TemporaryDirectory() as temporary:
            workspace=Path(temporary); _,_,workspace_fd=agent_runtime._verified_workspace(workspace); credential_read,credential_write=os.pipe(); os.write(credential_write,b"x"); os.close(credential_write)
            observed={}
            def spawn(_exe,argv,_env,**kwargs): observed["argv"]=argv; observed["actions"]=kwargs["file_actions"]; return 4242
            try:
                with mock.patch.object(agent_runtime.os,"posix_spawn",side_effect=spawn): self.assertEqual(agent_runtime._spawn_with_credential_fd(["/bin/echo","4096"],{},"OPENAI_API_KEY",credential_read,"password",workspace_fd),4242)
                targets=[action[2] for action in observed["actions"] if action[0]==os.POSIX_SPAWN_DUP2]
                self.assertEqual(set(targets),{0,1,2,7,8,9}); self.assertIn("7",observed["argv"]); self.assertIn("8",observed["argv"]); self.assertIn("9",observed["argv"])
            finally:
                os.close(workspace_fd)
    def test_socket_descriptors_are_non_inheritable_by_default(self):
        left,right=socket.socketpair()
        try: self.assertFalse(os.get_inheritable(left.fileno())); self.assertFalse(os.get_inheritable(right.fileno()))
        finally: left.close(); right.close()
    def test_real_product_host_rejects_extra_byte_without_ack(self):
        repo=Path(__file__).resolve().parents[2]; binary=repo/"connector/target/debug/nomad-product-host"
        subprocess.run(["cargo","build","--bin","nomad-product-host"],cwd=repo/"connector",check=True,stdout=subprocess.DEVNULL)
        parent,child=socket.socketpair()
        saved=None
        try:
            try: saved=os.dup(10)
            except OSError: pass
            os.dup2(child.fileno(),10); process=subprocess.Popen([str(binary)],pass_fds=(10,),stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        finally:
            if saved is None: os.close(10)
            else: os.dup2(saved,10); os.close(saved)
        child.close()
        value={"schema":"nomad.product-host.bootstrap.v1","run_id":"a"*64,"origin":"http://127.0.0.1:4096","session_id":"ses_1","server_password":"secret","workspace_binding_digest":"b"*64}
        raw=json.dumps(value,separators=(",",":")).encode(); parent.sendall(len(raw).to_bytes(4,"big")+raw+b"x"); parent.shutdown(socket.SHUT_WR)
        self.assertEqual(parent.recv(1024),b""); parent.close(); self.assertEqual(process.wait(timeout=5),70)
    def test_product_host_identity_failure_kills_and_reaps(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary); log=root/"host.log"; left,right=socket.socketpair(); seen=[]; original=os.posix_spawn
            def spawn(*args,**kwargs):
                pid=original(*args,**kwargs); seen.append(pid); return pid
            try:
                with mock.patch.object(launcher.os,"posix_spawn",side_effect=spawn), mock.patch.object(launcher.processes,"process_identity",side_effect=RuntimeError("identity")):
                    with self.assertRaisesRegex(RuntimeError,"identity"): launcher._spawn_product_host(Path("/usr/bin/yes"),root,log,right)
                self.assertEqual(len(seen),1)
                with self.assertRaises(ProcessLookupError): os.kill(seen[0],0)
                with self.assertRaises(ChildProcessError): os.waitpid(seen[0],os.WNOHANG)
            finally: left.close(); right.close()
    def test_process_identity_uses_host_matching_fixed_environment(self):
        completed=SimpleNamespace(returncode=0,stdout=b"stable process identity\n")
        with mock.patch.object(subprocess,"run",return_value=completed) as run:
            identity=launcher.processes.process_identity(4242)
        self.assertEqual(identity,hashlib.sha256(completed.stdout).hexdigest())
        self.assertEqual(run.call_args.kwargs["env"],{"LANG":"C","LC_ALL":"C","PATH":"/usr/bin:/bin:/usr/sbin:/sbin"})

if __name__=="__main__": unittest.main()
