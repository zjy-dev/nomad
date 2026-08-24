"""Structural A0 protocol tests; no Provider or certificate is available here."""
from __future__ import annotations
import contextlib, importlib.util, io, json, os, shutil, stat, sys, tempfile, unittest, urllib.error
from pathlib import Path
from unittest import mock

SPEC = importlib.util.spec_from_file_location("discover_lifecycle", Path(__file__).with_name("discover_lifecycle.py"))
mod = importlib.util.module_from_spec(SPEC); assert SPEC and SPEC.loader
sys.modules[SPEC.name] = mod; SPEC.loader.exec_module(mod)
ROUTES = mod.verified_routes(); WORKSPACE = Path("/tmp/project"); FILTER = {"directory": str(WORKSPACE)}

def event(kind, session="s1", **props):
    properties = ({"sessionID": session, **props} if session is not None else props)
    return {"id": "evt", "type": kind, "properties": properties}

def happy(events=None, overrides=None):
    prompt = mod.PROMPT_PATH.read_text(encoding="utf-8")
    requests = [
        ("POST", "/session", FILTER, {"permission": list(mod.SESSION_PERMISSION_RULES)}, 200, {"id":"s1"}),
        ("GET", "/session/s1", FILTER, None, 200, {"id":"s1"}),
        ("POST", "/api/session/s1/prompt", None, {"prompt":{"text":prompt}}, 200, {}),
        ("GET", "/question", FILTER, None, 200, [{"id":"q1","sessionID":"s1"}]),
        ("POST", "/api/session/s1/question/q1/reply", None, {"answers":[["keep add"]]}, 200, {}),
        ("GET", "/session/s1/diff", FILTER, None, 200, [{"file":"redacted"}]),
        ("GET", "/permission", FILTER, None, 200, [{"id":"p1","sessionID":"s1","permission":"bash","patterns":[mod.TEST_COMMAND]}]),
        ("POST", "/api/session/s1/permission/p1/reply", None, {"reply":"reject"}, 200, {}),
        ("POST", "/api/session/s1/interrupt", None, None, 200, {}),
    ]
    if overrides:
        for index, value in overrides.items(): requests[index] = value
    stream = events or [event("server.connected", None), event("session.created"), event("question.asked"), event("session.diff"), event("permission.asked")]
    return mod.ScriptedTransport(stream, requests)

class ProtocolTests(unittest.TestCase):
    def run_happy(self, transport=None):
        transport = transport or happy(); candidate = mod._run_protocol(transport, WORKSPACE, ROUTES, 1); transport.assert_consumed(); return candidate, transport

    def test_happy_exact_sequence_requests_queries_bodies_and_rules(self):
        candidate, transport = self.run_happy(); self.assertIsInstance(candidate, mod.StructuralCandidate); self.assertEqual(transport.started_query, FILTER); self.assertTrue(transport.stopped and transport.joined); self.assertEqual(candidate.evidence["diff_file_count"], 1)
    def test_candidate_cannot_be_written_or_certified_by_protocol(self):
        candidate, _ = self.run_happy(); self.assertNotIsInstance(candidate, mod.CompletedRealDiscovery)
        self.assertFalse(hasattr(mod, "atomic_certificate_write")); self.assertFalse(hasattr(mod, "atomic_shape_write"))
    def test_real_authority_cannot_be_constructed_normally(self):
        with self.assertRaisesRegex(mod.DiscoveryError, "SYNTHETIC_TEST_NOT_CERTIFIED"): mod.RealRunAuthority("a"*64, object())
    def test_no_caller_controlled_live_run_kind(self):
        source=Path(__file__).with_name("discover_lifecycle.py").read_text(); self.assertNotIn("live_run_kind", source); self.assertIn("def _run_protocol(", source)
    def test_invalid_session_id(self):
        t=happy(overrides={0:("POST","/session",FILTER,{"permission":list(mod.SESSION_PERMISSION_RULES)},200,{"id":"bad id"})})
        with self.assertRaisesRegex(mod.DiscoveryError, "SESSION_RESPONSE_INVALID"): mod._run_protocol(t,WORKSPACE,ROUTES,1)
    def test_readiness_timeout_closes_reader(self):
        t=happy(events=[]); t._events=[]
        with self.assertRaisesRegex(mod.DiscoveryError, "SSE_TIMEOUT"): mod._run_protocol(t,WORKSPACE,ROUTES,0)
        self.assertTrue(t.stopped and t.joined)
    def test_malformed_event(self):
        t=happy(events=[event("server.connected",None),{"type":"session.created"}])
        with self.assertRaisesRegex(mod.DiscoveryError, "UNEXPECTED_EVENT_SCHEMA"): mod._run_protocol(t,WORKSPACE,ROUTES,1)
    def test_wrong_session_is_ignored(self):
        stream=[event("server.connected",None),event("question.asked","other"),event("session.created"),event("question.asked"),event("session.diff"),event("permission.asked")]; self.run_happy(happy(stream))
    def test_out_of_order_marker(self):
        t=happy([event("server.connected",None),event("question.asked")])
        with self.assertRaisesRegex(mod.DiscoveryError, "EVENT_ORDER"): mod._run_protocol(t,WORKSPACE,ROUTES,1)
    def test_duplicate_marker(self):
        t=happy([event("server.connected",None),event("session.created"),event("session.created")])
        with self.assertRaisesRegex(mod.DiscoveryError, "EVENT_ORDER"): mod._run_protocol(t,WORKSPACE,ROUTES,1)
    def test_replied_rejected_updated_are_ignored(self):
        stream=[event("server.connected",None),event("question.replied"),event("permission.rejected"),event("session.created"),event("question.asked"),event("session.diff"),event("permission.asked")]; self.run_happy(happy(stream))

    def snapshot_failure(self,index,response,code="SNAPSHOT_CORRELATION"):
        base=happy(); old=base._requests[index]; base._requests[index]=(*old[:5],response)
        with self.assertRaisesRegex(mod.DiscoveryError,code): mod._run_protocol(base,WORKSPACE,ROUTES,1)
    def test_session_snapshot_wrong_id(self): self.snapshot_failure(1,{"id":"other"})
    def test_session_snapshot_non_object(self): self.snapshot_failure(1,[])
    def test_question_zero(self): self.snapshot_failure(3,[])
    def test_question_multiple(self): self.snapshot_failure(3,[{"id":"a","sessionID":"s1"},{"id":"b","sessionID":"s1"}])
    def test_question_wrong_session(self): self.snapshot_failure(3,[{"id":"a","sessionID":"other"}])
    def test_permission_zero(self): self.snapshot_failure(6,[])
    def test_permission_multiple(self): self.snapshot_failure(6,[{"id":"a","sessionID":"s1"},{"id":"b","sessionID":"s1"}])
    def test_permission_wrong_session(self): self.snapshot_failure(6,[{"id":"a","sessionID":"other"}])
    def test_permission_wrong_command(self): self.snapshot_failure(6,[{"id":"a","sessionID":"s1","permission":"bash","patterns":["wrong"]}],"PERMISSION_TRIGGER_UNCERTIFIED")
    def test_permission_singular_pattern_schema_is_rejected(self): self.snapshot_failure(6,[{"id":"a","sessionID":"s1","permission":"bash","pattern":mod.TEST_COMMAND}],"PERMISSION_TRIGGER_UNCERTIFIED")
    def test_permission_extra_pattern_is_rejected(self): self.snapshot_failure(6,[{"id":"a","sessionID":"s1","permission":"bash","patterns":[mod.TEST_COMMAND,"other"]}],"PERMISSION_TRIGGER_UNCERTIFIED")
    def test_http_non_2xx_normalized_and_closes(self):
        t=happy(); old=t._requests[0]; t._requests[0]=(*old[:4],500,{})
        with self.assertRaisesRegex(mod.DiscoveryError,"UPSTREAM_HTTP_REJECTED"): mod._run_protocol(t,WORKSPACE,ROUTES,1)
        self.assertTrue(t.stopped and t.joined)
    def test_diff_zero(self): self.snapshot_failure(5,[],"DIFF_ZERO")
    def test_reader_exception_normalized_and_closed(self):
        t=happy(events=[RuntimeError("secret")])
        with self.assertRaisesRegex(mod.DiscoveryError,"SSE_TIMEOUT"): mod._run_protocol(t,WORKSPACE,ROUTES,1)
        self.assertTrue(t.stopped and t.joined)
    def test_permission_rule_precedence_exact_after_wildcard(self): mod._validate_permission_rule_precedence(mod.SESSION_PERMISSION_RULES)
    def test_permission_rule_precedence_uncertain_fails_closed(self):
        with self.assertRaisesRegex(mod.DiscoveryError,"PERMISSION_TRIGGER_UNCERTIFIED"): mod._validate_permission_rule_precedence(tuple(reversed(mod.SESSION_PERMISSION_RULES)))
    def test_directory_is_only_filter(self):
        _,t=self.run_happy(); queries=[query for _,_,query,_ in t.calls if query is not None]; self.assertTrue(all(query == FILTER for query in queries)); self.assertTrue(all(set(query)=={"directory"} for query in queries))

class EvidenceTests(unittest.TestCase):
    def test_shape_extractor_bool_list_depth_count_and_policy(self):
        shaped=mod._extract_property_shape({"sessionID":True,"info":{"id":"x","slug":"x","projectID":"x","directory":"x","title":"x","version":"x","time":{}},},mod._POLICY["session.created"])
        self.assertEqual(shaped["properties"]["sessionID"]["type"],"bool")
        self.assertLessEqual(len(shaped["properties"]),16)
        with self.assertRaisesRegex(mod.DiscoveryError,"CONTENT_POLICY"): mod._extract_property_shape({"secret":"x"},mod._POLICY["session.created"])
        with self.assertRaisesRegex(mod.DiscoveryError,"CONTENT_POLICY"): mod._extract_property_shape({"unknown":"x"},mod._POLICY["session.created"])

    def test_build_manifest_binds_sources_and_relations(self):
        evidence=self.valid(); completed=mod.CompletedRealDiscovery(evidence,mod._COMPLETION_TOKEN)
        shapes=[mod._event_shape("created","session.created",{"sessionID":"s","info":{"id":"s","slug":"x","projectID":"x","directory":"x","title":"x","version":"x","time":{}}}),mod._event_shape("question","question.asked",{"id":"q","sessionID":"s","questions":[],"tool":{}}),mod._event_shape("diff","session.diff",{"sessionID":"s","diff":[]}),mod._event_shape("permission","permission.asked",{"id":"p","sessionID":"s","permission":"bash","patterns":[],"metadata":{},"always":False,"tool":{}})]
        candidate=mod.StructuralCandidate(evidence,{})
        cards={"/session/{id}":1,"/question":1,"/permission":1,"/session/{id}/diff":1}
        manifest=mod._build_shape_manifest(candidate,completed,launch_provenance_digest="a"*64,task_spec_digest="b"*64,fixture_manifest_digest="c"*64,command_shapes_canonical_digest="d"*64,event_shapes=shapes,snapshot_cardinalities=cards,session_id="s",session_snapshot={"id":"s"},question_id="q",permission_id="p",question_reply_route="/api/session/s/question/q/reply",permission_reply_route="/api/session/s/permission/p/reply",routes=ROUTES,permission_snapshot={"permission":"bash","patterns":[mod.TEST_COMMAND]})
        self.assertEqual(len(manifest["events"]),4);self.assertTrue(manifest["session_id_equality"]);self.assertTrue(manifest["question_permission_ids_distinct"]);self.assertEqual(manifest["certificate_structural_digest"],evidence["structural_digest"])
        self.assertEqual(manifest["manifest_digest"],mod.canonical_digest({k:v for k,v in manifest.items() if k!="manifest_digest"}))
        bad=mod._build_shape_manifest(candidate,completed,launch_provenance_digest="a"*64,task_spec_digest="b"*64,fixture_manifest_digest="c"*64,command_shapes_canonical_digest="d"*64,event_shapes=shapes,snapshot_cardinalities=cards,session_id="s",session_snapshot={"id":"s"},question_id="q",permission_id="p",question_reply_route="/api/session/s/question/wrong/reply",permission_reply_route="/api/session/s/permission/p/reply",routes=ROUTES,permission_snapshot={"permission":"bash","patterns":[mod.TEST_COMMAND]})
        self.assertFalse(bad["question_snapshot_id_used_in_reply_route"])

    def test_shape_extractor_rejects_silent_truncation(self):
        with self.assertRaisesRegex(mod.DiscoveryError,"CONTENT_POLICY"):mod._extract_property_shape({f"k{i}":i for i in range(17)},{"":{f"k{i}" for i in range(17)}})
        with self.assertRaisesRegex(mod.DiscoveryError,"CONTENT_POLICY"):mod._extract_property_shape(list(range(10001)),{"":set()})

    def test_reviewed_policy_accepts_locked_11816_candidate_shapes(self):
        session={"sessionID":"s","info":{"id":"s","slug":"x","projectID":"x","directory":"x","title":"x","version":"1","time":{"created":1,"updated":2,"archived":3,"compacting":1},"model":{"id":"m","providerID":"p","variant":"v"},"tokens":{"input":1,"output":2,"reasoning":0,"cache":{"read":0,"write":0}},"summary":{"additions":1,"deletions":0,"files":1,"diffs":[]},"permission":[{"permission":"bash","pattern":"x","action":"ask"}],"metadata":{"dynamic-secret-looking-key":"not-recorded"}}}
        question={"id":"q","sessionID":"s","questions":[{"question":"x","header":"h","options":[{"label":"l","description":"d"}],"multiple":False,"custom":True}],"tool":{"messageID":"m","callID":"c"}}
        diff={"sessionID":"s","diff":[{"file":"x","additions":1,"deletions":0,"status":"M","patch":"x"}]}
        legacy_permission={"id":"p","sessionID":"s","permission":"bash","patterns":["x"],"metadata":{"arbitrary":"hidden"},"always":[],"tool":{"messageID":"m","callID":"c"}}
        v2_permission={"id":"p","sessionID":"s","action":"bash","resources":["x"],"metadata":{},"save":[],"source":{"type":"tool","messageID":"m","callID":"c"}}
        for event_type,payload in (("session.created",session),("question.asked",question),("question.v2.asked",question),("session.diff",diff),("permission.asked",legacy_permission),("permission.v2.asked",v2_permission)):
            shaped=mod._event_shape("created" if event_type=="session.created" else "question" if "question" in event_type else "diff" if event_type=="session.diff" else "permission",event_type,payload)
            self.assertEqual(shaped["property_field_count"],len(payload))
        metadata_shape=mod._event_shape("created","session.created",session)["property_field_types"]["info"]["properties"]["metadata"]
        self.assertEqual(metadata_shape,{"type":"dict","dynamic_keys":True,"field_count":1})
        self.assertNotIn("dynamic-secret-looking-key",json.dumps(metadata_shape))

    def test_staged_write_is_exclusive_0600_and_preserves_preexisting_bytes(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/"candidate.tmp"; mod._stage_bytes(path,{"ok":True},"BLOCKED_TEST_EXISTS")
            self.assertEqual(path.stat().st_mode & 0o777,0o600); original=path.read_bytes()
            with self.assertRaisesRegex(mod.DiscoveryError,"BLOCKED_TEST_EXISTS"): mod._stage_bytes(path,{"ok":False},"BLOCKED_TEST_EXISTS")
            self.assertEqual(path.read_bytes(),original)
    def valid(self):
        core={"schema_version":"nomad.stock-opencode.lifecycle-certificate.v1","expected_event_sequence":["session.created","question.asked","session.diff","permission.asked"],"diff_file_count":1,"v1_routes_verified":mod.CERTIFICATE_V1_ROUTES,"v2_routes_verified":[ROUTES[name]["route"] for name in ("session_prompt","question_reply","permission_reply","stop")]}; return {**core,"structural_digest":mod.canonical_digest(core)}
    def assert_bad(self,evidence):
        completed=mod.CompletedRealDiscovery(evidence,mod._COMPLETION_TOKEN)
        with self.assertRaisesRegex(mod.DiscoveryError,"BLOCKED_CONTENT_POLICY"): mod._validate_completed(completed)
    def test_extra_field(self): e=self.valid();e["extra"]=1;self.assert_bad(e)
    def test_bad_schema(self): e=self.valid();e["schema_version"]="bad";self.assert_bad(e)
    def test_bad_digest(self): e=self.valid();e["structural_digest"]="0"*64;self.assert_bad(e)
    def test_non_ascii_event(self): e=self.valid();e["expected_event_sequence"][0]="会话";self.assert_bad(e)
    def test_zero_diff(self): e=self.valid();e["diff_file_count"]=0;self.assert_bad(e)
    def test_event_bounds(self): e=self.valid();e["expected_event_sequence"]=["a"*129];self.assert_bad(e)
    def test_forbidden_values_in_routes(self): e=self.valid();e["v1_routes_verified"]=["/tmp/secret"];e["structural_digest"]=mod.canonical_digest({k:v for k,v in e.items() if k!="structural_digest"});self.assert_bad(e)

class OuterTests(unittest.TestCase):
    class Process:
        pid = 12345
        alive = True
        def poll(self): return None if self.alive else 0

    class Launch:
        port = 1
        provenance_digest = "a" * 64
        def __init__(self, root, *, remove=True, stop=True):
            self.root=Path(root); self.install=self.root/"install"; self.workspace=self.root/"workspace"
            self.root.mkdir(); self.install.mkdir(); self.workspace.mkdir(); self.process=OuterTests.Process()
            self.remove=remove; self.stop=stop; self.cleaned=False
        def cleanup(self):
            self.cleaned=True
            if self.stop: self.process.alive=False
            if self.remove: shutil.rmtree(self.root, ignore_errors=False)

    def stage_paths(self, parent):
        root=Path(parent)/"stock"; real=root/"real-task"; root.mkdir(); real.mkdir()
        root.chmod(0o755); real.chmod(0o755)
        return mod.StagePaths.under(root,real)

    def test_missing_credential_no_certificate(self):
        with self.assertRaisesRegex(mod.DiscoveryError,"TEMPORARY_PROVIDER_CREDENTIAL_REQUIRED"): mod.discover("OPENAI_API_KEY",{},reviewed_version="v0.1.0")
        self.assertFalse(mod.CERTIFICATE_PATH.exists())

    def test_preexisting_tmp_blocks_before_wp1_or_launcher_and_preserves_bytes(self):
        with tempfile.TemporaryDirectory() as temp:
            paths=self.stage_paths(temp)
            for temporary,code in ((paths.shape_tmp,"BLOCKED_SHAPE_TMP_EXISTS"),(paths.certificate_tmp,"BLOCKED_CERTIFICATE_TMP_EXISTS"),(paths.evidence_tmp,"BLOCKED_EVIDENCE_TMP_EXISTS")):
                with self.subTest(temporary=temporary.name):
                    original=b"orphan-temp-bytes"; temporary.write_bytes(original)
                    with mock.patch.object(mod,"_wp1",side_effect=AssertionError("must not initialize wp1")):
                        with self.assertRaisesRegex(mod.DiscoveryError,code): mod._discover_staged("OPENAI_API_KEY","v0.1.0",{"OPENAI_API_KEY":"secret"},1,paths)
                    self.assertEqual(temporary.read_bytes(),original); self.assertFalse(paths.certificate.exists()); self.assertFalse(paths.shape.exists()); self.assertFalse(paths.evidence.exists()); temporary.unlink()

    def test_staged_mode_never_calls_legacy_final_writer(self):
        with tempfile.TemporaryDirectory() as parent:
            paths=self.stage_paths(parent); launch=self.Launch(Path(parent)/"run")
            class WP1:
                credential_present=lambda *_a: True
                load_task_spec=lambda *_a: ({},"a"*64)
                launch_locked_opencode=lambda *_a,**_k: launch
                verify_fixture_manifest=lambda *_a: {"digest":"b"*64}
                verify_command_shape_fixture=lambda *_a: {}
            candidate,_=ProtocolTests().run_happy()
            with mock.patch.object(mod,"_wp1",return_value=WP1()),mock.patch.object(mod,"_run_protocol",return_value=candidate),mock.patch.object(mod,"verified_routes",return_value=ROUTES),mock.patch.object(mod,"_verify_cli",return_value=True),mock.patch.object(mod,"_derive_evidence",return_value={"schema_version":"test"}):
                result=mod._discover_staged("OPENAI_API_KEY","v0.1.0",{"OPENAI_API_KEY":"secret"},1,paths)
            self.assertEqual(result,{"status":"CANDIDATE_STAGED"})
            self.assertTrue(all(path.exists() for path in (paths.certificate_tmp,paths.shape_tmp,paths.evidence_tmp)))
            self.assertTrue(all(not path.exists() for path in (paths.certificate,paths.shape,paths.evidence)))
    def test_http_error_normalization(self):
        old=mod.urllib.request.urlopen
        error=urllib.error.HTTPError("redacted",500,"redacted",{},None)
        try:
            mod.urllib.request.urlopen=lambda *_a,**_k: (_ for _ in ()).throw(error)
            with self.assertRaisesRegex(mod.DiscoveryError,"UPSTREAM_HTTP_REJECTED"): mod._request("http://x","GET","/x")
            self.assertTrue(error.closed)
        finally: error.close(); mod.urllib.request.urlopen=old
    def test_outer_launcher_cleanup_on_protocol_exception(self):
        with tempfile.TemporaryDirectory() as parent:
            paths=self.stage_paths(parent); launch=self.Launch(Path(parent)/"run")
            class WP1:
                credential_present=lambda *_a: True
                load_task_spec=lambda *_a: ({},"digest")
                launch_locked_opencode=lambda *_a,**_k: launch
            with mock.patch.object(mod,"_wp1",return_value=WP1()),mock.patch.object(mod,"verified_routes",return_value=ROUTES),mock.patch.object(mod,"_run_protocol",side_effect=mod.DiscoveryError("BLOCKED_TEST")):
                with self.assertRaisesRegex(mod.DiscoveryError,"BLOCKED_TEST"): mod._discover_staged("OPENAI_API_KEY","v0.1.0",{"OPENAI_API_KEY":"secret"},1,paths)
            self.assertTrue(launch.cleaned); self.assertFalse(paths.certificate.exists())
    def test_authority_binds_identity_and_verified_cleanup(self):
        with tempfile.TemporaryDirectory() as parent:
            launch=self.Launch(Path(parent)/"run"); authority=mod.RealRunAuthority(launch,mod._AUTHORITY_TOKEN)
            authority.verify_live(launch); launch.cleanup(); authority.verify_cleanup(launch)
            candidate,_=ProtocolTests().run_happy(); completed=mod._certify(authority,candidate)
            self.assertIsInstance(completed,mod.CompletedRealDiscovery)
            with self.assertRaisesRegex(mod.DiscoveryError,"SYNTHETIC_TEST_NOT_CERTIFIED"): mod._certify(authority,candidate)
    def test_authority_rejects_process_identity_change(self):
        with tempfile.TemporaryDirectory() as parent:
            launch=self.Launch(Path(parent)/"run"); authority=mod.RealRunAuthority(launch,mod._AUTHORITY_TOKEN); launch.process=self.Process()
            with self.assertRaisesRegex(mod.DiscoveryError,"LOCKED_RUNTIME_UNAVAILABLE"): authority.verify_live(launch)
            shutil.rmtree(launch.root); authority._process.alive=False
    def test_authority_rejects_path_escape(self):
        with tempfile.TemporaryDirectory() as parent:
            launch=self.Launch(Path(parent)/"run"); outside=Path(parent)/"outside"; outside.mkdir(); launch.workspace=outside
            with self.assertRaisesRegex(mod.DiscoveryError,"LOCKED_RUNTIME_UNAVAILABLE"): mod.RealRunAuthority(launch,mod._AUTHORITY_TOKEN)
            launch.process.alive=False; shutil.rmtree(launch.root); outside.rmdir()
    def test_authority_rejects_incomplete_cleanup_root_remains(self):
        with tempfile.TemporaryDirectory() as parent:
            launch=self.Launch(Path(parent)/"run",remove=False); authority=mod.RealRunAuthority(launch,mod._AUTHORITY_TOKEN); launch.cleanup()
            with self.assertRaisesRegex(mod.DiscoveryError,"WORKSPACE_CLEANUP_INCOMPLETE"): authority.verify_cleanup(launch)
            shutil.rmtree(launch.root)
    def test_authority_rejects_cleanup_with_live_process(self):
        with tempfile.TemporaryDirectory() as parent:
            launch=self.Launch(Path(parent)/"run",stop=False); authority=mod.RealRunAuthority(launch,mod._AUTHORITY_TOKEN); launch.cleanup()
            with self.assertRaisesRegex(mod.DiscoveryError,"WORKSPACE_CLEANUP_INCOMPLETE"): authority.verify_cleanup(launch)
            launch.process.alive=False
    def test_no_credential_cli_content_free(self):
        old_argv=sys.argv
        try:
            sys.argv=["discover_lifecycle.py","--provider-credential-env","OPENAI_API_KEY","--reviewed-version","v0.1.0"]; output=io.StringIO()
            with contextlib.redirect_stdout(output): status=mod.main()
            self.assertEqual(status,1); self.assertEqual(json.loads(output.getvalue())["reason_codes"],["BLOCKED_TEMPORARY_PROVIDER_CREDENTIAL_REQUIRED"])
        finally: sys.argv=old_argv

    def test_reviewed_version_is_explicit_and_strict(self):
        with tempfile.TemporaryDirectory() as temp:
            paths=self.stage_paths(temp)
            for value in ("", "has space", "x"*129, None):
                with self.subTest(value=value),mock.patch.object(mod,"_wp1",side_effect=AssertionError("preflight first")):
                    with self.assertRaisesRegex(mod.DiscoveryError,"BLOCKED_REVIEWED_VERSION_REQUIRED"):
                        mod._discover_staged("OPENAI_API_KEY",value,{},1,paths)
        old_argv=sys.argv
        try:
            sys.argv=["discover_lifecycle.py","--provider-credential-env","OPENAI_API_KEY"]
            output=io.StringIO()
            with contextlib.redirect_stdout(output): status=mod.main()
            self.assertEqual(status,1); self.assertEqual(json.loads(output.getvalue())["reason_codes"],["BLOCKED_REVIEWED_VERSION_REQUIRED"])
        finally: sys.argv=old_argv

    def test_preflight_all_six_paths_and_broken_symlink(self):
        cases=(("certificate","BLOCKED_CERTIFICATE_ALREADY_EXISTS"),("shape","BLOCKED_SHAPE_ALREADY_EXISTS"),("evidence","BLOCKED_EVIDENCE_ALREADY_EXISTS"),("certificate_tmp","BLOCKED_CERTIFICATE_TMP_EXISTS"),("shape_tmp","BLOCKED_SHAPE_TMP_EXISTS"),("evidence_tmp","BLOCKED_EVIDENCE_TMP_EXISTS"))
        for attribute,code in cases:
            with self.subTest(attribute=attribute),tempfile.TemporaryDirectory() as temp:
                paths=self.stage_paths(temp); target=getattr(paths,attribute); target.symlink_to(paths.root/"missing")
                with self.assertRaisesRegex(mod.DiscoveryError,code): mod._preflight(paths)
                self.assertTrue(target.is_symlink())

    def test_preflight_missing_symlink_and_unsafe_directory_policy(self):
        with tempfile.TemporaryDirectory() as temp:
            parent=Path(temp); root=parent/"missing"; paths=mod.StagePaths.under(root,root/"real-task")
            with self.assertRaisesRegex(mod.DiscoveryError,"BLOCKED_OUTPUT_DIR_MISSING"): mod._preflight(paths)
            real=parent/"actual"; real.mkdir(); root.symlink_to(real, target_is_directory=True)
            paths=mod.StagePaths.under(root,root/"real-task")
            with self.assertRaisesRegex(mod.DiscoveryError,"BLOCKED_OUTPUT_DIR_POLICY"): mod._preflight(paths)
        with tempfile.TemporaryDirectory() as temp:
            paths=self.stage_paths(temp); paths.real_task_root.chmod(0o777)
            with self.assertRaisesRegex(mod.DiscoveryError,"BLOCKED_OUTPUT_DIR_POLICY"): mod._preflight(paths)

    def test_stage_failures_preserve_tmp_and_never_create_final(self):
        for operation,error_type in (("write",OSError),("fsync",OSError),("close",OSError),("write",KeyboardInterrupt)):
            with self.subTest(operation=operation,error=error_type.__name__),tempfile.TemporaryDirectory() as temp:
                path=Path(temp)/"candidate.tmp"; original=getattr(mod.os,operation); original_close=mod.os.close; closed=[]
                def fail(*args,**kwargs):
                    if operation=="write": original(*args,**kwargs)
                    raise error_type("redacted")
                close_side=fail if operation=="close" else lambda fd:(closed.append(fd),original_close(fd))[1]
                context=mock.patch.object(mod.os,"close",side_effect=close_side) if operation in {"write","close"} else contextlib.nullcontext()
                with mock.patch.object(mod.os,operation,side_effect=fail),context:
                    expected=error_type if error_type is KeyboardInterrupt else mod.DiscoveryError
                    with self.assertRaises(expected): mod._stage_bytes(path,{"x":1},"BLOCKED_EXISTS")
                self.assertTrue(path.exists()); self.assertFalse((Path(temp)/"candidate").exists())
                if error_type is KeyboardInterrupt: self.assertTrue(closed)

    def test_verify_cli_exact_bounded_timeout_and_stderr_policy(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); argument=root/"arg"; argument.write_text("x")
            def run(body,timeout=1):
                script=root/"verifier.py"; script.write_text(body)
                return mod._verify_cli(script,[argument],timeout_seconds=timeout)
            self.assertTrue(run("import sys;sys.stderr.write('diagnostic');print('VERIFIED')"))
            self.assertFalse(run("print('WRONG')")); self.assertFalse(run("raise SystemExit(3)"))
            self.assertFalse(run("import sys;sys.stdout.write('x'*4097)"))
            self.assertFalse(run("import sys;sys.stderr.write('x'*4097);print('VERIFIED')"))
            self.assertFalse(run("import time;time.sleep(1);print('VERIFIED')",0.02))

    def test_verify_cli_uses_exact_scrubbed_environment(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); argument=root/"arg"; argument.write_text("x"); script=root/"env.py"
            script.write_text("print('VERIFIED')")
            expected={"PYTHONDONTWRITEBYTECODE":"1","PYTHONIOENCODING":"utf-8","LC_ALL":"C","LANG":"C"}; seen=[]; original=mod.subprocess.Popen
            def recording(*args,**kwargs): seen.append(dict(kwargs["env"])); return original(*args,**kwargs)
            with mock.patch.dict(os.environ,{"OPENAI_API_KEY":"canary","EXTRA":"secret"},clear=False),mock.patch.object(mod.subprocess,"Popen",side_effect=recording): self.assertTrue(mod._verify_cli(script,[argument]))
            self.assertEqual(seen,[expected])

    def test_derivation_controlled_failure_restores_import_state(self):
        before_flag=sys.dont_write_bytecode; sentinel=object(); before_module=sys.modules.get("nomad_b01_public"); sys.modules["nomad_b01_public"]=sentinel
        with tempfile.TemporaryDirectory() as temp:
            old_root=mod.ROOT; mod.ROOT=Path(temp)
            try:
                with self.assertRaisesRegex(mod.DiscoveryError,"FAIL_B0_1_DERIVATION"): mod._derive_evidence({}, {}, "v0.1.0")
            finally: mod.ROOT=old_root
        self.assertIs(sys.dont_write_bytecode,before_flag); self.assertIs(sys.modules.get("nomad_b01_public"),sentinel)
        if before_module is None: sys.modules.pop("nomad_b01_public",None)
        else: sys.modules["nomad_b01_public"]=before_module

    def test_real_verifier_chain_accepts_staged_contract_pair(self):
        with tempfile.TemporaryDirectory() as temp:
            paths=self.stage_paths(temp); evidence_test=EvidenceTests(); cert=evidence_test.valid(); completed=mod.CompletedRealDiscovery(cert,mod._COMPLETION_TOKEN)
            shapes=[mod._event_shape("created","session.created",{"sessionID":"s","info":{}}),mod._event_shape("question","question.asked",{"id":"q","sessionID":"s","questions":[],"tool":{}}),mod._event_shape("diff","session.diff",{"sessionID":"s","diff":[]}),mod._event_shape("permission","permission.asked",{"id":"p","sessionID":"s","permission":"bash","patterns":[mod.TEST_COMMAND],"metadata":{},"always":False,"tool":{}})]
            source=importlib.util.spec_from_file_location("b02_b01",Path(__file__).with_name("verify_evidence_manifest.py")); b01=importlib.util.module_from_spec(source); sys.modules[source.name]=b01; source.loader.exec_module(b01)
            old_root=b01.ROOT; b01.ROOT=Path(__file__).resolve().parent
            try:
                task,fixture,commands,_=b01._current_sources(); shape=mod._build_shape_manifest(mod.StructuralCandidate(cert),completed,launch_provenance_digest="a"*64,task_spec_digest=task,fixture_manifest_digest=fixture,command_shapes_canonical_digest=commands,event_shapes=shapes,snapshot_cardinalities=b01.CARDINALITIES,session_id="s",session_snapshot={"id":"s"},question_id="q",permission_id="p",question_reply_route="/api/session/s/question/q/reply",permission_reply_route="/api/session/s/permission/p/reply",routes=ROUTES,permission_snapshot={"permission":"bash","patterns":[mod.TEST_COMMAND]})
                manifest=b01.derive_evidence_manifest(cert,shape,"v0.1.0")
            finally: b01.ROOT=old_root; sys.modules.pop(source.name,None)
            mod._stage_bytes(paths.certificate_tmp,cert,"BLOCKED_CERTIFICATE_TMP_EXISTS"); mod._stage_bytes(paths.shape_tmp,shape,"BLOCKED_SHAPE_TMP_EXISTS"); mod._stage_bytes(paths.evidence_tmp,manifest,"BLOCKED_EVIDENCE_TMP_EXISTS")
            self.assertTrue(mod._verify_cli(Path(__file__).with_name("verify_certificate.py"),[paths.certificate_tmp]))
            self.assertTrue(mod._verify_cli(Path(__file__).with_name("verify_shape_manifest.py"),[paths.shape_tmp,paths.certificate_tmp]))
            self.assertTrue(mod._verify_cli(Path(__file__).with_name("verify_evidence_manifest.py"),[paths.evidence_tmp,paths.certificate_tmp,paths.shape_tmp]))

    def test_gate_order_and_failures_preserve_staged_prefix(self):
        for fail_index,code,expected in ((0,"FAIL_A3_VERIFY",(True,True,False)),(1,"FAIL_A4_2_VERIFY",(True,True,False)),(2,"FAIL_B0_1_DERIVATION",(True,True,False)),(3,"FAIL_B0_1_VERIFY",(True,True,True))):
            with self.subTest(code=code),tempfile.TemporaryDirectory() as parent:
                paths=self.stage_paths(parent); launch=self.Launch(Path(parent)/"run"); candidate,_=ProtocolTests().run_happy(); calls=[]
                class WP1:
                    credential_present=lambda *_a: True
                    load_task_spec=lambda *_a: ({},"a"*64)
                    launch_locked_opencode=lambda *_a,**_k: launch
                    verify_fixture_manifest=lambda *_a: {"digest":"b"*64}
                    verify_command_shape_fixture=lambda *_a: {}
                def verify(script,args):
                    calls.append(script.name)
                    failing={"FAIL_A3_VERIFY":"verify_certificate.py","FAIL_A4_2_VERIFY":"verify_shape_manifest.py","FAIL_B0_1_VERIFY":"verify_evidence_manifest.py"}.get(code)
                    return script.name!=failing
                derive=mock.Mock(return_value={"schema_version":"test"})
                if fail_index==2: derive.side_effect=mod.DiscoveryError(code)
                with mock.patch.object(mod,"_wp1",return_value=WP1()),mock.patch.object(mod,"_run_protocol",return_value=candidate),mock.patch.object(mod,"verified_routes",return_value=ROUTES),mock.patch.object(mod,"_verify_cli",side_effect=verify),mock.patch.object(mod,"_derive_evidence",derive):
                    with self.assertRaisesRegex(mod.DiscoveryError,code): mod._discover_staged("OPENAI_API_KEY","v0.1.0",{"OPENAI_API_KEY":"secret"},1,paths)
                self.assertEqual(tuple(path.exists() for path in (paths.certificate_tmp,paths.shape_tmp,paths.evidence_tmp)),expected)
                self.assertTrue(all(not path.exists() for path in (paths.certificate,paths.shape,paths.evidence)))

if __name__ == "__main__": unittest.main()
