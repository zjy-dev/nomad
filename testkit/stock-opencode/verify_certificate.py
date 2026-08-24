#!/usr/bin/env python3
"""Read-only verifier for a content-free A0 lifecycle certificate."""
from __future__ import annotations
import hashlib, json, os, re, stat, sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
MAX_BYTES = 64 * 1024
FIELDS = frozenset({"schema_version", "expected_event_sequence", "diff_file_count", "v1_routes_verified", "v2_routes_verified", "structural_digest"})
V1 = ["/session(POST)", "/event", "/session/{id}", "/session/{id}/diff", "/question", "/permission"]
MARKER_ORDER = ("created", "question", "diff", "permission")
MARKER_CANDIDATES = {
    "created": frozenset({"session.created"}),
    "question": frozenset({"question.v2.asked", "question.asked"}),
    "diff": frozenset({"session.diff"}),
    "permission": frozenset({"permission.v2.asked", "permission.asked"}),
}
ASCII_EVENT = re.compile(r"^[a-z][a-z0-9._-]{0,127}$")
V2 = [
    "/api/session/{sessionID}/prompt",
    "/api/session/{sessionID}/question/{requestID}/reply",
    "/api/session/{sessionID}/permission/{requestID}/reply",
    "/api/session/{sessionID}/interrupt",
]

@dataclass(frozen=True)
class Verdict: status: str; code: str
class _Duplicate(ValueError): pass
def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result: raise _Duplicate
        result[key] = value
    return result
def _digest(value: object)->str:return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode("ascii")).hexdigest()
def _read_bounded_regular(path: Path) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise FileNotFoundError
        chunks=[]; remaining=MAX_BYTES+1
        while remaining:
            piece=os.read(fd,min(65536,remaining))
            if not piece: break
            chunks.append(piece); remaining-=len(piece)
        raw=b"".join(chunks)
        if len(raw)>MAX_BYTES: raise OverflowError
        return raw
    finally:
        os.close(fd)

def verify_certificate(path: Path)->Verdict:
    try:
        raw=_read_bounded_regular(path); value=json.loads(raw.decode("utf-8"),object_pairs_hook=_pairs)
    except FileNotFoundError:return Verdict("BLOCKED","BLOCKED_CERTIFICATE_MISSING")
    except OverflowError:return Verdict("FAIL","FAIL_CERTIFICATE_SIZE")
    except UnicodeDecodeError:return Verdict("FAIL","FAIL_CERTIFICATE_UTF8")
    except _Duplicate:return Verdict("FAIL","FAIL_CERTIFICATE_DUPLICATE")
    except json.JSONDecodeError:return Verdict("FAIL","FAIL_CERTIFICATE_JSON")
    except OSError:return Verdict("BLOCKED","BLOCKED_CERTIFICATE_MISSING")
    if not isinstance(value,dict) or set(value)!=FIELDS:return Verdict("FAIL","FAIL_CERTIFICATE_FIELDS")
    if value["schema_version"]!="nomad.stock-opencode.lifecycle-certificate.v1":return Verdict("FAIL","FAIL_CERTIFICATE_SCHEMA")
    events=value["expected_event_sequence"]
    if not isinstance(events,list) or len(events)!=4 or any(not isinstance(x,str) or not ASCII_EVENT.fullmatch(x) or x not in MARKER_CANDIDATES[name] for x,name in zip(events,MARKER_ORDER)):return Verdict("FAIL","FAIL_CERTIFICATE_EVENTS")
    count=value["diff_file_count"]
    if type(count)is not int or not 1<=count<=10000:return Verdict("FAIL","FAIL_CERTIFICATE_DIFF")
    if value["v1_routes_verified"]!=V1:return Verdict("FAIL","FAIL_CERTIFICATE_V1_ROUTES")
    if value["v2_routes_verified"]!=V2:return Verdict("FAIL","FAIL_CERTIFICATE_V2_ROUTES")
    core={key:value[key] for key in FIELDS-{"structural_digest"}}
    if not isinstance(value["structural_digest"],str) or len(value["structural_digest"])!=64 or any(c not in "0123456789abcdef" for c in value["structural_digest"]) or _digest(core)!=value["structural_digest"]:return Verdict("FAIL","FAIL_CERTIFICATE_DIGEST")
    return Verdict("VERIFIED","VERIFIED")
def main()->int:
    verdict=verify_certificate(Path(sys.argv[1])) if len(sys.argv)==2 else Verdict("BLOCKED","BLOCKED_CERTIFICATE_MISSING")
    stream=sys.stdout if verdict.status=="VERIFIED" else sys.stderr; stream.write(verdict.code+"\n"); return 0 if verdict.status=="VERIFIED" else 1
if __name__=="__main__":raise SystemExit(main())
