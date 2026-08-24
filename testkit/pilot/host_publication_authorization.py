"""Private B1 join for an exact externally approved, post-CAS Host image.

This module creates launch authorization only.  It creates no command authority
and does not spawn the Host or OpenCode.
"""
from __future__ import annotations

import hashlib
import importlib.util
import os
import stat
import sys
import weakref
from pathlib import Path

HERE = Path(__file__).resolve().parent
AGENT_EVIDENCE = HERE.parent / "agent-evidence"
MAX_HOST_BYTES = 64 * 1024 * 1024
BLOCKED = "BLOCKED_PUBLISHED_HOST_AUTHORIZATION"


class AuthorizationError(Exception):
    def __init__(self) -> None:
        super().__init__(BLOCKED)


def _load(name: str, path: Path):
    existing = sys.modules.get(name)
    if existing is not None:
        return existing
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise AuthorizationError
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


relation = _load("nomad_b1_production_relation", AGENT_EVIDENCE / "verify_host_production_relation.py")
approval = _load("nomad_b1_host_approval", AGENT_EVIDENCE / "verify_host_approval.py")
post_cas = _load("nomad_b1_post_cas", AGENT_EVIDENCE / "verify_host_post_cas_checkout.py")


class _OpaqueAuthorization:
    __slots__ = (
        "host_manifest_digest", "artifact_raw_sha256",
        "release_index_digest", "bundle_manifest_digest",
        "evidence_manifest_digest", "approval_record_digest",
        "approval_signature_raw_digest", "host_approval_digest",
        "candidate_id", "host_artifact_sequence", "source_commit_oid",
        "publication_sequence", "operation",
        "proposed_commit_oid", "protected_ref", "active_index_digest",
        "executable_vnode_digest", "binary_path", "binary_identity",
        "__weakref__",
    )
    def __init__(self, *_: object) -> None:
        raise TypeError("private published Host authorization")
    def __setattr__(self, _name: str, _value: object) -> None:
        raise TypeError("frozen published Host authorization")
    def __reduce__(self) -> object:
        raise TypeError("private published Host authorization")
    def __repr__(self) -> str:
        return f"{type(self).__name__}(<redacted>)"


class _PublishedHostAuthorization(_OpaqueAuthorization):
    __slots__ = ()


class _TestPublishedHostAuthorization(_OpaqueAuthorization):
    __slots__ = ()


_PRODUCTION_AUTHORIZATIONS = weakref.WeakKeyDictionary()
_TEST_AUTHORIZATIONS = weakref.WeakKeyDictionary()
_TEST_AUTHORIZATION_TOKEN = object()


def _authorization_snapshot(value):
    return tuple(getattr(value, name) for name in _OpaqueAuthorization.__slots__
                 if name != "__weakref__")


def _is_verified_production_authorization(value) -> bool:
    return (type(value) is _PublishedHostAuthorization
            and _PRODUCTION_AUTHORIZATIONS.get(value) is not None
            and _PRODUCTION_AUTHORIZATIONS.get(value) == _authorization_snapshot(value))


def _is_verified_test_authorization(value) -> bool:
    return (type(value) is _TestPublishedHostAuthorization
            and _TEST_AUTHORIZATIONS.get(value) is not None
            and _TEST_AUTHORIZATIONS.get(value) == _authorization_snapshot(value))


_is_published_host_authorization = _is_verified_production_authorization
_is_test_published_host_authorization = _is_verified_test_authorization


def _identity(value: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns,
            value.st_ctime_ns, value.st_nlink)


def _reopen_host(path: Path, expected_digest: str) -> tuple[Path, tuple[int, ...]]:
    try:
        canonical = path.resolve(strict=True)
        if canonical != path or path.name != "nomad-host":
            raise AuthorizationError
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        with os.fdopen(descriptor, "rb", closefd=True) as stream:
            before = os.fstat(stream.fileno())
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                    or not before.st_mode & 0o111
                    or not 0 < before.st_size <= MAX_HOST_BYTES):
                raise AuthorizationError
            raw = stream.read(MAX_HOST_BYTES + 1)
            after = os.fstat(stream.fileno())
        current = os.stat(path, follow_symlinks=False)
        if (len(raw) != before.st_size or _identity(before) != _identity(after)
                or _identity(before) != _identity(current)
                or hashlib.sha256(raw).hexdigest() != expected_digest):
            raise AuthorizationError
        return canonical, _identity(before)
    except AuthorizationError:
        raise
    except Exception:
        raise AuthorizationError from None


def _join(relation_value, approval_value, checkout_value, checks, cls, registry):
    relation_check, approval_check, checkout_check = checks
    if (not relation_check(relation_value) or not approval_check(approval_value)
            or not checkout_check(checkout_value) or approval_value.relation is not relation_value):
        raise AuthorizationError
    shared = ("host_manifest_digest", "artifact_raw_sha256",
              "release_index_digest", "bundle_manifest_digest",
              "evidence_manifest_digest", "source_commit_oid", "binary_path")
    if (any(getattr(relation_value, field) != getattr(checkout_value, field)
                   for field in shared)
            or approval_value.host_approval_digest != checkout_value.host_approval_digest
            or checkout_value.candidate_id != "sha256-" + relation_value.host_manifest_digest
            or checkout_value.protected_ref != post_cas.REF
            or relation_value.host_artifact_sequence != checkout_value.host_artifact_sequence
            or (checkout_value.operation == "forward"
                and checkout_value.publication_sequence != checkout_value.host_artifact_sequence)
            or (checkout_value.operation == "rollback"
                and checkout_value.publication_sequence <= checkout_value.host_artifact_sequence)
            or checkout_value.operation not in ("forward", "rollback")):
        raise AuthorizationError
    binary_path, binary_identity = _reopen_host(
        checkout_value.binary_path, relation_value.artifact_raw_sha256
    )
    value = object.__new__(cls)
    fields = {
        "host_manifest_digest": relation_value.host_manifest_digest,
        "artifact_raw_sha256": relation_value.artifact_raw_sha256,
        "release_index_digest": relation_value.release_index_digest,
        "bundle_manifest_digest": relation_value.bundle_manifest_digest,
        "evidence_manifest_digest": relation_value.evidence_manifest_digest,
        "approval_record_digest": relation_value.approval_record_digest,
        "approval_signature_raw_digest": relation_value.approval_signature_raw_digest,
        "host_approval_digest": approval_value.host_approval_digest,
        "candidate_id": checkout_value.candidate_id,
        "host_artifact_sequence": checkout_value.host_artifact_sequence,
        "publication_sequence": checkout_value.publication_sequence,
        "operation": checkout_value.operation,
        "source_commit_oid": checkout_value.source_commit_oid,
        "proposed_commit_oid": checkout_value.proposed_commit_oid,
        "protected_ref": checkout_value.protected_ref,
        "active_index_digest": checkout_value.active_index_digest,
        "executable_vnode_digest": relation_value.executable_vnode_digest,
        "binary_path": binary_path, "binary_identity": binary_identity,
    }
    for name, item in fields.items():
        object.__setattr__(value, name, item)
    registry[value] = _authorization_snapshot(value)
    return value


def _combine(token, relation_value, approval_value, checkout_value):
    if token is not _TEST_AUTHORIZATION_TOKEN:
        raise AuthorizationError
    return _join(
        relation_value, approval_value, checkout_value,
        (relation._is_verified_test, approval._is_verified_test,
         post_cas._is_verified_test),
        _TestPublishedHostAuthorization, _TEST_AUTHORIZATIONS,
    )


def authorize(binary, manifest, expected, release_root, sign_result, host_approval,
              request, tree, source, lineage):
    """Run only production verifiers and return exact opaque authorization."""
    try:
        relation_value = relation.verify(binary, manifest, expected, release_root, sign_result)
        if not relation._is_verified_production(relation_value):
            raise AuthorizationError
        approval_value = approval.verify_host_approval(host_approval, relation_value)
        if not approval._is_verified_production(approval_value):
            raise AuthorizationError
        checkout_value = post_cas.verify(request, tree, source, lineage)
        return _join(
            relation_value, approval_value, checkout_value,
            (relation._is_verified_production, approval._is_verified_production,
             post_cas._is_verified_production),
            _PublishedHostAuthorization, _PRODUCTION_AUTHORIZATIONS,
        )
    except AuthorizationError:
        raise
    except Exception:
        raise AuthorizationError from None
