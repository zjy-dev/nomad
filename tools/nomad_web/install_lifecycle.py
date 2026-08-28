"""Atomic, stopped-only installation lifecycle for verified Nomad bundles.

This module deliberately has no CLI surface.  It publishes immutable bundle
directories and one regular ``current.json`` selector.  Remote identity is not
part of the rollback snapshot and is never removed by this lifecycle.
"""

from __future__ import annotations

import ctypes
import errno
import hashlib
import json
import os
import re
import shutil
import stat
import sys
import uuid
from pathlib import Path
from typing import Any

from .bundle import MANIFEST, verify_bundle
from .state import lifecycle_lock, read_run_state, validate_home

CURRENT_SCHEMA = "nomad.web-companion.install-current.v1"
STATUS_SCHEMA = "nomad.web-companion.install-status.v1"
SNAPSHOT_SCHEMA = "nomad.web-companion.install-state-snapshot.v1"
MAX_CURRENT_BYTES = 4 * 1024 * 1024
MAX_MANIFEST_BYTES = 256 * 1024
MAX_STATE_FILE_BYTES = 2 * 1024 * 1024 * 1024
MAX_STATE_SNAPSHOT_BYTES = 4 * 1024 * 1024 * 1024

# The device registry is identity authority, not versioned application state.
# Keeping it out of this allowlist prevents rollback from resurrecting a
# revoked identity and prevents this module from deleting identity artifacts.
PERSISTENT_STATE_BASENAMES = (
    "pairing-coordinator.sqlite3",
    "remote-mailbox.sqlite3",
    "relay-v2.sqlite3",
)
PERSISTENT_STATE_NAMES = frozenset(
    f"{basename}{suffix}"
    for basename in PERSISTENT_STATE_BASENAMES
    for suffix in ("", "-wal", "-shm")
)
_DIGEST = re.compile(r"[0-9a-f]{64}")
def install(config: Any, bundle: Path | str) -> dict[str, Any]:
    """Install the first verified bundle, or return the identical install."""
    source = Path(bundle).absolute()
    with lifecycle_lock(config, create=True):
        _require_stopped(config)
        home = _home(config)
        _ensure_layout(home)
        current = _read_current(home)
        manifest = verify_bundle(source)
        digest = _manifest_digest(manifest)
        _checkpoint("source_verified")
        if current is not None:
            if current["bundle_digest"] != digest:
                raise RuntimeError("INSTALL_ALREADY_PRESENT_USE_UPGRADE")
            _verify_installed_bundle(home, digest)
            return _status_unlocked(home, current)

        _publish_bundle(source, manifest, home)
        record = _current_record(
            digest,
            [_history_entry(1, "install", None, digest, None, None)],
        )
        _checkpoint("before_current_switch")
        _write_current(home, record)
        _checkpoint("after_current_switch")
        return _status_unlocked(home, record)


def upgrade(config: Any, bundle: Path | str) -> dict[str, Any]:
    """Atomically select a new verified bundle after snapshotting state."""
    source = Path(bundle).absolute()
    with lifecycle_lock(config, create=True):
        _require_stopped(config)
        home = _home(config)
        _ensure_layout(home)
        old = _read_current(home)
        if old is None:
            raise RuntimeError("INSTALL_NOT_PRESENT")
        old_digest = old["bundle_digest"]
        _verify_installed_bundle(home, old_digest)
        manifest = verify_bundle(source)
        digest = _manifest_digest(manifest)
        _checkpoint("source_verified")
        if digest == old_digest:
            return _status_unlocked(home, old)

        snapshot_digest = _snapshot_persistent_state(home)
        _checkpoint("state_snapshotted")
        _publish_bundle(source, manifest, home)
        history = [*old["history"], _history_entry(
            len(old["history"]) + 1, "upgrade", old_digest, digest,
            snapshot_digest, None,
        )]
        record = _current_record(digest, history)
        _checkpoint("before_current_switch")
        _write_current(home, record)
        _checkpoint("after_current_switch")
        return _status_unlocked(home, record)


def rollback(config: Any) -> dict[str, Any]:
    """Roll back one code selector while persistent security state stays forward."""
    with lifecycle_lock(config, create=False) as owned:
        if not owned:
            raise RuntimeError("INSTALL_NOT_PRESENT")
        _require_stopped(config)
        home = _home(config)
        _ensure_layout(home)
        old = _read_current(home)
        if old is None:
            raise RuntimeError("INSTALL_NOT_PRESENT")
        _verify_installed_bundle(home, old["bundle_digest"])
        selected = _rollback_entry(old)
        if selected is None:
            return _status_unlocked(home, old)

        target_digest = selected["from_bundle_digest"]
        snapshot_digest = selected["state_snapshot_digest"]
        if target_digest is None or snapshot_digest is None:
            raise RuntimeError("INVALID_INSTALL_HISTORY")
        _verify_installed_bundle(home, target_digest)
        _validate_snapshot(home, snapshot_digest)
        history = [*old["history"], _history_entry(
            len(old["history"]) + 1, "rollback",
            old["bundle_digest"], target_digest, snapshot_digest,
            selected["sequence"],
        )]
        record = _current_record(target_digest, history)
        _checkpoint("before_current_switch")
        _write_current(home, record)
        _checkpoint("after_current_switch")
        return _status_unlocked(home, record)


def status(config: Any) -> dict[str, Any]:
    """Return the verified install selector and digest-only history."""
    with lifecycle_lock(config, create=False) as owned:
        if not owned:
            return _empty_status()
        home = _home(config)
        validate_home(config)
        current = _read_current(home)
        if current is None:
            return _empty_status()
        return _status_unlocked(home, current)


def select_bundle_for_start(config: Any, explicit_bundle: Path | str | None) -> Path | None:
    """Select a verified installed bundle while the caller holds lifecycle_lock.

    A first explicit bundle is installed and made current.  Once a selector
    exists, an explicit bundle is only an assertion: a different digest fails
    closed and the launcher always executes the installed current directory.
    None is returned only for the legacy explicit source-build mode when no
    install selector exists.
    """
    home = _home(config)
    _ensure_layout(home)
    current = _read_current(home)
    explicit_manifest = None
    explicit_path = Path(explicit_bundle).absolute() if explicit_bundle is not None else None
    if explicit_path is not None:
        explicit_manifest = verify_bundle(explicit_path)
    if current is not None:
        selected = _verify_installed_bundle(home, current["bundle_digest"])
        if (
            explicit_manifest is not None
            and _manifest_digest(explicit_manifest) != _manifest_digest(selected)
        ):
            raise RuntimeError("EXPLICIT_BUNDLE_CURRENT_CONFLICT")
        # On macOS /var is an alias of /private/var.  Node canonicalizes
        # import.meta.url but retains process.argv[1] verbatim; returning a
        # lexical /var path would therefore make the Gateway's direct-entry
        # check false and exit cleanly without listening.
        return (home / "bundles" / current["bundle_digest"]).resolve(strict=True)
    if explicit_manifest is None:
        return None
    if read_run_state(config) is not None:
        raise RuntimeError("INSTALL_SELECTOR_INITIALIZATION_REQUIRES_STOP")
    digest = _manifest_digest(explicit_manifest)
    _publish_bundle(explicit_path, explicit_manifest, home)
    record = _current_record(
        digest,
        [_history_entry(1, "install", None, digest, None, None)],
    )
    _write_current(home, record)
    return (home / "bundles" / digest).resolve(strict=True)


def _get(config: Any, name: str) -> Any:
    if hasattr(config, name):
        return getattr(config, name)
    if isinstance(config, dict) and name in config:
        return config[name]
    raise RuntimeError(f"CONFIG_{name.upper()}_MISSING")


def _home(config: Any) -> Path:
    home = Path(os.path.abspath(os.fspath(_get(config, "home"))))
    resolved = home.resolve(strict=False)
    if resolved in (Path("/"), Path.home().resolve()):
        raise RuntimeError("UNSAFE_NOMAD_WEB_HOME")
    return home


def _require_stopped(config: Any) -> None:
    observed = read_run_state(config)
    if observed is not None:
        raise RuntimeError("INSTALL_LIFECYCLE_REQUIRES_STOP")
    _checkpoint("stopped_verified")


def _ensure_layout(home: Path) -> None:
    validate_home(type("ConfigView", (), {"home": home})())
    install_root = _ensure_private_dir(home / "install", home)
    _ensure_private_dir(install_root / "staging", install_root)
    _ensure_private_dir(install_root / "snapshots", install_root)
    _ensure_private_dir(home / "bundles", home)


def _ensure_private_dir(path: Path, parent: Path) -> Path:
    if path.parent != parent:
        raise RuntimeError("UNSAFE_INSTALL_DIRECTORY")
    created = False
    try:
        os.mkdir(path, 0o700)
        created = True
        os.chmod(path, 0o700)
    except FileExistsError:
        pass
    info = path.lstat()
    if (
        not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
        or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise RuntimeError("UNSAFE_INSTALL_DIRECTORY")
    if created:
        _fsync_directory(path)
        _fsync_directory(parent)
    return path


def _manifest_digest(manifest: dict[str, Any]) -> str:
    digest = manifest.get("bundle_digest")
    if not isinstance(digest, str) or _DIGEST.fullmatch(digest) is None:
        raise RuntimeError("INVALID_BUNDLE_DIGEST")
    return digest


def _publish_bundle(source: Path, manifest: dict[str, Any], home: Path) -> Path:
    digest = _manifest_digest(manifest)
    bundles = home / "bundles"
    target = bundles / digest
    if os.path.lexists(target):
        installed = verify_bundle(target)
        if _manifest_digest(installed) != digest:
            raise RuntimeError("BUNDLE_SNAPSHOT_MISMATCH")
        _checkpoint("bundle_reused")
        return target

    staging_root = home / "install" / "staging"
    temporary = staging_root / f"bundle-{uuid.uuid4().hex}.tmp"
    os.mkdir(temporary, 0o700)
    os.chmod(temporary, 0o700)
    _fsync_directory(staging_root)
    try:
        _copy_bundle_exact(source, temporary, manifest)
        _checkpoint("bundle_copied")
        installed = verify_bundle(temporary)
        if _manifest_digest(installed) != digest:
            raise RuntimeError("BUNDLE_SNAPSHOT_MISMATCH")
        _checkpoint("bundle_verified")
        try:
            _rename_exclusive(temporary, target)
        except FileExistsError:
            installed = verify_bundle(target)
            if _manifest_digest(installed) != digest:
                raise RuntimeError("BUNDLE_SNAPSHOT_MISMATCH")
            _remove_owned_stage(temporary, staging_root)
        _fsync_directory(bundles)
        installed = verify_bundle(target)
        if _manifest_digest(installed) != digest:
            raise RuntimeError("BUNDLE_SNAPSHOT_MISMATCH")
        _checkpoint("bundle_published")
        return target
    except Exception:
        if os.path.lexists(temporary):
            _remove_owned_stage(temporary, staging_root)
        raise


def _copy_bundle_exact(source: Path, destination: Path, manifest: dict[str, Any]) -> None:
    files = manifest.get("files")
    if not isinstance(files, list) or not files:
        raise RuntimeError("INVALID_BUNDLE_MANIFEST")
    directories: set[Path] = set()
    for entry in files:
        if not isinstance(entry, dict):
            raise RuntimeError("INVALID_BUNDLE_MANIFEST")
        relative = _safe_relative(entry.get("path"))
        for parent in relative.parents:
            if str(parent) != ".":
                directories.add(parent)
    for relative in sorted(directories, key=lambda item: (len(item.parts), str(item))):
        path = destination / relative
        os.mkdir(path, 0o700)
        os.chmod(path, 0o700)

    for entry in files:
        relative = _safe_relative(entry["path"])
        try:
            mode = int(entry["mode"], 8)
            size = int(entry["size_bytes"])
            digest = str(entry["raw_sha256"])
        except (KeyError, TypeError, ValueError) as error:
            raise RuntimeError("INVALID_BUNDLE_MANIFEST") from error
        _copy_exact_file(source / relative, destination / relative, mode, size, digest)

    expected_manifest = _canonical(manifest) + b"\n"
    _copy_exact_file(
        source / MANIFEST, destination / MANIFEST, 0o644,
        len(expected_manifest), hashlib.sha256(expected_manifest).hexdigest(),
    )
    for relative in sorted(directories, key=lambda item: (-len(item.parts), str(item))):
        os.chmod(destination / relative, 0o755)
        _fsync_directory(destination / relative)
    os.chmod(destination, 0o755)
    _fsync_directory(destination)


def _copy_exact_file(source: Path, destination: Path, mode: int, size: int, digest: str) -> None:
    if size < 0 or _DIGEST.fullmatch(digest) is None:
        raise RuntimeError("INVALID_BUNDLE_MANIFEST")
    source_fd = os.open(source, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    destination_fd: int | None = None
    try:
        before = os.fstat(source_fd)
        if (
            not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != mode
        ):
            raise RuntimeError("UNSAFE_BUNDLE_FILE")
        destination_fd = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            mode,
        )
        os.fchmod(destination_fd, mode)
        observed = hashlib.sha256()
        copied = 0
        while True:
            chunk = os.read(source_fd, 1024 * 1024)
            if not chunk:
                break
            copied += len(chunk)
            if copied > size:
                raise RuntimeError("BUNDLE_FILE_MISMATCH")
            observed.update(chunk)
            _write_all(destination_fd, chunk)
        os.fsync(destination_fd)
        after = os.fstat(source_fd)
        stable = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
        if stable != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise RuntimeError("BUNDLE_SOURCE_CHANGED")
        if copied != size or observed.hexdigest() != digest:
            raise RuntimeError("BUNDLE_FILE_MISMATCH")
    except Exception:
        if destination_fd is not None:
            os.close(destination_fd)
            destination_fd = None
        destination.unlink(missing_ok=True)
        raise
    finally:
        if destination_fd is not None:
            os.close(destination_fd)
        os.close(source_fd)


def _snapshot_persistent_state(home: Path) -> str:
    snapshots = home / "install" / "snapshots"
    staging = home / "install" / "staging"
    temporary = staging / f"state-{uuid.uuid4().hex}.tmp"
    os.mkdir(temporary, 0o700)
    os.chmod(temporary, 0o700)
    _fsync_directory(staging)
    entries: list[dict[str, Any]] = []
    total = 0
    try:
        private = home / "private"
        if os.path.lexists(private):
            _validate_private_state_dir(private)
            for name in sorted(PERSISTENT_STATE_NAMES):
                source = private / name
                if not os.path.lexists(source):
                    continue
                size, digest = _copy_state_file(source, temporary / name)
                total += size
                if total > MAX_STATE_SNAPSHOT_BYTES:
                    raise RuntimeError("STATE_SNAPSHOT_TOO_LARGE")
                entries.append({"path": name, "size_bytes": size, "raw_sha256": digest})
        core = {"schema": SNAPSHOT_SCHEMA, "files": entries}
        digest = hashlib.sha256(_canonical(core)).hexdigest()
        manifest = {**core, "snapshot_digest": digest}
        _write_new_file(temporary / MANIFEST, _canonical(manifest) + b"\n", 0o600)
        _fsync_directory(temporary)
        target = snapshots / digest
        try:
            _rename_exclusive(temporary, target)
        except FileExistsError:
            existing = _validate_snapshot(home, digest)
            if existing != manifest:
                raise RuntimeError("STATE_SNAPSHOT_MISMATCH")
            _remove_owned_stage(temporary, staging)
        _fsync_directory(snapshots)
        if _validate_snapshot(home, digest) != manifest:
            raise RuntimeError("STATE_SNAPSHOT_MISMATCH")
        return digest
    except Exception:
        if os.path.lexists(temporary):
            _remove_owned_stage(temporary, staging)
        raise


def _copy_state_file(source: Path, destination: Path) -> tuple[int, str]:
    source_fd = _open_private_file(source)
    destination_fd: int | None = None
    try:
        before = os.fstat(source_fd)
        destination_fd = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
        )
        digest = hashlib.sha256()
        size = 0
        while True:
            chunk = os.read(source_fd, 1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if size > MAX_STATE_FILE_BYTES:
                raise RuntimeError("STATE_FILE_TOO_LARGE")
            digest.update(chunk)
            _write_all(destination_fd, chunk)
        os.fsync(destination_fd)
        after = os.fstat(source_fd)
        stable = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
        if stable != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise RuntimeError("PERSISTENT_STATE_CHANGED")
        return size, digest.hexdigest()
    except Exception:
        if destination_fd is not None:
            os.close(destination_fd)
            destination_fd = None
        destination.unlink(missing_ok=True)
        raise
    finally:
        if destination_fd is not None:
            os.close(destination_fd)
        os.close(source_fd)


def _validate_snapshot(home: Path, digest: str) -> dict[str, Any]:
    if _DIGEST.fullmatch(digest) is None:
        raise RuntimeError("INVALID_STATE_SNAPSHOT")
    root = home / "install" / "snapshots" / digest
    info = root.lstat()
    if (
        not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
        or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise RuntimeError("UNSAFE_STATE_SNAPSHOT")
    manifest_raw = _read_private_file(root / MANIFEST, MAX_MANIFEST_BYTES)
    try:
        manifest = json.loads(manifest_raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError("INVALID_STATE_SNAPSHOT") from error
    if (
        not isinstance(manifest, dict)
        or set(manifest) != {"schema", "files", "snapshot_digest"}
        or manifest["schema"] != SNAPSHOT_SCHEMA
        or manifest["snapshot_digest"] != digest
        or manifest_raw != _canonical(manifest) + b"\n"
        or not isinstance(manifest["files"], list)
    ):
        raise RuntimeError("INVALID_STATE_SNAPSHOT")
    observed: list[str] = []
    total = 0
    for entry in manifest["files"]:
        if not isinstance(entry, dict) or set(entry) != {"path", "size_bytes", "raw_sha256"}:
            raise RuntimeError("INVALID_STATE_SNAPSHOT")
        name = entry["path"]
        if (
            name not in PERSISTENT_STATE_NAMES or name in observed
            or type(entry["size_bytes"]) is not int or entry["size_bytes"] < 0
            or not isinstance(entry["raw_sha256"], str)
            or _DIGEST.fullmatch(entry["raw_sha256"]) is None
        ):
            raise RuntimeError("INVALID_STATE_SNAPSHOT")
        raw = _read_private_file(root / name, MAX_STATE_FILE_BYTES)
        total += len(raw)
        if (
            total > MAX_STATE_SNAPSHOT_BYTES or len(raw) != entry["size_bytes"]
            or hashlib.sha256(raw).hexdigest() != entry["raw_sha256"]
        ):
            raise RuntimeError("STATE_SNAPSHOT_MISMATCH")
        observed.append(name)
    if observed != sorted(observed):
        raise RuntimeError("INVALID_STATE_SNAPSHOT")
    actual = {entry.name for entry in root.iterdir()}
    if actual != set(observed) | {MANIFEST}:
        raise RuntimeError("STATE_SNAPSHOT_FILE_SET_MISMATCH")
    core = {"schema": SNAPSHOT_SCHEMA, "files": manifest["files"]}
    if hashlib.sha256(_canonical(core)).hexdigest() != digest:
        raise RuntimeError("STATE_SNAPSHOT_MISMATCH")
    return manifest


def _rollback_entry(current: dict[str, Any]) -> dict[str, Any] | None:
    if current["history"][-1]["operation"] == "rollback":
        return None
    consumed = {
        entry["rollback_of_sequence"]
        for entry in current["history"]
        if entry["operation"] == "rollback"
    }
    for entry in reversed(current["history"]):
        if (
            entry["operation"] == "upgrade"
            and entry["sequence"] not in consumed
            and entry["to_bundle_digest"] == current["bundle_digest"]
        ):
            return entry
    return None


def _history_entry(
    sequence: int, operation: str, from_digest: str | None, to_digest: str,
    snapshot_digest: str | None, rollback_of: int | None,
) -> dict[str, Any]:
    return {
        "sequence": sequence,
        "operation": operation,
        "from_bundle_digest": from_digest,
        "to_bundle_digest": to_digest,
        "state_snapshot_digest": snapshot_digest,
        "rollback_of_sequence": rollback_of,
    }


def _current_record(digest: str, history: list[dict[str, Any]]) -> dict[str, Any]:
    return {"schema": CURRENT_SCHEMA, "bundle_digest": digest, "history": history}


def _current_path(home: Path) -> Path:
    return home / "install" / "current.json"


def _read_current(home: Path) -> dict[str, Any] | None:
    path = _current_path(home)
    if not os.path.lexists(path):
        return None
    raw = _read_private_file(path, MAX_CURRENT_BYTES)
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError("INVALID_INSTALL_CURRENT") from error
    _validate_current(value)
    if raw != _canonical(value) + b"\n":
        raise RuntimeError("INVALID_INSTALL_CURRENT")
    return value


def _validate_current(value: Any) -> None:
    if (
        not isinstance(value, dict)
        or set(value) != {"schema", "bundle_digest", "history"}
        or value["schema"] != CURRENT_SCHEMA
        or not isinstance(value["bundle_digest"], str)
        or _DIGEST.fullmatch(value["bundle_digest"]) is None
        or not isinstance(value["history"], list) or not value["history"]
    ):
        raise RuntimeError("INVALID_INSTALL_CURRENT")
    previous_to: str | None = None
    upgrade_sequences: set[int] = set()
    rollback_sequences: set[int] = set()
    for expected, entry in enumerate(value["history"], 1):
        if not isinstance(entry, dict) or set(entry) != {
            "sequence", "operation", "from_bundle_digest",
            "to_bundle_digest", "state_snapshot_digest",
            "rollback_of_sequence",
        }:
            raise RuntimeError("INVALID_INSTALL_HISTORY")
        operation = entry["operation"]
        source = entry["from_bundle_digest"]
        target = entry["to_bundle_digest"]
        snapshot = entry["state_snapshot_digest"]
        rollback_of = entry["rollback_of_sequence"]
        if (
            entry["sequence"] != expected or operation not in {"install", "upgrade", "rollback"}
            or not isinstance(target, str) or _DIGEST.fullmatch(target) is None
            or (source is not None and (not isinstance(source, str) or _DIGEST.fullmatch(source) is None))
            or (snapshot is not None and (not isinstance(snapshot, str) or _DIGEST.fullmatch(snapshot) is None))
        ):
            raise RuntimeError("INVALID_INSTALL_HISTORY")
        if expected == 1:
            if operation != "install" or source is not None or snapshot is not None or rollback_of is not None:
                raise RuntimeError("INVALID_INSTALL_HISTORY")
        elif source != previous_to:
            raise RuntimeError("INVALID_INSTALL_HISTORY")
        if operation == "upgrade":
            if source is None or snapshot is None or rollback_of is not None or source == target:
                raise RuntimeError("INVALID_INSTALL_HISTORY")
            upgrade_sequences.add(expected)
        elif operation == "rollback":
            if (
                source is None or snapshot is None or type(rollback_of) is not int
                or rollback_of not in upgrade_sequences or rollback_of in rollback_sequences
            ):
                raise RuntimeError("INVALID_INSTALL_HISTORY")
            rollback_sequences.add(rollback_of)
        elif expected != 1:
            raise RuntimeError("INVALID_INSTALL_HISTORY")
        previous_to = target
    if previous_to != value["bundle_digest"]:
        raise RuntimeError("INVALID_INSTALL_CURRENT")


def _write_current(home: Path, value: dict[str, Any]) -> None:
    _validate_current(value)
    raw = _canonical(value) + b"\n"
    if len(raw) > MAX_CURRENT_BYTES:
        raise RuntimeError("INSTALL_HISTORY_TOO_LARGE")
    install_root = home / "install"
    temporary = install_root / f".current-{uuid.uuid4().hex}.tmp"
    _write_new_file(temporary, raw, 0o600)
    try:
        os.replace(temporary, _current_path(home))
        _fsync_directory(install_root)
    finally:
        temporary.unlink(missing_ok=True)


def _verify_installed_bundle(home: Path, digest: str) -> dict[str, Any]:
    manifest = verify_bundle(home / "bundles" / digest)
    if _manifest_digest(manifest) != digest:
        raise RuntimeError("BUNDLE_SNAPSHOT_MISMATCH")
    return manifest


def _status_unlocked(home: Path, current: dict[str, Any]) -> dict[str, Any]:
    _validate_current(current)
    _verify_installed_bundle(home, current["bundle_digest"])
    bundles: list[str] = []
    for entry in (home / "bundles").iterdir():
        info = entry.lstat()
        if (
            _DIGEST.fullmatch(entry.name) is None or not stat.S_ISDIR(info.st_mode)
            or stat.S_ISLNK(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o755
        ):
            raise RuntimeError("UNSAFE_BUNDLE_STORE")
        _verify_installed_bundle(home, entry.name)
        bundles.append(entry.name)
    return {
        "schema": STATUS_SCHEMA,
        "state": "INSTALLED",
        "current_bundle_digest": current["bundle_digest"],
        "bundle_digests": sorted(bundles),
        "history": [dict(entry) for entry in current["history"]],
    }


def _empty_status() -> dict[str, Any]:
    return {
        "schema": STATUS_SCHEMA, "state": "NOT_INSTALLED",
        "current_bundle_digest": None, "bundle_digests": [], "history": [],
    }


def _validate_private_state_dir(path: Path) -> None:
    info = path.lstat()
    if (
        not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
        or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise RuntimeError("UNSAFE_PERSISTENT_STATE_DIRECTORY")


def _open_private_file(path: Path) -> int:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600
        ):
            raise RuntimeError("UNSAFE_PRIVATE_FILE")
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _read_private_file(path: Path, limit: int) -> bytes:
    descriptor = _open_private_file(path)
    try:
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, limit + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > limit:
                raise RuntimeError("PRIVATE_FILE_TOO_LARGE")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _write_new_file(path: Path, raw: bytes, mode: int) -> None:
    descriptor = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, mode,
    )
    try:
        os.fchmod(descriptor, mode)
        _write_all(descriptor, raw)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_all(descriptor: int, raw: bytes) -> None:
    view = memoryview(raw)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise RuntimeError("SHORT_WRITE")
        view = view[written:]


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(
        path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | getattr(os, "O_DIRECTORY", 0),
    )
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISDIR(info.st_mode):
            raise RuntimeError("UNSAFE_INSTALL_DIRECTORY")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _safe_relative(value: Any) -> Path:
    if not isinstance(value, str) or not value or "\\" in value:
        raise RuntimeError("INVALID_BUNDLE_PATH")
    path = Path(value)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        raise RuntimeError("INVALID_BUNDLE_PATH")
    return path


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _rename_exclusive(source: Path, target: Path) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    if sys.platform == "darwin":
        rename = libc.renamex_np
        rename.argtypes = (ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint)
        rename.restype = ctypes.c_int
        result = rename(os.fsencode(source), os.fsencode(target), 0x00000004)
    elif sys.platform.startswith("linux"):
        rename = libc.renameat2
        rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
        rename.restype = ctypes.c_int
        result = rename(-100, os.fsencode(source), -100, os.fsencode(target), 1)
    else:
        raise RuntimeError("UNSUPPORTED_ATOMIC_RENAME_PLATFORM")
    if result == 0:
        return
    error = ctypes.get_errno()
    if error == errno.EEXIST:
        raise FileExistsError(error, os.strerror(error), target)
    raise OSError(error, os.strerror(error), target)


def _remove_owned_stage(path: Path, staging_root: Path) -> None:
    if (
        path.parent != staging_root
        or not (path.name.startswith("bundle-") or path.name.startswith("state-"))
        or not path.name.endswith(".tmp")
    ):
        raise RuntimeError("REFUSE_UNOWNED_STAGE_REMOVAL")
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid != os.geteuid():
        raise RuntimeError("REFUSE_UNOWNED_STAGE_REMOVAL")
    shutil.rmtree(path)
    _fsync_directory(staging_root)


def _checkpoint(_stage: str) -> None:
    """Patchable, side-effect-free failure-injection boundary for tests."""


__all__ = ["install", "upgrade", "rollback", "status", "select_bundle_for_start"]
