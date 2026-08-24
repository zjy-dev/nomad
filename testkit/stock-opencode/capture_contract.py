#!/usr/bin/env python3
"""Content-free, registry-integrity-bound OpenCode 1.18.16 capture."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
import urllib.parse
import platform
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

PACKAGE = "opencode-ai"
EXPECTED_VERSION = "1.18.16"
EXPECTED_NPM_VERSION = "11.12.1"
EXECUTION_PROVENANCE_SCOPE = "registry_archives_exact_lock_fresh_npm_ci_selected_packages_and_spawned_entrypoint"
REGISTRY_ORIGIN = "https://registry.npmjs.org"
LOCKED_RUNTIME = Path(__file__).with_name("locked-runtime")
LOCKED_PACKAGE = LOCKED_RUNTIME / "package.json"
LOCKED_LOCK = LOCKED_RUNTIME / "package-lock.json"
EVENT_FIELDS = ("id", "type", "properties")
REQUIRED_ROUTES = (
    "/global/health", "/event", "/session", "/session/{sessionID}",
    "/session/{sessionID}/message", "/session/{sessionID}/diff",
    "/permission", "/question",
)
SENSITIVE_FIELDS = frozenset({
    "command", "content", "diff", "directory", "file", "files",
    "metadata", "output", "patch", "path", "patterns", "prompt",
    "questions", "source", "summary", "text", "title",
})


class CaptureError(Exception):
    def __init__(self, code: str) -> None:
        self.code = code


@dataclass(frozen=True)
class RegistryArtifact:
    integrity: str
    shasum: str
    tarball: str


@dataclass(frozen=True)
class LockedDependency:
    location: str
    name: str
    version: str
    integrity: str
    resolved: str


def canonical_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def clean_env(home: str) -> dict[str, str]:
    npm = shutil.which("npm")
    if not npm:
        raise CaptureError("BLOCKED_EXTERNAL_NPM_OR_BINARY")
    return {
        "PATH": f"{Path(npm).parent}:{os.defpath}",
        "HOME": home,
        "LANG": "C",
        "npm_config_loglevel": "error",
        "npm_config_registry": REGISTRY_ORIGIN,
    }


def run(args: list[str], *, cwd: Path, env: dict[str, str], timeout: int = 30) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(args, cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=timeout, check=True)
    except (OSError, subprocess.SubprocessError):
        raise CaptureError("BLOCKED_EXTERNAL_NPM_OR_BINARY") from None


def registry_package_artifact(name: str, version: str) -> RegistryArtifact:
    try:
        encoded_name = urllib.parse.quote(name, safe="")
        with urllib.request.urlopen(f"{REGISTRY_ORIGIN}/{encoded_name}/{version}", timeout=15) as response:
            data = json.load(response)
        dist = data["dist"]
        if data.get("name") != name or data.get("version") != version:
            raise ValueError
        if not all(isinstance(dist.get(key), str) for key in ("integrity", "shasum", "tarball")):
            raise ValueError
        return RegistryArtifact(dist["integrity"], dist["shasum"], dist["tarball"])
    except Exception:
        raise CaptureError("BLOCKED_NPM_REGISTRY") from None


def registry_artifact() -> RegistryArtifact:
    return registry_package_artifact(PACKAGE, EXPECTED_VERSION)


def sri_matches(data: bytes, integrity: str) -> bool:
    try:
        algorithm, encoded = integrity.split("-", 1)
        return base64.b64encode(hashlib.new(algorithm, data).digest()).decode() == encoded
    except Exception:
        return False


def sri_for(data: bytes, integrity: str) -> str:
    algorithm = integrity.split("-", 1)[0]
    return f"{algorithm}-{base64.b64encode(hashlib.new(algorithm, data).digest()).decode()}"


def pack_exact(work: Path, artifact: RegistryArtifact, env: dict[str, str]) -> Path:
    output = run(["npm", "pack", f"{PACKAGE}@{EXPECTED_VERSION}", "--json", f"--registry={REGISTRY_ORIGIN}"], cwd=work, env=env).stdout
    try:
        packed = json.loads(output)[0]
        expected_filename = f"{PACKAGE}-{EXPECTED_VERSION}.tgz"
        tarball = work / packed["filename"]
        content = tarball.read_bytes()
        if packed.get("name") != PACKAGE or packed.get("version") != EXPECTED_VERSION:
            raise ValueError
        if tarball.name != expected_filename:
            raise ValueError
        if packed.get("integrity") not in (None, artifact.integrity):
            raise ValueError
        if packed.get("shasum") not in (None, artifact.shasum):
            raise ValueError
        if not sri_matches(content, artifact.integrity) or hashlib.sha1(content).hexdigest() != artifact.shasum:
            raise ValueError
        return tarball
    except Exception:
        raise CaptureError("PACK_INTEGRITY_MISMATCH") from None


def package_name_from_location(location: str) -> str:
    marker = "node_modules/"
    if marker not in location:
        raise ValueError
    tail = location.rsplit(marker, 1)[1]
    if tail.startswith("@"):
        parts = tail.split("/")
        if len(parts) < 2:
            raise ValueError
        return "/".join(parts[:2])
    return tail.split("/", 1)[0]


def locked_dependencies(lock_path: Path) -> list[LockedDependency]:
    try:
        lock = json.loads(lock_path.read_text())
        if lock.get("lockfileVersion") not in (2, 3):
            raise ValueError
        packages = lock.get("packages")
        if not isinstance(packages, Mapping):
            raise ValueError
        entries: list[LockedDependency] = []
        for location, entry in packages.items():
            if location == "":
                continue
            if not isinstance(location, str) or not isinstance(entry, Mapping):
                raise ValueError
            if entry.get("link") or str(entry.get("resolved", "")).startswith("file:"):
                raise CaptureError("NON_REGISTRY_DEPENDENCY")
            version, integrity, resolved = entry.get("version"), entry.get("integrity"), entry.get("resolved")
            if not isinstance(version, str) or not isinstance(integrity, str):
                raise ValueError
            if not isinstance(resolved, str) or not resolved.startswith(f"{REGISTRY_ORIGIN}/"):
                raise CaptureError("NON_REGISTRY_DEPENDENCY")
            entries.append(LockedDependency(location, package_name_from_location(location), version, integrity, resolved))
        if not entries:
            raise ValueError
        return sorted(entries, key=lambda entry: (entry.name, entry.location))
    except CaptureError:
        raise
    except Exception:
        raise CaptureError("LOCKFILE_INTEGRITY_INVALID") from None


def closure_digest(entries: list[LockedDependency]) -> str:
    return sha256(canonical_bytes(sorted((entry.name, entry.version, entry.integrity) for entry in entries)))


def full_locked_closure(lock_path: Path) -> dict[str, object]:
    entries = locked_dependencies(lock_path)
    return {
        "full_locked_dependency_count": len(entries),
        "full_locked_dependency_digest": closure_digest(entries),
        "all_locked_dependencies_registry_integrity_bound": True,
    }


def validate_registry_closure(lock_path: Path) -> None:
    for entry in locked_dependencies(lock_path):
        artifact = registry_package_artifact(entry.name, entry.version)
        if artifact.integrity != entry.integrity or artifact.tarball != entry.resolved:
            raise CaptureError("LOCK_DEPENDENCY_REGISTRY_MISMATCH")


def installed_platform_closure(lock_path: Path, install: Path) -> dict[str, object]:
    installed: list[LockedDependency] = []
    for entry in locked_dependencies(lock_path):
        package_dir = install / entry.location
        if not package_dir.is_dir():
            continue
        try:
            package = json.loads((package_dir / "package.json").read_text())
            if package.get("name") != entry.name or package.get("version") != entry.version:
                raise ValueError
        except Exception:
            raise CaptureError("INSTALLED_CLOSURE_INVALID") from None
        installed.append(entry)
    if not installed or not any(entry.name == PACKAGE for entry in installed):
        raise CaptureError("INSTALLED_CLOSURE_INVALID")
    return {
        "installed_platform_dependency_count": len(installed),
        "installed_platform_dependency_digest": closure_digest(installed),
    }


def observed_installed_entrypoint(binary: Path, install: Path) -> tuple[Path, dict[str, object]]:
    """Validate and hash the observed npm-ci entrypoint without archive-equivalence claims."""
    try:
        wrapper_bytes = os.readlink(binary).encode() if binary.is_symlink() else binary.read_bytes()
        resolved = binary.resolve(strict=True)
        resolved.relative_to((install / "node_modules").resolve(strict=True))
        if not resolved.is_file():
            raise ValueError
        return resolved, {
            "observed_installed_entrypoint_wrapper_sha256": sha256(wrapper_bytes),
            "observed_installed_entrypoint_target_sha256": sha256(resolved.read_bytes()),
        }
    except (OSError, ValueError):
        raise CaptureError("BLOCKED_ENTRYPOINT_OUTSIDE_LOCKED_RUNTIME") from None


def validate_locked_runtime(artifact: RegistryArtifact) -> dict[str, object]:
    """Validate the committed public npm-ci input before it is copied."""
    try:
        package = json.loads(LOCKED_PACKAGE.read_text())
        lock = json.loads(LOCKED_LOCK.read_text())
        expected_package = {
            "name": "nomad-stock-opencode-locked-runtime",
            "version": "1.0.0",
            "private": True,
            "packageManager": f"npm@{EXPECTED_NPM_VERSION}",
            "dependencies": {PACKAGE: EXPECTED_VERSION},
        }
        if package != expected_package:
            raise CaptureError("LOCKED_PACKAGE_INVALID")
        root = lock.get("packages", {}).get("", {})
        stock = lock.get("packages", {}).get(f"node_modules/{PACKAGE}", {})
        if root != {"name": expected_package["name"], "version": expected_package["version"], "dependencies": {PACKAGE: EXPECTED_VERSION}}:
            raise CaptureError("LOCKED_PACKAGE_INVALID")
        if stock.get("version") != EXPECTED_VERSION or stock.get("integrity") != artifact.integrity:
            raise CaptureError("LOCK_ROOT_REGISTRY_MISMATCH")
        if stock.get("resolved") != artifact.tarball:
            raise CaptureError("LOCK_ROOT_REGISTRY_MISMATCH")
        return {
            **full_locked_closure(LOCKED_LOCK),
            "package_json_sha256": sha256(LOCKED_PACKAGE.read_bytes()),
            "package_lock_sha256": sha256(LOCKED_LOCK.read_bytes()),
            "lock_artifact": "locked-runtime/package-lock.json",
        }
    except CaptureError:
        raise
    except Exception:
        raise CaptureError("LOCKED_RUNTIME_INVALID") from None


def closure_diagnostic(left: Mapping[str, object], right: Mapping[str, object]) -> dict[str, object]:
    """Content-free closure drift summary; never returns package names or URLs."""
    keys = ("full_locked_dependency_count", "full_locked_dependency_digest",
            "installed_platform_dependency_count", "installed_platform_dependency_digest")
    return {
        "difference_type": "closure_digest_mismatch",
        "different_fields": [key for key in keys if left.get(key) != right.get(key)],
        "left_entry_hash": sha256(canonical_bytes({key: left.get(key) for key in keys})),
        "right_entry_hash": sha256(canonical_bytes({key: right.get(key) for key in keys})),
    }


def schema_shape(schema: object, schemas: Mapping[str, object]) -> dict[str, object]:
    if isinstance(schema, Mapping) and isinstance(schema.get("$ref"), str):
        schema = schemas.get(schema["$ref"].rsplit("/", 1)[-1], {})
    schema = schema if isinstance(schema, Mapping) else {}
    properties = schema.get("properties", {})
    names = sorted(properties) if isinstance(properties, Mapping) else []
    safe = [name for name in names if name.lower() not in SENSITIVE_FIELDS]
    result = {"kind": schema.get("type", "unspecified"), "safe_property_names": safe, "redacted_property_count": len(names) - len(safe), "required_field_count": len(schema.get("required", []))}
    if schema.get("type") == "array":
        result["item_shape"] = schema_shape(schema.get("items", {}), schemas)
    return result


def get_json(base: str, route: str) -> object:
    with urllib.request.urlopen(base + route, timeout=5) as response:
        return json.load(response)


def event_shape(base: str) -> dict[str, object]:
    with urllib.request.urlopen(base + "/event", timeout=5) as response:
        for line in response:
            if not line.startswith(b"data: "):
                continue
            payload = json.loads(line[6:])
            if not isinstance(payload, Mapping):
                raise CaptureError("EVENT_SHAPE_INVALID")
            allowed = sorted(key for key in EVENT_FIELDS if key in payload)
            if set(allowed) != set(EVENT_FIELDS):
                raise CaptureError("EVENT_ENVELOPE_MISSING")
            return {"top_level_fields": allowed, "field_types": {key: type(payload[key]).__name__ for key in allowed}, "properties_shape": "object" if isinstance(payload["properties"], Mapping) else type(payload["properties"]).__name__, "unexpected_field_count": len(set(payload) - set(EVENT_FIELDS))}
    raise CaptureError("EVENT_ENVELOPE_MISSING")


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_health(base: str) -> Mapping[str, object]:
    for _ in range(30):
        try:
            health = get_json(base, "/global/health")
            if isinstance(health, Mapping):
                return health
        except Exception:
            time.sleep(0.2)
    raise CaptureError("SERVER_HEALTH_TIMEOUT")


def capture_from_server(base: str, provenance: dict[str, object]) -> dict[str, object]:
    health, openapi = wait_health(base), get_json(base, "/doc")
    if health.get("version") != EXPECTED_VERSION or not isinstance(openapi, Mapping):
        raise CaptureError("SERVER_VERSION_OR_OPENAPI_INVALID")
    paths, schemas = openapi.get("paths", {}), openapi.get("components", {}).get("schemas", {})
    if not isinstance(paths, Mapping) or not isinstance(schemas, Mapping) or any(route not in paths for route in REQUIRED_ROUTES):
        raise CaptureError("REQUIRED_ROUTE_MISSING")
    snapshots = {}
    for route in REQUIRED_ROUTES[2:]:
        operation = paths[route].get("get", {})
        content = operation.get("responses", {}).get("200", {}).get("content", {})
        snapshots[route] = {"available": True, "media_types": sorted(content), "response_shapes": {media: schema_shape(value.get("schema", {}), schemas) for media, value in content.items()}}
    return {"schema": "nomad.stock-opencode.contract-capture.v2", "provenance": provenance, "health": {"healthy": health.get("healthy"), "version": EXPECTED_VERSION}, "openapi": {"route": "/doc", "version": openapi.get("openapi"), "relevant_routes_present": list(REQUIRED_ROUTES)}, "event": {"route_present": True, "transport": sorted(paths["/event"].get("get", {}).get("responses", {}).get("200", {}).get("content", {})), "observed_envelope": event_shape(base), "required_envelope_fields": list(EVENT_FIELDS)}, "snapshots": snapshots, "evidence_claims": {key: "not_observed_without_provider_backed_task" for key in ("question", "permission", "diff", "stop")}}


def official_capture() -> dict[str, object]:
    artifact = registry_artifact()
    locked = validate_locked_runtime(artifact)
    validate_registry_closure(LOCKED_LOCK)
    with tempfile.TemporaryDirectory(prefix="nomad-stock-opencode-") as temp:
        root, env = Path(temp), clean_env(temp)
        tarball = pack_exact(root, artifact, env)
        install = root / "locked-runtime"
        shutil.copytree(LOCKED_RUNTIME, install)
        run(["npm", "ci", f"--registry={REGISTRY_ORIGIN}", "--ignore-scripts=false", "--no-audit", "--no-fund"], cwd=install, env=env)
        if sha256((install / "package.json").read_bytes()) != locked["package_json_sha256"] or sha256((install / "package-lock.json").read_bytes()) != locked["package_lock_sha256"]:
            raise CaptureError("BLOCKED_DEPENDENCY_CLOSURE_MISMATCH")
        full_closure = full_locked_closure(install / "package-lock.json")
        if full_closure != {key: locked[key] for key in full_closure}:
            raise CaptureError("BLOCKED_DEPENDENCY_CLOSURE_MISMATCH")
        installed_closure = installed_platform_closure(install / "package-lock.json", install)
        npm_version = run(["npm", "--version"], cwd=root, env=env).stdout.strip()
        binary = install / "node_modules" / ".bin" / "opencode"
        if not binary.is_file():
            raise CaptureError("INSTALLED_BINARY_MISSING")
        resolved_entrypoint, entrypoint_observation = observed_installed_entrypoint(binary, install)
        if run([str(resolved_entrypoint), "--version"], cwd=root, env=env, timeout=10).stdout.strip() != EXPECTED_VERSION:
            raise CaptureError("BINARY_VERSION_MISMATCH")
        process = None
        try:
            port = free_port()
            process = subprocess.Popen([str(resolved_entrypoint), "serve", "--pure", "--hostname", "127.0.0.1", "--port", str(port)], cwd=root, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            tarball_bytes = tarball.read_bytes()
            provenance = {"classification": "official_registry_integrity_bound_stock_contract", "execution_provenance_scope": EXECUTION_PROVENANCE_SCOPE, "postinstall_final_code_attested": False, "package": PACKAGE, "version": EXPECTED_VERSION, "registry_origin": REGISTRY_ORIGIN, "registry_integrity": artifact.integrity, "registry_shasum": artifact.shasum, "packed_integrity": sri_for(tarball_bytes, artifact.integrity), "packed_shasum": hashlib.sha1(tarball_bytes).hexdigest(), "tarball_sha256": sha256(tarball_bytes), "server_binding_method": "same_observed_validated_npm_ci_entrypoint_spawned_loopback", "verification_method": "registry_exact_pack_plus_locked_npm_ci_observed_entrypoint_process", "npm_version": npm_version, "os": sys.platform, "arch": platform.machine(), "npm_compatibility_rule": "exact", "provider_backed_task": False, "content_policy": "shape_only_no_raw_bodies_or_values", **entrypoint_observation, **full_closure, **installed_closure, **locked}
            return capture_from_server(f"http://127.0.0.1:{port}", provenance)
        finally:
            if process is not None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)


def manifest_for(fixture: object, script: Path) -> dict[str, object]:
    provenance = fixture["provenance"]
    package_hash = sha256(LOCKED_PACKAGE.read_bytes())
    lock_hash = sha256(LOCKED_LOCK.read_bytes())
    full_closure = full_locked_closure(LOCKED_LOCK)
    locally_bound = {
        "package_json_sha256": package_hash,
        "package_lock_sha256": lock_hash,
        "full_locked_dependency_count": full_closure["full_locked_dependency_count"],
        "full_locked_dependency_digest": full_closure["full_locked_dependency_digest"],
    }
    if any(provenance.get(key) != value for key, value in locally_bound.items()):
        raise CaptureError("FIXTURE_LOCAL_ASSET_MISMATCH")
    return {
        "schema": "nomad.stock-opencode.capture-manifest.v3",
        "fixture_schema": fixture["schema"],
        "fixture_canonical_sha256": sha256(canonical_bytes(fixture)),
        "capture_contract_sha256": sha256(script.read_bytes()),
        "package_json_sha256": package_hash,
        "package_lock_sha256": lock_hash,
        "lock_artifact": "locked-runtime/package-lock.json",
        "registry_integrity": provenance["registry_integrity"],
        "registry_shasum": provenance["registry_shasum"],
        "tarball_sha256": provenance["tarball_sha256"],
        "full_locked_dependency_count": full_closure["full_locked_dependency_count"],
        "full_locked_dependency_digest": full_closure["full_locked_dependency_digest"],
        "installed_platform_dependency_count": provenance["installed_platform_dependency_count"],
        "installed_platform_dependency_digest": provenance["installed_platform_dependency_digest"],
        "classification": provenance["classification"],
        "execution_provenance_scope": provenance["execution_provenance_scope"],
        "postinstall_final_code_attested": provenance["postinstall_final_code_attested"],
        "observed_installed_entrypoint_wrapper_sha256": provenance["observed_installed_entrypoint_wrapper_sha256"],
        "observed_installed_entrypoint_target_sha256": provenance["observed_installed_entrypoint_target_sha256"],
        "os": provenance["os"], "arch": provenance["arch"],
        "npm_version": provenance["npm_version"],
        "npm_compatibility_rule": provenance["npm_compatibility_rule"],
    }


def verify_fixture(fixture_path: Path, manifest_path: Path) -> int:
    try:
        fixture, manifest = json.loads(fixture_path.read_text()), json.loads(manifest_path.read_text())
        if manifest != manifest_for(fixture, Path(__file__)):
            raise CaptureError("MANIFEST_MISMATCH")
        with tempfile.TemporaryDirectory(prefix="nomad-stock-opencode-env-") as temp:
            env = clean_env(temp)
            npm_version = run(["npm", "--version"], cwd=Path(temp), env=env).stdout.strip()
        expected = fixture["provenance"]
        if (expected["os"], expected["arch"], expected["npm_version"]) != (sys.platform, platform.machine(), npm_version):
            raise CaptureError("BLOCKED_ENVIRONMENT_COMPATIBILITY_MISMATCH")
        live = official_capture()
        actual = live["provenance"]
        if closure_diagnostic(expected, actual)["different_fields"]:
            raise CaptureError("BLOCKED_DEPENDENCY_CLOSURE_MISMATCH")
        if canonical_bytes(live) != canonical_bytes(fixture):
            raise CaptureError("LIVE_CAPTURE_MISMATCH")
        return 0
    except CaptureError as error:
        sys.stdout.write(json.dumps({"schema": "nomad.stock-opencode.capture-error.v1", "status": "BLOCKED", "error_code": error.code}, sort_keys=True) + "\n")
        return 2
    except Exception:
        sys.stdout.write(json.dumps({"schema": "nomad.stock-opencode.capture-error.v1", "status": "BLOCKED", "error_code": "INTERNAL_CAPTURE_ERROR"}, sort_keys=True) + "\n")
        return 2


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--verify-fixture", type=Path)
    args = parser.parse_args()
    if args.verify_fixture:
        if not args.manifest:
            return 2
        return verify_fixture(args.verify_fixture, args.manifest)
    try:
        payload, status = official_capture(), 0
        if args.manifest:
            args.manifest.write_text(json.dumps(manifest_for(payload, Path(__file__)), indent=2, sort_keys=True) + "\n")
    except CaptureError as error:
        payload, status = {"schema": "nomad.stock-opencode.capture-error.v1", "status": "BLOCKED", "error_code": error.code}, 2
    except Exception:
        payload, status = {"schema": "nomad.stock-opencode.capture-error.v1", "status": "BLOCKED", "error_code": "INTERNAL_CAPTURE_ERROR"}, 2
    output = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(output)
    else:
        sys.stdout.write(output)
    return status


if __name__ == "__main__":
    raise SystemExit(main())
