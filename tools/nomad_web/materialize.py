"""Build and atomically materialize a local Web Companion bundle."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from .bundle import (
    AGENT_ENTRYPOINT_SHA256,
    AGENT_RUNTIME,
    GATEWAY_MODULES,
    MANIFEST,
    NODE_ENTRYPOINT_SHA256,
    NODE_LICENSE_SHA256,
    NODE_RUNTIME,
    REQUIRED_PACKAGE,
    SCHEMA,
    _rename_exclusive,
    gateway_module_closure,
    verify_bundle,
)
from .processes import run_checked

SOURCE_ONLY_MODULES = {"onboarding.py"}


def materialize(repo: Path, output: Path) -> dict[str, Any]:
    repo, output = repo.resolve(), output.absolute()
    if os.path.lexists(output):
        raise RuntimeError("BUNDLE_OUTPUT_EXISTS")
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise RuntimeError("UNSUPPORTED_BUNDLE_PLATFORM")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".nomad-web-bundle-", dir=output.parent) as temporary:
        root = Path(temporary) / "bundle"
        for directory in (
            root / "bin", root / "agent", root / "gateway", root / "web",
            root / "lib" / "nomad_web", root / "runtime",
            root / "testkit" / "remote-v2",
        ):
            directory.mkdir(parents=True, exist_ok=True)
        ingress_source = repo / "relay" / "cmd" / "nomad-ingress"
        if not ingress_source.is_dir():
            raise RuntimeError("INGRESS_SOURCE_UNAVAILABLE")
        relay = root / "bin" / "nomad-relay"
        run_checked(["go", "build", "-o", str(relay), "./cmd/relay"], repo / "relay")
        ingress = root / "bin" / "nomad-ingress"
        run_checked(["go", "build", "-o", str(ingress), "./cmd/nomad-ingress"], repo / "relay")
        run_checked(["cargo", "build", "--release", "--bin", "nomad-product-host"], repo / "connector")
        host = root / "bin" / "nomad-product-host"
        shutil.copyfile(repo / "connector" / "target" / "release" / "nomad-product-host", host)
        run_checked(["npm", "run", "build"], repo / "mobile-reference")
        _materialize_agent(repo, Path(temporary), root)
        node_version = _materialize_node(root)
        gateway_source = repo / "mobile-reference" / "pilot-gateway"
        gateway_modules = gateway_module_closure(gateway_source)
        if {f"gateway/{name}" for name in gateway_modules} != set(GATEWAY_MODULES):
            raise RuntimeError("GATEWAY_MODULE_ALLOWLIST_MISMATCH")
        for name in sorted(gateway_modules):
            destination = root / "gateway" / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(gateway_source / name, destination)
        (root / "gateway" / "package.json").write_text("{\"type\":\"module\"}\n", encoding="utf-8")
        shutil.copytree(repo / "mobile-reference" / "dist", root / "web", dirs_exist_ok=True)
        for relative in sorted(REQUIRED_PACKAGE):
            source = repo / "tools" / Path(relative).relative_to("lib")
            shutil.copyfile(source, root / relative)
        runner_source = repo / "testkit" / "remote-v2"
        for name in ("run_m3e_product_slice.py", "run_m3e_desktop_browser.py"):
            shutil.copyfile(runner_source / name, root / "testkit" / "remote-v2" / name)
        wrapper = root / "bin" / "nomad-web"
        wrapper.write_text(
            "#!/bin/sh\nset -eu\nBUNDLE=$(CDPATH= cd -- \"$(/usr/bin/dirname -- \"$0\")/..\" && /bin/pwd -P)\n"
            "export NOMAD_WEB_BUNDLE=\"$BUNDLE\"\n"
            "PATH=\"$BUNDLE/runtime:/usr/bin:/bin:/usr/sbin:/sbin\"\nexport PATH\n"
            "unset PYTHONPATH PYTHONHOME\n"
            "exec python3 -I -B -c '"
            "import runpy,sys; sys.path.insert(0,sys.argv.pop(1)); "
            "runpy.run_module(\"nomad_web\",run_name=\"__main__\")' "
            "\"$BUNDLE/lib\" \"$@\"\n", encoding="utf-8"
        )
        for directory in sorted((item for item in root.rglob("*") if item.is_dir()), reverse=True):
            os.chmod(directory, 0o755)
        os.chmod(root, 0o755)
        executable_files = {
            relay, ingress, host, wrapper, root / "agent" / "opencode",
            root / NODE_RUNTIME["entrypoint"],
        }
        for path in root.rglob("*"):
            if path.is_file():
                os.chmod(path, 0o755 if path in executable_files else 0o644)
        files = []
        for path in sorted(item for item in root.rglob("*") if item.is_file() and item != root / MANIFEST):
            raw = path.read_bytes()
            files.append({"path": str(path.relative_to(root)), "size_bytes": len(raw), "raw_sha256": hashlib.sha256(raw).hexdigest(), "mode": f"{path.stat().st_mode & 0o777:04o}"})
        core = {
            "schema": SCHEMA, "classification": "repo-local-prebuilt-not-production-authority",
            "platform": "darwin-arm64", "launcher_version": "0.1.0",
            "source_commit_oid": _git(repo, "rev-parse", "HEAD"),
            "source_dirty": bool(_git(repo, "status", "--porcelain")),
            "build_tools": {"go": _line(["go", "version"]), "node": node_version, "npm": _line(["npm", "--version"]), "python": platform.python_version()},
            "agent_runtime": AGENT_RUNTIME,
            "node_runtime": NODE_RUNTIME,
            "files": files,
        }
        value = {**core, "bundle_digest": hashlib.sha256(json.dumps(core, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()}
        (root / MANIFEST).write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")
        os.chmod(root / MANIFEST, 0o644)
        verify_bundle(root)
        _rename_exclusive(root, output)
        return {"schema": SCHEMA, "state": "MATERIALIZED", "bundle": str(output), "bundle_digest": value["bundle_digest"], "production_ready": False}


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=repo, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, check=True).stdout.strip()


def _line(command: list[str]) -> str:
    return subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, check=True).stdout.strip().splitlines()[0][:160]


def _materialize_agent(repo: Path, temporary: Path, root: Path) -> None:
    source = repo / "testkit" / "stock-opencode" / "locked-runtime"
    capture_path = repo / "testkit" / "stock-opencode" / "capture-manifest.json"
    package, lock = source / "package.json", source / "package-lock.json"
    try:
        capture = json.loads(capture_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError("AGENT_PROVENANCE_UNAVAILABLE") from error
    expected = {
        "package_json_sha256": "e1c3f7612fafffe24bb3452c1cbd1259be05827fe836b20a72304599b1922bb5",
        "package_lock_sha256": "a8b262bae6dbbe1d2d05b1be06843e62201b2b47d879e19dd68b8613ebefd8b0",
        "observed_installed_entrypoint_target_sha256": AGENT_ENTRYPOINT_SHA256,
        "npm_version": "11.12.1",
    }
    if any(capture.get(name) != value for name, value in expected.items()):
        raise RuntimeError("AGENT_PROVENANCE_MISMATCH")
    for path, field in ((package, "package_json_sha256"), (lock, "package_lock_sha256")):
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected[field]:
            raise RuntimeError("AGENT_LOCK_INPUT_MISMATCH")
    if _line(["npm", "--version"]) != expected["npm_version"]:
        raise RuntimeError("AGENT_BUILD_NPM_VERSION_MISMATCH")
    install = temporary / "agent-build"
    install.mkdir(mode=0o700)
    shutil.copyfile(package, install / "package.json")
    shutil.copyfile(lock, install / "package-lock.json")
    run_checked(["npm", "ci", "--ignore-scripts=false", "--no-audit", "--no-fund"], install)
    entrypoint = (install / "node_modules" / "opencode-darwin-arm64" / "bin" / "opencode").resolve(strict=True)
    if (
        not entrypoint.is_file()
        or hashlib.sha256(entrypoint.read_bytes()).hexdigest() != AGENT_ENTRYPOINT_SHA256
        or _line([str(entrypoint), "--version"]) != AGENT_RUNTIME["package_version"]
    ):
        raise RuntimeError("AGENT_ENTRYPOINT_MISMATCH")
    shutil.copyfile(entrypoint, root / "agent" / "opencode")
    shutil.copyfile(install / "node_modules" / "opencode-ai" / "LICENSE", root / "agent" / "LICENSE")


def _materialize_node(root: Path) -> str:
    selected = shutil.which("node")
    if selected is None:
        raise RuntimeError("NODE_BUILD_RUNTIME_UNAVAILABLE")
    candidate = Path(selected)
    if not candidate.is_absolute():
        raise RuntimeError("NODE_BUILD_RUNTIME_UNSAFE")
    try:
        entrypoint = candidate.resolve(strict=True)
        info = entrypoint.stat()
    except OSError as error:
        raise RuntimeError("NODE_BUILD_RUNTIME_UNSAFE") from error
    if (
        not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
        or info.st_uid not in (0, os.geteuid())
        or not os.access(entrypoint, os.X_OK)
        or stat.S_IMODE(info.st_mode) & 0o022
    ):
        raise RuntimeError("NODE_BUILD_RUNTIME_UNSAFE")
    for ancestor in entrypoint.parents:
        try:
            ancestor_info = ancestor.lstat()
        except OSError as error:
            raise RuntimeError("NODE_BUILD_RUNTIME_UNSAFE") from error
        if (
            not stat.S_ISDIR(ancestor_info.st_mode)
            or stat.S_ISLNK(ancestor_info.st_mode)
            or ancestor_info.st_uid not in (0, os.geteuid())
            or stat.S_IMODE(ancestor_info.st_mode) & 0o022
        ):
            raise RuntimeError("NODE_BUILD_RUNTIME_UNSAFE")
    installation = entrypoint.parent.parent
    license_path = installation / "LICENSE"
    try:
        license_info = license_path.lstat()
    except OSError as error:
        raise RuntimeError("NODE_LICENSE_MISMATCH") from error
    if (
        not entrypoint.is_file()
        or hashlib.sha256(entrypoint.read_bytes()).hexdigest() != NODE_ENTRYPOINT_SHA256
        or _line([str(entrypoint), "--version"]) != f"v{NODE_RUNTIME['version']}"
    ):
        raise RuntimeError("NODE_ENTRYPOINT_MISMATCH")
    if (
        not stat.S_ISREG(license_info.st_mode) or stat.S_ISLNK(license_info.st_mode)
        or license_info.st_nlink != 1 or license_info.st_uid not in (0, os.geteuid())
        or stat.S_IMODE(license_info.st_mode) & 0o022
        or hashlib.sha256(license_path.read_bytes()).hexdigest() != NODE_LICENSE_SHA256
    ):
        raise RuntimeError("NODE_LICENSE_MISMATCH")
    shutil.copyfile(entrypoint, root / NODE_RUNTIME["entrypoint"])
    shutil.copyfile(license_path, root / NODE_RUNTIME["license"])
    return f"v{NODE_RUNTIME['version']}"
