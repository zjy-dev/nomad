"""Strict verification for a prebuilt repo-local Web Companion bundle."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import uuid
from pathlib import Path
from collections.abc import Callable, Mapping, Set
from typing import Any

SCHEMA_V1 = "nomad.web-companion.prebuilt.v1"
SCHEMA = "nomad.web-companion.prebuilt.v2"
SUPPORTED_SCHEMAS = {SCHEMA_V1, SCHEMA}
MANIFEST = "manifest.json"
MAX_MANIFEST = 256 * 1024
COMMON_REQUIRED = {
    "bin/nomad-web": 0o755,
    "bin/nomad-relay": 0o755,
    "bin/nomad-product-host": 0o755,
    "agent/opencode": 0o755,
    "agent/LICENSE": 0o644,
    "gateway/package.json": 0o644,
    "web/index.html": 0o644,
}
GATEWAY_MODULES_V1 = {
    "gateway/server.mjs": 0o644,
    "gateway/relay-client.mjs": 0o644,
    "gateway/view.mjs": 0o644,
    "gateway/alpha-store.mjs": 0o644,
    "gateway/command-security.mjs": 0o644,
    "gateway/product-host-client.mjs": 0o644,
}
GATEWAY_MODULES = {**GATEWAY_MODULES_V1, "gateway/pairing-session.mjs": 0o644}
REQUIRED_V1 = {**COMMON_REQUIRED, **GATEWAY_MODULES_V1}
REQUIRED = {
    **COMMON_REQUIRED,
    **GATEWAY_MODULES,
    "bin/nomad-ingress": 0o755,
}
REQUIRED_BY_SCHEMA = {SCHEMA_V1: REQUIRED_V1, SCHEMA: REQUIRED}
REQUIRED_PACKAGE_V1 = {
    f"lib/nomad_web/{name}" for name in (
        "__init__.py", "__main__.py", "bundle.py", "cli.py",
        "agent_runtime.py", "config.py", "doctor.py", "launcher.py", "materialize.py",
        "processes.py", "state.py",
    )
}
REQUIRED_PACKAGE = REQUIRED_PACKAGE_V1 | {
    f"lib/nomad_web/{name}"
    for name in (
        "diagnostics.py", "evidence_resume.py", "install_lifecycle.py",
        "lifecycle_coordinator.py", "recovery.py", "release_verify.py",
    )
}
REQUIRED_RUNNER_CLOSURE = {
    "testkit/remote-v2/run_m3e_product_slice.py",
    "testkit/remote-v2/run_m3e_desktop_browser.py",
}
# Both accepted schemas carry the current Python CLI closure.  Schema v1/v2
# distinguishes the native/gateway artifact set, not the launcher package.
PACKAGE_BY_SCHEMA = {SCHEMA_V1: REQUIRED_PACKAGE, SCHEMA: REQUIRED_PACKAGE}
RUNNERS_BY_SCHEMA = {
    SCHEMA_V1: REQUIRED_RUNNER_CLOSURE, SCHEMA: REQUIRED_RUNNER_CLOSURE,
}
TOP_KEYS = {"schema", "classification", "platform", "launcher_version", "source_commit_oid", "source_dirty", "build_tools", "agent_runtime", "files", "bundle_digest"}
FILE_KEYS = {"path", "size_bytes", "raw_sha256", "mode"}
AGENT_ENTRYPOINT_SHA256 = "a41776bf64c75786d6baf531b840ffb873c090d7c44793ae2dd4b1896de56a1f"
AGENT_RUNTIME = {
    "classification": "official-registry-locked-prebuilt-not-provider-evidence",
    "package_name": "opencode-ai",
    "package_version": "1.18.16",
    "platform_package": "opencode-darwin-arm64",
    "entrypoint": "agent/opencode",
    "entrypoint_raw_sha256": AGENT_ENTRYPOINT_SHA256,
    "provider_backed": False,
}


def verify_bundle(root: Path) -> dict[str, Any]:
    root = root.absolute()
    info = root.lstat()
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o755:
        raise RuntimeError("UNSAFE_BUNDLE_ROOT")
    raw_manifest = _read(root / MANIFEST, MAX_MANIFEST, 0o644)
    actual, directories = _walk(root)
    return _verify_bundle_inputs(
        raw_manifest,
        lambda name, limit, mode: _read(root / name, limit, mode),
        actual,
        directories,
    )


def verify_bundle_snapshot(
    files: Mapping[str, bytes], modes: Mapping[str, int], directories: Set[str],
) -> dict[str, Any]:
    """Verify one already captured bundle without reading its paths again.

    The installed launcher uses this after it has captured every regular file
    under the lifecycle lock.  Keeping the manifest contract here makes the
    bytes that were checked exactly the bytes later imported by the launcher.
    """
    if (
        not isinstance(files, Mapping) or not isinstance(modes, Mapping)
        or not isinstance(directories, Set)
        or set(files) != set(modes)
        or any(not isinstance(name, str) or not isinstance(raw, bytes) for name, raw in files.items())
        or any(type(mode) is not int for mode in modes.values())
        or modes.get(MANIFEST) != 0o644
    ):
        raise RuntimeError("INVALID_BUNDLE_SNAPSHOT")
    raw_manifest = files.get(MANIFEST)
    if raw_manifest is None or len(raw_manifest) > MAX_MANIFEST:
        raise RuntimeError("INVALID_BUNDLE_SNAPSHOT")

    def read_snapshot(name: str, limit: int, expected_mode: int) -> bytes:
        raw = files.get(name)
        if raw is None or modes.get(name) != expected_mode:
            raise RuntimeError("UNSAFE_BUNDLE_FILE")
        if len(raw) > limit:
            raise RuntimeError("BUNDLE_FILE_TOO_LARGE")
        return raw

    return _verify_bundle_inputs(
        raw_manifest, read_snapshot, set(files), set(directories),
    )


def _verify_bundle_inputs(
    raw_manifest: bytes,
    read_file: Callable[[str, int, int], bytes],
    actual: set[str],
    directories: set[str],
) -> dict[str, Any]:
    try:
        value = json.loads(raw_manifest)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError("INVALID_BUNDLE_MANIFEST") from error
    if not isinstance(value, dict) or set(value) != TOP_KEYS or value["schema"] not in SUPPORTED_SCHEMAS:
        raise RuntimeError("INVALID_BUNDLE_MANIFEST")
    required = REQUIRED_BY_SCHEMA[value["schema"]]
    required_package = PACKAGE_BY_SCHEMA[value["schema"]]
    required_runners = RUNNERS_BY_SCHEMA[value["schema"]]
    if value["classification"] != "repo-local-prebuilt-not-production-authority" or value["platform"] != "darwin-arm64":
        raise RuntimeError("INVALID_BUNDLE_MANIFEST")
    if value["agent_runtime"] != AGENT_RUNTIME:
        raise RuntimeError("INVALID_AGENT_RUNTIME")
    if (
        not isinstance(value["launcher_version"], str)
        or re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", value["launcher_version"]) is None
        or not isinstance(value["source_commit_oid"], str)
        or re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", value["source_commit_oid"]) is None
        or type(value["source_dirty"]) is not bool
        or not isinstance(value["build_tools"], dict)
        or set(value["build_tools"]) != {"go", "node", "npm", "python"}
        or not all(isinstance(item, str) and 0 < len(item) <= 160 for item in value["build_tools"].values())
        or not isinstance(value["bundle_digest"], str)
        or re.fullmatch(r"[0-9a-f]{64}", value["bundle_digest"]) is None
    ):
        raise RuntimeError("INVALID_BUNDLE_MANIFEST")
    if raw_manifest != _canonical(value) + b"\n":
        raise RuntimeError("NONCANONICAL_BUNDLE_MANIFEST")
    files = value["files"]
    if not isinstance(files, list) or not files:
        raise RuntimeError("INVALID_BUNDLE_MANIFEST")
    observed: set[str] = set()
    if files != sorted(files, key=lambda item: item.get("path", "") if isinstance(item, dict) else ""):
        raise RuntimeError("INVALID_BUNDLE_MANIFEST")
    for entry in files:
        if not isinstance(entry, dict) or set(entry) != FILE_KEYS:
            raise RuntimeError("INVALID_BUNDLE_MANIFEST")
        name = entry["path"]
        if not _safe_relative(name) or name in observed:
            raise RuntimeError("INVALID_BUNDLE_PATH")
        observed.add(name)
        mode = required.get(
            name,
            0o644
            if name.startswith("web/")
            or name in required_package
            or name in required_runners
            else None,
        )
        if (
            mode is None
            or type(entry["size_bytes"]) is not int
            or entry["size_bytes"] <= 0
            or not isinstance(entry["raw_sha256"], str)
            or re.fullmatch(r"[0-9a-f]{64}", entry["raw_sha256"]) is None
            or entry["mode"] != f"{mode:04o}"
        ):
            raise RuntimeError("INVALID_BUNDLE_MODE")
        limit = 192 * 1024 * 1024 if name == AGENT_RUNTIME["entrypoint"] else 64 * 1024 * 1024
        raw = read_file(name, limit, mode)
        if entry["size_bytes"] != len(raw) or entry["raw_sha256"] != hashlib.sha256(raw).hexdigest():
            raise RuntimeError("BUNDLE_FILE_MISMATCH")
        if name == AGENT_RUNTIME["entrypoint"] and entry["raw_sha256"] != AGENT_ENTRYPOINT_SHA256:
            raise RuntimeError("AGENT_ENTRYPOINT_MISMATCH")
    expected_files = observed | {MANIFEST}
    expected_dirs = {str(parent) for name in expected_files for parent in Path(name).parents if str(parent) != "."}
    if (
        actual != expected_files
        or directories != expected_dirs
        or not set(required).issubset(observed)
        or observed & (REQUIRED_PACKAGE | REQUIRED_PACKAGE_V1) != required_package
        or observed & REQUIRED_RUNNER_CLOSURE != required_runners
    ):
        raise RuntimeError("BUNDLE_FILE_SET_MISMATCH")
    closure = _gateway_module_closure(
        lambda name: read_file(f"gateway/{name}", 2 * 1024 * 1024, 0o644)
    )
    expected_gateway_modules = GATEWAY_MODULES if value["schema"] == SCHEMA else GATEWAY_MODULES_V1
    if {f"gateway/{name}" for name in closure} != set(expected_gateway_modules):
        raise RuntimeError("GATEWAY_MODULE_ALLOWLIST_MISMATCH")
    if read_file("gateway/package.json", 1024, 0o644) != b'{"type":"module"}\n':
        raise RuntimeError("INVALID_GATEWAY_PACKAGE")
    core = dict(value)
    digest = core.pop("bundle_digest")
    if digest != hashlib.sha256(_canonical(core)).hexdigest():
        raise RuntimeError("BUNDLE_DIGEST_MISMATCH")
    return value


def gateway_module_closure(gateway_root: Path, entrypoint: str = "server.mjs") -> set[str]:
    """Return the complete local ESM closure, rejecting non-bundled dependencies."""
    return _gateway_module_closure(
        lambda name: _read(gateway_root / name, 2 * 1024 * 1024, 0o644),
        entrypoint,
    )


def _gateway_module_closure(
    read_module: Callable[[str], bytes], entrypoint: str = "server.mjs",
) -> set[str]:
    pending = [entrypoint]
    observed: set[str] = set()
    while pending:
        name = pending.pop()
        if name in observed:
            continue
        if not _safe_relative(name) or not name.endswith(".mjs"):
            raise RuntimeError("INVALID_GATEWAY_MODULE_PATH")
        try:
            raw = read_module(name)
            source = raw.decode("utf-8")
        except (OSError, UnicodeDecodeError, RuntimeError) as error:
            raise RuntimeError("GATEWAY_MODULE_MISSING") from error
        observed.add(name)
        for specifier in _gateway_module_specifiers(source):
            if specifier.startswith("node:"):
                continue
            if specifier.startswith("../"):
                raise RuntimeError("INVALID_GATEWAY_MODULE_PATH")
            if not specifier.startswith("./"):
                raise RuntimeError("GATEWAY_EXTERNAL_DEPENDENCY")
            relative = Path(name).parent / specifier
            normalized = Path(os.path.normpath(relative))
            normalized_name = str(normalized)
            if not _safe_relative(normalized_name) or not normalized_name.endswith(".mjs"):
                raise RuntimeError("INVALID_GATEWAY_MODULE_PATH")
            pending.append(normalized_name)
    return observed


def _gateway_module_specifiers(source: str) -> list[str]:
    tokens = _gateway_javascript_tokens(source)
    specifiers: list[str] = []
    for index, token in enumerate(tokens):
        kind, value = token
        if kind != "identifier":
            continue
        if value == "import":
            previous = tokens[index - 1] if index else None
            following = tokens[index + 1] if index + 1 < len(tokens) else None
            if previous == ("punctuation", "."):
                continue
            if following == ("punctuation", "("):
                raise RuntimeError("GATEWAY_DYNAMIC_IMPORT_FORBIDDEN")
            if following == ("punctuation", "."):
                continue
            if following and following[0].startswith("string"):
                specifiers.append(_gateway_string_specifier(following))
                continue
            if following and (
                following[0] == "identifier"
                or following == ("punctuation", "{")
                or following == ("punctuation", "*")
            ):
                specifiers.append(_gateway_from_specifier(tokens, index + 1))
        elif value == "export":
            previous = tokens[index - 1] if index else None
            if previous == ("punctuation", "."):
                continue
            following = tokens[index + 1] if index + 1 < len(tokens) else None
            if following == ("punctuation", "*"):
                specifiers.append(_gateway_from_specifier(tokens, index + 1))
            elif following == ("punctuation", "{"):
                close = _gateway_matching_brace(tokens, index + 1)
                after = tokens[close + 1] if close + 1 < len(tokens) else None
                if after == ("identifier", "from"):
                    specifier = tokens[close + 2] if close + 2 < len(tokens) else None
                    specifiers.append(_gateway_string_specifier(specifier))
    return specifiers


def _gateway_from_specifier(tokens: list[tuple[str, str]], start: int) -> str:
    for index in range(start, len(tokens)):
        token = tokens[index]
        if token == ("punctuation", ";"):
            break
        if token == ("identifier", "from"):
            following = tokens[index + 1] if index + 1 < len(tokens) else None
            return _gateway_string_specifier(following)
    raise RuntimeError("GATEWAY_IMPORT_SYNTAX")


def _gateway_string_specifier(token: tuple[str, str] | None) -> str:
    if token is None or token[0] != "string" or not token[1]:
        raise RuntimeError("GATEWAY_IMPORT_SYNTAX")
    return token[1]


def _gateway_matching_brace(tokens: list[tuple[str, str]], opening: int) -> int:
    depth = 0
    for index in range(opening, len(tokens)):
        if tokens[index] == ("punctuation", "{"):
            depth += 1
        elif tokens[index] == ("punctuation", "}"):
            depth -= 1
            if depth == 0:
                return index
    raise RuntimeError("GATEWAY_IMPORT_SYNTAX")


def _gateway_javascript_tokens(source: str) -> list[tuple[str, str]]:
    """Lex the import-relevant JavaScript subset without executing it."""
    tokens: list[tuple[str, str]] = []
    length = len(source)

    def scan_code(index: int, template_expression: bool = False) -> int:
        brace_depth = 0
        while index < length:
            character = source[index]
            if character.isspace():
                index += 1
                continue
            if index == 0 and source.startswith("#!", index):
                index = scan_line_comment(index + 2)
                continue
            if source.startswith("//", index):
                index = scan_line_comment(index + 2)
                continue
            if source.startswith("/*", index):
                close = source.find("*/", index + 2)
                if close < 0:
                    raise RuntimeError("GATEWAY_JAVASCRIPT_LEX_ERROR")
                index = close + 2
                continue
            if character in ("'", '"'):
                index, token = scan_string(index, character)
                tokens.append(token)
                continue
            if character == "`":
                index = scan_template(index + 1)
                continue
            if character == "/" and not source.startswith(("//", "/*"), index) and regex_allowed():
                index = scan_regex(index + 1)
                continue
            if character.isalpha() or character in "_$":
                end = index + 1
                while end < length and (source[end].isalnum() or source[end] in "_$\u200c\u200d"):
                    end += 1
                tokens.append(("identifier", source[index:end]))
                index = end
                continue
            if template_expression and character == "}" and brace_depth == 0:
                return index + 1
            if character == "{":
                brace_depth += 1
            elif character == "}" and brace_depth:
                brace_depth -= 1
            tokens.append(("punctuation", character))
            index += 1
        if template_expression:
            raise RuntimeError("GATEWAY_JAVASCRIPT_LEX_ERROR")
        return index

    def scan_string(index: int, quote: str) -> tuple[int, tuple[str, str]]:
        index += 1
        start = index
        escaped = False
        while index < length:
            character = source[index]
            if character == quote:
                return index + 1, ("escaped-string" if escaped else "string", source[start:index])
            if character in "\r\n\u2028\u2029":
                raise RuntimeError("GATEWAY_JAVASCRIPT_LEX_ERROR")
            if character == "\\":
                escaped = True
                index += 2
            else:
                index += 1
        raise RuntimeError("GATEWAY_JAVASCRIPT_LEX_ERROR")

    def scan_template(index: int) -> int:
        while index < length:
            if source[index] == "\\":
                index += 2
            elif source[index] == "`":
                return index + 1
            elif source.startswith("${", index):
                index = scan_code(index + 2, template_expression=True)
            else:
                index += 1
        raise RuntimeError("GATEWAY_JAVASCRIPT_LEX_ERROR")

    def scan_line_comment(index: int) -> int:
        while index < length and source[index] not in "\r\n\u2028\u2029":
            index += 1
        if index < length and source[index] == "\r" and index + 1 < length and source[index + 1] == "\n":
            return index + 2
        return min(index + 1, length)

    def regex_allowed() -> bool:
        if not tokens:
            return True
        kind, value = tokens[-1]
        return (
            kind == "punctuation" and value in "([{,:;=!?&|+-*%^~<>"
        ) or (
            kind == "identifier" and value in {
                "await", "case", "delete", "in", "instanceof", "new",
                "of", "return", "throw", "typeof", "void", "yield",
            }
        )

    def scan_regex(index: int) -> int:
        in_class = False
        while index < length:
            character = source[index]
            if character in "\r\n\u2028\u2029":
                raise RuntimeError("GATEWAY_JAVASCRIPT_LEX_ERROR")
            if character == "\\":
                index += 2
                continue
            if character == "[":
                in_class = True
            elif character == "]":
                in_class = False
            elif character == "/" and not in_class:
                index += 1
                while index < length and source[index].isascii() and source[index].isalpha():
                    index += 1
                return index
            index += 1
        raise RuntimeError("GATEWAY_JAVASCRIPT_LEX_ERROR")

    scan_code(0)
    return tokens


def install_snapshot(source: Path, home: Path) -> Path:
    manifest = verify_bundle(source)
    digest = manifest["bundle_digest"]
    parent = home / "bundles"
    parent.mkdir(parents=True, exist_ok=True)
    parent_info = parent.lstat()
    if not stat.S_ISDIR(parent_info.st_mode) or stat.S_ISLNK(parent_info.st_mode) or parent_info.st_uid != os.getuid():
        raise RuntimeError("UNSAFE_BUNDLE_STAGING")
    os.chmod(parent, 0o700)
    target = parent / digest
    if os.path.lexists(target):
        installed = verify_bundle(target)
        if installed["bundle_digest"] != digest:
            raise RuntimeError("BUNDLE_SNAPSHOT_MISMATCH")
        return target.resolve(strict=True)
    temporary = parent / f".bundle-{uuid.uuid4().hex}.tmp"
    temporary.mkdir(mode=0o700)
    try:
        for entry in manifest["files"]:
            relative = Path(entry["path"])
            destination = temporary / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            _copy_exact(source / relative, destination, int(entry["mode"], 8))
        _copy_exact(source / MANIFEST, temporary / MANIFEST, 0o644)
        for directory in temporary.rglob("*"):
            if directory.is_dir():
                os.chmod(directory, 0o755)
        os.chmod(temporary, 0o755)
        installed = verify_bundle(temporary)
        if installed["bundle_digest"] != digest:
            raise RuntimeError("BUNDLE_SNAPSHOT_MISMATCH")
        _rename_exclusive(temporary, target)
        installed = verify_bundle(target)
        if installed["bundle_digest"] != digest:
            raise RuntimeError("BUNDLE_SNAPSHOT_MISMATCH")
        return target.resolve(strict=True)
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise


def _read(path: Path, limit: int, expected_mode: int) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != expected_mode:
            raise RuntimeError("UNSAFE_BUNDLE_FILE")
        chunks = []
        remaining = limit + 1
        while remaining:
            chunk = os.read(fd, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > limit:
            raise RuntimeError("BUNDLE_FILE_TOO_LARGE")
        return raw
    finally:
        os.close(fd)


def _safe_relative(value: Any) -> bool:
    if not isinstance(value, str) or not value or chr(92) in value:
        return False
    path = Path(value)
    return not path.is_absolute() and all(part not in ("", ".", "..") for part in path.parts)


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _walk(root: Path) -> tuple[set[str], set[str]]:
    files, directories = set(), set()
    def visit(directory: Path) -> None:
        with os.scandir(directory) as entries:
            for entry in entries:
                relative = str(Path(entry.path).relative_to(root))
                info = entry.stat(follow_symlinks=False)
                if stat.S_ISLNK(info.st_mode):
                    raise RuntimeError("BUNDLE_SYMLINK_FORBIDDEN")
                if stat.S_ISDIR(info.st_mode):
                    if stat.S_IMODE(info.st_mode) != 0o755:
                        raise RuntimeError("INVALID_BUNDLE_MODE")
                    directories.add(relative)
                    visit(Path(entry.path))
                elif stat.S_ISREG(info.st_mode):
                    files.add(relative)
                else:
                    raise RuntimeError("BUNDLE_NONREGULAR_FORBIDDEN")
    visit(root)
    return files, directories


def _copy_exact(source: Path, destination: Path, mode: int) -> None:
    limit = 192 * 1024 * 1024 if destination.name == "opencode" else 64 * 1024 * 1024
    raw = _read(source, limit, mode)
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, mode)
    try:
        view = memoryview(raw)
        while view:
            written = os.write(fd, view)
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)


def _rename_exclusive(source: Path, target: Path) -> None:
    import ctypes
    import sys
    if sys.platform != "darwin":
        raise RuntimeError("UNSUPPORTED_BUNDLE_PLATFORM")
    libc = ctypes.CDLL(None, use_errno=True)
    renamex_np = libc.renamex_np
    renamex_np.argtypes = (ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint)
    renamex_np.restype = ctypes.c_int
    if renamex_np(os.fsencode(source), os.fsencode(target), 0x00000004) != 0:
        error = ctypes.get_errno()
        if error == 17:
            raise RuntimeError("BUNDLE_OUTPUT_EXISTS")
        raise OSError(error, os.strerror(error))
