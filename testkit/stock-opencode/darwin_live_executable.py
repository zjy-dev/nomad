"""Credential-free Darwin live executable vnode verifier for C1a2a."""
from __future__ import annotations

import ctypes
import ctypes.util
import errno
import fcntl
import hashlib
import json
import os
import platform
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Protocol

ABI_PATH = Path(__file__).with_name("darwin-libproc-abi.json")
ABI_RAW_SHA256 = "5c31426f123ed78c1d6ed52929d9c728890500bc3a68b25fa211f0d867f838eb"
MAX_REGIONS = 4096
BLOCKED = "BLOCKED_DARWIN_LIVE_EXECUTABLE_UNVERIFIED"


class VerificationError(Exception):
    def __init__(self) -> None:
        super().__init__(BLOCKED)


class Process(Protocol):
    pid: int
    def poll(self) -> int | None: ...


@dataclass(frozen=True)
class _ProcessIdentity:
    pid: int
    ppid: int
    start_sec: int
    start_usec: int


@dataclass(frozen=True)
class _VnodeIdentity:
    device: int
    inode: int
    size: int
    mtime: int
    mtime_nsec: int
    ctime: int
    ctime_nsec: int
    generation: int
    mode: int


class _VerifiedLiveExecutable:
    """Private, non-serializable measurement retained only in supervisor memory."""
    __slots__ = ("__process", "__vnode", "__realpath", "__raw_digest")
    def __init__(self, *_: object) -> None:
        raise TypeError("private verified measurement")
    def __repr__(self) -> str:
        return "VerifiedLiveExecutable(<redacted>)"
    def __reduce__(self) -> object:
        raise TypeError("private verified measurement")


_SINK_TOKEN = object()


class _LockedLaunchMeasurementSink:
    __slots__ = ("__target", "__unused")

    def __init__(self, *_: object) -> None:
        raise TypeError("private locked launch sink")

    def __repr__(self) -> str:
        return "LockedLaunchMeasurementSink(<redacted>)"

    def __reduce__(self) -> object:
        raise TypeError("private locked launch sink")


def _new_locked_launch_measurement_sink(token: object, target: object) -> _LockedLaunchMeasurementSink:
    """Bind the verifier to the exact opaque Package-A target, never a callback."""
    target_type = type(target)
    module = sys.modules.get(target_type.__module__)
    module_path = Path(getattr(module, "__file__", "")).resolve() if module else None
    if (token is not _SINK_TOKEN
            or target_type.__name__ != "_LockedOpenCodeLaunchMeasurement"
            or module_path != Path(__file__).with_name("real_task_capture.py").resolve()
            or getattr(target, "_sealed", None) is not False):
        raise VerificationError
    sink = object.__new__(_LockedLaunchMeasurementSink)
    object.__setattr__(sink, "_LockedLaunchMeasurementSink__target", target)
    object.__setattr__(sink, "_LockedLaunchMeasurementSink__unused", True)
    return sink


def _bridge_verified_live_executable(
    measurement: _VerifiedLiveExecutable, sink: _LockedLaunchMeasurementSink, /,
    **context: object
) -> object:
    """Pass verified facts directly to a private supervisor constructor.

    This deliberately exposes no facts as a mapping or public return value.  The
    exact verifier result type is required so lookalikes and subclasses cannot be
    used to mint a locked-launch measurement.
    """
    if (type(measurement) is not _VerifiedLiveExecutable
            or type(sink) is not _LockedLaunchMeasurementSink
            or not object.__getattribute__(
                sink, "_LockedLaunchMeasurementSink__unused"
            )):
        raise VerificationError
    object.__setattr__(sink, "_LockedLaunchMeasurementSink__unused", False)
    if context:
        raise VerificationError
    target = object.__getattribute__(sink, "_LockedLaunchMeasurementSink__target")
    object.__setattr__(sink, "_LockedLaunchMeasurementSink__target", None)
    object.__setattr__(target, "_process_pid", object.__getattribute__(
        measurement, "_VerifiedLiveExecutable__process"
    ).pid)
    object.__setattr__(target, "_entrypoint_realpath", object.__getattribute__(
        measurement, "_VerifiedLiveExecutable__realpath"
    ))
    object.__setattr__(target, "_entrypoint_raw_digest", object.__getattribute__(
        measurement, "_VerifiedLiveExecutable__raw_digest"
    ))
    object.__setattr__(target, "_sealed", True)
    return target


class _ProcBsdInfo(ctypes.Structure):
    _fields_ = [
        ("flags", ctypes.c_uint32), ("status", ctypes.c_uint32),
        ("xstatus", ctypes.c_uint32), ("pid", ctypes.c_uint32),
        ("ppid", ctypes.c_uint32), ("uid", ctypes.c_uint32),
        ("gid", ctypes.c_uint32), ("ruid", ctypes.c_uint32),
        ("rgid", ctypes.c_uint32), ("svuid", ctypes.c_uint32),
        ("svgid", ctypes.c_uint32), ("reserved", ctypes.c_uint32),
        ("comm", ctypes.c_char * 16), ("name", ctypes.c_char * 32),
        ("nfiles", ctypes.c_uint32), ("pgid", ctypes.c_uint32),
        ("pjobc", ctypes.c_uint32), ("tdev", ctypes.c_uint32),
        ("tpgid", ctypes.c_uint32), ("nice", ctypes.c_int32),
        ("start_sec", ctypes.c_uint64), ("start_usec", ctypes.c_uint64),
    ]


class _RegionInfo(ctypes.Structure):
    _fields_ = [
        ("protection", ctypes.c_uint32), ("max_protection", ctypes.c_uint32),
        ("inheritance", ctypes.c_uint32), ("flags", ctypes.c_uint32),
        ("file_offset", ctypes.c_uint64), ("behavior", ctypes.c_uint32),
        ("user_wired", ctypes.c_uint32), ("user_tag", ctypes.c_uint32),
        ("pages_resident", ctypes.c_uint32), ("pages_shared", ctypes.c_uint32),
        ("pages_swapped", ctypes.c_uint32), ("pages_dirtied", ctypes.c_uint32),
        ("ref_count", ctypes.c_uint32), ("shadow_depth", ctypes.c_uint32),
        ("share_mode", ctypes.c_uint32), ("private_pages", ctypes.c_uint32),
        ("shared_pages", ctypes.c_uint32), ("object_id", ctypes.c_uint32),
        ("depth", ctypes.c_uint32), ("address", ctypes.c_uint64),
        ("size", ctypes.c_uint64),
    ]


class _VinfoStat(ctypes.Structure):
    _fields_ = [
        ("device", ctypes.c_uint32), ("mode", ctypes.c_uint16),
        ("nlink", ctypes.c_uint16), ("inode", ctypes.c_uint64),
        ("uid", ctypes.c_uint32), ("gid", ctypes.c_uint32),
        ("atime", ctypes.c_int64), ("atime_nsec", ctypes.c_int64),
        ("mtime", ctypes.c_int64), ("mtime_nsec", ctypes.c_int64),
        ("ctime", ctypes.c_int64), ("ctime_nsec", ctypes.c_int64),
        ("birthtime", ctypes.c_int64), ("birthtime_nsec", ctypes.c_int64),
        ("size", ctypes.c_int64), ("blocks", ctypes.c_int64),
        ("block_size", ctypes.c_int32), ("flags", ctypes.c_uint32),
        ("generation", ctypes.c_uint32), ("rdev", ctypes.c_uint32),
        ("spare", ctypes.c_int64 * 2),
    ]


class _Fsid(ctypes.Structure):
    _fields_ = [("value", ctypes.c_int32 * 2)]


class _VnodeInfo(ctypes.Structure):
    _fields_ = [("stat", _VinfoStat), ("type", ctypes.c_int),
                ("padding", ctypes.c_int), ("fsid", _Fsid)]


class _VnodePath(ctypes.Structure):
    _fields_ = [("vnode", _VnodeInfo), ("path", ctypes.c_char * 1024)]


class _RegionWithPath(ctypes.Structure):
    _fields_ = [("region", _RegionInfo), ("vnode_path", _VnodePath)]


def _exact_keys(value: object, keys: set[str]) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys:
        raise VerificationError
    return value


def _load_abi(path: Path = ABI_PATH) -> dict[str, object]:
    try:
        raw = path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != ABI_RAW_SHA256:
            raise VerificationError
        value = json.loads(raw)
        value = _exact_keys(value, {"arch", "constants", "generated_by", "platform", "schema_version", "structs"})
        if (value["schema_version"] != "nomad.darwin-libproc-abi.v1"
                or value["platform"] != "darwin" or value["arch"] != "arm64"
                or value["generated_by"] != "darwin_libproc_abi_probe.c"):
            raise VerificationError
        constants = _exact_keys(value["constants"], {"max_path_len", "proc_flag_inexit", "proc_pid_region_path_info", "proc_pid_tbsd_info", "sidl", "sleep", "srun", "sstop", "szomb", "vm_prot_execute"})
        expected_constants = {"max_path_len":1024,"proc_flag_inexit":4,"proc_pid_region_path_info":8,"proc_pid_tbsd_info":3,"sidl":1,"sleep":3,"srun":2,"sstop":4,"szomb":5,"vm_prot_execute":4}
        if constants != expected_constants:
            raise VerificationError
        structs = _exact_keys(value["structs"], {"proc_bsdinfo","proc_regioninfo","proc_regionwithpathinfo","vinfo_stat"})
        expected = {
            "proc_bsdinfo": (136, {"flags":0,"status":4,"pid":12,"ppid":16,"start_sec":120,"start_usec":128}),
            "proc_regioninfo": (96, {"protection":0,"file_offset":16,"address":80,"size":88}),
            "proc_regionwithpathinfo": (1272, {"region":0,"vnode":96,"vnode_stat":96,"path":248}),
            "vinfo_stat": (136, {"device":0,"mode":4,"inode":8,"mtime":40,"mtime_nsec":48,"ctime":56,"ctime_nsec":64,"size":88,"generation":112}),
        }
        for name, (size, offsets) in expected.items():
            item = _exact_keys(structs[name], {"size", "offsets"})
            if item["size"] != size or item["offsets"] != offsets:
                raise VerificationError
        runtime = {
            "proc_bsdinfo": (_ProcBsdInfo, {field:getattr(_ProcBsdInfo, field).offset for field in ("flags","status","pid","ppid","start_sec","start_usec")}),
            "proc_regioninfo": (_RegionInfo, {field:getattr(_RegionInfo, field).offset for field in ("protection","file_offset","address","size")}),
            "proc_regionwithpathinfo": (_RegionWithPath, {"region":_RegionWithPath.region.offset,"vnode":_RegionWithPath.vnode_path.offset,"vnode_stat":_RegionWithPath.vnode_path.offset + _VnodePath.vnode.offset + _VnodeInfo.stat.offset,"path":_RegionWithPath.vnode_path.offset + _VnodePath.path.offset}),
            "vinfo_stat": (_VinfoStat, {field:getattr(_VinfoStat, field).offset for field in ("device","mode","inode","mtime","mtime_nsec","ctime","ctime_nsec","size","generation")}),
        }
        for name, (structure, actual_offsets) in runtime.items():
            if ctypes.sizeof(structure) != expected[name][0] or actual_offsets != expected[name][1]:
                raise VerificationError
        return value
    except VerificationError:
        raise
    except Exception:
        raise VerificationError from None


class _LibProc:
    def __init__(self) -> None:
        library = ctypes.util.find_library("proc")
        if not library:
            raise VerificationError
        self.library = ctypes.CDLL(library, use_errno=True)
        try:
            function = self.library.proc_pidinfo
        except AttributeError:
            raise VerificationError from None
        function.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_int]
        function.restype = ctypes.c_int
        self.pidinfo = function


def _process_identity(proc: Process, supervisor_pid: int, api: _LibProc) -> _ProcessIdentity:
    if proc.poll() is not None or not isinstance(proc.pid, int) or proc.pid <= 0:
        raise VerificationError
    value = _ProcBsdInfo()
    ctypes.set_errno(0)
    result = api.pidinfo(proc.pid, 3, 0, ctypes.byref(value), ctypes.sizeof(value))
    if result != ctypes.sizeof(value) or ctypes.get_errno() != 0:
        raise VerificationError
    if (value.pid != proc.pid or value.ppid != supervisor_pid
            or value.status not in (2, 3) or value.flags & 4
            or value.start_sec == 0):
        raise VerificationError
    return _ProcessIdentity(value.pid, value.ppid, value.start_sec, value.start_usec)


def _vnode(value: _VinfoStat) -> _VnodeIdentity:
    return _VnodeIdentity(value.device, value.inode, value.size, value.mtime, value.mtime_nsec, value.ctime, value.ctime_nsec, value.generation, value.mode)


def _regions(proc: Process, target: _VnodeIdentity, api: _LibProc) -> tuple[tuple[int, ...], ...]:
    address = 0
    matches: list[tuple[int, ...]] = []
    for _ in range(MAX_REGIONS):
        value = _RegionWithPath()
        ctypes.set_errno(0)
        result = api.pidinfo(proc.pid, 8, address, ctypes.byref(value), ctypes.sizeof(value))
        error = ctypes.get_errno()
        # libproc uses a zero result as the only enumeration terminator and may
        # leave errno as EINVAL for the first address beyond the final region.
        # errno is authoritative only for nonzero/short returns here.
        if result == 0 and error in (0, errno.EINVAL):
            return tuple(sorted(matches))
        if result == 0:
            raise VerificationError
        if result != ctypes.sizeof(value) or error != 0 or value.region.size == 0:
            raise VerificationError
        next_address = value.region.address + value.region.size
        if next_address <= address or next_address > (1 << 64) - 1:
            raise VerificationError
        identity = _vnode(value.vnode_path.vnode.stat)
        if (identity.device, identity.inode) == (target.device, target.inode):
            matches.append((value.region.address, value.region.size, value.region.protection, value.region.file_offset, identity.device, identity.inode, identity.size, identity.mtime, identity.mtime_nsec, identity.ctime, identity.ctime_nsec, identity.generation, identity.mode))
        address = next_address
    raise VerificationError


def _digest(file: BinaryIO) -> str:
    file.seek(0)
    digest = hashlib.sha256()
    while True:
        block = file.read(64 * 1024)
        if not block:
            break
        digest.update(block)
    file.seek(0)
    return digest.hexdigest()


def verify_live_executable(proc: subprocess.Popen[bytes], executable: BinaryIO, containment_root: Path, supervisor_pid: int) -> _VerifiedLiveExecutable:
    """Verify one live Darwin process against an owned pre-open executable FD."""
    return _verify_live_executable(proc, executable, containment_root, supervisor_pid, ABI_PATH, _LibProc())


def _verify_live_executable(proc: Process, executable: BinaryIO, containment_root: Path, supervisor_pid: int, abi_path: Path, api: _LibProc) -> _VerifiedLiveExecutable:
    try:
        if (sys.platform != "darwin" or platform.machine() != "arm64"
                or supervisor_pid != os.getpid()
                or not isinstance(proc, subprocess.Popen)):
            raise VerificationError
        _load_abi(abi_path)
        fd = executable.fileno()
        if fd < 0 or fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE != os.O_RDONLY:
            raise VerificationError
        if not fcntl.fcntl(fd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC:
            raise VerificationError
        before_stat = os.fstat(fd)
        if not stat.S_ISREG(before_stat.st_mode) or not before_stat.st_mode & 0o111:
            raise VerificationError
        path_buffer = fcntl.fcntl(fd, fcntl.F_GETPATH, bytes(1024))
        fd_path = Path(path_buffer.split(b"\0", 1)[0].decode("utf-8", "strict")).resolve(strict=True)
        root = containment_root.resolve(strict=True)
        if fd_path == root or not fd_path.is_relative_to(root):
            raise VerificationError
        before_digest = _digest(executable)
        target = _VnodeIdentity(before_stat.st_dev, before_stat.st_ino, before_stat.st_size, before_stat.st_mtime_ns // 1_000_000_000, before_stat.st_mtime_ns % 1_000_000_000, before_stat.st_ctime_ns // 1_000_000_000, before_stat.st_ctime_ns % 1_000_000_000, getattr(before_stat, "st_gen", 0), before_stat.st_mode)
        first_process = _process_identity(proc, supervisor_pid, api)
        first = _regions(proc, target, api)
        middle_process = _process_identity(proc, supervisor_pid, api)
        second = _regions(proc, target, api)
        final_process = _process_identity(proc, supervisor_pid, api)
        if first_process != middle_process or first_process != final_process or not first or first != second:
            raise VerificationError
        vnode_fields = {row[4:] for row in first}
        if len(vnode_fields) != 1 or next(iter(vnode_fields)) != (target.device,target.inode,target.size,target.mtime,target.mtime_nsec,target.ctime,target.ctime_nsec,target.generation,target.mode) or not any(row[2] & 4 for row in first):
            raise VerificationError
        after_stat = os.fstat(fd)
        path_stat = os.stat(fd_path, follow_symlinks=False)
        after_target = _VnodeIdentity(after_stat.st_dev, after_stat.st_ino, after_stat.st_size, after_stat.st_mtime_ns // 1_000_000_000, after_stat.st_mtime_ns % 1_000_000_000, after_stat.st_ctime_ns // 1_000_000_000, after_stat.st_ctime_ns % 1_000_000_000, getattr(after_stat, "st_gen", 0), after_stat.st_mode)
        path_target = _VnodeIdentity(path_stat.st_dev, path_stat.st_ino, path_stat.st_size, path_stat.st_mtime_ns // 1_000_000_000, path_stat.st_mtime_ns % 1_000_000_000, path_stat.st_ctime_ns // 1_000_000_000, path_stat.st_ctime_ns % 1_000_000_000, getattr(path_stat, "st_gen", 0), path_stat.st_mode)
        if target != after_target or target != path_target or before_digest != _digest(executable):
            raise VerificationError
        measurement = object.__new__(_VerifiedLiveExecutable)
        object.__setattr__(measurement, "_VerifiedLiveExecutable__process", first_process)
        object.__setattr__(measurement, "_VerifiedLiveExecutable__vnode", target)
        object.__setattr__(measurement, "_VerifiedLiveExecutable__realpath", str(fd_path))
        object.__setattr__(measurement, "_VerifiedLiveExecutable__raw_digest", before_digest)
        return measurement
    except VerificationError:
        raise
    except Exception:
        raise VerificationError from None
    finally:
        try:
            executable.close()
        except Exception:
            pass
