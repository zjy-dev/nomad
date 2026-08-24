"""Side-effect-free filesystem primitives for immutable artifact candidates."""
from __future__ import annotations
import errno, os, stat
from pathlib import Path

def write_exclusive(path: Path, raw: bytes, *, mode: int, limit: int) -> None:
    if not raw or len(raw) > limit: raise OSError(errno.EFBIG, "bounded")
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_CLOEXEC",0)|getattr(os,"O_NOFOLLOW",0),mode);failure=None
    try:
        os.fchmod(fd,mode);total=0
        while total<len(raw):
            wrote=os.write(fd,raw[total:])
            if wrote<=0: raise OSError(errno.EIO,"write")
            total+=wrote
        os.fsync(fd)
    except BaseException as error: failure=error
    try: os.close(fd)
    except OSError as error:
        if failure is None: failure=error
    if failure is not None: raise failure

def fsync_dir(path: Path) -> None:
    fd=os.open(path,os.O_RDONLY|getattr(os,"O_DIRECTORY",0)|getattr(os,"O_CLOEXEC",0)|getattr(os,"O_NOFOLLOW",0))
    try: os.fsync(fd)
    finally: os.close(fd)

def mkdir_exact(path: Path, mode: int) -> None:
    os.mkdir(path,mode);os.chmod(path,mode);info=os.lstat(path)
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or stat.S_IMODE(info.st_mode)!=mode: raise OSError(errno.EPERM,"directory policy")
