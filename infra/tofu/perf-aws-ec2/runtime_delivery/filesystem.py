"""Fixed guest delivery filesystem responsibility."""

from __future__ import annotations

import os
import stat
import tempfile
from pathlib import Path

from runtime_delivery.common import fail

OWNER_UID = 0

OWNED_ROOT = Path("/")

AWS_REQUIRED_PATH = Path("/usr/bin/aws")

MAX_SYMLINKS = 40


def protected_path(path: Path, *, regular: bool = False) -> Path:
    if (
        not path.is_absolute()
        or not path.is_relative_to(OWNED_ROOT)
        or str(path) != os.path.normpath(str(path))
    ):
        fail("absolute protected path required")
    current = OWNED_ROOT
    for part in (None, *path.relative_to(OWNED_ROOT).parts):
        if part is not None:
            current = current / part
        metadata = current.lstat()
        final_file = regular and current == path
        correct_kind = (
            stat.S_ISREG(metadata.st_mode) if final_file else stat.S_ISDIR(metadata.st_mode)
        )
        if not correct_kind or metadata.st_uid != OWNER_UID or metadata.st_mode & 18:
            fail("unsafe protected path")
    return path


def prepare_directory(directory: Path) -> None:
    if directory.is_symlink():
        fail("unsafe runtime directory")
    if not directory.exists():
        protected_path(directory.parent)
        directory.mkdir(mode=448)
    protected_path(directory)
    if directory.lstat().st_mode & 63:
        fail("unsafe runtime directory")


def atomic_write(path: Path, data: bytes) -> None:
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=".delivery-")
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        Path(temporary).replace(path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def prepare_driver() -> None:
    directory = Path("/run/aegaeon-supplies")
    prepare_directory(directory)
    prepare_directory(Path("/opt/aegaeon/results"))
    lock = directory / "driver.lock"
    fd = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        metadata = os.fstat(fd)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != OWNER_UID
            or metadata.st_mode & 63
        ):
            fail("unsafe driver lock")
    finally:
        os.close(fd)


def aws_executable() -> Path:
    """Resolve only the fixed guest route through protected root-owned paths."""
    candidate = AWS_REQUIRED_PATH
    protected_path(OWNED_ROOT)
    if not candidate.is_relative_to(OWNED_ROOT):
        fail("unsafe AWS executable route")
    remaining = list(candidate.relative_to(OWNED_ROOT).parts)
    current = OWNED_ROOT
    links = 0
    while remaining:
        part = remaining.pop(0)
        if part == "..":
            current = current.parent if current != OWNED_ROOT else OWNED_ROOT
            continue
        current = current / part
        metadata = current.lstat()
        if aws_route_kind(metadata, remaining=bool(remaining)):
            links += 1
            if links > MAX_SYMLINKS:
                fail("unsafe AWS executable route")
            current, target_parts = aws_route_link(current)
            remaining = target_parts + remaining
    metadata = current.lstat()
    if aws_route_kind(metadata, remaining=False) or not metadata.st_mode & stat.S_IXUSR:
        fail("unsafe AWS executable route")
    # Path.readlink discards trailing '/' and '/.'; the original kernel route
    # must also name this exact regular file, rather than fail with ENOTDIR.
    route_metadata = AWS_REQUIRED_PATH.stat()
    if (route_metadata.st_dev, route_metadata.st_ino) != (metadata.st_dev, metadata.st_ino):
        fail("unsafe AWS executable route")
    protected_path(OWNED_ROOT)
    return current


def aws_route_link(current: Path) -> tuple[Path, list[str]]:
    target = current.readlink()
    if target.is_absolute():
        if not target.is_relative_to(OWNED_ROOT):
            fail("unsafe AWS executable route")
        return OWNED_ROOT, list(target.relative_to(OWNED_ROOT).parts)
    # Do not normalize '..' before visiting preceding symlink/directory components.
    return current.parent, list(target.parts)


def aws_route_kind(metadata: os.stat_result, *, remaining: bool) -> bool:
    if metadata.st_uid != OWNER_UID:
        fail("unsafe AWS executable route")
    if stat.S_ISLNK(metadata.st_mode):
        return True
    if metadata.st_mode & 18 or not (
        stat.S_ISDIR(metadata.st_mode) if remaining else stat.S_ISREG(metadata.st_mode)
    ):
        fail("unsafe AWS executable route")
    return False
