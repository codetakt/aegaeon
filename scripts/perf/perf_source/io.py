"""Immutable IO, JSON and shared source record primitives."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import stat
import tempfile
from typing import Any, Never

MODES = {
    "100644": stat.S_IFREG | 0o644,
    "100755": stat.S_IFREG | 0o755,
    "120000": stat.S_IFLNK | 0o777,
}
MANDATORY = {
    "Cargo.toml",
    "Cargo.lock",
    "flake.nix",
    "flake.lock",
    "rust-toolchain.toml",
    "scripts/perf/run_load_tests.sh",
    "scripts/perf/source_manifest.py",
    "scripts/perf/loadtest_supplier.py",
}
SHA256_LENGTH = 64
MAX_RUN_SECONDS = 86400
NANOS_PER_SECOND = 1000000000
UUID_VERSION = 4
LEGACY = {"artifacts/load-test-report.json", "artifacts/policy-mixed-report.json"}
MODULE_FILES = (
    "scripts/perf/perf_source/__init__.py",
    "scripts/perf/perf_source/io.py",
    "scripts/perf/perf_source/dependencies.py",
    "scripts/perf/perf_source/git_source.py",
    "scripts/perf/perf_source/boundaries.py",
    "scripts/perf/perf_source/invocation.py",
    "scripts/perf/perf_source/status.py",
)
MANDATORY.update(MODULE_FILES)


class SourceError(RuntimeError):
    """A source or evidence boundary was not established."""


def fail(message: str) -> Never:
    raise SourceError(message)


def stamp(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
    ).encode("utf-8")


def ancestors(path: pathlib.Path) -> None:
    for parent in reversed(path.parents):
        if (parent.exists() or parent.is_symlink()) and (not stat.S_ISDIR(parent.lstat().st_mode)):
            fail("path ancestor is not a regular directory")


def publish(path: pathlib.Path, raw: bytes) -> None:
    ancestors(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".source-publish-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        pathlib.Path(temporary).chmod(0o444)
        os.link(temporary, path, follow_symlinks=False)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        pathlib.Path(temporary).unlink()


def load_json(path: pathlib.Path) -> tuple[bytes, Any]:
    ancestors(path)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 146:
        fail("frozen evidence is not an owned read-only regular file")
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), "rb") as stream:
        raw = stream.read()
    return (raw, strict_json(raw))


def strict_json(raw: bytes | str) -> object:

    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                fail("duplicate JSON field")
            result[key] = value
        return result

    return json.loads(
        raw, object_pairs_hook=unique, parse_constant=lambda _: fail("nonfinite JSON number")
    )


def executable(path: pathlib.Path) -> str:
    ancestors(path)
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or not before.st_mode & 73:
        fail("build executable is not regular and executable")
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), "rb") as stream:
        raw = stream.read()
    if stamp(path.lstat()) != stamp(before):
        fail("build executable changed while reading")
    return digest(raw)


def required(value: str | None) -> str:
    if not value:
        fail("required producer observation is missing")
    return value
