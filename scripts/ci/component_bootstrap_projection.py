"""Authenticate original source bytes and retain their exclusive projection.

This module never imports or executes candidate source. Retained FDs and source
rechecks do not establish process isolation, an admitted import closure, readonly
mounts, native execution admission, or production runtime/CA/credential access.
Those independent gates remain required before any candidate execution.
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from types import MappingProxyType
from typing import TYPE_CHECKING

from component_bootstrap_origin import (
    path_parts,
    require,
    verify_original_sources,
)

if TYPE_CHECKING:
    from pathlib import Path

    from component_bootstrap_origin import BootstrapPremises, OriginalRead, VerifiedSources

DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
READ_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
WRITE_FLAGS = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
PROJECTION_NAME = "bootstrap-package"
Identity = tuple[int, ...]


def _identity(info: os.stat_result) -> Identity:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_uid,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _anchor_identity(info: os.stat_result) -> Identity:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid)


@dataclass(frozen=True)
class _Entry:
    descriptor: int
    identity: Identity


class RetainedProjection:
    """FD-retained exact projection; no existing destination is repaired."""

    def __init__(self, original: VerifiedSources, parent: Path) -> None:
        self.original = original
        self.root = parent / PROJECTION_NAME
        self._anchors: list[tuple[int, str, int, Identity]] = []
        self._owned: list[int] = []
        self._directories: dict[str, _Entry] = {}
        self._files: dict[str, _Entry] = {}
        self._closed = False
        contents = {"source/" + name: raw for name, raw in original.sources.items()}
        contents["authority/pr-policy.json"] = original.policy
        contents["authority/component-release.json"] = original.descriptor
        self._contents = MappingProxyType(contents)
        try:
            self._create(parent)
            self.recheck()
        except BaseException:
            self.close()
            raise

    def _open(self, name: str, flags: int, parent: int | None = None) -> int:
        descriptor = os.open(name, flags, dir_fd=parent)
        self._owned.append(descriptor)
        return descriptor

    def _create(self, parent: Path) -> None:  # noqa: PLR0915 - ordered exclusive writes/fsync
        self.original.premises.verify()
        require(
            parent.is_absolute() and ".." not in parent.parts, "absolute original parent required"
        )
        root_anchor = self._open("/", DIRECTORY_FLAGS)
        current = root_anchor
        for part in parent.parts[1:]:
            following = self._open(part, DIRECTORY_FLAGS, current)
            self._anchors.append((current, part, following, _anchor_identity(os.fstat(following))))
            current = following
        os.mkdir(PROJECTION_NAME, mode=0o700, dir_fd=current)
        root = self._open(PROJECTION_NAME, DIRECTORY_FLAGS, current)
        self._anchors.append((current, PROJECTION_NAME, root, _anchor_identity(os.fstat(root))))
        directories: dict[str, int] = {"": root}
        for name in sorted(self._contents):
            parts = path_parts(name)
            for depth in range(1, len(parts)):
                path = "/".join(parts[:depth])
                if path not in directories:
                    parent_fd = directories["/".join(parts[: depth - 1])]
                    os.mkdir(parts[depth - 1], mode=0o700, dir_fd=parent_fd)
                    directories[path] = self._open(parts[depth - 1], DIRECTORY_FLAGS, parent_fd)
            directory = directories["/".join(parts[:-1])]
            descriptor = os.open(parts[-1], WRITE_FLAGS, 0o600, dir_fd=directory)
            self._owned.append(descriptor)
            raw = self._contents[name]
            remaining = memoryview(raw)
            while remaining:
                written = os.write(descriptor, remaining)
                require(written > 0, "exclusive source write stalled")
                remaining = remaining[written:]
            original_name = name.removeprefix("source/")
            mode = 0o555 if self.original.modes.get(original_name) == "100755" else 0o444
            os.fchmod(descriptor, mode)
            os.fsync(descriptor)
            original_identity = _identity(os.fstat(descriptor))
            readonly = self._open(parts[-1], READ_FLAGS, directory)
            require(
                original_identity
                == _identity(os.fstat(readonly))
                == _identity(os.stat(parts[-1], dir_fd=directory, follow_symlinks=False)),
                "exclusive source changed during readonly FD handoff",
            )
            os.close(descriptor)
            self._owned.remove(descriptor)
            self._files[name] = _Entry(readonly, original_identity)
        for name in sorted(directories, key=lambda value: value.count("/"), reverse=True):
            os.fchmod(directories[name], 0o555)
            os.fsync(directories[name])
        for name, descriptor in directories.items():
            self._directories[name] = _Entry(descriptor, _identity(os.fstat(descriptor)))
        # chmod changed only the final root mode; retain the resulting original.
        prior, name, descriptor, _ = self._anchors[-1]
        self._anchors[-1] = (prior, name, descriptor, _anchor_identity(os.fstat(descriptor)))
        for parent_fd, _, _, _ in self._anchors:
            os.fsync(parent_fd)

    def recheck(self) -> None:
        """Recheck held FDs, all ancestor links and the complete named domain."""
        require(not self._closed, "original source projection closed")
        self.original.premises.verify()
        for parent, name, descriptor, identity in self._anchors:
            require(
                _anchor_identity(os.fstat(descriptor))
                == identity
                == _anchor_identity(os.stat(name, dir_fd=parent, follow_symlinks=False)),
                "original projection ancestor replaced",
            )
        for name, entry in {**self._directories, **self._files}.items():
            require(
                _identity(os.fstat(entry.descriptor)) == entry.identity,
                "retained original entry identity changed",
            )
            if name:
                parts = path_parts(name)
                parent = self._directories["/".join(parts[:-1])].descriptor
                require(
                    _identity(os.stat(parts[-1], dir_fd=parent, follow_symlinks=False))
                    == entry.identity,
                    "named original entry replaced",
                )
        for name, entry in self._directories.items():
            prefix = name + "/" if name else ""
            expected = {
                path.removeprefix(prefix).split("/")[0]
                for path in {*self._directories, *self._files}
                if path.startswith(prefix) and path != name
            }
            require(
                set(os.listdir(entry.descriptor)) == expected,  # noqa: PTH208 - retain checked FD
                "complete projection entry domain differs",
            )
        for name, entry in self._files.items():
            raw = self._contents[name]
            require(
                stat.S_ISREG(os.fstat(entry.descriptor).st_mode)
                and os.fstat(entry.descriptor).st_nlink == 1
                and os.pread(entry.descriptor, len(raw) + 1, 0) == raw,
                "whole original retained source readback differs",
            )
        self.original.premises.verify()

    def source_bytes(self, path: str) -> bytes:
        self.recheck()
        name = "source/" + path
        require(name in self._files, "unadmitted source path")
        raw = self._contents[name]
        observed = os.pread(self._files[name].descriptor, len(raw) + 1, 0)
        require(observed == raw, "source changed at read boundary")
        self.recheck()
        return observed

    def close(self) -> None:
        """Close handles; preserve successful or failed owned filesystem state."""
        if not self._closed:
            self._closed = True
            for descriptor in reversed(self._owned):
                os.close(descriptor)


def authenticate_and_project(
    reader: OriginalRead, premises: BootstrapPremises, policy: bytes, parent: Path
) -> RetainedProjection:
    original = verify_original_sources(reader, premises, policy)
    return RetainedProjection(original, parent)
