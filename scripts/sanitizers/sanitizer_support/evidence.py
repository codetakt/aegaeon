"""Bind evidence operations to owned, no-follow directory and regular-file identities."""

from __future__ import annotations

import contextlib
import json
import os
import secrets
import stat
from pathlib import Path
from typing import TYPE_CHECKING, Any

from sanitizer_support.core import parse_json, require

if TYPE_CHECKING:
    from collections.abc import Iterator
    from typing import BinaryIO

DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW


class Directory:
    """Reopen and verify every admitted component; all leaf operations are fd-relative."""

    def __init__(
        self,
        path: Path,
        identities: list[list[int]] | None = None,
        *,
        create: bool = False,
        owned: bool = True,
    ) -> None:
        require(
            path.is_absolute() and (not owned or path != Path("/")) and ".." not in path.parts,
            "Invalid validated sanitizer directory",
        )
        self.path = path
        self.identities = identities
        self.owned = owned
        with self.open(create=create):
            pass

    @contextlib.contextmanager
    def open(self, *, create: bool = False) -> Iterator[int]:
        descriptor = os.open("/", DIRECTORY_FLAGS)
        observed = []
        try:
            for name in (None, *self.path.parts[1:]):
                if name is not None:
                    if create:
                        with contextlib.suppress(FileExistsError):
                            os.mkdir(name, dir_fd=descriptor)
                    child = os.open(name, DIRECTORY_FLAGS, dir_fd=descriptor)
                    os.close(descriptor)
                    descriptor = child
                info = os.fstat(descriptor)
                observed.append([info.st_dev, info.st_ino])
                require(
                    self.identities is None or observed == self.identities[: len(observed)],
                    "Sanitizer directory component identity changed",
                )
            require(
                not self.owned or info.st_uid == os.getuid(),
                "Sanitizer directory must belong to the producer",
            )
            require(
                self.identities is None or observed == self.identities,
                "Invalid sanitizer directory binding",
            )
            self.identities = observed
            yield descriptor
        finally:
            os.close(descriptor)

    def binding(self) -> dict[str, Any]:
        return {"target": str(self.path), "identities": self.identities}


def checked_file(directory: int, name: str, flags: int) -> int:
    require(Path(name).name == name and name not in {".", ".."}, "Invalid evidence leaf")
    descriptor = os.open(name, flags | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=directory)
    try:
        opened = os.fstat(descriptor)
        current = os.stat(name, dir_fd=directory, follow_symlinks=False)
        require(
            stat.S_ISREG(opened.st_mode)
            and opened.st_nlink == 1
            and opened.st_uid == os.getuid()
            and stat.S_ISREG(current.st_mode)
            and (opened.st_dev, opened.st_ino) == (current.st_dev, current.st_ino),
            "Unsafe sanitizer evidence alias, ownership or identity",
        )
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def checked_summary(directory: int) -> tuple[os.stat_result, bytes, dict[str, Any]]:
    descriptor = checked_file(directory, "run-summary.json", os.O_RDONLY)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        raw = stream.read()
        current = os.stat("run-summary.json", dir_fd=directory, follow_symlinks=False)
        require(
            (current.st_dev, current.st_ino, current.st_nlink, current.st_uid)
            == (info.st_dev, info.st_ino, 1, os.getuid()),
            "Sanitizer summary identity changed",
        )
    receipt = parse_json(raw.decode())
    require(isinstance(receipt, dict), "Malformed sanitizer summary")
    return info, raw, receipt


def replace_summary(directory: int, receipt: dict[str, Any]) -> None:
    # Reject unsafe existing leaves even though rename itself would not follow them.
    try:
        descriptor = checked_file(directory, "run-summary.json", os.O_RDONLY)
    except FileNotFoundError:
        pass
    else:
        os.close(descriptor)
    name = ".run-summary-" + secrets.token_hex(16)
    descriptor = os.open(
        name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory
    )
    try:
        with os.fdopen(descriptor, "w") as stream:
            json.dump(receipt, stream, indent=2)
            stream.write("\n")
        os.replace(name, "run-summary.json", src_dir_fd=directory, dst_dir_fd=directory)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(name, dir_fd=directory)


class EvidenceStore:
    """One directory binding covers summaries and every captured command stream."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.directory = Directory(path) if path.exists() else None

    def prepare(self) -> None:
        if self.directory is None:
            self.directory = Directory(self.path, create=True)
        else:
            with self.directory.open():
                pass

    def bind(self) -> Directory:
        if self.directory is None:
            self.directory = Directory(self.path)
        return self.directory

    def save(self, receipt: dict[str, Any]) -> None:
        with self.bind().open() as directory:
            replace_summary(directory, receipt)

    @contextlib.contextmanager
    def log(self, name: str) -> Iterator[BinaryIO]:
        with self.bind().open() as directory:
            descriptor = checked_file(directory, name, os.O_WRONLY | os.O_CREAT)
            with os.fdopen(descriptor, "wb") as stream:
                # No truncation occurs before regular/single-link/owner/identity checks.
                os.ftruncate(stream.fileno(), 0)
                yield stream

    def read(self, name: str) -> str:
        with self.bind().open() as directory:
            descriptor = checked_file(directory, name, os.O_RDONLY)
            with os.fdopen(descriptor, "r") as stream:
                return stream.read()
