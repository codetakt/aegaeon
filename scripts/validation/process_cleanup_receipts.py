"""Carry nested process-stop confirmation across an owned controller boundary."""

from __future__ import annotations

import fcntl
import json
import os
import re
import stat
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Iterator

ENVIRONMENT = "AEGAEON_PROCESS_CLEANUP_RECEIPTS"
LEDGER = "registrations"
MAX_INVOCATIONS = 64
LOCK_SECONDS = 1.0


def read_at(directory: int, name: str) -> dict[str, Any]:
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    with os.fdopen(descriptor, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("cleanup receipt is not a regular file")
        data = stream.read(1024 * 1024 + 1)
    if len(data) > 1024 * 1024:
        raise ValueError("cleanup receipt exceeds its bound")

    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate cleanup receipt field")
            value[key] = item
        return value

    value = json.loads(data, object_pairs_hook=unique)
    if not isinstance(value, dict):
        raise ValueError("cleanup receipt is not an object")
    return value


def identity_of(directory: int, ledger: int) -> dict[str, int]:
    parent, register = os.fstat(directory), os.fstat(ledger)
    if not stat.S_ISREG(register.st_mode):
        raise ValueError("cleanup receipt ledger is not a regular file")
    return {
        "device": parent.st_dev,
        "inode": parent.st_ino,
        "ledger_device": register.st_dev,
        "ledger_inode": register.st_ino,
    }


def check_paths(directory: Path, descriptor: int, ledger: int) -> None:
    current = directory.lstat()
    register = os.stat(LEDGER, dir_fd=descriptor, follow_symlinks=False)
    identity = identity_of(descriptor, ledger)
    if (
        not stat.S_ISDIR(current.st_mode)
        or (current.st_dev, current.st_ino) != (identity["device"], identity["inode"])
        or not stat.S_ISREG(register.st_mode)
        or (register.st_dev, register.st_ino)
        != (identity["ledger_device"], identity["ledger_inode"])
    ):
        raise ValueError("cleanup receipt directory or ledger identity changed")


def write_json(directory: int, name: str, value: dict[str, Any]) -> None:
    descriptor = os.open(
        name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory
    )
    with os.fdopen(descriptor, "w") as stream:
        json.dump(value, stream)
        stream.flush()
        os.fsync(stream.fileno())


def append(ledger: int, data: bytes) -> None:
    if os.write(ledger, data) != len(data):
        raise OSError("partial cleanup receipt registration write")
    os.fsync(ledger)


@contextmanager
def initialize(directory: Path, owner: str) -> Iterator[dict[str, int]]:
    """Pin both inodes until the parent's work and policy cleanup have ended."""
    directory.mkdir(mode=0o700)
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    ledger = None
    try:
        write_json(descriptor, "owner.json", {"version": 1, "owner": owner})
        ledger = os.open(
            LEDGER,
            os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=descriptor,
        )
        append(ledger, ("aegaeon-process-cleanup-v1\n" + owner + "\n").encode("ascii"))
        os.fsync(descriptor)
        check_paths(directory, descriptor, ledger)
        yield identity_of(descriptor, ledger)
    finally:
        if ledger is not None:
            os.close(ledger)
        os.close(descriptor)


@contextmanager
def locked(directory: Path) -> Iterator[tuple[int, int]]:
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    ledger = None
    try:
        ledger = os.open(
            LEDGER, os.O_RDWR | os.O_APPEND | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor
        )
        identity_of(descriptor, ledger)
        deadline = time.monotonic() + LOCK_SECONDS
        while True:
            try:
                fcntl.flock(ledger, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise TimeoutError("cleanup receipt registration lock deadline") from None
                time.sleep(0.01)
        check_paths(directory, descriptor, ledger)
        yield descriptor, ledger
        check_paths(directory, descriptor, ledger)
    finally:
        if ledger is not None:
            os.close(ledger)
        os.close(descriptor)


def registered(directory: int, ledger: int) -> tuple[dict[str, Any], list[str]]:
    owner = read_at(directory, "owner.json")
    if (
        set(owner) != {"version", "owner"}
        or type(owner["version"]) is not int
        or owner["version"] != 1
        or not isinstance(owner["owner"], str)
        or not re.fullmatch("aegaeon-userns-[0-9a-f]{32}", owner["owner"])
    ):
        raise ValueError("invalid cleanup receipt owner")
    os.lseek(ledger, 0, os.SEEK_SET)
    data = bytearray()
    while len(data) <= 16 * 1024:
        chunk = os.read(ledger, 16 * 1024 + 1 - len(data))
        if not chunk:
            break
        data.extend(chunk)
    header = ("aegaeon-process-cleanup-v1\n" + owner["owner"] + "\n").encode("ascii")
    if len(data) > 16 * 1024 or not data.startswith(header) or not data.endswith(b"\n"):
        raise ValueError("invalid or partial cleanup receipt registration ledger")
    rows = data[len(header) :].splitlines()
    if any(re.fullmatch(rb"[0-9a-f]{32}", row) is None for row in rows):
        raise ValueError("invalid cleanup receipt registration")
    identifiers = [row.decode("ascii") for row in rows]
    if len(identifiers) > MAX_INVOCATIONS or len(set(identifiers)) != len(identifiers):
        raise ValueError("too many or duplicate nested cleanup registrations")
    expected = {"owner.json", LEDGER, *(identifier + ".json" for identifier in identifiers)}
    with os.scandir(directory) as entries:
        names = set()
        for entry in entries:
            names.add(entry.name)
            if entry.name not in expected:
                raise ValueError("unfinished or unknown nested cleanup receipt")
    if names != expected:
        raise ValueError("registered nested cleanup receipt is missing")
    return owner, identifiers


def validate_record(row: dict[str, Any], owner: dict[str, Any], identifier: str) -> None:
    if (
        set(row) != {"version", "owner", "invocation", "group", "confirmed"}
        or type(row["version"]) is not int
        or row["version"] != 1
        or row["owner"] != owner["owner"]
        or row["invocation"] != identifier
        or type(row["confirmed"]) is not bool
        or (row["group"] is not None and (type(row["group"]) is not int or row["group"] <= 0))
        or (row["confirmed"] and row["group"] is None)
    ):
        raise ValueError("nested process cleanup is unconfirmed or malformed")
    return


def read_receipt(directory: int, owner: dict[str, Any], identifier: str) -> dict[str, Any]:
    row = read_at(directory, identifier + ".json")
    validate_record(row, owner, identifier)
    return row


def begin() -> tuple[Path, dict[str, Any]] | None:
    selected = os.environ.get(ENVIRONMENT)
    if selected is None:
        return None
    directory = Path(selected)
    with locked(directory) as (descriptor, ledger):
        owner, identifiers = registered(descriptor, ledger)
        for identifier in identifiers:
            read_receipt(descriptor, owner, identifier)
        if len(identifiers) >= MAX_INVOCATIONS:
            raise ValueError("too many nested cleanup registrations")
        identifier = uuid.uuid4().hex
        if identifier in identifiers:
            raise ValueError("duplicate nested cleanup registration")
        record = {**owner, "invocation": identifier, "group": None, "confirmed": False}
        # Registration is durable before a receipt or Popen can be created.
        append(ledger, (identifier + "\n").encode("ascii"))
        write_json(descriptor, identifier + ".json", record)
        os.fsync(descriptor)
    return directory / (identifier + ".json"), record


def update(receipt: tuple[Path, dict[str, Any]] | None, **changes: Any) -> None:
    if receipt is None:
        return
    path, record = receipt
    with locked(path.parent) as (directory, ledger):
        owner, identifiers = registered(directory, ledger)
        identifier = path.stem
        if identifier not in identifiers or read_receipt(directory, owner, identifier) != record:
            raise ValueError("cleanup receipt registration or state changed")
        if not set(changes) <= {"group", "confirmed"}:
            raise ValueError("unknown cleanup receipt update")
        value = {**record, **changes}
        validate_record(value, owner, identifier)
        temporary = path.with_suffix(".tmp").name
        write_json(directory, temporary, value)
        os.replace(temporary, path.name, src_dir_fd=directory, dst_dir_fd=directory)
        os.fsync(directory)
        record.update(changes)


def confirm(directory: Path, owner: str, identity: dict[str, int]) -> list[dict[str, Any]]:
    with locked(directory) as (descriptor, ledger):
        if identity_of(descriptor, ledger) != identity:
            raise ValueError("cleanup receipt directory identity changed or ledger replaced")
        actual_owner, identifiers = registered(descriptor, ledger)
        if actual_owner != {"version": 1, "owner": owner}:
            raise ValueError("cleanup receipt owner changed")
        result = [read_receipt(descriptor, actual_owner, identifier) for identifier in identifiers]
        if any(row["confirmed"] is not True for row in result):
            raise ValueError("nested process cleanup is unconfirmed")
        return result
