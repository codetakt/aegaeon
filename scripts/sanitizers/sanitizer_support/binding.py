"""Shell adapters for bound sanitizer preparation, receipt preservation and cleanup."""

from __future__ import annotations

import contextlib
import json
import os
import secrets
import stat
import sys
from pathlib import Path

from sanitizer_support.core import parse_json, require
from sanitizer_support.evidence import DIRECTORY_FLAGS, Directory, checked_summary
from sanitizer_support.receipt import reject_completed, validate_completed

MAX_EXIT_STATUS = 255


def launcher_receipt(directory: int, operation: str, snapshot: str, status: str) -> None:
    metadata, raw, receipt = checked_summary(directory)
    identity = [metadata.st_dev, metadata.st_ino]
    if operation == "summary-snapshot":
        require(
            not (
                receipt.get("status") != "failed"
                or receipt.get("stage") != "preflight"
                or receipt.get("commands") != []
                or (receipt.get("units") != [])
                or set(receipt) - {"status", "stage", "commands", "units", "previous_attempt"}
            ),
            "Sanitizer invocation initialization receipt changed",
        )
        print(json.dumps({"identity": identity, "content": raw.hex()}))
        return
    initial = json.loads(snapshot)
    if identity != initial["identity"] or raw != bytes.fromhex(initial["content"]):
        # A child receipt (including a replacement with identical bytes) owns
        # its content. A launcher failure must not overwrite that evidence.
        return
    code = int(status)
    require(bool(0 < code <= MAX_EXIT_STATUS), "Invalid sanitizer launcher status")
    receipt.update(status="failed", stage="preflight", preflight_phase="launcher", exit_code=code)
    name = ".launcher-summary-" + secrets.token_hex(16)
    descriptor = os.open(
        name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory
    )
    try:
        with os.fdopen(descriptor, "w") as stream:
            json.dump(receipt, stream, indent=2)
            stream.write("\n")
        # Recheck the admitted leaf immediately before the fd-relative replace.
        current, current_raw, _ = checked_summary(directory)
        require(
            not ([current.st_dev, current.st_ino] != identity or current_raw != raw),
            "Sanitizer initialization receipt changed before recording",
        )
        os.replace(name, "run-summary.json", src_dir_fd=directory, dst_dir_fd=directory)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(name, dir_fd=directory)


def remove_contents(directory: int) -> None:
    # Every traversal remains anchored to an open, no-follow directory handle.
    for entry in os.scandir(directory):
        info = os.stat(entry.name, dir_fd=directory, follow_symlinks=False)
        if stat.S_ISDIR(info.st_mode):
            child = os.open(entry.name, DIRECTORY_FLAGS, dir_fd=directory)
            try:
                opened = os.fstat(child)
                require(
                    (info.st_dev, info.st_ino) == (opened.st_dev, opened.st_ino),
                    "Sanitizer child entry changed; refusing cleanup",
                )
                remove_contents(child)
                current = os.stat(entry.name, dir_fd=directory, follow_symlinks=False)
                require(
                    (current.st_dev, current.st_ino) == (opened.st_dev, opened.st_ino),
                    "Sanitizer child entry changed; refusing cleanup",
                )
                os.rmdir(entry.name, dir_fd=directory)
            finally:
                os.close(child)
        else:
            os.unlink(entry.name, dir_fd=directory)


def main() -> int:
    operation, value, snapshot, status = sys.argv[1:]
    require(
        operation
        in {
            "prepare",
            "validate",
            "cleanup",
            "summary-snapshot",
            "launcher-failure",
            "validate-completed",
        },
        "Unknown sanitizer binding operation",
    )
    if operation == "prepare":
        directory = Directory(Path(value), create=True)
    else:
        binding = parse_json(value)
        directory = Directory(Path(binding["target"]), binding["identities"])
    with directory.open() as descriptor:
        if operation == "prepare":
            print(json.dumps(directory.binding()))
        elif operation == "cleanup":
            remove_contents(descriptor)
            parent = Directory(directory.path.parent, directory.identities[:-1], owned=False)
            with parent.open() as parent_fd:
                current = os.stat(directory.path.name, dir_fd=parent_fd, follow_symlinks=False)
                require(
                    stat.S_ISDIR(current.st_mode)
                    and [current.st_dev, current.st_ino] == directory.identities[-1],
                    "Sanitizer target entry changed; refusing cleanup",
                )
                os.rmdir(directory.path.name, dir_fd=parent_fd)
        elif operation in {"summary-snapshot", "launcher-failure"}:
            launcher_receipt(descriptor, operation, snapshot, status)
        elif operation == "validate-completed":
            try:
                validate_completed(directory, snapshot, Path(status))
            except Exception as error:  # rejected success cannot remain current
                reject_completed(directory, error)
                raise
    return 0
