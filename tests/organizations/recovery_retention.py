"""Real file/process interruption checks for exclusive receipt publication."""

from __future__ import annotations

import argparse
import errno
import hashlib
import importlib.util
import json
import os
import signal
import stat
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

VALUE = {"operation": "fixture", "secret": "nonproduction-test-material"}
DATA = json.dumps(VALUE, sort_keys=True, separators=(",", ":")).encode() + b"\n"
INTERRUPTED = 91


def interrupted(directory, retain, stage):
    """Execute actual inode writes/link then terminate without Python cleanup."""
    pid = os.fork()
    if pid == 0:
        signal.alarm(5)
        original_sync, original_link = os.fsync, os.link

        def sync(fd):
            if stat.S_ISREG(os.fstat(fd).st_mode):
                if stage == "partial":
                    os.ftruncate(fd, 7)
                    os._exit(INTERRUPTED)
                original_sync(fd)
                if stage == "file-synced":
                    os._exit(INTERRUPTED)
            else:
                original_sync(fd)
                if stage == "directory-synced":
                    os._exit(INTERRUPTED)

        def link(*args, **kwargs):
            original_link(*args, **kwargs)
            if stage == "linked":
                os._exit(INTERRUPTED)

        with patch.object(os, "fsync", sync), patch.object(os, "link", link):
            retain(directory, "receipt.json", VALUE)
        os._exit(92)
    assert os.waitpid(pid, 0)[1] == INTERRUPTED << 8


def crash_cases(root, retain):
    for stage in ("partial", "file-synced", "linked", "directory-synced"):
        path = root / stage
        path.mkdir(mode=0o700)
        descriptor = os.open(path, os.O_DIRECTORY)
        try:
            interrupted(descriptor, retain, stage)
            if stage in ("partial", "file-synced"):
                assert not list(path.iterdir()), "incomplete final name exposed"
                assert retain(descriptor, "receipt.json", VALUE) == hashlib.sha256(DATA).hexdigest()
            else:
                assert (path / "receipt.json").read_bytes() == DATA
                with pytest.raises(FileExistsError):
                    retain(descriptor, "receipt.json", {"changed": True})
            info = (path / "receipt.json").stat()
            assert info.st_nlink == 1
            assert stat.S_IMODE(info.st_mode) == 0o600
            assert (path / "receipt.json").read_bytes() == DATA
        finally:
            os.close(descriptor)


def failures(root, retain):  # noqa: PLR0915 — finite filesystem fault inventory
    path = root / "errors"
    path.mkdir(mode=0o700)
    descriptor = os.open(path, os.O_DIRECTORY)
    try:
        original_open, original_sync = os.open, os.fsync

        def unsupported(name, flags, *args, **kwargs):
            if flags & os.O_TMPFILE == os.O_TMPFILE:
                raise OSError(errno.EOPNOTSUPP, "fixture unsupported filesystem")
            return original_open(name, flags, *args, **kwargs)

        with (
            patch.object(os, "open", unsupported),
            pytest.raises(OSError, match="unsupported") as caught,
        ):
            retain(descriptor, "unsupported.json", VALUE)
        assert caught.value.errno == errno.EOPNOTSUPP
        assert not list(path.iterdir())
        with (
            patch.object(os, "fsync", side_effect=OSError(errno.ENOSPC, "fixture full")),
            pytest.raises(OSError, match="fixture full"),
        ):
            retain(descriptor, "full.json", VALUE)
        assert not list(path.iterdir())
        with (
            patch.object(os, "link", side_effect=OSError(errno.EIO, "fixture link failure")),
            pytest.raises(OSError, match="link failure"),
        ):
            retain(descriptor, "link.json", VALUE)
        assert not list(path.iterdir())

        def directory_failure(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                raise OSError(errno.EIO, "fixture directory synchronization failure")
            original_sync(fd)

        with (
            patch.object(os, "fsync", directory_failure),
            pytest.raises(OSError, match="directory synchronization"),
        ):
            retain(descriptor, "uncertain.json", VALUE)
        assert (path / "uncertain.json").read_bytes() == DATA
        with pytest.raises(FileExistsError):
            retain(descriptor, "uncertain.json", VALUE)
        target = path / "target"
        target.write_bytes(b"preserved")
        (path / "symlink.json").symlink_to(target)
        with pytest.raises(FileExistsError):
            retain(descriptor, "symlink.json", VALUE)
        os.link(target, path / "hardlink.json")
        with pytest.raises(FileExistsError):
            retain(descriptor, "hardlink.json", VALUE)
        assert target.read_bytes() == b"preserved"
        for name in ("../escape.json", "/escape.json", "nested/receipt.json", "..", ""):
            with pytest.raises(Exception, match="basename"):
                retain(descriptor, name, VALUE)
    finally:
        os.close(descriptor)


def concurrent(root, retain):
    path = root / "concurrent"
    path.mkdir(mode=0o700)
    descriptor = os.open(path, os.O_DIRECTORY)
    read, write = os.pipe()
    pids = []
    try:
        for index in range(2):
            pid = os.fork()
            if pid == 0:
                signal.alarm(5)
                os.close(write)
                assert os.read(read, 1) == b"x"
                try:
                    retain(descriptor, "receipt.json", {"winner": index})
                except FileExistsError:
                    os._exit(11)
                os._exit(0)
            pids.append(pid)
        os.close(read)
        os.write(write, b"xx")
        os.close(write)
        assert sorted(os.waitpid(pid, 0)[1] for pid in pids) == [0, 11 << 8]
        assert json.loads((path / "receipt.json").read_bytes()) in ({"winner": 0}, {"winner": 1})
        assert len(list(path.iterdir())) == 1
        assert (path / "receipt.json").stat().st_nlink == 1
    finally:
        os.close(descriptor)


def negative(root, module):
    # Original publication order: the exact same partial-write interruption
    # leaves a truncated final pathname. The invariant above must detect it.
    original = """def legacy(directory, name, value):
    data = json.dumps(value,sort_keys=True,separators=(",",":")).encode()+b"\\n"
    fd = os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory)
    with os.fdopen(fd,"wb") as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())
    os.fsync(directory)
    return hashlib.sha256(data).hexdigest()
"""
    namespace = {"os": os, "json": json, "hashlib": hashlib}
    exec(compile(original, "<retained-original-order>", "exec"), namespace)  # noqa: S102
    path = root / "negative"
    path.mkdir(mode=0o700)
    descriptor = os.open(path, os.O_DIRECTORY)
    try:
        interrupted(descriptor, namespace["legacy"], "partial")
        assert (path / "receipt.json").read_bytes() == DATA[:7]
        with pytest.raises(AssertionError, match="incomplete final name exposed"):
            assert not list(path.iterdir()), "incomplete final name exposed"
    finally:
        os.close(descriptor)
    return {
        "legacy_sha256": hashlib.sha256(original.encode()).hexdigest(),
        "candidate_sha256": hashlib.sha256(Path(module.__file__).read_bytes()).hexdigest(),
        "original_partial_name_detected": True,
    }


def directory_entry(root, module):
    path = root / "provisioned"
    path.mkdir(mode=0o700)
    expected = [(p.stat().st_dev, p.stat().st_ino) for p in (path, root)]
    original = os.fsync
    for fault in (None, 0, 1):
        observed = []

        def sync(fd, seen=observed, failed_at=fault):
            info = os.fstat(fd)
            seen.append((info.st_dev, info.st_ino))
            if failed_at == len(seen) - 1:
                raise OSError(errno.EIO, "injected directory persistence failure")
            original(fd)

        with patch.object(os, "fsync", sync):
            if fault is None:
                module.sync_directory_entry(path)
            else:
                with pytest.raises(OSError, match="directory persistence"):
                    module.sync_directory_entry(path)
        assert observed == expected[: len(observed)]
        assert len(observed) == (2 if fault is None else fault + 1)
    link = root / "provisioned-link"
    link.symlink_to(path, target_is_directory=True)
    with pytest.raises(NotADirectoryError):
        module.sync_directory_entry(link)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--operator", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    signal.alarm(25)
    source = args.operator / "share/aegaeon/scripts/operations"
    sys.path.insert(0, str(source))
    spec = importlib.util.spec_from_file_location(
        "organization_recovery", source / "organization_recovery.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    with tempfile.TemporaryDirectory(prefix="aegaeon-receipt-") as temporary:
        root = Path(temporary)
        directory_entry(root, module)
        crash_cases(root, module.retain)
        failures(root, module.retain)
        concurrent(root, module.retain)
        mutation = negative(root, module)
    args.output.write_text(
        json.dumps(
            {
                "passed": True,
                "actual_process_interruption_stages": 4,
                "faults": ["unsupported", "file-sync", "link", "directory-sync"],
                "concurrent_publishers": 2,
                "no_overwrite": True,
                "symlink_hardlink_escape_refused": True,
                "negative_control": mutation,
                "power_loss_qualification": False,
                "new_directory_and_parent_synced_before_store_work": True,
                "new_atomic_discharge": 0,
            },
            indent=2,
        )
        + "\n"
    )


if __name__ == "__main__":
    main()
