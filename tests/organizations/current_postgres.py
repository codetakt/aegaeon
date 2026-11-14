"""Verify the fixed local PostgreSQL role before signalling its pinned process.

Records are private fixture ownership evidence, not protection against arbitrary
same-UID record or process mutation. A pidfd, never a numeric PID fallback, binds
any stop signal to the process verified by this operation.
"""

from __future__ import annotations

import contextlib
import os
import select
import signal
import time
from pathlib import Path


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def snapshot(pid):
    try:
        process = Path(f"/proc/{pid}")
        fields = (process / "stat").read_text().rsplit(") ", 1)[1].split()
        return {
            "pid": pid,
            "group": int(fields[2]),
            "session": int(fields[3]),
            "starttime": fields[19],
            "uid": process.stat().st_uid,
        }, fields[0]
    except (FileNotFoundError, ProcessLookupError):
        return None


def definition(pg, data):
    executable = pg.resolve(strict=True) / "postgres"
    directory = data.resolve(strict=True)
    status = directory.stat()
    return {
        "schema": 1,
        "executable": str(executable.resolve(strict=True)),
        "argv": [str(executable), "-D", str(directory)],
        "data": {"path": str(directory), "device": status.st_dev, "inode": status.st_ino},
    }


def pidfile(data):
    try:
        lines = (data / "postmaster.pid").read_text().splitlines()
    except FileNotFoundError:
        return None
    require(len(lines) >= 2, "incomplete PostgreSQL PID file")
    require(lines[0].isascii() and lines[0].isdigit(), "invalid PostgreSQL PID")
    require(int(lines[0]) > 0, "invalid PostgreSQL PID")
    require(lines[1] == str(data.resolve(strict=True)), "PostgreSQL PID file data mismatch")
    return int(lines[0])


def validate_record(pg, data, record):
    expected = definition(pg, data)
    require(type(record) is dict, "missing PostgreSQL ownership record")
    require(set(record) == {*expected, "identity"}, "invalid PostgreSQL ownership fields")
    require(type(record["schema"]) is int, "invalid PostgreSQL ownership schema")
    require(type(record["data"]) is dict, "invalid PostgreSQL data identity")
    require(set(record["data"]) == {"path", "device", "inode"}, "invalid PostgreSQL data fields")
    for key in ("device", "inode"):
        require(type(record["data"][key]) is int, "invalid PostgreSQL data identity type")
    require({key: record[key] for key in expected} == expected, "PostgreSQL role/data changed")
    owned = record["identity"]
    require(type(owned) is dict, "invalid PostgreSQL process identity")
    require(
        set(owned) == {"pid", "group", "session", "starttime", "uid"},
        "invalid PostgreSQL process identity fields",
    )
    for key in ("pid", "group", "session", "uid"):
        require(type(owned[key]) is int, "invalid PostgreSQL process identity type")
        require(owned[key] >= (0 if key == "uid" else 1), "invalid PostgreSQL process identity")
    require(
        type(owned["starttime"]) is str
        and owned["starttime"].isascii()
        and owned["starttime"].isdigit(),
        "invalid PostgreSQL starttime",
    )
    require(owned["uid"] == os.getuid(), "PostgreSQL owner UID changed")
    return owned


def exited(descriptor):
    poller = select.poll()
    poller.register(descriptor, select.POLLIN)
    events = poller.poll(0)
    require(
        all(event & select.POLLIN and not event & select.POLLNVAL for _fd, event in events),
        "PostgreSQL pidfd polling failed",
    )
    return bool(events)


def inspect_role(pg, data, pid, expected):
    before = snapshot(pid)
    if before is None or before[1] in ("Z", "X"):
        message = "PostgreSQL is not live"
        raise ProcessLookupError(message)
    process = Path(f"/proc/{pid}")
    require(
        str((process / "exe").readlink()) == expected["executable"], "PostgreSQL executable changed"
    )
    require(
        (process / "cmdline").read_bytes()
        == b"\0".join(os.fsencode(v) for v in expected["argv"]) + b"\0",
        "PostgreSQL command/data changed",
    )
    require(pidfile(data) == pid, "PostgreSQL PID file changed")
    require(definition(pg, data) == expected, "PostgreSQL data directory changed")
    after = snapshot(pid)
    if after is None or after[1] in ("Z", "X"):
        message = "PostgreSQL exited during identity check"
        raise ProcessLookupError(message)
    require(after[0] == before[0], "PostgreSQL process identity changed")
    require(after[0]["uid"] == os.getuid(), "PostgreSQL owner UID changed")
    return after[0]


def capture(pg, data):
    expected = definition(pg, data)
    pid = pidfile(data)
    require(pid is not None, "PostgreSQL ownership requires a PID file")
    descriptor = os.pidfd_open(pid)
    try:
        owned = inspect_role(pg, data, pid, expected)
        require(not exited(descriptor), "PostgreSQL exited during ownership capture")
        return {**expected, "identity": owned}
    finally:
        os.close(descriptor)


def wait_stopped(descriptor, data, deadline):
    while True:
        if exited(descriptor) and pidfile(data) is None:
            return
        if time.monotonic() >= deadline:
            message = "PostgreSQL exit/PID file cleanup was not confirmed"
            raise TimeoutError(message)
        time.sleep(min(0.02, max(0, deadline - time.monotonic())))


def stop(pg, data, record, *, mode, timeout):
    require(mode in ("fast", "immediate"), "unsupported PostgreSQL stop mode")
    require(type(timeout) in (int, float) and 0 < timeout <= 25, "invalid PostgreSQL stop bound")
    deadline = time.monotonic() + timeout
    owned = validate_record(pg, data, record)
    try:
        descriptor = os.pidfd_open(owned["pid"])
    except ProcessLookupError:
        require(pidfile(data) is None, "PostgreSQL PID file remains without its owned process")
        return
    try:
        actual = snapshot(owned["pid"])
        if actual is None or actual[1] in ("Z", "X"):
            if actual is not None:
                require(actual[0] == owned, "postmaster PID was reused")
            require(exited(descriptor), "PostgreSQL process exit was not confirmed")
            wait_stopped(descriptor, data, deadline)
            return
        require(actual[0] == owned, "postmaster PID was reused")
        require(pidfile(data) == owned["pid"], "owned PostgreSQL remains live without its PID file")
        expected = {key: value for key, value in record.items() if key != "identity"}
        try:
            require(
                inspect_role(pg, data, owned["pid"], expected) == owned, "postmaster PID was reused"
            )
        except (FileNotFoundError, ProcessLookupError):
            # A completed process can vanish during /proc reads. Its pinned FD
            # must confirm exit and the PID file must also be gone.
            require(exited(descriptor), "PostgreSQL identity became unavailable while live")
            wait_stopped(descriptor, data, deadline)
            return
        require(time.monotonic() < deadline, "PostgreSQL stop deadline expired before signal")
        with contextlib.suppress(ProcessLookupError):
            signal.pidfd_send_signal(
                descriptor, signal.SIGINT if mode == "fast" else signal.SIGQUIT
            )
        wait_stopped(descriptor, data, deadline)
    finally:
        os.close(descriptor)
