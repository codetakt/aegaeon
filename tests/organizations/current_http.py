"""Owned HTTP probes with total deadlines, including while sibling probes wait."""

from __future__ import annotations

import contextlib
import json
import math
import os
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from current_http_probe import validate_request
from current_process import check_cancellation, cleanup_scope, stop_owned, track_owned


class ConnectionFailureError(OSError):
    """A request connection failed; malformed private evidence is a separate error."""


def unique_fields(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            message = "duplicate HTTP probe result field"
            raise ValueError(message)
        result[key] = value
    return result


def read_result(path, base, endpoint, window):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > 4096:
            message = "HTTP probe result must be a bounded regular file"
            raise ValueError(message)
        data = stream.read(4097)
    if len(data) > 4096:
        message = "HTTP probe result grew beyond its bound"
        raise ValueError(message)
    result = json.loads(data, object_pairs_hook=unique_fields)
    if not isinstance(result, dict) or (result.get("base"), result.get("path")) != (base, endpoint):
        message = "HTTP probe request identity mismatch"
        raise ValueError(message)
    completed = result.pop("completed_at", None)
    if type(completed) not in (int, float) or not math.isfinite(completed):
        message = "HTTP probe completion time missing or invalid"
        raise ValueError(message)
    if not window[0] <= completed < window[1]:
        message = "HTTP probe completed outside its total deadline"
        raise TimeoutError(message)
    if result == {"base": base, "path": endpoint, "error": "connection"}:
        message = "loopback HTTP probe connection failed"
        raise ConnectionFailureError(message)
    status = result.get("status")
    if (
        set(result) != {"base", "path", "status"}
        or type(status) is not int
        or not 100 <= status <= 599
    ):
        message = "invalid HTTP probe status"
        raise ValueError(message)
    return status


class Probe:
    def __init__(self, base, endpoint, directory, timeout):
        validate_request(base, endpoint)
        if not 0 < timeout <= 38:
            message = "HTTP probe deadline must be positive and at most 38 seconds"
            raise ValueError(message)
        self.base, self.endpoint, self.timeout = base, endpoint, timeout
        self.result = Path(tempfile.mkdtemp(prefix="http-", dir=directory)) / "result.json"
        self.child = None
        self.finished = False
        self.status = None
        self.deadline = None

    def start(self):
        check_cancellation()
        self.deadline = time.monotonic() + self.timeout
        self.child = subprocess.Popen(  # noqa: S603 - fixed Python helper and validated local URL.
            [
                sys.executable,
                str(Path(__file__).with_name("current_http_probe.py")),
                self.base,
                self.endpoint,
                str(self.timeout),
                str(self.result),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        track_owned(self.child)
        check_cancellation()

    def poll(self):
        if self.finished:
            return
        check_cancellation()
        code = self.child.poll()
        # Observe completion before considering its deadline: a previously
        # completed probe remains completed during the longer outage interval.
        if code is not None:
            stop_owned(self.child)
            self.finished = True
            if code:
                message = "HTTP probe exited without a successful result"
                raise RuntimeError(message)
            self.status = read_result(
                self.result, self.base, self.endpoint, (self.deadline - self.timeout, self.deadline)
            )
        elif time.monotonic() >= self.deadline:
            message = "loopback HTTP probe total deadline"
            raise TimeoutError(message)

    def stop(self):
        if self.child is not None and not self.finished:
            stop_owned(self.child)
            self.finished = True


def stop_all(probes, primary):
    failure = primary
    with cleanup_scope():
        for probe in probes:
            try:
                probe.stop()
            except BaseException as error:  # noqa: BLE001 - attempt every cleanup, then propagate.
                if failure is None:
                    failure = error
                else:
                    failure.add_note(f"HTTP probe cleanup unconfirmed: {type(error).__name__}")
    if primary is None and failure is not None:
        raise failure


@contextlib.contextmanager
def probes(base, endpoints, directory, *, timeout=38):
    owned = [Probe(base, endpoint, directory, timeout) for endpoint in endpoints]
    try:
        for probe in owned:
            probe.start()
        yield owned
    finally:
        stop_all(owned, sys.exception())


def poll_all(owned):
    for probe in owned:
        probe.poll()


def pause(duration, pending):
    until = time.monotonic() + duration
    while time.monotonic() < until:
        check_cancellation()
        poll_all(pending)
        time.sleep(max(0, min(0.05, until - time.monotonic())))


def response(base, path, directory, *, timeout=38, pending=()):
    with probes(base, (path,), directory, timeout=timeout) as owned:
        while not owned[0].finished:
            check_cancellation()
            poll_all(pending)
            poll_all(owned)
            if not owned[0].finished:
                time.sleep(0.05)
        status = owned[0].status
    check_cancellation()
    return status
