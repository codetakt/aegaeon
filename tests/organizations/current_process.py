"""Cooperative cancellation for the current-runtime fixture and its owned commands."""

from __future__ import annotations

import signal
import subprocess
import tempfile
import time

from database_execution import cleanup_cancellation_guard, defer_cancellation, stop_process_group

_cancellation_seen = False


def ignore_cancellation():
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, signal.SIG_IGN)


def interrupted(signum, _frame):
    global _cancellation_seen  # noqa: PLW0603 - one process-wide installed handler.
    if _cancellation_seen:
        return
    _cancellation_seen = True
    message = f"current-runtime fixture interrupted by signal {signum}"
    # selectors may consume InterruptedError as syscall EINTR and resume waiting.
    error = RuntimeError(message)
    if not defer_cancellation(error):
        raise error


def install_cancellation():
    global _cancellation_seen  # noqa: PLW0603 - reset only before command startup.
    _cancellation_seen = False
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, interrupted)


def run_owned(  # noqa: PLR0913 — explicit subprocess lifecycle options
    args, *, root, env, data=None, timeout=180, before_wait=None, retain_supplier=False
):
    # Output retained by descendants must not delay observing the leader's exit.
    # Ordinary commands are reclaimed before reading these private output files.
    with tempfile.TemporaryFile(mode="w+") as output, tempfile.TemporaryFile(mode="w+") as error:
        child = None
        retained = False
        try:
            with cleanup_cancellation_guard():
                child = subprocess.Popen(  # noqa: S603 — explicit fixed-tool argv, private fixture inputs
                    list(map(str, args)),
                    cwd=root,
                    env=env,
                    text=True,
                    stdin=subprocess.PIPE if data else subprocess.DEVNULL,
                    stdout=output,
                    stderr=error,
                    start_new_session=True,
                )
            started = time.monotonic()
            if before_wait is not None:
                before_wait(child)
            remaining = timeout - (time.monotonic() - started)
            if remaining <= 0:
                raise subprocess.TimeoutExpired(args, timeout)
            child.communicate(data, timeout=remaining)
            retained = retain_supplier and child.returncode == 0
        finally:
            # Only an explicitly tracked successful supplier start is retained.
            # Ordinary native/CLI commands are reclaimed even after leader exit.
            if child is not None and not retained:
                stop_process_group(child, grace=2)
        output.seek(0)
        error.seek(0)
        return subprocess.CompletedProcess(args, child.returncode, output.read(), error.read())
