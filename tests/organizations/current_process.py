"""Cooperative cancellation for the current-runtime fixture and its owned commands."""

from __future__ import annotations

import signal
import subprocess
import tempfile
import time

from database_execution import stop_process_group


def ignore_cancellation():
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, signal.SIG_IGN)


def interrupted(signum, _frame):
    ignore_cancellation()
    message = f"current-runtime fixture interrupted by signal {signum}"
    # selectors may consume InterruptedError as syscall EINTR and resume waiting.
    raise RuntimeError(message)


def install_cancellation():
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, interrupted)


def run_owned(  # noqa: PLR0913 — explicit subprocess lifecycle options
    args, *, root, env, data=None, timeout=180, before_wait=None, retain_supplier=False
):
    # Output retained by descendants must not delay observing the leader's exit.
    # Ordinary commands are reclaimed before reading these private output files.
    with tempfile.TemporaryFile(mode="w+") as output, tempfile.TemporaryFile(mode="w+") as error:
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
        retained = False
        started = time.monotonic()
        try:
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
            if not retained:
                stop_process_group(child, grace=2)
        output.seek(0)
        error.seek(0)
        return subprocess.CompletedProcess(args, child.returncode, output.read(), error.read())
