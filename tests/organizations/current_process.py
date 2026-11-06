"""Cooperative cancellation for the current-runtime fixture and its owned commands."""

from __future__ import annotations

import signal
import subprocess
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
    args, *, root, env, data=None, timeout=180, before_wait=None
):
    child = subprocess.Popen(  # noqa: S603 — explicit fixed-tool argv, private fixture inputs
        list(map(str, args)),
        cwd=root,
        env=env,
        text=True,
        stdin=subprocess.PIPE if data else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    completed = False
    started = time.monotonic()
    try:
        if before_wait is not None:
            before_wait(child)
        remaining = timeout - (time.monotonic() - started)
        if remaining <= 0:
            raise subprocess.TimeoutExpired(args, timeout)
        out, err = child.communicate(data, timeout=remaining)
        completed = True
        return subprocess.CompletedProcess(args, child.returncode, out, err)
    finally:
        # Successful pg_ctl start intentionally leaves a tracked supplier for
        # the outer fixture's shutdown. An interrupted command never does.
        if not completed:
            stop_process_group(child, grace=2)
