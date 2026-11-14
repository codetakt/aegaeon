"""Cooperative cancellation for the current-runtime fixture and its owned commands."""

from __future__ import annotations

import contextlib
import os
import signal
import subprocess
import tempfile
import time

from database_execution import stop_process_group

_cancellation = None
_cleaning = False
_unconfirmed_groups = set()
_supplier_groups = set()


def ignore_cancellation():
    # Historical callers enter terminal cleanup; signals remain recorded.
    global _cleaning  # noqa: PLW0603 - process-wide terminal cleanup phase.
    _cleaning = True


def interrupted(signum, _frame):
    global _cancellation  # noqa: PLW0603 - one process-wide installed handler.
    if _cancellation is None:
        _cancellation = RuntimeError(f"current-runtime fixture interrupted by signal {signum}")


def check_cancellation():
    if _cancellation is not None and not _cleaning:
        raise _cancellation


def cancellation_recorded():
    return _cancellation is not None


@contextlib.contextmanager
def cleanup_scope():
    global _cleaning  # noqa: PLW0603 - cleanup suppresses checkpoints, not signal recording.
    previous = _cleaning
    _cleaning = True
    try:
        yield
    finally:
        _cleaning = previous


def unconfirmed_groups():
    return sorted(_unconfirmed_groups)


def supplier_start_groups():
    # These are ownership transfers, not claims that the starter is still live.
    return sorted(_supplier_groups)


def track_owned(child):
    _unconfirmed_groups.add(child.pid)


def stop_owned(child, *, grace=2):
    stop_process_group(child, grace=grace)
    _unconfirmed_groups.remove(child.pid)


def install_cancellation():
    global _cancellation, _cleaning
    _cancellation, _cleaning = None, False
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, interrupted)


def wait_owned(child, args, data, timeout, started):
    while True:
        check_cancellation()
        remaining = timeout - (time.monotonic() - started)
        if remaining <= 0:
            raise subprocess.TimeoutExpired(args, timeout)
        try:
            child.communicate(data, timeout=min(remaining, 0.1))
        except subprocess.TimeoutExpired:
            # communicate retains its input offset across timeout retries.
            data = None
        else:
            return


def capture_command_diagnostics(failure, args, status, output, error, private_log):  # noqa: PLR0913, PLR0917 - one command's separate output sinks.
    try:
        result = subprocess.CompletedProcess(args, status, None, None)
        failure.__dict__["command_result"] = result
        if private_log is None:
            # Snapshot each file once, without changing a writer's shared offset
            # or reading a growing file until EOF. Keep partial capture on error.
            result.stdout = os.pread(output.fileno(), os.fstat(output.fileno()).st_size, 0).decode(
                errors="replace"
            )
            if isinstance(failure, (subprocess.CalledProcessError, subprocess.TimeoutExpired)):
                failure.output = result.stdout
            result.stderr = os.pread(error.fileno(), os.fstat(error.fileno()).st_size, 0).decode(
                errors="replace"
            )
            if isinstance(failure, (subprocess.CalledProcessError, subprocess.TimeoutExpired)):
                failure.stderr = result.stderr
        else:
            # Credential-bearing DDL output stays in its private file.
            failure.__dict__["private_log"] = str(private_log)
    except BaseException as capture_error:  # noqa: BLE001 - preserve the primary failure.
        failure.add_note(f"command diagnostic capture failed: {type(capture_error).__name__}")


def run_owned(  # noqa: C901, PLR0912, PLR0913, PLR0915 — one explicit subprocess ownership boundary
    args,
    *,
    root,
    env,
    data=None,
    timeout=180,
    before_wait=None,
    retain_supplier=False,
    private_log=None,
):
    # Output retained by descendants must not delay observing the leader's exit.
    # Ordinary commands are reclaimed before reading these private output files.
    # The credential-bearing DDL caller needs partial output after failure too.
    # Its owner-only file is retained even when wait/cleanup raises; all other
    # callers retain the existing separate temporary stdout/stderr behavior.
    with (
        (
            tempfile.TemporaryFile(mode="w+") if private_log is None else private_log.open("w+")
        ) as output,
        tempfile.TemporaryFile(mode="w+") as error,
    ):
        child = None
        retained = False
        primary_error = None
        try:
            check_cancellation()
            child = subprocess.Popen(  # noqa: S603 — explicit fixed-tool argv, private fixture inputs
                list(map(str, args)),
                cwd=root,
                env=env,
                text=True,
                stdin=subprocess.PIPE if data else subprocess.DEVNULL,
                stdout=output,
                stderr=error if private_log is None else output,
                start_new_session=True,
            )
            track_owned(child)
            started = time.monotonic()
            check_cancellation()
            if before_wait is not None:
                before_wait(child)
            wait_owned(child, args, data, timeout, started)
            retained = retain_supplier and child.returncode == 0
            if retained:
                # The caller registered the PostgreSQL cluster before starting
                # it. Transfer ownership before propagating pending cancellation.
                _supplier_groups.add(child.pid)
                _unconfirmed_groups.remove(child.pid)
        except BaseException as failure:
            primary_error = failure
            raise
        finally:
            # Only an explicitly tracked successful supplier start is retained.
            # Ordinary native/CLI commands are reclaimed even after leader exit.
            if child is not None and not retained:
                observed_status = child.returncode
                try:
                    stop_owned(child)
                except BaseException as failure:
                    diagnostic_error = primary_error or failure
                    if primary_error is None and observed_status not in (None, 0):
                        diagnostic_error = subprocess.CalledProcessError(observed_status, args)
                    capture_command_diagnostics(
                        diagnostic_error, args, observed_status, output, error, private_log
                    )
                    if primary_error is None:
                        if diagnostic_error is failure:
                            raise
                        raise diagnostic_error from failure
                    primary_error.add_note(
                        f"owned process cleanup unconfirmed: {type(failure).__name__}"
                    )
                else:
                    if primary_error is not None:
                        capture_command_diagnostics(
                            primary_error, args, observed_status, output, error, private_log
                        )
        # Keep an observed command failure and its output when cancellation
        # arrives during cleanup. The signal stays recorded for later checks.
        if child.returncode == 0:
            try:
                check_cancellation()
            except BaseException as failure:
                capture_command_diagnostics(
                    failure, args, child.returncode, output, error, private_log
                )
                raise
        output.seek(0)
        error.seek(0)
        return subprocess.CompletedProcess(args, child.returncode, output.read(), error.read())
