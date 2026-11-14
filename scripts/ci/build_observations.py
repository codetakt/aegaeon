"""Timestamp the full Nix build log without changing its command or exit status."""

from __future__ import annotations

import json
import os
import selectors
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

if TYPE_CHECKING:
    from collections.abc import Callable
    from typing import BinaryIO

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "validation"))
import process_cleanup_receipts as cleanup_receipts
from database_execution import cancellation_scope, check_cancellation, stop_process_group

MAX_BYTES = 64 * 1024 * 1024


FAILURE_STDERR_BYTES = 256 * 1024
FAILURE_STDERR_SECONDS = 0.1
FAILURE_STDERR_READS = 32


def preserve_failure_output(  # noqa: C901, PLR0912, PLR0915 - bounded failure-only snapshot and delivery boundary
    output: BinaryIO,
    pending: bytes,
    attempted: bytes,
    forward: Callable[[bytes], None],
    failure: BaseException,
) -> None:
    """Snapshot available bytes, never await EOF or resend an attempted fragment."""
    chunks = [pending] if pending else []
    size = len(attempted) + len(pending)
    deadline = time.monotonic() + FAILURE_STDERR_SECONDS
    state: dict[str, Any] = {
        "byte_limit": FAILURE_STDERR_BYTES,
        "seconds_limit": FAILURE_STDERR_SECONDS,
        "read_limit": FAILURE_STDERR_READS,
        "attempted_bytes_not_resent": len(attempted),
        "reason": "read_limit",
        "reads": 0,
        "capture_error": None,
        "forward_errors": [],
    }
    try:
        descriptor = output.fileno()
        os.set_blocking(descriptor, False)
        for _ in range(FAILURE_STDERR_READS):
            if size >= FAILURE_STDERR_BYTES:
                state["reason"] = "byte_limit"
                break
            if time.monotonic() >= deadline:
                state["reason"] = "time_limit"
                break
            state["reads"] += 1
            try:
                chunk = os.read(descriptor, min(16384, FAILURE_STDERR_BYTES - size))
            except BlockingIOError:
                state["reason"] = "would_block"
                break
            except InterruptedError:
                continue
            if not chunk:
                state["reason"] = "eof"
                break
            chunks.append(chunk)
            size += len(chunk)
        if size >= FAILURE_STDERR_BYTES:
            state["reason"] = "byte_limit"
    except BaseException as error:  # noqa: BLE001 - diagnostics cannot replace the primary failure.
        state["reason"] = "capture_error"
        state["capture_error"] = type(error).__name__
        failure.add_note(f"stderr recovery capture failed: {type(error).__name__}")
    captured = attempted + b"".join(chunks)
    # Attach every captured byte before fallible synchronous output delivery.
    cast("Any", failure).observed_stderr = captured
    cast("Any", failure).stderr_recovery = state
    if (
        isinstance(failure, (subprocess.CalledProcessError, subprocess.TimeoutExpired))
        and failure.stderr is None
    ):
        failure.stderr = captured
    state["captured_bytes"] = len(captured)
    failure.add_note(
        f"stderr recovery snapshot: {len(captured)} bytes; {state['reason']}; "
        "later writes may be omitted; delivery assumes output sinks make progress"
    )
    for chunk in chunks:
        try:
            forward(chunk)
        except BaseException as error:  # noqa: BLE001 - preserve the original command/cancellation error.
            state["forward_errors"].append(type(error).__name__)
            failure.add_note(f"stderr recovery forwarding failed: {type(error).__name__}")


def observe_process(  # noqa: C901, PLR0912, PLR0915 - one child ownership and finalizer boundary
    command: list[str],
    forward: Callable[[bytes], None],
    *,
    status_observed: Callable[[int], None] | None = None,
) -> int:
    process = None
    cleaned = False
    status = None
    primary_error: BaseException | None = None
    receipt = cleanup_receipts.begin()
    try:
        check_cancellation()
        process = subprocess.Popen(command, stderr=subprocess.PIPE, start_new_session=True)
        output = cast("BinaryIO", process.stderr)  # Popen creates this configured PIPE.
        with output:
            pending = attempted = b""
            try:
                cleanup_receipts.update(receipt, group=process.pid)
                check_cancellation()
                with selectors.DefaultSelector() as watcher:
                    watcher.register(output, selectors.EVENT_READ)
                    while True:
                        # A failure already observed before cleanup remains primary.
                        # Keep draining its output while retaining cancellation state.
                        if process.returncode in (None, 0):
                            check_cancellation()
                        observed = process.poll()
                        if observed is not None:
                            status = observed
                            if status_observed is not None:
                                status_observed(status)
                            if not cleaned:
                                try:
                                    stop_process_group(process, grace=10)
                                except BaseException as failure:
                                    if status:
                                        raise subprocess.CalledProcessError(
                                            status, command
                                        ) from failure
                                    raise
                                cleaned = True
                                cleanup_receipts.update(receipt, confirmed=True)
                        if not watcher.select(timeout=0.1):
                            continue
                        chunk = os.read(output.fileno(), 16384)
                        if not chunk:
                            if pending:
                                attempted, pending = pending, b""
                                forward(attempted)
                                attempted = b""
                            break
                        pending += chunk
                        while len(pending) >= 16384 or b"\n" in pending:
                            newline = pending.find(b"\n", 0, 16384)
                            length = newline + 1 if newline >= 0 else 16384
                            attempted, pending = pending[:length], pending[length:]
                            forward(attempted)
                            attempted = b""
            except BaseException as failure:
                diagnostic_error = failure
                if status and not isinstance(failure, subprocess.CalledProcessError):
                    # Receipt/callback/output publication cannot replace a command
                    # failure already observed. Keep the secondary error as cause.
                    diagnostic_error = subprocess.CalledProcessError(status, command)
                try:
                    preserve_failure_output(output, pending, attempted, forward, diagnostic_error)
                except BaseException as recovery_error:  # noqa: BLE001 - the primary failure stays authoritative.
                    diagnostic_error.add_note(
                        f"stderr recovery failed: {type(recovery_error).__name__}"
                    )
                if diagnostic_error is not failure:
                    raise diagnostic_error from failure
                raise
        while process.poll() is None:
            check_cancellation()
            time.sleep(0.05)
        status = process.wait()
        if status_observed is not None:
            status_observed(status)
        if status == 0:
            check_cancellation()
        return status  # noqa: TRY300 - return remains inside the owned finalizer boundary.
    except BaseException as failure:
        if status and not isinstance(failure, subprocess.CalledProcessError):
            # Also cover the final status callback after the pipe is closed;
            # its already forwarded output remains in the observation trace.
            primary_error = subprocess.CalledProcessError(status, command)
            raise primary_error from failure
        primary_error = failure
        raise
    finally:
        if process is not None and not cleaned:
            try:
                stop_process_group(process, grace=10)
                cleanup_receipts.update(receipt, confirmed=True)
            except BaseException as failure:
                if primary_error is None:
                    if status:
                        raise subprocess.CalledProcessError(status, command) from failure
                    raise
                primary_error.add_note(
                    f"observed process cleanup unconfirmed: {type(failure).__name__}"
                )


def run_observed(command: list[str], path: Path) -> None:  # noqa: C901, PLR0915 - one command/trace lifetime.
    path.parent.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    identifier = uuid.uuid4().hex
    size = 0
    truncated = False
    primary_error = None
    try:
        with cancellation_scope(), path.open("a") as trace:

            def record(value: dict[str, Any]) -> None:
                nonlocal size, truncated
                row = (
                    json.dumps(
                        {
                            "invocation": identifier,
                            "unix_time": time.time(),
                            "elapsed_seconds": time.monotonic() - started,
                            **value,
                        }
                    )
                    + "\n"
                )
                if size + len(row.encode()) > MAX_BYTES and value["event"] == "output":
                    truncated = True
                    return
                trace.write(row)
                trace.flush()
                size += len(row.encode())

            record(
                {
                    "event": "start",
                    "command": command,
                    "context": {
                        key: os.environ.get(key)
                        for key in (
                            "GITHUB_REPOSITORY",
                            "GITHUB_RUN_ID",
                            "GITHUB_RUN_ATTEMPT",
                            "GITHUB_SHA",
                            "GITHUB_EVENT_NAME",
                            "RUNNER_ARCH",
                            "RUNNER_OS",
                        )
                    },
                    "scope": (
                        "observed log delivery times; not CPU time, exact test duration "
                        "or cache-hit inference"
                    ),
                }
            )

            def forward(chunk: bytes) -> None:
                # Preserve complete stderr and the existing bounded line records.
                sys.stderr.buffer.write(chunk)
                sys.stderr.buffer.flush()
                record({"event": "output", "text": chunk.decode(errors="replace")})

            status = None

            def observed_status(value: int) -> None:
                nonlocal status
                status = value

            try:
                status = observe_process(command, forward, status_observed=observed_status)
                if status:
                    raise subprocess.CalledProcessError(status, command)  # noqa: TRY301 - preserve command failure before finalization.
            except BaseException as failure:
                primary_error = failure
                raise
            finally:
                try:
                    record({"event": "finish", "returncode": status, "truncated": truncated})
                except BaseException as failure:
                    if primary_error is None:
                        raise
                    primary_error.add_note(
                        f"observation finish record failed: {type(failure).__name__}"
                    )
    except BaseException as failure:
        if primary_error is not None and failure is not primary_error:
            primary_error.add_note(f"observation trace close failed: {type(failure).__name__}")
            raise primary_error  # noqa: B904 - keep its original cleanup cause; close failure is a note.
        raise
