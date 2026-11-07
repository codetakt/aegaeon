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
from database_execution import cancellation_scope, cleanup_cancellation_guard, stop_process_group

MAX_BYTES = 64 * 1024 * 1024


def observe_process(command: list[str], forward: Callable[[bytes], None]) -> int:
    process = None
    cleaned = False
    try:
        with cleanup_cancellation_guard():
            process = subprocess.Popen(command, stderr=subprocess.PIPE, start_new_session=True)
        output = cast("BinaryIO", process.stderr)  # Popen creates this configured PIPE.
        with output, selectors.DefaultSelector() as watcher:
            watcher.register(output, selectors.EVENT_READ)
            pending = b""
            while True:
                if process.poll() is not None and not cleaned:
                    stop_process_group(process, grace=10)
                    cleaned = True
                if not watcher.select(timeout=0.1):
                    continue
                chunk = os.read(output.fileno(), 16384)
                if not chunk:
                    if pending:
                        forward(pending)
                    break
                pending += chunk
                while len(pending) >= 16384 or b"\n" in pending:
                    newline = pending.find(b"\n", 0, 16384)
                    length = newline + 1 if newline >= 0 else 16384
                    forward(pending[:length])
                    pending = pending[length:]
        return process.wait()
    finally:
        if process is not None and not cleaned:
            stop_process_group(process, grace=10)


def run_observed(command: list[str], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    identifier = uuid.uuid4().hex
    size = 0
    truncated = False
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
        try:
            status = observe_process(command, forward)
            if status:
                raise subprocess.CalledProcessError(status, command)
        finally:
            record({"event": "finish", "returncode": status, "truncated": truncated})
