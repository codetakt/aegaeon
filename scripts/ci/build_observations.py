"""Timestamp the full Nix build log without changing its command or exit status."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import uuid
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pathlib import Path

MAX_BYTES = 64 * 1024 * 1024


def run_observed(command: list[str], path: Path) -> None:  # noqa: PLR0915 - one process lifecycle
    path.parent.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    identifier = uuid.uuid4().hex
    size = 0
    truncated = False
    with path.open("a") as trace:

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
        status = None
        try:
            process = subprocess.Popen(command, stderr=subprocess.PIPE)
            output = process.stderr
            if output is None:
                raise RuntimeError("Nix stderr pipe is unavailable")
            try:
                with output:
                    for chunk in iter(lambda: output.readline(16384), b""):
                        # Preserve the existing stderr, including every failure.
                        sys.stderr.buffer.write(chunk)
                        sys.stderr.buffer.flush()
                        record({"event": "output", "text": chunk.decode(errors="replace")})
                status = process.wait()
            finally:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=10)
            if status:
                raise subprocess.CalledProcessError(status, command)
        finally:
            record({"event": "finish", "returncode": status, "truncated": truncated})
