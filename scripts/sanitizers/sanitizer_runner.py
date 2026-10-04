#!/usr/bin/env python3
"""Launch the sanitizer controller from its fixed physical support package."""

from __future__ import annotations

import contextlib
import os
import signal
import sys
from dataclasses import asdict
from pathlib import Path

# Isolated mode excludes cwd/PYTHONPATH. Only the physical helper directory is added.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from sanitizer_support.core import (  # noqa: F401 - retained direct controller interfaces
    Failure,
    Interrupted,
    Settings,
    parse_json,
)
from sanitizer_support.execution import Supervisor
from sanitizer_support.protocol import (  # noqa: F401 - retained evidence interfaces
    completed,
    listed,
    target_inventory,
    target_selector,
)
from sanitizer_support.supervision import (  # noqa: F401 - retained supervision interfaces
    group_alive,
    interrupted,
    terminate,
)


def report(message: str, *, error: bool = False) -> Exception | None:
    """Flush here so terminal failure cannot override a chosen exit at shutdown."""
    stream = sys.stderr if error else sys.stdout
    try:
        print(message, file=stream, flush=True)
    except Exception as caught:  # noqa: BLE001 - caller records terminal failures
        # Buffered stream shutdown otherwise replaces the primary status with 120.
        with contextlib.suppress(Exception):
            descriptor = os.open(os.devnull, os.O_WRONLY)
            try:
                os.dup2(descriptor, stream.fileno())
            finally:
                os.close(descriptor)
        return caught
    return None


def finish(supervisor: Supervisor, status: int) -> int:
    summary = supervisor.summary
    if status == 0:
        message = (
            "[INFO] Sanitizer-backed tests completed; evidence: "
            f"{supervisor.artifacts / 'run-summary.json'}"
        )
    else:
        message = f"[FAIL] Sanitizer execution failed: {summary.get('error', 'unknown failure')}"
    logging_error = report(message, error=status != 0)
    if logging_error is not None:
        logging_status = getattr(logging_error, "status", 1)
        summary.update(
            status="failed", logging_error=str(logging_error), logging_exit_code=logging_status
        )
        status = status or logging_status
    summary["exit_code"] = status
    try:
        if supervisor.artifacts.is_dir():
            supervisor.save()
    except Exception as error:  # noqa: BLE001 - final evidence failure cannot succeed
        summary["status"] = "failed"
        status = status or getattr(error, "status", 1)
        report(f"[FAIL] Sanitizer evidence write failed: {error}", error=True)
    return status


def main() -> int:
    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, interrupted)
    settings = Settings(*sys.argv[1:])
    workspace = Path.cwd().resolve()
    # Preserve the admitted lexical route instead of resolving a replacement.
    artifacts = Path(settings.artifact_text).absolute()
    summary = {
        "status": "failed",
        "workspace": str(workspace),
        "host": settings.host,
        "settings": asdict(settings),
        "commands": [],
        "units": [],
    }
    if os.environ.get("SANITIZER_INVOCATION_BINDING"):
        summary["invocation"] = parse_json(os.environ["SANITIZER_INVOCATION_BINDING"])
    try:
        supervisor = Supervisor(artifacts, summary)
    except Exception as error:  # noqa: BLE001 - unsafe evidence must never receive writes
        report(f"[FAIL] Sanitizer evidence admission failed: {error}", error=True)
        return getattr(error, "status", 1)
    exit_status = 0
    try:
        supervisor.execute(settings, workspace)
        summary["status"] = "completed"
    except Exception as error:  # noqa: BLE001 - failure receipt covers malformed external evidence
        summary["error"] = str(error)
        exit_status = getattr(error, "status", 1)
    return finish(supervisor, exit_status)


if __name__ == "__main__":
    raise SystemExit(main())
