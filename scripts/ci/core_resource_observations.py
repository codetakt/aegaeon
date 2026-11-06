"""Stream bounded resource observations while core checks run, including failed runs."""

from __future__ import annotations

import contextlib
import json
import os
import sys
import threading
import time
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterator

from observe_disk_capacity import observe

MEMORY_FIELDS = {"MemTotal", "MemAvailable", "SwapTotal", "SwapFree"}
EVENT_FIELDS = {"low", "high", "max", "oom", "oom_kill", "oom_group_kill"}


def counters(path: Path, fields: set[str]) -> dict[str, int | str]:
    """Read only named kernel counters, never arbitrary environment or process data."""
    try:
        with path.open(encoding="ascii") as source:
            raw = source.read(65537)
    except (OSError, UnicodeError) as error:
        return {"error": str(error)}
    if len(raw) > 65536:
        return {"error": "counter file exceeds bound"}
    result: dict[str, int | str] = {}
    try:
        for line in raw.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0].removesuffix(":") in fields:
                result[parts[0].removesuffix(":")] = int(parts[1])
    except ValueError as error:
        return {"error": str(error)}
    return result


def sample() -> dict[str, object]:
    paths = [str(Path.cwd()), os.environ.get("RUNNER_TEMP", "/"), "/nix"]
    return {
        "unix_time": time.time(),
        "filesystems": [observe(path) for path in paths],
        "memory_kib": counters(Path("/proc/meminfo"), MEMORY_FIELDS),
        "root_cgroup_memory_events": counters(Path("/sys/fs/cgroup/memory.events"), EVENT_FIELDS),
        "scope": "sampled diagnostics; not peak usage or a failure-cause determination",
    }


def report() -> None:
    # Diagnostics cannot override the actual check's exit status.
    with contextlib.suppress(OSError, ValueError):
        print("core-resource-observation " + json.dumps(sample()), file=sys.stderr, flush=True)


@contextlib.contextmanager
def observations() -> Iterator[None]:
    stopped = threading.Event()

    def monitor() -> None:
        # No subprocess or privileged operation; at most the existing 120-minute
        # job bound. Streaming does not rely on a post-shutdown artifact step.
        for _ in range(240):
            report()
            if stopped.wait(30):
                break

    thread = threading.Thread(target=monitor, daemon=True, name="core-resource-observer")
    try:
        thread.start()
    except (OSError, RuntimeError):
        yield
        return
    try:
        yield
    finally:
        stopped.set()
        thread.join(timeout=1)
