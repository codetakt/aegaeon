"""Private bounded Linux resource observer; does not run or govern build commands.

No argv, environment, executable symlink, credentials or arbitrary file contents
are emitted. Missing readings remain errors, never synthetic zero measurements.
Output is flushed each sample so job-finalization upload is not the only record.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable

MAX_READ = 65536
MAX_PIDS = 4096
MEMORY = {
    "MemTotal",
    "MemFree",
    "MemAvailable",
    "SwapTotal",
    "SwapFree",
    "CommitLimit",
    "Committed_AS",
}
VMSTAT = {"oom_kill", "pswpin", "pswpout", "pgmajfault"}
PROCESS_FIELDS = {"VmRSS", "VmHWM", "VmSwap", "Threads"}
CGROUP_EVENTS = {"low", "high", "max", "oom", "oom_kill", "oom_group_kill"}
PROCESS_CLASSES = {
    "rustc",
    "cargo",
    "cc1plus",
    "cc1",
    "ld",
    "ld.lld",
    "nix",
    "nix-daemon",
    "Runner.Listener",
    "Runner.Worker",
}


def read(path: Path) -> str:
    with path.open("rb") as f:
        data = f.read(MAX_READ + 1)
    if len(data) > MAX_READ:
        raise ValueError("read_bound_exceeded")
    return data.decode("ascii")


def integers(path: Path, allowed: set[str], *, colon: bool = False) -> dict[str, int]:
    result = {}
    for line in read(path).splitlines():
        fields = line.replace(":", " ", 1).split() if colon else line.split()
        if fields and fields[0] in allowed:
            if len(fields) not in (2, 3) or not fields[1].isdigit():
                raise ValueError("invalid_numeric_field")
            if len(fields) == 3 and fields[2] != "kB":
                raise ValueError("unexpected_unit")
            result[fields[0]] = int(fields[1])
    if not result:
        raise ValueError("no_selected_fields")
    return result


def observed(function: Callable[[], object]) -> dict[str, Any]:
    try:
        return {"value": function()}
    except (OSError, ValueError, UnicodeError, subprocess.SubprocessError) as exc:
        return {"unavailable": type(exc).__name__, "errno": getattr(exc, "errno", None)}


def processes(proc: Path) -> dict[str, Any]:
    names = [p for p in proc.iterdir() if p.name.isdigit()]
    if len(names) > MAX_PIDS:
        raise ValueError("pid_inventory_bound_exceeded")
    rows: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    for path in names:
        try:
            before = read(path / "stat")
            # comm can contain spaces and parentheses; split after its final ')'.
            start = before.rsplit(")", 1)[1].split()[19]
            status = integers(path / "status", PROCESS_FIELDS, colon=True)
            after = read(path / "stat").rsplit(")", 1)[1].split()[19]
            if start != after:
                raise ValueError("process_identity_changed")  # noqa: TRY301 - retain per-PID race
            comm = read(path / "comm").strip() if (path / "comm").exists() else ""
            rows.append(
                {
                    "pid": int(path.name),
                    "start_ticks": int(start),
                    "class": comm if comm in PROCESS_CLASSES else "other",
                    **status,
                }
            )
        except (OSError, ValueError, IndexError, UnicodeError) as exc:
            errors.append(
                {
                    "pid": int(path.name),
                    "unavailable": type(exc).__name__,
                    "errno": getattr(exc, "errno", None),
                }
            )
    # Per-process RSS sums can double-count shared pages. These are observations,
    # not a claim of exclusive memory use or an atomic process census.
    return {
        "seen": len(names),
        "read": len(rows),
        "errors": errors[:16],
        "error_count": len(errors),
        "top_rss": sorted(rows, key=lambda r: r.get("VmRSS", -1), reverse=True)[:12],
        "runner_processes": [r for r in rows if r["class"].startswith("Runner.")][:16],
        "sample_is_atomic": False,
    }


def cgroup_values(root: Path) -> dict[str, Any]:
    result = {}
    for name in (
        "memory.current",
        "memory.peak",
        "memory.max",
        "memory.swap.current",
        "memory.swap.max",
        "pids.current",
        "pids.max",
    ):

        def scalar(name: str = name) -> str | int:
            value = read(root / name).strip()
            if value != "max" and not value.isdigit():
                raise ValueError("invalid_scalar")
            return value if value == "max" else int(value)

        result[name] = observed(scalar)
    result["memory.events"] = observed(lambda: integers(root / "memory.events", CGROUP_EVENTS))
    return result


def cgroups(
    proc: Path, rows: list[dict[str, Any]], root: Path = Path("/sys/fs/cgroup")
) -> dict[str, Any]:
    groups = {root.resolve()}
    for pid in [os.getpid()] + [r["pid"] for r in rows]:
        try:
            for line in read(proc / str(pid) / "cgroup").splitlines():
                if line.startswith("0::/"):
                    p = (root / line[4:]).resolve()
                    if not p.is_relative_to(root.resolve()):
                        raise ValueError("cgroup_path_escape")  # noqa: TRY301 - mark incomplete membership
                    # Include ancestors: an OOM limit may belong to a parent.
                    while p.is_relative_to(root.resolve()):
                        groups.add(p)
                        p = p.parent
        except (OSError, UnicodeError, ValueError):
            continue  # Host counters remain separate; missing membership is recorded below.
    if len(groups) > 64:
        raise ValueError("cgroup_inventory_bound")
    return {
        "memberships_complete": False,
        "groups": [
            {
                "id": hashlib.sha256(str(p).encode()).hexdigest()[:16],
                "host_root": p == root.resolve(),
                "values": cgroup_values(p),
            }
            for p in sorted(groups)
        ],
    }


def kernel_oom() -> dict[str, Any]:
    # Do not emit kernel messages or command names; only matching event counts
    # and victim PIDs. Access failures remain unavailable, not a zero count.
    result = subprocess.run(
        ["sudo", "-n", "journalctl", "-k", "-b", "-n", "200", "--no-pager", "-o", "json"],
        capture_output=True,
        timeout=2,
        check=True,
    )
    if len(result.stdout) > 1024 * 1024:
        raise ValueError("kernel_record_bound")
    events = []
    for line in result.stdout.decode().splitlines():
        row = json.loads(line)
        message = row.get("MESSAGE", "")
        if isinstance(message, str) and re.search(
            r"out of memory|oom-kill|killed process", message, re.IGNORECASE
        ):
            match = re.search(r"Killed process (\d+)", message, re.IGNORECASE)
            events.append(
                {
                    "timestamp": row.get("__MONOTONIC_TIMESTAMP"),
                    "victim_pid": int(match[1]) if match else None,
                }
            )
    return {"last_records_limit": 200, "events": events, "complete_kernel_history": False}


def runner_events() -> dict[str, Any]:
    files = sorted(
        Path("/home/runner/runners").glob("*/_diag/Runner_*.log"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    if not files:
        raise FileNotFoundError("runner_log_unavailable")
    with files[0].open("rb") as stream:
        stream.seek(0, 2)
        size = stream.tell()
        stream.seek(max(0, size - MAX_READ))
        lines = stream.read(MAX_READ).decode("utf-8", errors="replace").splitlines()
    kinds = ("shutdown", "cancel", "unload", "signal", "renew", "exception", "error", "finish")
    events = []
    for line in lines:
        selected = [kind for kind in kinds if kind in line.lower()]
        stamp = re.match(r"\[(\d{4}-\d\d-\d\d \d\d:\d\d:\d\dZ)", line)
        if selected:
            events.append({"timestamp": stamp[1] if stamp else None, "kinds": selected})
    return {"bytes": size, "tail_bound": MAX_READ, "events": events[-32:]}


def sample(proc: Path) -> dict[str, Any]:
    census = observed(lambda: processes(proc))
    return {
        "schema": 2,
        "unix_time_ns": time.time_ns(),
        "meminfo_kib": observed(lambda: integers(proc / "meminfo", MEMORY, colon=True)),
        "vmstat": observed(lambda: integers(proc / "vmstat", VMSTAT)),
        "processes": census,
        "cgroups": observed(
            lambda: cgroups(
                proc,
                census.get("value", {}).get("top_rss", [])
                + census.get("value", {}).get("runner_processes", []),
            )
        ),
        "kernel_oom": observed(kernel_oom),
        "runner_events": observed(runner_events),
        "scope": "read-only diagnostic; no command environment or arguments",
    }


def monitor(
    proc: Path, interval: float, duration: float, emit: Callable[..., object] = print
) -> None:
    if not 1 <= interval <= 60 or not 0 < duration <= 7200:
        raise ValueError("interval or duration outside fixed budget")
    start = time.monotonic()
    while True:
        emit("AEGAEON_RESOURCE " + json.dumps(sample(proc), separators=(",", ":")), flush=True)
        elapsed = time.monotonic() - start
        if elapsed >= duration:
            break
        time.sleep(min(interval, duration - elapsed))
    emit(
        "AEGAEON_RESOURCE_END "
        + json.dumps({"reason": "deadline", "elapsed_seconds": time.monotonic() - start}),
        flush=True,
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--interval", type=float, default=5)
    parser.add_argument("--duration", type=float, default=7200)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    if args.once:
        print(json.dumps(sample(Path("/proc")), separators=(",", ":")), flush=True)
    else:
        monitor(Path("/proc"), args.interval, args.duration)
