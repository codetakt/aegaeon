"""Bounded, original-run diagnostics; never an input to statistical decisions."""

from __future__ import annotations

import errno
import hashlib
import os
import platform
import struct
import time
from pathlib import Path
from typing import Any, cast

from dudect_candidate import canonical
from dudect_results import BATCH_SIZE, PROFILES
from dudect_support import require

TRACE_NAME = "native.samples"
TRACE_ENV = "AEGAEON_DUDECT_TRACE_FD"
CONTEXT_NAME = "runtime.jsonl"
HEADER_SIZE = 200
FRAME = struct.Struct("<4Q")


def file_identity(path: Path) -> dict[str, Any]:
    require(path.is_file() and not path.is_symlink(), "Missing regular diagnostic file")
    with path.open("rb") as source:
        sha = hashlib.file_digest(source, "sha256").hexdigest()
    return {"sha256": sha, "bytes": path.stat().st_size}


def validate_trace(path: Path, binding: dict[str, Any], profile: str) -> dict[str, Any]:
    """Validate complete framing and binding, without changing the inference."""
    identity = file_identity(path)
    frames = PROFILES[profile][0][-1] + 1  # Includes the independent pilot.
    size = HEADER_SIZE + frames * (FRAME.size + BATCH_SIZE * 41)
    require(identity["bytes"] == size, "Incomplete or extra ordered sample evidence")
    with path.open("rb") as source:
        header = b"AEGTRC01" + b"".join(
            binding[key].encode("ascii")
            for key in ("build_sha256", "contract_sha256", "numerical_sha256")
        )
        require(source.read(HEADER_SIZE) == header, "Ordered sample binding mismatch")
        for batch in range(frames):
            require(
                source.read(FRAME.size) == FRAME.pack(batch, BATCH_SIZE, 128, 32),
                "Ordered sample dimensions or sequence mismatch",
            )
            source.seek(BATCH_SIZE * 8, os.SEEK_CUR)  # Original int64 timestamp order.
            classes = source.read(BATCH_SIZE)
            inputs = source.read(BATCH_SIZE * 32)
            require(set(classes) <= {0, 1}, "Invalid ordered sample class")
            require(
                all(
                    inputs[i * 32 : (i + 1) * 32] == bytes(32)
                    for i, label in enumerate(classes)
                    if label == 0
                ),
                "Invalid fixed-class comparison input",
            )
        require(source.read(1) == b"", "Trailing ordered sample evidence")
    return {**identity, "format": "AEGTRC01", "frames": frames, "complete": True}


def read_optional(path: str) -> dict[str, Any]:
    """Missing/privileged telemetry remains an explicit limitation, not a pass."""
    try:
        with Path(path).open() as source:
            value = source.read(65537)
        if len(value) > 65536:
            return {"unavailable": "size limit"}
        return {"value": value.strip()}
    except OSError as error:
        return {"unavailable_errno": error.errno}


def msr(cpu: int) -> dict[str, Any]:
    try:
        fd = os.open(f"/dev/cpu/{cpu}/msr", os.O_RDONLY | os.O_CLOEXEC)
        try:
            counters = {}
            for name, register in (("aperf", 0xE8), ("mperf", 0xE7)):
                value = os.pread(fd, 8, register)
                if len(value) != 8:
                    raise OSError(errno.EIO, "Incomplete MSR read")
                counters[name] = int.from_bytes(value, "little")
            return counters
        finally:
            os.close(fd)
    except OSError as error:
        return {"unavailable_errno": error.errno}


def speculation_policy(pid: int) -> dict[str, Any]:
    """Retain the owned task's reported policy, without changing or inferring it."""
    status = read_optional(f"/proc/{pid}/status")
    if "value" not in status:
        return status
    allowed = (
        "Speculation_Store_Bypass",
        "SpeculationIndirectBranch",
        "NoNewPrivs",
        "Seccomp",
    )
    fields = {
        key.strip(): value.strip()
        for line in status["value"].splitlines()
        if ":" in line
        for key, value in (line.split(":", 1),)
        if key.strip() in allowed
    }
    return {"fields": fields, "missing_fields": [key for key in allowed if key not in fields]}


def cpu_identity() -> dict[str, Any]:
    try:
        with Path("/proc/cpuinfo").open() as source:
            first = source.read(65536).split("\n\n", 1)[0]
        allowed = {
            "vendor_id",
            "cpu family",
            "model",
            "model name",
            "stepping",
            "microcode",
            "cpu MHz",
            "cache size",
            "flags",
        }
        return {
            key.strip(): value.strip()
            for line in first.splitlines()
            if ":" in line
            for key, value in (line.split(":", 1),)
            if key.strip() in allowed
        }
    except OSError as error:
        return {"unavailable_errno": error.errno}


class RuntimeCapture:
    """Snapshot while native work awaits ACK, never poll inside measured loops."""

    def __init__(self, output: Any) -> None:
        self.output = output
        self.cpus = sorted(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else []
        require(len(self.cpus) <= 4096, "Unbounded CPU affinity")
        # Limit expensive optional per-CPU telemetry on unpinned CI hosts.
        self.telemetry_cpus = self.cpus[:64]

    def snapshot(self, phase: str, pid: int | None = None, **look: Any) -> None:
        affinity: Any = self.cpus
        if pid is not None and hasattr(os, "sched_getaffinity"):
            try:
                affinity = sorted(os.sched_getaffinity(pid))
                self.cpus = affinity
                self.telemetry_cpus = affinity[:64]
            except OSError as error:
                affinity = {"unavailable_errno": error.errno}
        record: dict[str, Any] = {
            "phase": phase,
            "monotonic_ns": time.monotonic_ns(),
            "unix_time_ns": time.time_ns(),
            "native_affinity": affinity,
            "telemetry_cpu_limit": 64,
            **look,
            "system": {
                name: read_optional(f"/proc/{name}")
                for name in ("stat", "loadavg", "meminfo", "pressure/cpu", "pressure/io")
            },
            "cpus": {
                str(cpu): {
                    "msr": msr(cpu),
                    "frequency": {
                        name: read_optional(f"/sys/devices/system/cpu/cpu{cpu}/cpufreq/{name}")
                        for name in ("scaling_cur_freq", "scaling_governor")
                    },
                }
                for cpu in self.telemetry_cpus
            },
        }
        if phase == "start":
            record["platform"] = {
                "kernel": platform.release(),
                "machine": platform.machine(),
                "cpu_info": cpu_identity(),
                "boot_id": read_optional("/proc/sys/kernel/random/boot_id"),
                "isolation": {
                    name: read_optional(f"/sys/devices/system/cpu/{name}")
                    for name in ("isolated", "nohz_full", "smt/active", "online")
                },
                "clocksource": read_optional(
                    "/sys/devices/system/clocksource/clocksource0/current_clocksource"
                ),
                "spec_store_bypass": read_optional(
                    "/sys/devices/system/cpu/vulnerabilities/spec_store_bypass"
                ),
            }
        if pid is not None:
            record["native_process"] = {
                name: read_optional(f"/proc/{pid}/{name}")
                for name in ("stat", "sched", "schedstat")
            }
            record["native_process"]["speculation_policy"] = speculation_policy(pid)
        record["capture_finished_monotonic_ns"] = time.monotonic_ns()
        self.output.write(canonical(record) + b"\n")
        self.output.flush()


def validate_diagnostics(
    output: Path, process: dict[str, Any], bindings: dict[str, Any], profile: str
) -> None:
    # Avoid a module cycle: timing shares the immutable diagnostic file helper.
    from dudect_timing import TIMING_NAME, validate_timing  # noqa: PLC0415

    diagnostics = process.get("diagnostics")
    require(isinstance(diagnostics, dict), "Missing original-run diagnostics")
    diagnostics = cast("dict[str, Any]", diagnostics)
    require(
        diagnostics.get("runtime") == file_identity(output / CONTEXT_NAME),
        "Runtime diagnostic identity mismatch",
    )
    require(
        diagnostics.get("timing") == validate_timing(output / TIMING_NAME, bindings, profile),
        "All-case timing diagnostic identity mismatch",
    )
    if "ct_eq_128" in bindings:
        require(
            diagnostics.get("samples")
            == validate_trace(output / TRACE_NAME, bindings["ct_eq_128"], profile),
            "Ordered sample diagnostic identity mismatch",
        )
