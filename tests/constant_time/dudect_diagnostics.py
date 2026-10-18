"""Bounded, original-run diagnostics; never an input to statistical decisions."""

from __future__ import annotations

import errno
import hashlib
import os
import platform
import re
import struct
import time
from pathlib import Path
from typing import Any, cast

from dudect_candidate import canonical
from dudect_results import BATCH_SIZE, CANDIDATE_PROFILES as PROFILES
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
    size = HEADER_SIZE + frames * (FRAME.size + BATCH_SIZE * 137)
    require(identity["bytes"] == size, "Incomplete or extra ordered sample evidence")
    with path.open("rb") as source:
        header = b"AEGTRC02" + b"".join(
            binding[key].encode("ascii")
            for key in ("build_sha256", "contract_sha256", "numerical_sha256")
        )
        require(source.read(HEADER_SIZE) == header, "Ordered sample binding mismatch")
        for batch in range(frames):
            require(
                source.read(FRAME.size) == FRAME.pack(batch, BATCH_SIZE, 128, 128),
                "Ordered sample dimensions or sequence mismatch",
            )
            source.seek(BATCH_SIZE * 8, os.SEEK_CUR)  # Original int64 timestamp order.
            classes = source.read(BATCH_SIZE)
            inputs = source.read(BATCH_SIZE * 128)
            require(set(classes) <= {0, 1}, "Invalid ordered sample class")
            require(
                all(
                    inputs[i * 128 : (i + 1) * 128] == bytes(128)
                    for i, label in enumerate(classes)
                    if label == 0
                ),
                "Invalid fixed-class comparison input",
            )
        require(source.read(1) == b"", "Trailing ordered sample evidence")
    return {**identity, "format": "AEGTRC02", "frames": frames, "complete": True}


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


def mapping_fields(line: str) -> dict[str, Any] | None:
    """Keep address relationships without retaining paths or named-map labels."""
    match = re.fullmatch(
        r"([0-9a-fA-F]{1,16})-([0-9a-fA-F]{1,16}) ([r-][w-][x-][ps]) "
        r"([0-9a-fA-F]{1,16}) ([0-9a-fA-F]{1,8}):([0-9a-fA-F]{1,8}) "
        r"([0-9]{1,20})(?:\s+(.*))?",
        line,
    )
    if match is None:
        return None
    start, end, permissions, offset, major, minor, inode, label = match.groups()
    begin, limit, identity = int(start, 16), int(end, 16), int(inode)
    if begin >= limit or identity >= 2**64:
        return None
    kinds = {f"[{name}]": name for name in ("heap", "stack", "vdso", "vvar", "vsyscall")}
    return {
        "start": begin,
        "end": limit,
        "permissions": permissions,
        "file_offset": int(offset, 16),
        "device": [int(major, 16), int(minor, 16)],
        "inode": identity,
        "reported_kind": kinds.get(label, "file_or_named_mapping" if label else "anonymous"),
    }


def layout_fields(value: str) -> dict[str, Any]:
    lines = value.splitlines()
    if not 0 < len(lines) <= 1024:
        return {"unavailable": "mapping count"}
    mappings = [mapping_fields(line) for line in lines]
    end = 0
    for mapping in mappings:
        if mapping is None or mapping["start"] < end:
            return {"unavailable": "invalid or overlapping mappings"}
        end = mapping["end"]
    return {"mappings": mappings, "pathnames": "excluded"}


def memory_layout(pid: int) -> dict[str, Any]:
    """Read only the owned waiting task; malformed/denied telemetry stays explicit."""
    try:
        source = read_optional(f"/proc/{pid}/maps")
    except UnicodeError:
        return {"unavailable": "mapping encoding"}
    if "value" in source:
        source = layout_fields(source["value"])
    if "mappings" in source:
        try:
            executable = Path(f"/proc/{pid}/exe").stat()
            source["executable_identity"] = {
                "device": [os.major(executable.st_dev), os.minor(executable.st_dev)],
                "inode": executable.st_ino,
            }
        except OSError as error:
            source["executable_identity"] = {"unavailable_errno": error.errno}
    return source


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
            # Before launch and after exit there is no live native process to
            # inspect. Do not label the collector mask or a stale mask as native.
            "native_affinity": affinity if pid is not None else None,
            "native_pid": pid,
            "collector_affinity": sorted(os.sched_getaffinity(0))
            if hasattr(os, "sched_getaffinity")
            else None,
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
            record["native_process"]["memory_layout"] = memory_layout(pid)
        record["capture_finished_monotonic_ns"] = time.monotonic_ns()
        self.output.write(canonical(record) + b"\n")
        self.output.flush()


def validate_diagnostics(
    output: Path, process: dict[str, Any], bindings: dict[str, Any], profile: str
) -> None:
    # Avoid a module cycle: timing shares the immutable diagnostic file helper.
    from dudect_affinity import validate_placement  # noqa: PLC0415
    from dudect_process import load_json  # noqa: PLC0415
    from dudect_timing import TIMING_NAME, validate_timing  # noqa: PLC0415

    diagnostics = process.get("diagnostics")
    require(isinstance(diagnostics, dict), "Missing original-run diagnostics")
    diagnostics = cast("dict[str, Any]", diagnostics)
    require(
        diagnostics.get("runtime") == file_identity(output / CONTEXT_NAME),
        "Runtime diagnostic identity mismatch",
    )
    require(
        diagnostics.get("affinity") == file_identity(output / "affinity.json"),
        "CPU affinity diagnostic identity mismatch",
    )
    validate_placement(
        process,
        load_json((output / "affinity.json").read_bytes()),
        [load_json(line) for line in (output / CONTEXT_NAME).read_bytes().splitlines()],
    )
    require(
        diagnostics.get("timing")
        == validate_timing(
            output / TIMING_NAME,
            bindings,
            profile,
            load_json((output / "observations.json").read_bytes()),
        ),
        "All-case timing diagnostic identity mismatch",
    )
    if profile == "pr":
        require(
            diagnostics.get("sparse") == file_identity(output / "sparse-prefixes.jsonl"),
            "Sparse evidence identity mismatch",
        )
    if "ct_eq_128" in bindings:
        require(
            diagnostics.get("samples")
            == validate_trace(output / TRACE_NAME, bindings["ct_eq_128"], profile),
            "Ordered sample diagnostic identity mismatch",
        )
