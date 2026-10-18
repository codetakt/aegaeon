"""Local, non-timing systemd placement prototype. Not a Hosted launcher.

Mutations are deliberately limited to owned fixture units. Unset cpusets are
rejected: the tested kernel cannot restore an empty cpuset while it has tasks.
No third-party TID is ever passed to sched_setaffinity or a signal syscall.
"""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time


PREFIX = "aegaeon-dudect-placement-fixture-"
ROOT = Path("/var/lib/aegaeon-dudect-placement-fixtures")
CGROUP = Path("/sys/fs/cgroup")


class Refused(RuntimeError):
    pass


def run(*args: str) -> str:
    result = subprocess.run(args, check=True, text=True, capture_output=True, timeout=10)
    return result.stdout.strip()


def mask(text: str) -> list[int]:
    result = set()
    for item in text.strip().replace(" ", ",").split(","):
        if not item:
            continue
        if not re.fullmatch(r"[0-9]+(?:-[0-9]+)?", item):
            raise Refused("unrecognized CPU mask")
        ends = [int(x) for x in item.split("-")]
        if ends[-1] < ends[0] or ends[-1] > 65535:
            raise Refused("invalid CPU range")
        result.update(range(ends[0], ends[-1] + 1))
    return sorted(result)


def mask_arg(cpus: list[int]) -> str:
    if not cpus:
        raise Refused("empty requested CPU set")
    return ",".join(str(x) for x in cpus)


def owned(unit: str) -> str:
    if not re.fullmatch(PREFIX + r"[a-z0-9-]+\.service", unit):
        raise Refused("prototype refuses non-owned unit")
    return unit


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def process(pid: int) -> dict:
    base = Path(f"/proc/{pid}")
    # comm can contain spaces and ')'; field 22 follows the final closing ')'.
    stat = (base / "stat").read_text().rsplit(")", 1)[1].split()
    exe = base / "exe"
    st = exe.stat()
    status = dict(line.split(":", 1) for line in (base / "status").read_text().splitlines())
    cg = (base / "cgroup").read_text().strip()
    result = {"pid": pid, "start": int(stat[19]), "uid": status["Uid"].split(),
              "exe": str(exe.resolve()), "device": st.st_dev, "inode": st.st_ino,
              "sha256": digest(exe), "cmdline_sha256": digest(base / "cmdline"), "cgroup": cg}
    if (base / "stat").read_text().rsplit(")", 1)[1].split()[19] != str(result["start"]):
        raise Refused("process identity changed during inspection")
    return result


def threads(pid: int) -> dict:
    result = {}
    for directory in Path(f"/proc/{pid}/task").iterdir():
        try:
            start = int((directory / "stat").read_text().rsplit(")", 1)[1].split()[19])
            cpus = sorted(os.sched_getaffinity(int(directory.name)))
            if int((directory / "stat").read_text().rsplit(")", 1)[1].split()[19]) == start:
                result[directory.name] = {"start": start, "cpus": cpus}
        except (FileNotFoundError, ProcessLookupError):
            continue  # Exited threads are not restoration targets.
    return result


def properties(unit: str) -> dict:
    names = ["Id", "ActiveState", "InvocationID", "ControlGroup", "MainPID", "AllowedCPUs",
             "FragmentPath", "DropInPaths", "CPUWeight", "CPUQuotaPerSecUSec", "MemoryMax",
             "CPUSchedulingPolicy", "CPUSchedulingPriority", "User", "Group"]
    raw = run("systemctl", "show", owned(unit), "--property=" + ",".join(names))
    return dict(line.split("=", 1) for line in raw.splitlines())


def files(unit: str) -> dict:
    props = properties(unit)
    paths = [props["FragmentPath"], *props["DropInPaths"].split()]
    # Include runtime files even before systemd refreshes its DropInPaths list.
    for root in ("/run/systemd/transient", "/run/systemd/system.control"):
        paths.extend(str(p) for p in (Path(root) / (unit + ".d")).glob("*.conf"))
    return {p: Path(p).read_text() for p in sorted(set(paths)) if p and Path(p).exists()}


def ancestors(cg: Path) -> dict:
    result = {}
    for parent in cg.parents:
        if not parent.is_relative_to(CGROUP):
            break
        names = ("cpuset.cpus.effective", "cpuset.mems.effective")
        if parent != CGROUP:  # Root has effective masks, not a cpuset.cpus knob.
            names += ("cpuset.cpus",)
        result[str(parent)] = {name: (parent / name).read_text().strip() for name in names}
    return result


def snapshot(unit: str) -> dict:
    props = properties(unit)
    if props["ActiveState"] != "active" or not props["InvocationID"] or not props["ControlGroup"]:
        raise Refused("unit is not active and identifiable")
    cg = CGROUP / props["ControlGroup"].lstrip("/")
    if not cg.resolve().is_relative_to(CGROUP) or cg == CGROUP:
        raise Refused("invalid unit cgroup")
    pids = set()
    for file in [cg / "cgroup.procs", *cg.glob("**/cgroup.procs")]:
        pids.update(int(p) for p in file.read_text().split())
    members = {str(pid): process(pid) for pid in sorted(pids)}
    return {"properties": props, "members": members,
            "threads": {pid: threads(int(pid)) for pid in members}, "files": files(unit),
            "cpus": mask((cg / "cpuset.cpus").read_text()),
            "effective": mask((cg / "cpuset.cpus.effective").read_text()),
            "ancestors": ancestors(cg),
            "online": Path("/sys/devices/system/cpu/online").read_text().strip(),
            "boot": Path("/proc/sys/kernel/random/boot_id").read_text().strip()}


def preflight(original: dict, measurement: dict, target: list[int], identities: dict) -> None:
    bg = original["properties"]["ControlGroup"]
    mc = measurement["properties"]["ControlGroup"]
    if mc == bg or mc.startswith(bg + "/") or bg.startswith(mc + "/"):
        raise Refused("measurement and background cgroups overlap")
    if not original["cpus"] or not mask(original["properties"]["AllowedCPUs"]):
        raise Refused("unset cpuset cannot be restored with resident tasks; no mutation")
    if original["cpus"] != mask(original["properties"]["AllowedCPUs"]):
        raise Refused("systemd and kernel CPU policy disagree")
    if not target or not set(target) <= set(original["effective"]):
        raise Refused("requested background CPUs are unavailable")
    if not measurement["effective"]:
        raise Refused("measurement CPU set is empty")
    if original["members"] != identities or not identities:
        raise Refused("unapproved member or changed process identity")


def check_override(content: str, permitted: list[list[int]]) -> None:
    """Do not erase another actor's settings in the CPU property drop-in."""
    lines = [line.strip() for line in content.splitlines()
             if line.strip() and not line.lstrip().startswith("#")]
    if not lines or lines[0] != "[Service]" or len(lines) < 2:
        raise Refused("unrecognized CPU override")
    value = []
    for line in lines[1:]:
        if not line.startswith("AllowedCPUs="):
            raise Refused("external setting in CPU override")
        parsed = mask(line.split("=", 1)[1])
        value = sorted(set(value) | set(parsed)) if parsed else []
    if value not in permitted:
        raise Refused("external CPU override value")


def journal_path(path: str | Path) -> Path:
    path = Path(path)
    if not re.fullmatch(r"[a-z0-9-]+", path.parent.name) or path.name != "state.json":
        raise Refused("invalid journal name")
    if path.parent.parent != ROOT or path.parent.is_symlink() or path.is_symlink():
        raise Refused("invalid journal location")
    for directory in (ROOT, path.parent):
        st = directory.stat()
        if st.st_uid != 0 or st.st_mode & 0o022:
            raise Refused("journal directory must be root-owned and not writable by others")
    return path


def save(path: Path, data: dict) -> None:
    path = journal_path(path)
    temporary = path.with_suffix(".new")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(data, stream, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)



def changed(original: dict, current: dict, expected: list[int], members: bool = True) -> None:
    for field in ("boot", "online", "ancestors"):
        if current[field] != original[field]:
            raise Refused(f"changed {field}")
    for field in ("Id", "ControlGroup", "CPUWeight", "CPUQuotaPerSecUSec", "MemoryMax",
                  "CPUSchedulingPolicy", "CPUSchedulingPriority", "User", "Group"):
        if current["properties"][field] != original["properties"][field]:
            raise Refused(f"changed unit {field}")
    if members and (current["members"] != original["members"] or
                    current["properties"]["InvocationID"] != original["properties"]["InvocationID"]):
        raise Refused("changed service invocation or process identity")
    if current["cpus"] != expected or mask(current["properties"]["AllowedCPUs"]) != expected:
        raise Refused("external CPU policy change or failed readback")
    if current["effective"] != expected:
        raise Refused("effective CPU constraint differs from requested constraint")
    if any(not set(t["cpus"]) <= set(expected) for ts in current["threads"].values() for t in ts.values()):
        raise Refused("thread exceeds effective CPU constraint")
    if "files" in original:
        if set(original["files"]) - set(current["files"]):
            raise Refused("external unit file removal")
        for name, content in current["files"].items():
            if name.endswith("/50-AllowedCPUs.conf"):
                check_override(content, [expected])
            elif original["files"].get(name) != content:
                raise Refused("external unit file change")


# Mutation and recovery entry points live in recovery.py.
