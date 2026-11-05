"""Exact stopped unit publication and dedicated account custody, without start."""

from __future__ import annotations

import hashlib
import json
import os
import pwd
import re
import stat
import subprocess
from pathlib import Path

import organization_cutover_startup_inputs as inputs
import organization_recovery as recovery
from organization_recovery_store import require

UNIT_DIRECTORY = Path("/run/systemd/system")
MAX_PROCESSES = 65536
MAX_UNIT = 65536
UID_FIELDS = 4
UNIT_MODE = 0o644
EXEC_FIELDS = 10


def manager(*arguments: str) -> str:
    result = subprocess.run(  # noqa: S603 — fixed service manager and validated exact units
        ["systemctl", *arguments],  # noqa: S607 — Nix wrapper supplies the fixed systemctl
        check=True,
        capture_output=True,
        text=True,
        timeout=15,
    )
    require(len(result.stdout) <= MAX_UNIT, "service manager output bound exceeded")
    return result.stdout


def properties(unit: str) -> dict:
    names = [
        "Id",
        "LoadState",
        "FragmentPath",
        "DropInPaths",
        "NeedDaemonReload",
        "Transient",
        "User",
        "Group",
    ]
    result = dict(
        line.split("=", 1)
        for line in manager(
            "show", unit, "--no-pager", "--property=" + ",".join(names)
        ).splitlines()
    )
    require(set(result) == set(names) and result["Id"] == unit, "complete unit properties required")
    return result


def absent(unit: str) -> None:
    names = ("Id", "LoadState", "FragmentPath", "DropInPaths")
    value = dict(
        line.split("=", 1)
        for line in manager(
            "show", unit, "--no-pager", "--property=" + ",".join(names)
        ).splitlines()
    )
    require(
        value == {"Id": unit, "LoadState": "not-found", "FragmentPath": "", "DropInPaths": ""},
        "fresh unloaded unit required",
    )


def service_property(unit: str, name: str, signature: str) -> list:
    require(name in ("ExecStart", "LoadCredential"), "fixed service property required")
    path = "/org/freedesktop/systemd1/unit/" + "".join(
        c if c.isascii() and c.isalnum() else "_" + format(ord(c), "02x") for c in unit
    )
    result = subprocess.run(  # noqa: S603 — fixed D-Bus service and bounded exact unit
        [  # noqa: S607 — Nix wrapper supplies the fixed systemd tools
            "busctl",
            "--system",
            "--json=short",
            "get-property",
            "org.freedesktop.systemd1",
            path,
            "org.freedesktop.systemd1.Service",
            name,
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=15,
    )
    require(len(result.stdout) <= MAX_UNIT, "service property budget exceeded")
    value = json.loads(result.stdout)
    require(
        set(value) == {"type", "data"}
        and value["type"] == signature
        and type(value["data"]) is list,
        "service property type differs",
    )
    return value["data"]


def account_inventory(settings: dict, old_services: list, config: dict) -> list:
    excluded = {recovery.user_id(row["User"]) for row in old_services}
    for store in config["inspection"]["stores"]:
        connection = store["connection"]
        if "peer_user" in connection:
            excluded.add(recovery.user_id(connection["peer_user"]))
    selected = []
    inventory = pwd.getpwall()
    for worker in settings["workers"]:
        entry = pwd.getpwnam(worker["user"])
        require(
            entry.pw_uid != 0
            and entry.pw_gid != 0
            and entry.pw_uid not in excluded
            and entry.pw_shell.rsplit("/", 1)[-1] in ("nologin", "false")
            and os.getgrouplist(entry.pw_name, entry.pw_gid) == [entry.pw_gid]
            and all(
                other.pw_name == entry.pw_name
                or (other.pw_uid != entry.pw_uid and other.pw_gid != entry.pw_gid)
                for other in inventory
            ),
            "fresh dedicated nonlogin worker account required",
        )
        selected.append({"name": entry.pw_name, "uid": entry.pw_uid, "gid": entry.pw_gid})
    require(len({row["uid"] for row in selected}) == len(selected), "worker accounts must differ")
    return selected


def accounts(settings: dict, old_services: list, config: dict) -> list:
    selected = account_inventory(settings, old_services, config)
    no_processes({row["uid"] for row in selected})
    return selected


def no_processes(users: set[int]) -> None:
    processes = [p for p in Path("/proc").iterdir() if p.name.isdecimal()]
    require(len(processes) <= MAX_PROCESSES, "process census bound exceeded")
    for process in processes:
        try:
            status = (process / "status").read_text()
        except FileNotFoundError:
            continue
        rows = [line.split()[1:] for line in status.splitlines() if line.startswith("Uid:")]
        require(len(rows) == 1 and len(rows[0]) == UID_FIELDS, "process identity incomplete")
        require(not users.intersection(map(int, rows[0])), "selected worker account already runs")


def safe_path(path: Path | str) -> str:
    path = recovery.protected_path(path)
    require(re.fullmatch(r"/[A-Za-z0-9_./-]+", str(path)), "literal unit input path required")
    return str(path)


def render(worker: dict, account: dict, sources: list[dict]) -> str:
    # This fixed Nix artifact is not a secret source. The store directory may
    # be group writable to the trusted build group; its immutable output and
    # bytes are separately bound by the manifest. Secret paths stay stricter.
    launcher = str(inputs.LAUNCHER)
    require(
        launcher.startswith("/nix/store/")
        and re.fullmatch(r"/[A-Za-z0-9_./-]+", launcher)
        and inputs.LAUNCHER.is_file(),
        "fixed Nix worker launcher required",
    )
    lines = [
        "[Unit]",
        "Description=Aegaeon selected Organizations worker",
        "[Service]",
        "Type=exec",
        f"User={worker['user']}",
        f"Group={account['gid']}",
        f"ExecStart={launcher}",
        "WorkingDirectory=/",
        "UMask=0077",
        "Restart=no",
        "KillMode=control-group",
        "SendSIGKILL=yes",
        "Delegate=no",
        "TimeoutStartSec=15",
        "TimeoutStopSec=15",
        "NoNewPrivileges=yes",
        "CapabilityBoundingSet=",
        "AmbientCapabilities=",
        "ProtectSystem=strict",
        "ProtectHome=yes",
        "PrivateTmp=yes",
        "PrivateDevices=yes",
        "RestrictSUIDSGID=yes",
        "LockPersonality=yes",
    ]
    for row in sources:
        require(re.fullmatch(r"[a-z0-9.-]+", row["name"]), "literal credential name required")
        lines.append(f"LoadCredential={row['name']}:{safe_path(row['source'])}")
    result = "\n".join(lines) + "\n"
    require(len(result.encode()) <= MAX_UNIT, "unit input bound exceeded")
    return result


def read_unit(unit: str) -> bytes:
    path = recovery.protected_path(UNIT_DIRECTORY / unit)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as handle:
        info = os.fstat(handle.fileno())
        require(
            stat.S_ISREG(info.st_mode)
            and info.st_uid == 0
            and info.st_nlink == 1
            and stat.S_IMODE(info.st_mode) == UNIT_MODE,
            "protected generated unit required",
        )
        data = handle.read(MAX_UNIT + 1)
        require(len(data) <= MAX_UNIT, "unit input bound exceeded")
        return data


def publish(row: dict) -> None:
    unit, text = row["worker"]["unit"], row["unitText"]
    path = UNIT_DIRECTORY / unit
    recovery.protected_path(path)
    if path.exists() or path.is_symlink():
        require(read_unit(unit) == text.encode(), "conflicting existing unit fragment")
        return
    absent(unit)
    descriptor = os.open(UNIT_DIRECTORY, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        temporary = os.open(
            ".", os.O_WRONLY | os.O_TMPFILE | os.O_CLOEXEC, 0o600, dir_fd=descriptor
        )
        with os.fdopen(temporary, "wb") as output:
            output.write(text.encode())
            output.flush()
            os.fchmod(output.fileno(), 0o644)
            os.fsync(output.fileno())
            os.link(
                f"/proc/self/fd/{output.fileno()}",
                unit,
                dst_dir_fd=descriptor,
                follow_symlinks=True,
            )
            os.fsync(descriptor)
    finally:
        os.close(descriptor)
    require(read_unit(unit) == text.encode(), "published unit differs")


def definition(row: dict) -> dict:
    """Immutable definition shared by the distinct offline and serving guards."""
    unit = row["worker"]["unit"]
    require(read_unit(unit) == row["unitText"].encode(), "published unit bytes changed")
    actual = properties(unit)
    require(
        actual["LoadState"] == "loaded"
        and actual["FragmentPath"] == str(UNIT_DIRECTORY / unit)
        and not actual["DropInPaths"]
        and actual["NeedDaemonReload"] == "no"
        and actual["Transient"] == "no"
        and actual["User"] == row["account"]["name"]
        and actual["Group"] == str(row["account"]["gid"]),
        "loaded worker definition differs",
    )
    actual["ExecStart"] = service_property(unit, "ExecStart", "a(sasbttttuii)")
    require(
        len(actual["ExecStart"]) == 1
        and len(actual["ExecStart"][0]) == EXEC_FIELDS
        and actual["ExecStart"][0][:3] == [str(inputs.LAUNCHER), [str(inputs.LAUNCHER)], False],
        "loaded executable differs",
    )
    expected = sorted([item["name"], item["source"]] for item in row["sources"])
    actual["LoadCredential"] = sorted(service_property(unit, "LoadCredential", "a(ss)"))
    require(actual["LoadCredential"] == expected, "loaded credential sources differ")
    return actual


def stopped(row: dict) -> dict:
    unit = row["worker"]["unit"]
    actual = definition(row)
    require(
        actual["ExecStart"]
        == [[str(inputs.LAUNCHER), [str(inputs.LAUNCHER)], False, 0, 0, 0, 0, 0, 0, 0]],
        "loaded executable differs or worker has already started",
    )
    state = recovery.stopped(unit)
    return {
        "unit": unit,
        "unitSha256": hashlib.sha256(row["unitText"].encode()).hexdigest(),
        "account": row["account"],
        "loaded": actual,
        "state": state,
    }
