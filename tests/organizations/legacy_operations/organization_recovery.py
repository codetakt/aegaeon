"""Explicit offline maintenance recovery; no runtime or activation authority."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import signal
import stat
import subprocess
import sys
from contextlib import ExitStack
from pathlib import Path
from typing import Any
from uuid import UUID

import organization_recovery_runtime as runtime
import psycopg
from organization_recovery_peer import peer_connection, user_id
from organization_recovery_redis import RedisStore
from organization_recovery_resp import Resp
from organization_recovery_store import RecoveryRefusedError, Store, clear, fence, require, selected

MAX_CONFIG = 65536
MAX_STORES = 8
MAX_LOGINS = 64
MAX_SERVICES = 32
MAX_PORT = 65535
PROPERTIES = (
    "Id",
    "LoadState",
    "ActiveState",
    "SubState",
    "KillMode",
    "SendSIGKILL",
    "Delegate",
    "User",
    "ControlGroup",
    "MainPID",
    "ControlPID",
    "FragmentPath",
    "NoNewPrivileges",
    "CapabilityBoundingSet",
    "AmbientCapabilities",
)


def protected_path(path: Path | str) -> Path:
    path = Path(path)
    require(path.is_absolute() and ".." not in path.parts, "absolute private path required")
    for parent in path.parents:
        info = parent.lstat()
        require(
            stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
            "unsafe credential parent",
        )
    return path


def private_file(path: Path | str, limit: int = MAX_CONFIG) -> bytes:
    path = protected_path(path)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as handle:
        info = os.fstat(handle.fileno())
        require(
            stat.S_ISREG(info.st_mode)
            and info.st_uid == 0
            and not info.st_mode & 0o077
            and info.st_nlink == 1,
            "private root-owned file required",
        )
        data = handle.read(limit + 1)
        require(len(data) <= limit, "private file bound")
        return data


def sync_directory_entry(path: Path) -> None:
    """Caller has provisioned a protected directory; persist it before store work."""
    # File fsync and containing-directory fsync do not persist the directory's
    # own new name in its parent. Failure here must precede any dependent mutation.
    for target in (path, path.parent):
        descriptor = os.open(target, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def settings(data: bytes | str) -> dict[str, Any]:
    config = json.loads(data)
    if config.get("version") == runtime.VERSION:
        runtime.settings(config)
        inventory_settings(config, runtime_mode=True)
        return config
    require(
        set(config) == {"version", "maintenance", "stores", "services"} and config["version"] == 1,
        "unknown recovery configuration",
    )
    expected = config["maintenance"]
    require(
        set(expected) == {"deployment_id", "generation", "work_id", "plan_sha256"},
        "exact maintenance identity required",
    )
    for name in ["deployment_id", "work_id"]:
        require(
            str(UUID(expected[name])) == expected[name] and UUID(expected[name]).int != 0,
            "canonical nonnil identity required",
        )
    require(
        type(expected["generation"]) is int and 0 < expected["generation"] < 2**63,
        "invalid generation",
    )
    require(re.fullmatch(r"[0-9a-f]{64}", expected["plan_sha256"]), "invalid plan digest")
    inventory_settings(config)
    return config


def inventory_settings(config: dict, *, runtime_mode: bool = False) -> None:
    stores = config["stores"]
    require(type(stores) is list and 1 <= len(stores) <= MAX_STORES, "store inventory bound")
    clusters = set()
    for index, store in enumerate(stores):
        require(
            set(store) == {"kind", "identity", "connection", "old_logins"}, "unknown store fields"
        )
        require(
            store["kind"] == ("control" if index == 0 else "primary"),
            "control must precede primary stores",
        )
        identity = store["identity"]
        require(
            set(identity) == {"cluster", "database", "database_oid"},
            "exact store identity required",
        )
        require(
            re.fullmatch(r"[1-9][0-9]{0,19}", identity["cluster"])
            and identity["cluster"] not in clusters,
            "independent unique SQL clusters required",
        )
        clusters.add(identity["cluster"])
        names = store["old_logins"]
        require(
            type(names) is list and 1 <= len(names) <= MAX_LOGINS and len(set(names)) == len(names),
            "old login inventory bound",
        )
        require(
            all(re.fullmatch(r"[a-z][a-z0-9_]{0,62}", name) for name in names), "invalid old login"
        )
        connection = store["connection"]
        if "socket" in connection:
            require(
                index == 0
                and set(connection) == {"socket", "port", "dbname", "user", "peer_user"}
                and Path(connection["socket"]).is_absolute()
                and ".." not in Path(connection["socket"]).parts
                and re.fullmatch(r"[a-z][a-z0-9_-]{0,62}", connection["peer_user"])
                and type(connection["port"]) is int
                and 1 <= connection["port"] <= MAX_PORT
                and connection["dbname"] == identity["database"],
                "explicit local control peer required",
            )
            continue
        require(
            set(connection) == {"host", "port", "dbname", "user", "password_file", "ca_file"},
            "explicit TLS connection fields required",
        )
        require(
            type(connection["port"]) is int and 1 <= connection["port"] <= MAX_PORT,
            "invalid store port",
        )
        require(
            re.fullmatch(r"[A-Za-z0-9.-]+", connection["host"])
            and connection["dbname"] == identity["database"],
            "explicit matching TCP destination required",
        )
    services = config["services"]
    require(
        type(services) is list
        and 1 <= len(services) <= MAX_SERVICES
        and len(set(services)) == len(services),
        "service inventory bound",
    )
    require(
        all(
            re.fullmatch(
                r"aegaeon-organization-(?:maintenance|runtime)-[a-z0-9-]+\.service"
                if runtime_mode
                else r"aegaeon-organization-maintenance-[a-z0-9-]+\.service",
                name,
            )
            for name in services
        ),
        "dedicated maintenance services required",
    )


def service_state(unit: str, command: tuple[str, ...] = ("systemctl",)) -> dict[str, str]:
    result = subprocess.run(  # noqa: S603 — fixed service-manager argv, validated unit
        [*command, "show", unit, "--no-pager", "--property=" + ",".join(PROPERTIES)],
        check=True,
        capture_output=True,
        text=True,
        timeout=5,
    )
    state = dict(line.split("=", 1) for line in result.stdout.splitlines())
    require(set(state) == set(PROPERTIES) and state["Id"] == unit, "service identity incomplete")
    require(
        state["LoadState"] == "loaded"
        and state["KillMode"] == "control-group"
        and state["SendSIGKILL"] == "yes"
        and state["Delegate"] == "no"
        and state["NoNewPrivileges"] == "yes"
        and state["CapabilityBoundingSet"] == ""
        and state["AmbientCapabilities"] == "",
        "unsafe worker service boundary",
    )
    require(state["User"] not in ("", "root", "0"), "worker must not hold recovery authority")
    return state


def empty_group(group: str) -> None:
    if not group:
        return
    require(group.startswith("/") and ".." not in Path(group).parts, "invalid worker cgroup")
    path = Path("/sys/fs/cgroup") / group.removeprefix("/") / "cgroup.events"
    if path.exists():
        values = dict(line.split() for line in path.read_text().splitlines())
        require(values.get("populated") == "0", "worker descendants remain")


def stopped(unit: str, command: tuple[str, ...] = ("systemctl",)) -> dict[str, str]:
    state = service_state(unit, command)
    require(
        state["ActiveState"] == "inactive"
        and state["SubState"] == "dead"
        and state["MainPID"] == "0"
        and state["ControlPID"] == "0",
        "worker service termination unconfirmed",
    )
    empty_group(state["ControlGroup"])
    return state


def stop_services(
    units: list[str], command: tuple[str, ...] = ("systemctl",)
) -> list[dict[str, Any]]:
    before = [service_state(unit, command) for unit in units]
    for unit in units:
        subprocess.run([*command, "stop", unit], check=True, capture_output=True, timeout=15)  # noqa: S603
    after = [stopped(unit, command) for unit in units]
    for previous in before:
        empty_group(previous["ControlGroup"])
    return [{"before": first, "after": last} for first, last in zip(before, after, strict=True)]


def retain(directory: int, name: str, value: dict[str, Any]) -> str:
    require(re.fullmatch(r"[a-z][a-z0-9_-]*\.json", name), "private receipt basename required")
    data = json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    # No final pathname exists until every byte and the inode are synchronized.
    # O_EXCL would prevent linking an O_TMPFILE; linkat itself refuses replacement.
    # Unsupported filesystems/procfs and either fsync failure refuse, without a
    # named-temporary or overwrite fallback. The directory is already protected
    # and locked by the caller; /proc/self/fd selects only this still-owned inode.
    descriptor = os.open(".", os.O_WRONLY | os.O_TMPFILE | os.O_CLOEXEC, 0o600, dir_fd=directory)
    with os.fdopen(descriptor, "wb") as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())
        os.link(
            f"/proc/self/fd/{output.fileno()}", name, dst_dir_fd=directory, follow_symlinks=True
        )
        os.fsync(directory)
    return hashlib.sha256(data).hexdigest()


def connect(stack: ExitStack, config: dict[str, Any]) -> Store:
    value = config["connection"]
    options = (
        "-c statement_timeout=10000 -c lock_timeout=5000 "
        "-c idle_in_transaction_session_timeout=15000 -c search_path=pg_catalog"
    )
    if "socket" in value:
        connection = stack.enter_context(peer_connection(value, options))
        return Store(connection, config["identity"], config["old_logins"])
    password = private_file(value["password_file"]).decode().rstrip("\n")
    ca = private_file(value["ca_file"]).decode()
    require(
        password and "\0" not in password and "BEGIN CERTIFICATE" in ca,
        "credential material missing",
    )
    # Paths remain under root custody after validation; libpq reads only this CA.
    connection = stack.enter_context(
        psycopg.connect(
            host=value["host"],
            port=value["port"],
            dbname=value["dbname"],
            user=value["user"],
            password=password,
            sslmode="verify-full",
            sslrootcert=value["ca_file"],
            connect_timeout=5,
            application_name="aegaeon-organization-recovery",
            options=options,
            autocommit=True,
        )
    )
    return Store(connection, config["identity"], config["old_logins"])


def checked_catalog(control: Store) -> None:
    catalog = Path(__file__).resolve().parents[2] / "db/organization-witness"
    require(
        control.one((catalog / "catalog-v5.sql").read_text())
        == json.loads((catalog / "catalog-v16.json").read_text()),
        "control catalog differs",
    )


def recover(
    config: dict[str, Any],
    stores: list[Store],
    output: int,
    *,
    command: tuple[str, ...] = ("systemctl",),
) -> dict[str, Any]:
    control = stores[0]
    expected = config["maintenance"]
    peer = config["stores"][0]["connection"].get("peer_user")
    if peer:
        for unit in config["services"]:
            require(
                user_id(service_state(unit, command)["User"]) != user_id(peer),
                "old worker holds local database administrator identity",
            )
    for store in stores:
        store.check()
    require(
        not control.one(
            "SELECT EXISTS(SELECT FROM organization_witness.deployments WHERE deployment_id<>%s)",
            (expected["deployment_id"],),
        ),
        "shared control deployment is not an offline recovery target",
    )
    checked_catalog(control)
    with control.connection.transaction():
        fence(control, expected["deployment_id"])
        state = selected(control, expected)
        require(state["pending"], "owner already completed; inspect retained receipt")
        require(
            state["kind"] in ("history-import", "history-inspect") or len(stores) > 1,
            "primary store inventory required",
        )
    for unit in config["services"]:
        service_state(unit, command)
    exclusions = [store.exclude() for store in stores]
    services = stop_services(config["services"], command)
    drains = [store.drain() for store in stores]
    # Credentials are already durably excluded. Normal operations cannot acquire
    # another slot while this pending owner remains. Recheck under actual locks.
    with control.connection.transaction():
        fence(control, expected["deployment_id"])
        require(selected(control, expected) == state, "maintenance state changed during exclusion")
        for store in stores:
            store.check(excluded=True)
        for unit in config["services"]:
            stopped(unit, command)
        receipt = {
            "version": 1,
            "maintenance": state,
            "exclusions": exclusions,
            "services": services,
            "drains": drains,
            "outcome": "stopped-pending-reconciled",
            "activationAuthorized": False,
            "configurationSha256": hashlib.sha256(
                json.dumps(config, sort_keys=True).encode()
            ).hexdigest(),
        }
        digest = retain(output, "reconciliation.json", receipt)
        completed = clear(control, expected, digest)
    # If this write fails, the durable SQL digest and pre-COMMIT receipt still
    # distinguish completed recovery from pending work without repeating it.
    retain(output, "released.json", completed)
    return completed


def inspect_recovery(config: dict[str, Any], control: Store, receipt: bytes) -> str:
    """Resolve an uncertain reply without mutating any recovery authority."""
    value = json.loads(receipt)
    require(
        value["version"] == 1
        and value["outcome"] == "stopped-pending-reconciled"
        and value["activationAuthorized"] is False
        and value["configurationSha256"]
        == hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest(),
        "retained recovery receipt differs",
    )
    control.check(excluded=True)
    checked_catalog(control)
    with control.connection.transaction():
        state = selected(control, config["maintenance"])
        before = dict(state, pending=True, completion_sha256=None)
        require(value["maintenance"] == before, "retained recovery owner differs")
        if state["pending"]:
            return "pending"
        require(
            state["completion_sha256"] == hashlib.sha256(receipt).hexdigest(),
            "retained recovery digest differs",
        )
        return "completed"


def runtime_recovery(config: dict, stores: list[Store], token: RedisStore, output: int) -> dict:
    control, primary = stores
    expected = config["runtime"]
    plan = runtime.digest(config)
    for store in stores:
        store.check()
    token.check()
    checked_catalog(control)
    require(
        not control.one(
            "SELECT EXISTS(SELECT FROM organization_witness.deployments WHERE deployment_id<>%s)",
            (expected["deployment_id"],),
        ),
        "shared control deployment is not an offline recovery target",
    )
    with control.connection.transaction():
        require(
            runtime.completed(control, expected, plan) is None,
            "runtime recovery already completed; inspect receipt",
        )
        snapshot = runtime.state(control, expected["deployment_id"])
        runtime.selection(snapshot, expected, control, primary, token.identity)
    peer = config["stores"][0]["connection"].get("peer_user")
    for unit in config["services"]:
        state = service_state(unit)
        if peer:
            require(
                user_id(state["User"]) != user_id(peer),
                "worker holds database administrator identity",
            )
    exclusions = [store.exclude() for store in stores]
    token_exclusion = token.exclude()
    services = stop_services(config["services"])
    drains = [store.drain() for store in stores]
    token_drain = token.drain()
    with control.connection.transaction():
        require(
            runtime.state(control, expected["deployment_id"]) == snapshot,
            "runtime state changed during exclusion",
        )
        for store in stores:
            store.check(excluded=True)
        token.check(excluded=True)
        for unit in config["services"]:
            stopped(unit)
        receipt = {
            "version": 2,
            "runtime": expected,
            "prior_state": snapshot,
            "configurationSha256": plan,
            "exclusions": exclusions,
            "token_exclusion": token_exclusion,
            "services": services,
            "drains": drains,
            "token_drain": token_drain,
            "outcome": "stopped-runtime-reconciled",
            "activationAuthorized": False,
        }
        receipt_digest = retain(output, "reconciliation.json", receipt)
        result = runtime.release(control, expected, plan, snapshot, receipt_digest)
    retain(output, "released.json", result)
    return result


def inspect_runtime(config: dict, control: Store, receipt: bytes) -> str:
    value = json.loads(receipt)
    plan = runtime.digest(config)
    require(
        value["version"] == runtime.VERSION
        and value["runtime"] == config["runtime"]
        and value["configurationSha256"] == plan
        and value["activationAuthorized"] is False
        and value["outcome"] == "stopped-runtime-reconciled"
        and runtime.digest(value["prior_state"]) == config["runtime"]["state_sha256"],
        "runtime recovery receipt differs",
    )
    control.check(excluded=True)
    checked_catalog(control)
    with control.connection.transaction():
        result = runtime.completed(control, config["runtime"], plan)
        if result is None:
            require(
                runtime.state(control, config["runtime"]["deployment_id"]) == value["prior_state"],
                "unrecorded runtime recovery state changed",
            )
            return "pending"
        require(
            result["completion_sha256"] == hashlib.sha256(receipt).hexdigest()
            and result["prior_state"] == value["prior_state"],
            "runtime recovery completion differs",
        )
        return "completed"


def main() -> None:  # noqa: PLR0915 — bounded offline CLI lifecycle
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--inspect", action="store_true", help="read-only resolution of a lost reply"
    )
    parser.add_argument(
        "--runtime-inventory",
        action="store_true",
        help="retain current fenced runtime state without modifying it",
    )
    args = parser.parse_args()
    require(os.geteuid() == 0, "offline root recovery authority required")
    # No inherited libpq destination, role, startup-command or TLS overrides.
    for name in list(os.environ):
        if name.startswith("PG"):
            del os.environ[name]
    signal.signal(
        signal.SIGALRM, lambda *_: (_ for _ in ()).throw(RecoveryRefusedError("recovery deadline"))
    )
    signal.alarm(120)
    config = settings(private_file(args.config))
    if args.inspect:
        require(not args.runtime_inventory, "choose one read-only operation")
        receipt = private_file(args.output / "reconciliation.json", runtime.MAX_STATE * 2)
        with ExitStack() as stack:
            control = connect(stack, config["stores"][0])
            inspect = inspect_runtime if config["version"] == runtime.VERSION else inspect_recovery
            print(inspect(config, control, receipt))
        return
    # The output must be new; ambiguous completion is inspected, never retried
    # by overwriting evidence or accepting a caller-supplied completion digest.
    protected_path(args.output).mkdir(mode=0o700)
    sync_directory_entry(args.output)
    output = os.open(args.output, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        require(
            os.fstat(output).st_uid == 0 and not os.fstat(output).st_mode & 0o077,
            "private output directory required",
        )
        fcntl.flock(output, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with ExitStack() as stack:
            if args.runtime_inventory:
                require(config["version"] == runtime.VERSION, "runtime configuration required")
                control = connect(stack, config["stores"][0])
                control.check()
                checked_catalog(control)
                with control.connection.transaction():
                    snapshot = runtime.state(control, config["runtime"]["deployment_id"])
                    retain(
                        output,
                        "inventory.json",
                        {
                            "state": snapshot,
                            "state_sha256": runtime.digest(snapshot),
                            "activationAuthorized": False,
                        },
                    )
                print("runtime inventory retained; no state changed")
                return
            stores = [connect(stack, item) for item in config["stores"]]
            if config["version"] == runtime.VERSION:
                value = config["token"]
                credentials = value["connection"]
                link = Resp(
                    credentials["host"],
                    credentials["port"],
                    private_file(credentials["ca_file"]).decode(),
                    credentials["user"],
                    private_file(credentials["password_file"]).decode().rstrip("\n"),
                )
                stack.callback(link.close)
                token = RedisStore(
                    link, value["identity"], credentials["user"], value["old_logins"]
                )
                runtime_recovery(config, stores, token, output)
            else:
                recover(config, stores, output)
    finally:
        os.close(output)
    print("ownership reconciled; credentials remain excluded; activation not authorized")


if __name__ == "__main__":
    try:
        main()
    except Exception:  # noqa: BLE001 — never print driver URLs, SQL or credentials
        print(
            "recovery unconfirmed; retain exclusions, pending state and private receipts",
            file=sys.stderr,
        )
        sys.exit(1)
