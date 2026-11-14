"""Cancel actual packaged Redis tests and inspect real Compose teardown guards.

These three interrupted executions are separate from the full test inventory.
They use the discovered native package and unchanged lane/receipt controllers.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import ipaddress
import json
import os
import signal
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def save(path, value):
    with path.open("x") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def identity(pid):
    directory = Path(f"/proc/{pid}")
    try:
        fields = (directory / "stat").read_text().rsplit(") ", 1)[1].split()
        if fields[0] in ("Z", "X"):
            return None
        return {
            "pid": pid,
            "group": int(fields[2]),
            "session": int(fields[3]),
            "starttime": fields[19],
            "uid": directory.stat().st_uid,
            "argv_sha256": hashlib.sha256((directory / "cmdline").read_bytes()).hexdigest(),
        }
    except (FileNotFoundError, ProcessLookupError):
        return None


def command(argv, execution, *, timeout=5):
    with subprocess.Popen(  # noqa: S603 - fixed tools and exact owned resource arguments.
        argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True, text=True
    ) as child:
        try:
            out, err = child.communicate(timeout=timeout)
            require(child.returncode == 0, f"owned diagnostic command failed: {err[:1000]}")
            require(
                not execution.group_running(child.pid),
                "diagnostic command left descendants after successful exit",
            )
            return out.strip()
        finally:
            execution.stop_process_group(child, grace=0.2)


def native_processes(argv, results):
    expected = b"\0".join(value.encode() for value in argv) + b"\0"
    expected_environment = f"AEGAEON_DATABASE_EXECUTION_RESULTS={results}".encode()
    found = []
    for directory in Path("/proc").iterdir():
        if not directory.name.isdigit():
            continue
        try:
            if directory.stat().st_uid != os.getuid():
                continue
            if (directory / "cmdline").read_bytes() != expected:
                continue
            with (directory / "environ").open("rb") as stream:
                env = stream.read(1024 * 1024 + 1)
            require(len(env) <= 1024 * 1024, "native environment exceeds observation bound")
            if expected_environment not in env.split(b"\0"):
                continue
            require(
                str((directory / "exe").readlink()) == argv[0], "native executable identity differs"
            )
            row = identity(int(directory.name))
            if row is not None:
                require(
                    row["pid"] == row["group"] == row["session"], "native group is not independent"
                )
                found.append(row)
        except (FileNotFoundError, ProcessLookupError):
            continue
    return found


def redis(container, execution, *arguments):
    return command(["docker", "exec", container, "redis-cli", *arguments], execution)


def resource_definition(directory):
    configs = list(directory.glob("*/compose.json"))
    require(len(configs) == 1, "expected one exact owned Compose configuration")
    config = configs[0]
    project = config.parent.name
    compose = ["docker", "compose", "--project-name", project, "-f", str(config)]
    env = {**os.environ, "COMPOSE_PROJECT_NAME": project}
    return {
        "compose": compose,
        "environment": env,
        "directory": config.parent,
        "project": project,
        "owner_starttime": identity(os.getpid())["starttime"],
    }


def inspect_resource(resource, execution):
    container = command([*resource["compose"], "ps", "-q", "redis"], execution)
    require(
        len(container) == 64 and all(c in "0123456789abcdef" for c in container),
        "owned Redis identity is missing or ambiguous",
    )
    inspected = json.loads(command(["docker", "inspect", container], execution))[0]
    labels = inspected["Config"]["Labels"]
    require(
        labels["com.docker.compose.project"] == resource["project"]
        and labels["com.docker.compose.service"] == "redis",
        "foreign Redis supplier",
    )
    suppliers = {"redis": {"container": container, "image": inspected["Image"]}}
    require(redis(container, execution, "PING") == "PONG", "owned Redis is not reachable")
    resource.update(suppliers=suppliers, container=container)
    return resource


def has_external_client(container, execution):
    # Health checks and this observer connect inside the container. The native
    # suite connects through the unique published port from the host.
    for line in redis(container, execution, "CLIENT", "LIST").splitlines():
        values = dict(field.split("=", 1) for field in line.split() if "=" in field)
        host = values["addr"].rsplit(":", 1)[0].strip("[]")
        if not ipaddress.ip_address(host).is_loopback:
            return True
    return False


def resource_inventory(resource, execution):
    selector = f"label=com.docker.compose.project={resource['project']}"
    return {
        "containers": command(
            ["docker", "ps", "-aq", "--no-trunc", "--filter", selector], execution
        ),
        "volumes": command(["docker", "volume", "ls", "-q", "--filter", selector], execution),
        "networks": command(["docker", "network", "ls", "-q", "--filter", selector], execution),
    }


def stop_resource(resource, execution):
    # Supervisor recovery is separate from the lane teardown under test.
    command(
        [*resource["compose"], "down", "--volumes", "--remove-orphans", "--timeout", "10"],
        execution,
        timeout=25,
    )
    remaining = resource_inventory(resource, execution)
    require(not any(remaining.values()), "owned Compose recovery left project resources")
    return {"cleanup": True, "remaining": remaining}


def project_processes(resource):
    expected = {
        f"COMPOSE_PROJECT_NAME={resource['project']}".encode(),
        f"DEV_COMPOSE_FILE={resource['directory'] / 'compose.json'}".encode(),
    }
    rows = []
    for directory in Path("/proc").iterdir():
        if not directory.name.isdigit():
            continue
        try:
            if directory.stat().st_uid != os.getuid():
                continue
            fields = (directory / "stat").read_text().rsplit(") ", 1)[1].split()
            # Work created by this fixture cannot predate its supervisor. Avoid
            # reading unrelated long-lived agents' protected environments.
            if int(fields[19]) < int(resource["owner_starttime"]) or fields[0] in ("Z", "X"):
                continue
            with (directory / "environ").open("rb") as stream:
                env = stream.read(1024 * 1024 + 1)
            if len(env) <= 1024 * 1024 and expected.issubset(env.split(b"\0")):
                row = identity(int(directory.name))
                if row is not None:
                    rows.append(row)
        except (FileNotFoundError, ProcessLookupError):
            continue
    return rows


def recover_project_processes(resource):
    actions = []
    for signum in (signal.SIGTERM, signal.SIGKILL):
        for row in project_processes(resource):
            require(identity(row["pid"]) == row, "owned command identity changed during recovery")
            with contextlib.suppress(ProcessLookupError):
                os.kill(row["pid"], signum)
            actions.append({"identity": row, "signal": int(signum)})
        until = time.monotonic() + 3
        while project_processes(resource) and time.monotonic() < until:
            time.sleep(0.02)
    require(not project_processes(resource), "owned project commands remain live")
    return actions


def stop_native(owned, execution):
    if not execution.group_running(owned["group"]):
        return
    require(identity(owned["pid"]) == owned, "native identity changed; refusing recovery signal")
    with contextlib.suppress(ProcessLookupError):
        os.killpg(owned["group"], signal.SIGTERM)
    until = time.monotonic() + 3
    while execution.group_running(owned["group"]) and time.monotonic() < until:
        time.sleep(0.02)
    if execution.group_running(owned["group"]):
        require(identity(owned["pid"]) == owned, "native identity changed before escalation")
        with contextlib.suppress(ProcessLookupError):
            os.killpg(owned["group"], signal.SIGKILL)
    until = time.monotonic() + 2
    while execution.group_running(owned["group"]) and time.monotonic() < until:
        time.sleep(0.02)
    require(not execution.group_running(owned["group"]), "native work remains live")


def run_case(args, mode, plan, control, *, lanes, execution):  # noqa: C901, PLR0912, PLR0913, PLR0915 - one real fault lifecycle.
    directory = args.output / mode
    directory.mkdir(mode=0o700)
    results, work = directory / "results", directory / "suppliers"
    execution.initialize_receipts(args.plan, results)
    expected_native = execution.owned_command(plan, "redis")
    observed = {"case": mode, "passed": False, "events": []}
    child, resource = None, None
    native = []
    started = time.monotonic()
    work_deadline = min(args.deadline - 65, started + 180) - 85

    def event(name, **values):
        observed["events"].append({"event": name, "elapsed": time.monotonic() - started, **values})

    try:
        with (
            execution.pinned_results_directory(results) as pinned,
            (directory / "controller.log").open("xb") as log,
        ):
            child = subprocess.Popen(  # noqa: S603 - this harness invokes the actual source lane.
                [
                    sys.executable,
                    str(Path(__file__).resolve()),
                    "--root",
                    str(args.root),
                    "--plan",
                    str(args.plan),
                    "--output",
                    str(directory),
                    "--child",
                    "--device",
                    str(pinned[0]),
                    "--inode",
                    str(pinned[1]),
                ],
                cwd=args.root,
                stdout=log,
                stderr=log,
                start_new_session=True,
            )
            event("controller_started", identity=identity(child.pid), results_identity=list(pinned))
            until = min(work_deadline, time.monotonic() + 90)
            while time.monotonic() < until:
                execution.check_cancellation()
                require(child.poll() is None, "lane exited before real native work was observed")
                native = native_processes(expected_native, results)
                if native:
                    require(len(native) == 1, "native work identity is ambiguous")
                    resource = inspect_resource(resource_definition(work), execution)
                    if has_external_client(resource["container"], execution):
                        break
                time.sleep(0.02)
            else:
                message = "real native supplier use was not observed before deadline"
                raise TimeoutError(message)
            require(identity(native[0]["pid"]) == native[0], "native exited before fault injection")
            receipt_bytes = (results / "redis.json").read_bytes()
            receipt = json.loads(receipt_bytes)
            require(
                execution.started_receipt(receipt)
                and receipt["process_cleanup_confirmed"] is False,
                "expected one actually started, unconfirmed native obligation",
            )
            save(directory / "native-before.json", native)
            save(directory / "receipt-before.json", receipt)
            (directory / "receipt-before.raw.json").write_bytes(receipt_bytes)
            event("real_work_active", native=native, suppliers=resource["suppliers"])
            if mode == "missing-receipt":
                (results / "redis.json").unlink()
                event("started_receipt_removed", sha256=hashlib.sha256(receipt_bytes).hexdigest())
            elif mode == "replaced-directory":
                results.rename(directory / "retained-results")
                # Even valid not-started records in a different directory must
                # not authorize removal of this lane's real suppliers.
                execution.initialize_receipts(args.plan, results)
                event(
                    "results_directory_replaced",
                    original=list(pinned),
                    replacement=[results.stat().st_dev, results.stat().st_ino],
                )
            os.kill(child.pid, signal.SIGTERM)
            event("controller_cancelled")
            until = min(work_deadline, time.monotonic() + 75)
            while child.poll() is None and time.monotonic() < until:
                execution.check_cancellation()
                running = command(
                    [
                        "docker",
                        "ps",
                        "-q",
                        "--filter",
                        f"label=com.docker.compose.project={resource['project']}",
                    ],
                    execution,
                )
                # Recheck work after observing supplier absence, so a normal
                # stop between two observations cannot look like unsafe order.
                live = execution.group_running(native[0]["group"])
                require(
                    not live or bool(running), "supplier disappeared while native work remained"
                )
                time.sleep(0.05)
            require(child.poll() is not None, "lane cancellation exceeded deadline")
            require(child.returncode != 0, "interrupted lane incorrectly succeeded")
            require(
                not execution.group_running(native[0]["group"]), "native work survived lane exit"
            )
            event("lane_exited", returncode=child.returncode, native_group_stopped=True)
            lane = json.loads((results / "lane-redis.json").read_text())
            observed["lane_receipt"] = lane
            require(lane["complete"] is False, "interrupted lane produced a complete result")
            inventory = resource_inventory(resource, execution)
            observed["resources_before_recovery"] = inventory
            if mode == "cancel":
                require(
                    lane["cleanup"] is True, "confirmed cancellation failed to remove suppliers"
                )
                require(
                    not any(inventory.values()),
                    "lane reported cleanup while actual project resources remained",
                )
            else:
                require(
                    lane["cleanup"] is False and "cleanup_deferred" in lane and "recovery" in lane,
                    "missing or replaced evidence did not defer actual supplier teardown",
                )
                require(
                    inventory["containers"].splitlines() == [resource["container"]]
                    and inventory["volumes"]
                    and inventory["networks"],
                    "evidence failure did not preserve actual project resources",
                )
                require(
                    redis(resource["container"], execution, "PING") == "PONG",
                    "supplier was not retained after evidence failure",
                )
                if mode == "missing-receipt":
                    require(not (results / "redis.json").exists(), "missing evidence was recreated")
                else:
                    require(
                        (results.stat().st_dev, results.stat().st_ino) != pinned,
                        "replacement did not change the pinned directory identity",
                    )
            require(
                redis(control["container"], execution, "PING") == "PONG",
                "independent control supplier was affected",
            )
            observed["passed"] = True
    finally:
        # Keep incomplete/failing runs, and reclaim work before real containers.
        try:
            if child is not None:
                execution.stop_process_group(child, grace=15)
            known = {row["pid"]: row for row in native}
            known.update({row["pid"]: row for row in native_processes(expected_native, results)})
            for row in known.values():
                stop_native(row, execution)
            if resource is None and list(work.glob("*/compose.json")):
                resource = resource_definition(work)
            if resource is not None:
                observed["command_recovery"] = recover_project_processes(resource)
                observed["recovery"] = stop_resource(resource, execution)
            observed["owned_processes_stopped"] = True
            require(
                not observed.get("command_recovery"),
                "lane left owned commands alive; supervisor recovery is not a passing result",
            )
        except BaseException as error:
            observed.update(passed=False, cleanup_error=type(error).__name__)
            raise
        finally:
            observed["elapsed_seconds"] = time.monotonic() - started
            save(directory / "result.json", observed)
    return observed


def owner(args, lanes, execution):  # noqa: PLR0915 - fixed cases and final recovery.
    args.output.mkdir(mode=0o700, parents=True)
    plan = execution.load_plan(args.plan)
    execution.bind_package(plan, Path(plan["package"]))
    with (Path(plan["package"]) / "libexec/aegaeon_server").open("rb") as binary:
        require(binary.read(4) == b"\x7fELF", "qualification requires the actual native executable")
    control_dir = args.output / "control" / ("aeg-cleanup-control-" + uuid.uuid4().hex[:16])
    control_dir.mkdir(mode=0o700, parents=True)
    (control_dir / "compose.json").write_text(json.dumps(lanes.configuration("redis")))
    control = resource_definition(control_dir.parent)
    record = {
        "passed": False,
        "context": plan["context"],
        "plan_sha256": execution.sha(args.plan),
        "build_sha256": plan["build_sha256"],
        "cases": [],
        "scope": "three interrupted native executions; not full-suite success",
        "budget_seconds": 600,
    }
    args.deadline = time.monotonic() + 600
    try:
        with execution.cancellation_scope():
            with (control_dir / "startup.log").open("xb") as log:
                status = lanes.command(
                    [*control["compose"], "up", "-d"],
                    control["environment"],
                    log,
                    threading.Event(),
                    timeout=30,
                )
            require(status == 0, "control supplier startup failed")
            inspect_resource(control, execution)
            record["control_supplier"] = control["suppliers"]
            for mode in ("cancel", "missing-receipt", "replaced-directory"):
                execution.check_cancellation()
                require(
                    args.deadline - time.monotonic() >= 245,
                    "insufficient shared budget for another complete case and control cleanup",
                )
                record["cases"].append(
                    run_case(args, mode, plan, control, lanes=lanes, execution=execution)
                )
            record["passed"] = True
    finally:
        try:
            record["control_cleanup"] = stop_resource(control, execution)
            execution.check_cancellation()
        except BaseException as error:
            record.update(passed=False, cleanup_error=type(error).__name__)
            raise
        finally:
            save(args.output / "result.json", record)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--child", action="store_true")
    parser.add_argument("--device", type=int)
    parser.add_argument("--inode", type=int)
    args = parser.parse_args()
    args.root, args.plan, args.output = (
        args.root.resolve(),
        args.plan.resolve(),
        args.output.resolve(),
    )
    os.umask(0o077)
    sys.path[:0] = [str(args.root / "scripts/ci"), str(args.root / "scripts/validation")]
    import database_execution as execution  # noqa: PLC0415 - explicitly bound source root.
    import run_database_lanes as lanes  # noqa: PLC0415 - explicitly bound source root.

    if args.child:
        require(
            args.device is not None and args.inode is not None, "child needs pre-execution identity"
        )
        cancelled = threading.Event()
        for signum in (signal.SIGINT, signal.SIGTERM):
            signal.signal(signum, lambda *_: cancelled.set())
        raise SystemExit(
            lanes.lane_run(
                "redis",
                args.plan,
                args.output / "results",
                args.output / "suppliers",
                cancelled,
                expected_identity=(args.device, args.inode),
            )
        )
    # Record cancellation through the final recovery, not just the test body.
    with execution.cancellation_scope():
        owner(args, lanes, execution)


if __name__ == "__main__":
    main()
