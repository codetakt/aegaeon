#!/usr/bin/env python3
"""Run three bounded, independently owned service groups using one native package."""

from __future__ import annotations

import copy
import json
import os
import re
import signal
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from typing import BinaryIO

import yaml

ROOT = Path(__file__).resolve().parents[2]
CONTROLLER_GRACE = 10
CAPTURE_TIMEOUT = 30
sys.path.insert(0, str(ROOT / "scripts/validation"))
from database_execution import (  # noqa: E402
    LANES,
    SUPPLIERS,
    bind_package,
    confirm_lane_cleanup,
    initialize_receipts,
    load_plan,
    pinned_results_directory,
    replace_receipt,
    sha,
    stop_process_group,
)


class UnconfirmedCommandCleanupError(RuntimeError):
    def __init__(self, group: int) -> None:
        self.group = group
        super().__init__(f"owned command group cleanup is unconfirmed: {group}")


def configuration(lane: str) -> dict[str, Any]:
    original = yaml.safe_load((ROOT / "tests/docker/docker-compose.yml").read_text())
    names = SUPPLIERS[lane]
    services = {}
    for name in names:
        service = copy.deepcopy(original["services"][name])
        service.pop("container_name", None)
        service["ports"] = [
            {
                "target": 5432 if name == "postgres" else 6379,
                "host_ip": "127.0.0.1",
                "published": "0",
            }
        ]
        service["logging"] = {
            "driver": "json-file",
            "options": {"max-size": "10m", "max-file": "2"},
        }
        services[name] = service
    return {
        "services": services,
        "networks": original["networks"],
        "volumes": {f"{name}-data": original["volumes"][f"{name}-data"] for name in names},
    }


def stop(process: subprocess.Popen[bytes]) -> None:
    # Wait for controllers in this group to clean up their nested owned groups.
    stop_process_group(process, grace=CONTROLLER_GRACE)


def command(
    argv: list[str],
    env: dict[str, str],
    log: BinaryIO,
    cancelled: threading.Event,
    *,
    timeout: float,
) -> int:
    if cancelled.is_set():
        raise InterruptedError("database execution cancelled")
    process = subprocess.Popen(
        argv, cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True
    )
    deadline = time.monotonic() + timeout
    try:
        while process.poll() is None:
            if cancelled.wait(0.2):
                raise InterruptedError("database execution cancelled")
            if time.monotonic() >= deadline:
                raise TimeoutError("database command exceeded its bound")
        return process.returncode
    finally:
        try:
            stop(process)
        except Exception as error:
            # Distinguish uncertain ownership from a failed but stopped command.
            raise UnconfirmedCommandCleanupError(process.pid) from error


def wait_capture(
    process: subprocess.Popen[bytes], argv: list[str], cancelled: threading.Event
) -> None:
    deadline = time.monotonic() + CAPTURE_TIMEOUT
    while process.poll() is None:
        if cancelled.wait(0.1):
            raise InterruptedError("database execution cancelled")
        if time.monotonic() >= deadline:
            raise subprocess.TimeoutExpired(argv, CAPTURE_TIMEOUT)


def capture(
    argv: list[str], env: dict[str, str], *, cancelled: threading.Event | None = None
) -> str:
    # Setup observes lane cancellation; teardown inspection gets its own token.
    cancelled = cancelled if cancelled is not None else threading.Event()
    if cancelled.is_set():
        raise InterruptedError("database execution cancelled")
    # A descendant retaining stdout must not delay observing leader completion.
    with tempfile.TemporaryFile(mode="w+") as output:
        process = None
        try:
            try:
                process = subprocess.Popen(
                    argv, cwd=ROOT, env=env, stdout=output, start_new_session=True
                )
                wait_capture(process, argv, cancelled)
            finally:
                if process is not None:
                    try:
                        stop(process)
                    except Exception as error:
                        raise UnconfirmedCommandCleanupError(process.pid) from error
        except subprocess.TimeoutExpired as error:
            output.seek(0)
            error.output = output.buffer.read()
            raise
        output.seek(0)
        text = output.read()
        if process.returncode:
            raise subprocess.CalledProcessError(process.returncode, argv, output=text)
        if cancelled.is_set():
            raise InterruptedError("database execution cancelled")
        return text.strip()


def inspect_suppliers(
    compose: list[str],
    env: dict[str, str],
    services: dict[str, Any],
    cancelled: threading.Event,
) -> dict[str, Any]:
    suppliers = {}
    for service in services:
        identifier = capture([*compose, "ps", "-q", service], env, cancelled=cancelled)
        if not re.fullmatch(r"[a-f0-9]{64}", identifier):
            raise ValueError("database supplier is absent or ambiguous")
        inspected = json.loads(
            capture(["docker", "inspect", identifier], env, cancelled=cancelled)
        )[0]
        labels = inspected["Config"]["Labels"]
        if (
            labels["com.docker.compose.project"] != env["COMPOSE_PROJECT_NAME"]
            or labels["com.docker.compose.service"] != service
        ):
            raise ValueError("database supplier is outside the owned project")
        port = 5432 if service == "postgres" else 6379
        address = capture([*compose, "port", service, str(port)], env, cancelled=cancelled)
        if not re.fullmatch(r"127\.0\.0\.1:[0-9]{1,5}", address):
            raise ValueError("database supplier lacks its own loopback port")
        suppliers[service] = {
            "container": identifier,
            "image": inspected["Image"],
            "address": address,
        }
        if service == "postgres":
            url = f"postgres://aegaeon:aegaeon@{address}/aegaeon?sslmode=disable"
            env.update(
                AEGAEON_DATABASE_URL=url,
                DATABASE_URL=url,
                AEGAEON_TEST_ADMIN_DATABASE_URL=url,
            )
        else:
            env["AEGAEON_TEST_REDIS_URL"] = f"redis://{address}/0"
    return suppliers


def lane_run(  # noqa: PLR0913 - explicit supplier scope and pre-execution directory identity
    lane: str,
    plan_path: Path,
    results: Path,
    work: Path,
    cancelled: threading.Event,
    *,
    expected_identity: tuple[int, int] | None = None,
) -> int:
    # Capture before any owned work, and retain the descriptor so deletion
    # cannot permit reuse of its inode during this lane's lifetime.
    with pinned_results_directory(results, expected_identity) as identity:
        return _lane_run(lane, plan_path, results, work, cancelled, results_identity=identity)


def write_lane_recovery(
    directory: Path, receipt: Path, record: dict[str, Any], cancelled: threading.Event
) -> None:
    # Keep discovery outside results, which may have disappeared. Loss of this
    # project directory or a storage error remains a failure, never cleanup proof.
    snapshot = {
        **record,
        # This diagnostic survives publication failure; only the normal lane
        # receipt can certify completion for aggregate validation.
        "complete": False,
        "scope": "recovery-only; not a completed lane receipt",
        "recovery": {
            "project": record["project"],
            "compose_file": str(directory / "compose.json"),
            "execution_receipts": str(receipt.parent),
            "requirement": "Confirm owned and nested process cleanup before project teardown",
        },
    }
    try:
        descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            replace_receipt(descriptor, "recovery", snapshot)
        finally:
            os.close(descriptor)
    except OSError as error:
        cancelled.set()
        record["complete"] = False
        error.add_note(
            f"database lane {record['name']}: returncode={record['returncode']}; "
            f"work error={record.get('error')}; receipt error={record.get('receipt_error')}"
        )
        raise


def publish_lane_receipt(
    directory: Path, receipt: Path, record: dict[str, Any], cancelled: threading.Event
) -> None:
    if not record["complete"]:
        cancelled.set()
    # Persist the known outcome before attempting the fragile results path.
    write_lane_recovery(directory, receipt, record, cancelled)
    try:
        receipt.write_text(json.dumps(record, indent=2) + "\n")
    except OSError as error:
        cancelled.set()
        record["complete"] = False
        record["receipt_error"] = f"{type(error).__name__}: {error}"
        write_lane_recovery(directory, receipt, record, cancelled)


def initialize_lane_receipt(
    directory: Path, receipt: Path, record: dict[str, Any], cancelled: threading.Event
) -> None:
    # No supplier starts unless its independent recovery location is durable.
    write_lane_recovery(directory, receipt, record, cancelled)
    print(
        f"database lane {record['name']}: recovery record {directory / 'recovery.json'}",
        file=sys.stderr,
    )
    try:
        with receipt.open("x") as stream:
            json.dump(record, stream)
    except OSError as error:
        cancelled.set()
        record["receipt_error"] = f"{type(error).__name__}: {error}"
        write_lane_recovery(directory, receipt, record, cancelled)
        raise


def _lane_run(  # noqa: PLR0913, PLR0915 - one supplier/receipt ownership boundary
    lane: str,
    plan_path: Path,
    results: Path,
    work: Path,
    cancelled: threading.Event,
    *,
    results_identity: tuple[int, int],
) -> int:
    plan = load_plan(plan_path)
    project = "aegaeon-db-" + uuid.uuid4().hex[:16] + "-" + lane
    directory = work / project
    directory.mkdir(parents=True, mode=0o700)
    config = directory / "compose.json"
    config.write_text(json.dumps(configuration(lane)))
    compose = ["docker", "compose", "--project-name", project, "-f", str(config)]
    env = {
        **os.environ,
        "COMPOSE_PROJECT_NAME": project,
        "DEV_COMPOSE_FILE": str(config),
        "AEGAEON_DATABASE_EXECUTION_PLAN": str(plan_path),
        "AEGAEON_DATABASE_EXECUTION_RESULTS": str(results),
        "AEGAEON_DATABASE_TEST_PACKAGE": plan["package"],
        "AEGAEON_SERVER_CONTAINER_SKIP_UP": "1",
        "AEGAEON_SERVER_CONTAINER_DOWN": "0",
    }
    receipt = results / f"lane-{lane}.json"
    record: dict[str, Any] = {
        "name": f"lane-{lane}",
        "project": project,
        "context": plan["context"],
        "plan_sha256": sha(plan_path),
        "build_sha256": plan["build_sha256"],
        "suppliers": {},
        "complete": False,
        "cleanup": False,
        "returncode": 1,
        "started_unix": time.time(),
        "results_directory_identity": {
            "device": results_identity[0],
            "inode": results_identity[1],
        },
    }
    initialize_lane_receipt(directory, receipt, record, cancelled)
    started = time.monotonic()
    try:
        with (directory / "execution.log").open("wb") as log:
            status = command([*compose, "up", "-d"], env, log, cancelled, timeout=300)
            if status:
                raise RuntimeError("database supplier startup failed")  # noqa: TRY301 - finally tears down partial startup
            record["suppliers"] = inspect_suppliers(
                compose, env, configuration(lane)["services"], cancelled
            )
            record["setup_seconds"] = time.monotonic() - started
            tested = time.monotonic()
            record["returncode"] = command(
                ["bash", "scripts/tests/run_server_container_integration.sh", lane],
                env,
                log,
                cancelled,
                timeout=3600,
            )
            record["test_seconds"] = time.monotonic() - tested
    except UnconfirmedCommandCleanupError as error:
        record["error"] = f"{type(error).__name__}: {error}"
        record["unconfirmed_groups"] = [error.group]
        cancelled.set()
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError) as error:
        record["error"] = f"{type(error).__name__}: {error}"
        cancelled.set()
    finally:
        cleanup_started = time.monotonic()
        try:
            if record.get("unconfirmed_groups"):
                raise ValueError("outer command group cleanup is unconfirmed")  # noqa: TRY301 - record recovery
            # Missing evidence is always unsafe. Explicit not-started records
            # permit cleanup after an earlier suite failed before later work.
            confirm_lane_cleanup(plan_path, results, lane, expected_identity=results_identity)
        except (OSError, ValueError, KeyError, TypeError) as error:
            record["cleanup_deferred"] = f"{type(error).__name__}: {error}"
            record["recovery"] = {
                "project": project,
                "compose_file": str(config),
                "execution_receipts": str(results),
                "requirement": "Confirm owned and nested process cleanup before project teardown",
            }
        else:
            cleanup_suppliers(compose, env, directory, project, record)
        record["cleanup_seconds"] = time.monotonic() - cleanup_started
        record["elapsed_seconds"] = time.monotonic() - started
        record["finished_unix"] = time.time()
        record["complete"] = (
            record["returncode"] == 0 and record["cleanup"] and not cancelled.is_set()
        )
        publish_lane_receipt(directory, receipt, record, cancelled)
        print(
            f"database lane {lane}: status={record['returncode']} cleanup={record['cleanup']}",
            flush=True,
        )
    if not record["complete"]:
        cancelled.set()
        return 1
    return 0


def cleanup_suppliers(
    compose: list[str], env: dict[str, str], directory: Path, project: str, record: dict[str, Any]
) -> None:
    try:
        with (directory / "cleanup.log").open("wb") as log:
            # Cancellation must not suppress teardown. Bound it independently.
            code = command(
                [*compose, "down", "--volumes", "--remove-orphans", "--timeout", "10"],
                env,
                log,
                threading.Event(),
                timeout=60,
            )
        remaining = capture(
            ["docker", "ps", "-aq", "--filter", f"label=com.docker.compose.project={project}"],
            env,
        )
        volumes = capture(
            [
                "docker",
                "volume",
                "ls",
                "-q",
                "--filter",
                f"label=com.docker.compose.project={project}",
            ],
            env,
        )
        networks = capture(
            [
                "docker",
                "network",
                "ls",
                "-q",
                "--filter",
                f"label=com.docker.compose.project={project}",
            ],
            env,
        )
        record["cleanup"] = code == 0 and not remaining and not volumes and not networks
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        record["cleanup_error"] = f"{type(error).__name__}: {error}"
        if isinstance(error, UnconfirmedCommandCleanupError):
            record["unconfirmed_groups"] = [error.group]


def main() -> int:
    plan_path = Path(os.environ["AEGAEON_DATABASE_EXECUTION_PLAN"]).resolve()
    results = Path(os.environ["AEGAEON_DATABASE_EXECUTION_RESULTS"]).resolve()
    plan = load_plan(plan_path)
    bind_package(plan, Path(plan["package"]))
    results.mkdir(parents=True, exist_ok=True)
    work = results.parent / "suppliers"
    cancelled = threading.Event()
    for signum in (signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, lambda _signum, _frame: cancelled.set())
    # Pin before initialization and keep the same identity through every lane.
    with pinned_results_directory(results) as identity:
        initialize_receipts(plan_path, results)
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = [
                executor.submit(
                    lane_run, lane, plan_path, results, work, cancelled, expected_identity=identity
                )
                for lane in LANES
            ]
            statuses = [future.result() for future in futures]
    return 1 if any(statuses) or cancelled.is_set() else 0


if __name__ == "__main__":
    raise SystemExit(main())
