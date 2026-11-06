#!/usr/bin/env python3
"""Run three bounded, independently owned service groups using one native package."""

from __future__ import annotations

import contextlib
import copy
import json
import os
import re
import signal
import subprocess
import sys
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
sys.path.insert(0, str(ROOT / "scripts/validation"))
from database_execution import LANES, SUPPLIERS, bind_package, load_plan, sha  # noqa: E402


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
    # Each owned command has a new session; never signal a runner-wide group.
    with contextlib.suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGTERM)
    with contextlib.suppress(subprocess.TimeoutExpired):
        process.wait(timeout=10)
    # The leader may exit before a descendant that ignores TERM. Kill the owned
    # group even then, so a cancelled native test cannot outlive its suppliers.
    with contextlib.suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGKILL)
    process.wait(timeout=10)


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
        if process.poll() is None:
            stop(process)


def capture(argv: list[str], env: dict[str, str]) -> str:
    return subprocess.check_output(argv, cwd=ROOT, env=env, text=True, timeout=30).strip()


def inspect_suppliers(
    compose: list[str], env: dict[str, str], services: dict[str, Any]
) -> dict[str, Any]:
    suppliers = {}
    for service in services:
        identifier = capture([*compose, "ps", "-q", service], env)
        if not re.fullmatch(r"[a-f0-9]{64}", identifier):
            raise ValueError("database supplier is absent or ambiguous")
        inspected = json.loads(capture(["docker", "inspect", identifier], env))[0]
        labels = inspected["Config"]["Labels"]
        if (
            labels["com.docker.compose.project"] != env["COMPOSE_PROJECT_NAME"]
            or labels["com.docker.compose.service"] != service
        ):
            raise ValueError("database supplier is outside the owned project")
        port = 5432 if service == "postgres" else 6379
        address = capture([*compose, "port", service, str(port)], env)
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


def lane_run(  # noqa: PLR0915 - supplier ownership and receipt share one finally boundary
    lane: str, plan_path: Path, results: Path, work: Path, cancelled: threading.Event
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
    }
    with receipt.open("x") as stream:
        json.dump(record, stream)
    started = time.monotonic()
    try:
        with (directory / "execution.log").open("wb") as log:
            status = command([*compose, "up", "-d"], env, log, cancelled, timeout=300)
            if status:
                raise RuntimeError("database supplier startup failed")  # noqa: TRY301 - finally tears down partial startup
            record["suppliers"] = inspect_suppliers(compose, env, configuration(lane)["services"])
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
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError) as error:
        record["error"] = f"{type(error).__name__}: {error}"
        cancelled.set()
    finally:
        cleanup_started = time.monotonic()
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
        except (OSError, subprocess.SubprocessError) as error:
            record["cleanup_error"] = f"{type(error).__name__}: {error}"
        record["cleanup_seconds"] = time.monotonic() - cleanup_started
        record["elapsed_seconds"] = time.monotonic() - started
        record["finished_unix"] = time.time()
        record["complete"] = (
            record["returncode"] == 0 and record["cleanup"] and not cancelled.is_set()
        )
        receipt.write_text(json.dumps(record, indent=2) + "\n")
        print(
            f"database lane {lane}: status={record['returncode']} cleanup={record['cleanup']}",
            flush=True,
        )
    if not record["complete"]:
        cancelled.set()
        return 1
    return 0


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
    with ThreadPoolExecutor(max_workers=3) as executor:
        futures = [
            executor.submit(lane_run, lane, plan_path, results, work, cancelled) for lane in LANES
        ]
        statuses = [future.result() for future in futures]
    return 1 if any(statuses) or cancelled.is_set() else 0


if __name__ == "__main__":
    raise SystemExit(main())
