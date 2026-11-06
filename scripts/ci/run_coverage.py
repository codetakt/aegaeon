#!/usr/bin/env python3
"""Measure workspace and existing database tests in one fresh coverage attempt."""

from __future__ import annotations

import contextlib
import copy
import json
import os
import re
import signal
import subprocess
import threading
import time
import uuid
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[2]
DB_COMMAND = """set -euo pipefail
coverage_environment=$(cargo llvm-cov show-env --export-prefix)
eval "$coverage_environment"
bash scripts/tests/run_server_container_integration.sh all
"""


def group_running(group: int) -> bool:
    """Inspect live members of our Linux group, excluding exited zombie members."""
    try:
        os.killpg(group, 0)
    except ProcessLookupError:
        return False
    proc = Path("/proc")
    if not proc.is_dir():
        raise RuntimeError("cannot confirm coverage process group cleanup without procfs")
    for entry in proc.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            fields = (entry / "stat").read_text().rsplit(") ", 1)[1].split()
        except (FileNotFoundError, ProcessLookupError):
            continue
        if int(fields[2]) == group and fields[0] not in ("Z", "X"):
            return True
    return False


def stop_process_group(process: subprocess.Popen[bytes], *, grace: float) -> None:
    with contextlib.suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGTERM)
    deadline = time.monotonic() + grace
    try:
        while True:
            process.poll()
            if not group_running(process.pid) or time.monotonic() >= deadline:
                break
            time.sleep(0.02)
    finally:
        # An inspection failure must still stop the owned group, then propagate
        # as a failed execution instead of certifying successful cleanup.
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=2)
    deadline = time.monotonic() + 2
    while group_running(process.pid):
        if time.monotonic() >= deadline:
            raise TimeoutError("coverage process group did not stop before cleanup")
        time.sleep(0.02)


def stop(process: subprocess.Popen[bytes]) -> None:
    stop_process_group(process, grace=10)


def command(argv: list[str], env: dict[str, str], cancelled: threading.Event, timeout: int) -> None:
    if cancelled.is_set():
        raise InterruptedError("coverage execution cancelled")
    process = subprocess.Popen(argv, cwd=ROOT, env=env, start_new_session=True)
    deadline = time.monotonic() + timeout
    try:
        while process.poll() is None:
            if cancelled.wait(0.2):
                raise InterruptedError("coverage execution cancelled")
            if time.monotonic() >= deadline:
                raise TimeoutError("coverage command exceeded its bound")
        if process.returncode:
            raise subprocess.CalledProcessError(process.returncode, argv)
    finally:
        stop(process)


def configuration() -> dict[str, Any]:
    original = yaml.safe_load((ROOT / "tests/docker/docker-compose.yml").read_text())
    services = {}
    for name, port in (("postgres", 5432), ("redis", 6379)):
        service = copy.deepcopy(original["services"][name])
        service.pop("container_name", None)
        service["ports"] = [{"target": port, "host_ip": "127.0.0.1", "published": "0"}]
        service["logging"] = {
            "driver": "json-file",
            "options": {"max-size": "10m", "max-file": "2"},
        }
        services[name] = service
    return {
        "services": services,
        "networks": original["networks"],
        "volumes": {name: original["volumes"][name] for name in ("postgres-data", "redis-data")},
    }


def capture(argv: list[str], env: dict[str, str]) -> str:
    return subprocess.check_output(argv, cwd=ROOT, env=env, text=True, timeout=30).strip()


def database(env: dict[str, str], cancelled: threading.Event) -> None:
    directory = ROOT / "artifacts/coverage" / ("suppliers-" + uuid.uuid4().hex)
    directory.mkdir(parents=True, mode=0o700)
    config = directory / "compose.json"
    config.write_text(json.dumps(configuration()))
    project = "aegaeon-coverage-" + uuid.uuid4().hex
    env = {
        **env,
        "COMPOSE_PROJECT_NAME": project,
        "DEV_COMPOSE_FILE": str(config),
        "AEGAEON_SERVER_CONTAINER_SKIP_UP": "1",
        "AEGAEON_SERVER_CONTAINER_DOWN": "0",
        # `show-env` uses this directory directly, whereas the ordinary
        # `cargo llvm-cov` command uses its llvm-cov-target child.
        "CARGO_TARGET_DIR": str(Path(env["CARGO_TARGET_DIR"]) / "llvm-cov-target"),
    }
    compose = ["docker", "compose", "--project-name", project, "-f", str(config)]
    try:
        command([*compose, "up", "-d"], env, cancelled, 300)
        addresses = {}
        for name, port in (("postgres", 5432), ("redis", 6379)):
            address = capture([*compose, "port", name, str(port)], env)
            if not re.fullmatch(r"127\.0\.0\.1:[0-9]{1,5}", address):
                raise ValueError("coverage supplier lacks an owned loopback port")
            addresses[name] = address
        database_url = f"postgres://aegaeon:aegaeon@{addresses['postgres']}/aegaeon?sslmode=disable"
        env.update(
            AEGAEON_DATABASE_URL=database_url,
            DATABASE_URL=database_url,
            AEGAEON_TEST_ADMIN_DATABASE_URL=database_url,
            AEGAEON_TEST_REDIS_URL=f"redis://{addresses['redis']}/0",
        )
        command(["bash", "-c", DB_COMMAND], env, cancelled, 3600)
    finally:
        # A failed or cancelled test must still tear down only its own suppliers.
        command(
            [*compose, "down", "--volumes", "--remove-orphans", "--timeout", "10"],
            env,
            threading.Event(),
            60,
        )
        for args in (("ps", "-aq"), ("volume", "ls", "-q"), ("network", "ls", "-q")):
            if capture(
                ["docker", *args, "--filter", f"label=com.docker.compose.project={project}"], env
            ):
                raise RuntimeError("coverage supplier cleanup is incomplete")


def main() -> int:
    env = dict(os.environ)
    for name in (
        "AEGAEON_DATABASE_TEST_PACKAGE",
        "AEGAEON_RFC_TEST_PACKAGE",
        "JOSE_SERVER_TEST_PACKAGE",
    ):
        if env.get(name):
            raise ValueError("coverage cannot execute a separately compiled test package")
    for name in ("LLVM_PROFILE_FILE", "CARGO_LLVM_COV_TARGET_DIR", "CARGO_LLVM_COV_SHOW_ENV"):
        if env.get(name):
            raise ValueError("coverage cannot inherit another instrumentation attempt")
    env["CARGO_TARGET_DIR"] = str(
        Path(env.get("CARGO_TARGET_DIR", ROOT / "target/coverage")).resolve()
    )
    (ROOT / "lcov.info").unlink(missing_ok=True)
    cancelled = threading.Event()
    for signum in (signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, lambda _signum, _frame: cancelled.set())
    command(["cargo", "llvm-cov", "--workspace", "--no-report"], env, cancelled, 3600)
    try:
        database(env, cancelled)
    finally:
        # Retain partial coverage on a database failure; that failure still
        # rejects this step and cannot become a successful coverage result.
        command(
            ["cargo", "llvm-cov", "report", "--lcov", "--output-path", "lcov.info"],
            env,
            threading.Event(),
            300,
        )
    if cancelled.is_set():
        raise InterruptedError("coverage execution cancelled")
    if not (ROOT / "lcov.info").stat().st_size:
        raise ValueError("coverage report is empty")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
