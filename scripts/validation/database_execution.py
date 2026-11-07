#!/usr/bin/env python3
"""Bind complete database selections and execution occurrences to one CI attempt."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import re
import selectors as io_selectors
import signal
import subprocess
import sys
import threading
import time
from collections import Counter
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from database_test_package import validate

if TYPE_CHECKING:
    from collections.abc import Iterator

ROOT = Path(__file__).resolve().parents[2]
LANES = ("redis", "postgres", "mixed")
SUPPLIERS = {"redis": ("redis",), "postgres": ("postgres", "redis"), "mixed": ("postgres", "redis")}
AUXILIARIES = ("fixture-guards", "models", "production", "recovery", "grant")
IDENTITY = re.compile(r"[A-Za-z0-9_:]+")
# Retained successful PostgreSQL output is approximately 160 MB, including
# subprocess migration diagnostics. Keep that evidence with bounded headroom.
MAX_LOG_BYTES = 256 * 1024 * 1024
DRIVERS = (
    "ci/database-execution.json",
    "scripts/validation/database_execution.py",
    "scripts/validation/database_test_package.py",
    "scripts/validation/run_required_cargo_test.sh",
    "scripts/tests/run_server_container_integration.sh",
    "scripts/ci/run_database_lanes.py",
    "scripts/ci/with_organization_userns.py",
    "tests/organizations/current_runtime.py",
    "tests/organizations/current_process.py",
    "tests/organizations/current_outage.py",
    "scripts/tests/database_fixture_guards.sh",
    "scripts/tests/database_recovery_runner.sh",
    "scripts/tests/subject_ownership_fixture.py",
    "scripts/validation/test_client_jwks_cache.py",
    "scripts/validation/test_jwks_fingerprint_ledger.py",
    "tests/docker/docker-compose.yml",
)


def group_running(group: int) -> bool:
    """Inspect live members of our Linux group, excluding exited zombie members."""
    try:
        os.killpg(group, 0)
    except ProcessLookupError:
        return False
    proc = Path("/proc")
    if not proc.is_dir():
        raise RuntimeError("cannot confirm database process group cleanup without procfs")
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


_cleanup_cancellation = threading.local()


def defer_cancellation(error: BaseException) -> bool:
    """Let installed handlers retain their first cancellation during owned cleanup."""
    pending = getattr(_cleanup_cancellation, "pending", None)
    if pending is None:
        return False
    if not pending:
        pending.append(error)
    return True


@contextlib.contextmanager
def cleanup_cancellation_guard() -> Iterator[None]:
    # Installed handlers consult this state; cleanup never switches OS handlers.
    # Python delivers handlers on the main thread, so worker cleanup is unchanged.
    if threading.current_thread() is not threading.main_thread():
        yield
        return
    previous = getattr(_cleanup_cancellation, "pending", None)
    pending: list[BaseException] = []
    _cleanup_cancellation.pending = pending
    try:
        yield
    finally:
        _cleanup_cancellation.pending = previous
    # A cleanup error propagates before this point and must not be masked by
    # cancellation. Nested cleanup passes the first request to its outer owner.
    if pending and not defer_cancellation(pending[0]):
        raise pending[0]


def stop_process_group(process: subprocess.Popen[bytes], *, grace: float = 2) -> None:
    with cleanup_cancellation_guard():
        _stop_process_group(process, grace=grace)


def _stop_process_group(process: subprocess.Popen[bytes], *, grace: float) -> None:
    # Auxiliary controllers get a shorter grace than the outer lane's ten
    # seconds, so they can finish cleanup before that owner escalates.
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
            raise TimeoutError("database process group did not stop before cleanup")
        time.sleep(0.02)


@contextlib.contextmanager
def cancellation_scope() -> Iterator[None]:
    # execute() also runs through database_test_package imports: __main__ alone
    # cannot establish cancellation handling for those callers.
    seen = False

    def cancelled(signum: int, _frame: Any) -> None:
        nonlocal seen
        if seen:
            return
        seen = True
        error = SystemExit(128 + signum)
        if not defer_cancellation(error):
            raise error

    previous = {sig: signal.signal(sig, cancelled) for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        yield
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def sha(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def read(path: Path) -> Any:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, entry in pairs:
            if key in value:
                raise ValueError("duplicate database evidence field")
            value[key] = entry
        return value

    return json.loads(path.read_text(), object_pairs_hook=unique)


def context() -> dict[str, str]:
    keys = (
        "GITHUB_REPOSITORY",
        "GITHUB_RUN_ID",
        "GITHUB_RUN_ATTEMPT",
        "GITHUB_SHA",
        "GITHUB_EVENT_NAME",
    )
    present = {key: os.environ[key] for key in keys if key in os.environ}
    if present and len(present) != len(keys):
        raise ValueError("incomplete database run context")
    return present


def skips() -> list[str]:
    config = read(ROOT / "ci/database-execution.json")
    if (
        config["version"] != 1
        or config["lanes"] != list(LANES)
        or config["max_workers"] != 3
        or config["suppliers"] != {name: list(services) for name, services in SUPPLIERS.items()}
    ):
        raise ValueError("unexpected database partition contract")
    values = config["namespace_skips"]
    if len(values) != len(set(values)) or not all(IDENTITY.fullmatch(x) for x in values):
        raise ValueError("invalid owned-runner exclusions")
    return [item for value in values for item in ("--skip", value)]


def selectors() -> dict[str, tuple[str, list[str]]]:
    serial = ["--ignored", "--test-threads=1"]
    excluded = skips()
    return {
        "redis": ("aegaeon_server", ["redis_", *serial, "--skip", "shared_redis_", *excluded]),
        "pre-migration": ("aegaeon_server", ["pre_migration_", *serial]),
        "postgres": (
            "aegaeon_server",
            [*serial, "--skip", "redis_", "--skip", "pre_migration_", *excluded],
        ),
        "dcr": ("dcr_database_test", serial),
        "mixed": ("aegaeon_server", ["shared_redis_", *serial, *excluded]),
        "jwks": (
            "aegaeon_server",
            [
                "client_registry::jwks_",
                "--include-ignored",
                "--skip",
                "client_registry::jwks_runtime_state::redis_kid::",
                "--skip",
                "::pg_",
                "--skip",
                "::shared_redis_",
                "--test-threads=1",
            ],
        ),
        "fingerprint": (
            "aegaeon_server",
            [
                "client_registry::jwks_runtime_state::redis_kid::",
                "--include-ignored",
                "--test-threads=1",
            ],
        ),
    }


def listing(text: str) -> list[str]:
    names = re.findall(r"^([A-Za-z0-9_:]+): test$", text, re.MULTILINE)
    totals = re.findall(r"^(\d+) tests?, 0 benchmarks?$", text, re.MULTILINE)
    if (
        len(totals) != 1
        or int(totals[0]) != len(names)
        or not names
        or len(set(names)) != len(names)
    ):
        raise ValueError("empty, duplicate or incomplete database discovery")
    return names


def discover(package: Path, destination: Path) -> None:
    validate(package)
    expected = subprocess.check_output(
        ["nix", "eval", "--raw", ".#database-tests.outPath"], cwd=ROOT, text=True, timeout=120
    ).strip()
    if str(package.resolve()) != expected:
        raise ValueError("database package is not the current source derivation")
    if destination.exists():
        raise ValueError("database plan already exists")
    suites = {}
    for name, (target, args) in selectors().items():
        output = subprocess.check_output(
            [str(package / "libexec" / target), *args, "--list"], text=True, timeout=60
        )
        suites[name] = {"target": target, "args": args, "tests": listing(output)}
    # Discovery records occurrences by suite: an intentional occurrence in a
    # different owned runner is never silently deduplicated.
    record = {
        "version": 1,
        "context": context(),
        "package": str(package.resolve()),
        "build_sha256": sha(package / "build.json"),
        "build": read(package / "build.json"),
        "partition_sha256": sha(ROOT / "ci/database-execution.json"),
        "drivers": {name: sha(ROOT / name) for name in DRIVERS},
        "suites": suites,
        "auxiliaries": list(AUXILIARIES),
        "lanes": list(LANES),
    }
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(record, indent=2) + "\n")


def load_plan(path: Path) -> dict[str, Any]:
    plan = read(path)
    if (
        plan["version"] != 1
        or plan["context"] != context()
        or set(plan["suites"]) != set(selectors())
        or plan["auxiliaries"] != list(AUXILIARIES)
        or plan["lanes"] != list(LANES)
        or plan["partition_sha256"] != sha(ROOT / "ci/database-execution.json")
        or plan["drivers"] != {name: sha(ROOT / name) for name in DRIVERS}
    ):
        raise ValueError("database plan differs from current attempt or partition")
    for name, (target, args) in selectors().items():
        suite = plan["suites"][name]
        if (
            suite["target"] != target
            or suite["args"] != args
            or not suite["tests"]
            or not all(IDENTITY.fullmatch(x) for x in suite["tests"])
            or len(suite["tests"]) != len(set(suite["tests"]))
        ):
            raise ValueError("database suite differs from discovery contract")
    return cast("dict[str, Any]", plan)


def bind_package(plan: dict[str, Any], package: Path) -> None:
    validate(package)
    if (
        str(package.resolve()) != plan["package"]
        or sha(package / "build.json") != plan["build_sha256"]
        or read(package / "build.json") != plan["build"]
    ):
        raise ValueError("database package/source/profile differs from discovery")


def completed_tests(output: str, expected: list[str]) -> list[str]:
    results = []
    pending = None
    for original in output.splitlines():
        line = original
        start = re.fullmatch(r"test ([A-Za-z0-9_:]+) \.\.\. (.*)", line)
        if start:
            if pending is not None:
                raise ValueError("database test started before its predecessor completed")
            pending, line = start.groups()
        # Libtest captures Rust output, but child psql/Atlas processes can write
        # between the name and result. Serial execution gives one pending name.
        if re.fullmatch(r"ok|FAILED|ignored(?:,.*)?", line):
            if pending is None:
                raise ValueError("database test result has no matching start")
            results.append((pending, line))
            pending = None
    totals = re.findall(
        r"^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;",
        output,
        re.MULTILINE,
    )
    if (
        pending is not None
        or len(totals) != 1
        or totals[0] != ("ok", str(len(expected)), "0", "0")
        or any(status != "ok" for _, status in results)
        or Counter(name for name, _ in results) != Counter(expected)
    ):
        raise ValueError(
            "database execution omitted, duplicated, failed or skipped discovered tests"
        )
    return [name for name, _ in results]


def owned_cwd(name: str) -> Path:
    return (
        ROOT / "crates/server"
        if name in ("redis", "pre-migration", "postgres", "dcr", "mixed")
        else ROOT
    )


def owned_command(plan: dict[str, Any], name: str) -> list[str]:
    if name in ("jwks", "fingerprint"):
        script = (
            "test_client_jwks_cache.py" if name == "jwks" else "test_jwks_fingerprint_ledger.py"
        )
        return [
            "nix",
            "develop",
            ".#ci",
            "--command",
            "python3",
            "scripts/validation/" + script,
            "--sudo-netns",
            "--compiled-package",
            plan["package"],
        ]
    if name in plan["suites"]:
        suite = plan["suites"][name]
        return [str(Path(plan["package"]) / "libexec" / suite["target"]), *suite["args"]]
    commands = {
        "fixture-guards": ["bash", "scripts/tests/database_fixture_guards.sh"],
        "models": [
            "nix",
            "build",
            "--no-link",
            *[
                f".#checks.x86_64-linux.organizations-{x}"
                for x in (
                    "catalog-upgrade",
                    "deployment-control",
                    "deployment-progress",
                    "maintenance-control",
                )
            ],
        ],
        "production": [
            "python3",
            "scripts/ci/with_organization_userns.py",
            "--report",
            "artifacts/organization-userns-db.json",
            "--",
            "nix",
            "build",
            ".#checks.x86_64-linux.organizations-production-runtime",
            "--no-link",
        ],
        "recovery": ["bash", "scripts/tests/database_recovery_runner.sh"],
        "grant": [
            "nix",
            "develop",
            ".#ci",
            "--command",
            "python3",
            "scripts/validation/check_authcode_redis_grant.py",
            "--out-dir",
            "artifacts/authcode-redis-correspondence",
        ],
    }
    return commands[name]


def execute(
    plan_path: Path, directory: Path, name: str, command: list[str], *, test_suite: bool = False
) -> int:
    plan = load_plan(plan_path)
    if name not in (plan["suites"] if test_suite else plan["auxiliaries"]):
        raise ValueError("unknown database obligation")
    if command != owned_command(plan, name):
        raise ValueError("database runner differs from its owned command")
    bind_package(plan, Path(plan["package"]))
    directory.mkdir(parents=True, exist_ok=True)
    receipt = directory / f"{name}.json"
    record = {
        "name": name,
        "context": plan["context"],
        "plan_sha256": sha(plan_path),
        "build_sha256": plan["build_sha256"],
        "command": command,
        "cwd": str(owned_cwd(name)),
        "started_unix": time.time(),
        "complete": False,
    }
    # A duplicate invocation cannot overwrite its predecessor's failed result.
    with receipt.open("x") as stream:
        json.dump(record, stream)
    started = time.monotonic()
    log = directory / f"{name}.log"
    status = 1
    # The namespace wrapper owns observer shutdown (15s grace + 2s wait + 2s
    # confirmation) and three policy operations (each 5s + 2s wait + 2s confirm).
    # Its 46s bound gets four seconds for reporting. Recovery can also be inside
    # an outage: HTTP probes (38s), PG
    # restart (25s), server drain/escalation (55s + 10s), then PG stop (25s).
    # Include nested command group confirmation and leave time for its receipt;
    # killing that controller after 35s can strand its separate PostgreSQL group.
    cleanup_grace = {"production": 50, "recovery": 180}.get(name, 2)
    try:
        with cancellation_scope(), log.open("wb") as stream:
            process = None
            cleaned = False
            try:
                # Cancellation may arrive inside Popen, before its caller can
                # register the returned child. Propagate it only inside this try.
                with cleanup_cancellation_guard():
                    process = subprocess.Popen(
                        command,
                        cwd=owned_cwd(name),
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        start_new_session=True,
                    )
                output = process.stdout
                assert output is not None
                with output, io_selectors.DefaultSelector() as watcher:
                    watcher.register(output, io_selectors.EVENT_READ)
                    written = 0
                    while True:
                        # Descendants may retain the pipe after its leader exits.
                        # Poll independently of EOF, stop them, then drain bytes.
                        if process.poll() is not None and not cleaned:
                            stop_process_group(process, grace=cleanup_grace)
                            cleaned = True
                        if not watcher.select(timeout=0.1):
                            continue
                        chunk = os.read(output.fileno(), 65536)
                        if not chunk:
                            break
                        written += len(chunk)
                        if written > MAX_LOG_BYTES:
                            raise ValueError("database execution log exceeds storage bound")
                        stream.write(chunk)
                        sys.stdout.buffer.write(chunk)
                        sys.stdout.buffer.flush()
                status = process.wait()
            finally:
                if process is not None and not cleaned:
                    stop_process_group(process, grace=cleanup_grace)
        record["returncode"] = status
        if status == 0:
            if test_suite:
                if log.stat().st_size > MAX_LOG_BYTES:
                    raise ValueError("database test log exceeds admission bound")
                record["tests"] = completed_tests(
                    log.read_text(errors="replace"), plan["suites"][name]["tests"]
                )
            record["complete"] = True
    finally:
        record["elapsed_seconds"] = time.monotonic() - started
        record["finished_unix"] = time.time()
        if log.exists():
            record["log_sha256"] = sha(log)
        receipt.write_text(json.dumps(record, indent=2) + "\n")
    return status


def recorded_libtest(package: Path, target: str, args: list[str]) -> int:
    plan_path = Path(os.environ["AEGAEON_DATABASE_EXECUTION_PLAN"])
    plan = load_plan(plan_path)
    bind_package(plan, package)
    matches = [
        name
        for name, suite in plan["suites"].items()
        if suite["target"] == target and suite["args"] == args
    ]
    if len(matches) != 1:
        raise ValueError("unplanned database execution")
    return execute(
        plan_path,
        Path(os.environ["AEGAEON_DATABASE_EXECUTION_RESULTS"]),
        matches[0],
        [str(package.resolve() / "libexec" / target), *args],
        test_suite=True,
    )


def aggregate(plan_path: Path, directory: Path, output: Path) -> None:
    plan = load_plan(plan_path)
    bind_package(plan, Path(plan["package"]))
    if output.exists():
        raise ValueError("database aggregate already exists")
    expected = set(plan["suites"]) | set(plan["auxiliaries"]) | {f"lane-{x}" for x in LANES}
    files = {p.stem: p for p in directory.glob("*.json")}
    if set(files) != expected:
        raise ValueError("missing or extra database execution receipts")
    rows = []
    projects: set[str] = set()
    containers: set[str] = set()
    for name in sorted(expected):
        row = read(files[name])
        if (
            row.get("name") != name
            or row.get("context") != plan["context"]
            or row.get("plan_sha256") != sha(plan_path)
            or row.get("build_sha256") != plan["build_sha256"]
            or row.get("complete") is not True
            or row.get("returncode") != 0
        ):
            raise ValueError("incomplete, failed or foreign database receipt: " + name)
        if name.startswith("lane-"):
            lane = name.removeprefix("lane-")
            services = set(SUPPLIERS[lane])
            suppliers = row.get("suppliers", {})
            project = row.get("project", "")
            if (
                row.get("cleanup") is not True
                or not re.fullmatch(r"aegaeon-db-[a-f0-9]{16}-" + lane, project)
                or project in projects
                or set(suppliers) != services
            ):
                raise ValueError("database supplier cleanup is unconfirmed")
            projects.add(project)
            for supplier in suppliers.values():
                container = supplier.get("container", "")
                if not re.fullmatch(r"[a-f0-9]{64}", container) or container in containers:
                    raise ValueError("database lanes share or omit a supplier")
                containers.add(container)
        else:
            if row.get("command") != owned_command(plan, name) or row.get("cwd") != str(
                owned_cwd(name)
            ):
                raise ValueError("database runner receipt differs from owned command")
            log = directory / f"{name}.log"
            if log.stat().st_size > MAX_LOG_BYTES:
                raise ValueError("database execution log exceeds storage bound")
            if sha(log) != row.get("log_sha256"):
                raise ValueError("database execution log changed")
            if name in plan["suites"]:
                observed = completed_tests(
                    log.read_text(errors="replace"), plan["suites"][name]["tests"]
                )
                if observed != row.get("tests"):
                    raise ValueError("database occurrence receipt changed")
        rows.append(row)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(
            {
                "version": 1,
                "context": plan["context"],
                "plan_sha256": sha(plan_path),
                "complete": True,
                "occurrences": sum(len(x["tests"]) for x in plan["suites"].values()),
                "results": rows,
            },
            indent=2,
        )
        + "\n"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("skips", "discover", "run", "aggregate"))
    parser.add_argument(
        "--plan", type=Path, default=os.environ.get("AEGAEON_DATABASE_EXECUTION_PLAN")
    )
    parser.add_argument("--package", type=Path)
    parser.add_argument(
        "--results", type=Path, default=os.environ.get("AEGAEON_DATABASE_EXECUTION_RESULTS")
    )
    parser.add_argument("--output", type=Path)
    parser.add_argument("--name")
    args = parser.parse_args()
    try:
        if args.action == "skips":
            print("\n".join(skips()))
        elif args.action == "discover":
            discover(args.package, args.plan)
        elif args.action == "aggregate":
            aggregate(args.plan, args.results, args.output)
        else:
            plan = load_plan(args.plan)
            return execute(
                args.plan,
                args.results,
                args.name,
                owned_command(plan, args.name),
                test_suite=args.name in plan["suites"],
            )
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print(f"database execution rejected: {type(error).__name__}: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    with cancellation_scope():
        raise SystemExit(main())
