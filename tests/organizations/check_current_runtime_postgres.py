"""Exercise runtime cleanup against real PostgreSQL, including a refused stop.

This executes the runtime's exact run/finalizer functions, not its product startup
scenarios. The injected fault is a failed work-stop confirmation; PostgreSQL,
psql, process groups and cancellation signals are real.
"""

from __future__ import annotations

import argparse
import ast
import contextlib
import importlib.util
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import types
from pathlib import Path

import current_postgres as postgres_ownership


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def process_snapshot(pid):
    try:
        process = Path(f"/proc/{pid}")
        fields = (process / "stat").read_text().rsplit(") ", 1)[1].split()
        return (
            {
                "pid": pid,
                "group": int(fields[2]),
                "session": int(fields[3]),
                "starttime": fields[19],
                "uid": process.stat().st_uid,
            },
            fields[0],
        )
    except (FileNotFoundError, ProcessLookupError):
        return None


def identity(pid):
    snapshot = process_snapshot(pid)
    return None if snapshot is None else snapshot[0]


def save(path, value):
    with path.open("x") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def load_process(root):
    sys.path.insert(0, str(root / "scripts/validation"))
    spec = importlib.util.spec_from_file_location(
        "cleanup_current_process", root / "tests/organizations/current_process.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def command(argv, env, execution, timeout=3):
    # Separate sessions keep the owner able to reclaim a timed-out observer.
    with tempfile.TemporaryFile(mode="w+") as output:
        child = subprocess.Popen(  # noqa: S603 - explicit pinned tools, no shell.
            list(map(str, argv)),
            env=env,
            stdout=output,
            stderr=output,
            text=True,
            start_new_session=True,
        )
        try:
            status = child.wait(timeout=timeout)
        finally:
            execution.stop_process_group(child, grace=0.2)
        output.seek(0)
        return status, output.read().strip()


def environment(directory):
    return {
        **{key: value for key, value in os.environ.items() if not key.startswith("PG")},
        "PGHOST": str(directory / "socket"),
        "PGPORT": "5432",
        "PGUSER": "postgres",
        "PGDATABASE": "postgres",
        "PGCONNECT_TIMEOUT": "3",
    }


def start_postgres(run, pg, directory, cluster):
    """Publish captured ownership even when a late startup cancellation propagates."""
    primary_error = None
    try:
        result = run(
            [
                pg / "pg_ctl",
                "-D",
                directory / "data",
                "-l",
                directory / "postgres.log",
                "-w",
                "-t",
                "10",
                "start",
            ],
            supplier=directory / "data",
            timeout=15,
        )
        require(result.returncode == 0, "real PostgreSQL startup failed")
    except BaseException as error:
        primary_error = error
        raise
    finally:
        record = cluster.get("postgres_owner")
        if record is not None:
            try:
                postgres_ownership.validate_record(pg, directory / "data", record)
                save(directory / "postmaster-identity.json", record)
            except BaseException as error:
                if primary_error is None:
                    raise
                primary_error.add_note(
                    f"postmaster ownership publication failed: {type(error).__name__}: {error}"
                )


def controller(args, current, execution):  # noqa: PLR0915 - one bounded fault lifecycle.
    directory, pg = args.directory, args.postgres_bin
    env = environment(directory)
    current.install_cancellation()
    output = directory / "report"
    output.mkdir()
    report = {"passed": True}
    log = (directory / "setup.log").open("w")
    values = {
        **{
            name: getattr(current, name)
            for name in (
                "cleanup_scope",
                "unconfirmed_groups",
                "supplier_start_groups",
                "cancellation_recorded",
                "check_cancellation",
                "run_owned",
            )
        },
        "clusters": {"primary": {"data": directory / "data"}},
        "pg": pg,
        "root": args.root,
        "env": env,
        "setup_log": log,
        "report": report,
        "shutil": shutil,
        "temporary": directory,
        "a": types.SimpleNamespace(output=output),
        "json": json,
        "postgres_ownership": postgres_ownership,
        "subprocess": subprocess,
    }
    source = args.root / "tests/organizations/current_runtime.py"
    nodes = [
        node
        for node in ast.parse(source.read_text()).body
        if isinstance(node, ast.FunctionDef) and node.name in ("run", "finish_runtime")
    ]
    require(len(nodes) == 2, "runtime run/finalizer functions must both exist")
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(source), "exec"), values)  # noqa: S102 - exact local source functions.
    run = values["run"]
    result = run(
        [pg / "initdb", "-D", directory / "data", "-U", "postgres", "--auth=trust", "--no-locale"],
        timeout=20,
    )
    require(result.returncode == 0, "real PostgreSQL initialization failed")
    with (directory / "data/postgresql.conf").open("a") as config:
        config.write(
            f"\nlisten_addresses=''\nunix_socket_directories='{directory / 'socket'}'"
            "\nstatement_timeout=12000\n"
        )
    start_postgres(run, pg, directory, values["clusters"]["primary"])
    observed = {"mode": args.mode, "real_query_active_before_fault": False}

    def query(sql):
        return command([pg / "psql", "-XqAt", "-c", sql], env, execution)

    def before_wait(child):
        owned = identity(child.pid)
        require(
            owned is not None and owned["pid"] == owned["group"] == owned["session"],
            "psql must have an independent owned session",
        )
        save(directory / "work-identity.json", owned)
        until = time.monotonic() + 5
        while time.monotonic() < until:
            status, value = query(
                "select count(*) from pg_stat_activity where "
                "application_name='aeg-cleanup-work' and state='active' "
                "and query='select pg_sleep(10)'"
            )
            if status == 0 and value == "1":
                break
            time.sleep(0.05)
        else:
            message = "real PostgreSQL query did not start"
            raise TimeoutError(message)
        observed["real_query_active_before_fault"] = True
        if args.mode == "cancel":
            os.kill(os.getpid(), signal.SIGTERM)
        else:

            def unconfirmed_stop(*_args, **_kwargs):
                message = "injected work-stop confirmation failure"
                raise TimeoutError(message)

            current.stop_process_group = unconfirmed_stop
            message = "controlled original work failure"
            raise ValueError(message)

    failure = None
    original_stop = current.stop_process_group
    try:
        run(
            [pg / "psql", "-XqAt", "-c", "select pg_sleep(10)"],
            environment={**env, "PGAPPNAME": "aeg-cleanup-work"},
            timeout=20,
            before_wait=before_wait,
        )
    except BaseException as error:  # noqa: BLE001 - preserve the injected/cancellation error.
        failure = error
    finally:
        # The refusal remains active through the finalizer under test.
        try:
            values["finish_runtime"](primary_error=failure)
        finally:
            current.stop_process_group = original_stop
    observed.update(
        report=json.loads((output / "result.json").read_text()),
        unconfirmed_groups=current.unconfirmed_groups(),
        supplier_query_after_finalizer=query("select 1"),
        original_error=type(failure).__name__,
        original_error_notes=getattr(failure, "__notes__", []),
    )
    save(directory / "observation.json", observed)
    require(failure is not None and report["passed"] is False, "failure must not become success")
    if args.mode == "cancel":
        require(
            report["owned_suppliers_stopped"]
            and report["owned_work_stopped"]
            and report["cancellation_recorded"],
            "cancellation cleanup was not confirmed",
        )
        require(
            not current.unconfirmed_groups() and observed["supplier_query_after_finalizer"][0] != 0,
            "cancelled work or real PostgreSQL remained available",
        )
    else:
        require(isinstance(failure, ValueError), "original work failure was replaced")
        require(
            not report["owned_suppliers_stopped"] and not report["owned_work_stopped"],
            "unconfirmed work must retain the real supplier",
        )
        require(
            len(current.unconfirmed_groups()) == 1
            and observed["supplier_query_after_finalizer"] == (0, "1"),
            "real PostgreSQL must still serve queries after refused teardown",
        )
        require(
            report["recovery"]["confirm_work_before_supplier_cleanup"]
            == current.unconfirmed_groups(),
            "recovery omitted unconfirmed work",
        )


def recover(directory, pg, execution):
    # Reclaim the retained psql before stopping its independent PostgreSQL server.
    marker = directory / "work-identity.json"
    if marker.exists():
        owned = json.loads(marker.read_text())
        actual = identity(owned["pid"])
        if actual is not None:
            require(actual == owned, "psql identity changed; refusing recovery signal")
            with contextlib.suppress(ProcessLookupError):
                os.killpg(owned["group"], signal.SIGTERM)
        until = time.monotonic() + 3
        while execution.group_running(owned["group"]) and time.monotonic() < until:
            time.sleep(0.02)
        require(not execution.group_running(owned["group"]), "owned psql group did not stop")
    data = directory / "data"
    marker = directory / "postmaster-identity.json"
    try:
        record = json.loads(marker.read_text())
    except FileNotFoundError:
        message = "PostgreSQL ownership marker is missing"
        raise AssertionError(message) from None
    postgres_ownership.stop(pg, data, record, mode="immediate", timeout=10)


def finish_case(args, execution, child, result, primary_error):  # noqa: PLR0912, PLR0915 - preserve work, cleanup and publication failures.
    directory = Path(result["directory"])
    failure = primary_error
    result["owned_processes_stopped"] = False
    if primary_error is not None:
        result["passed"] = False
        result["error"] = f"{type(primary_error).__name__}: {primary_error}"
    stage = "controller"
    try:
        if child is not None:
            execution.stop_process_group(child, grace=0.2)
        # An unconfirmed controller may still start work. Do not reclaim its
        # work or PostgreSQL until the controller group is confirmed stopped.
        stage = "suppliers"
        recover(directory, args.postgres_bin, execution)
        result["owned_processes_stopped"] = True
    except BaseException as error:  # noqa: BLE001 - persist failure before propagation.
        result["passed"] = False
        result["cleanup_stage"] = stage
        result["cleanup_error"] = f"{type(error).__name__}: {error}"
        result["recovery"] = {
            "directory": str(directory),
            "controller_log": str(directory / "controller.log"),
            "work_identity": str(directory / "work-identity.json"),
            "postmaster_identity": str(directory / "postmaster-identity.json"),
            "requirement": "Confirm controller, then work, before PostgreSQL teardown",
        }
        if failure is None:
            failure = error
        else:
            failure.add_note(f"fixture cleanup failed: {result['cleanup_error']}")
    finally:
        path = args.output / f"{result['mode']}.json"
        try:
            save(path, result)
        except BaseException as error:  # noqa: BLE001 - publication cannot become success.
            result["passed"] = False
            if failure is None:
                failure = error
            else:
                failure.add_note(
                    f"case result publication failed at {path}: {type(error).__name__}: {error}"
                )
    if failure is not None:
        raise failure


def owner(args, execution):
    args.output.mkdir(mode=0o700, parents=True)
    cases = []
    with execution.cancellation_scope():
        for mode in ("cancel", "unconfirmed"):
            execution.check_cancellation()
            # A short socket pathname also works in a long Nix build directory.
            directory = Path(tempfile.mkdtemp(prefix="aeg-pg-cleanup-"))
            (directory / "socket").mkdir(mode=0o700)
            result = {"mode": mode, "directory": str(directory), "passed": False}
            child = None
            failure = None
            try:
                with (directory / "controller.log").open("x") as log:
                    child = subprocess.Popen(  # noqa: S603 - this source and fixed argument paths.
                        [
                            sys.executable,
                            str(Path(__file__).resolve()),
                            "--root",
                            str(args.root),
                            "--postgres-bin",
                            str(args.postgres_bin),
                            "--output",
                            str(args.output),
                            "--directory",
                            str(directory),
                            "--mode",
                            mode,
                        ],
                        stdout=log,
                        stderr=log,
                        start_new_session=True,
                    )
                    until = time.monotonic() + 60
                    while child.poll() is None and time.monotonic() < until:
                        execution.check_cancellation()
                        time.sleep(0.05)
                    require(child.poll() is not None, "PostgreSQL controller exceeded deadline")
                    require(
                        child.returncode == 0, f"{mode} failed; see {directory / 'controller.log'}"
                    )
                result["observation"] = json.loads((directory / "observation.json").read_text())
                result["passed"] = True
            except BaseException as error:  # noqa: BLE001 - preserve through cleanup/publication.
                failure = error
            finally:
                cases.append(result)
                finish_case(args, execution, child, result, failure)
    save(args.output / "result.json", {"passed": True, "cases": cases})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--postgres-bin", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--directory", type=Path)
    parser.add_argument("--mode", choices=("cancel", "unconfirmed"))
    args = parser.parse_args()
    require((args.directory is None) == (args.mode is None), "controller needs directory and mode")
    args.root, args.postgres_bin = args.root.resolve(), args.postgres_bin.resolve()
    os.umask(0o077)
    current = load_process(args.root)
    import database_execution as execution  # noqa: PLC0415 - source root was explicitly selected.

    if args.mode:
        controller(args, current, execution)
    else:
        owner(args, execution)


if __name__ == "__main__":
    main()
