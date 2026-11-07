"""Reject incomplete or foreign DB executions without rerunning service tests."""

from __future__ import annotations

import inspect
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/validation"))
sys.path.insert(0, str(ROOT / "scripts/ci"))
import database_execution as execution  # noqa: E402
import run_database_lanes as lanes  # noqa: E402
from build_observations import run_observed  # noqa: E402


def successful_output(names):
    return (
        "".join(f"test {name} ... ok\n" for name in names)
        + f"test result: ok. {len(names)} passed; 0 failed; 0 ignored;\n"
    )


def make_inventory(tmp_path, monkeypatch):
    for key in list(os.environ):
        if key.startswith("GITHUB_"):
            monkeypatch.delenv(key)
    package = tmp_path / "package"
    (package / "libexec").mkdir(parents=True)
    cases = {
        name: [name.replace("-", "_") + "::first", name.replace("-", "_") + "::second"]
        for name in execution.selectors()
    }
    receipt = {
        "schema_version": 1,
        "scope": "database-test-compilation-v1",
        "build": {"source": "fixture"},
        "binaries": {},
    }
    for target, kind in (("aegaeon_server", "lib"), ("dcr_database_test", "test")):
        selections = {
            json.dumps(args): cases[name]
            for name, (selected_target, args) in execution.selectors().items()
            if target == selected_target
        }
        binary = package / "libexec" / target
        binary.write_text(
            f"#!{sys.executable}\n"
            f"SELECTIONS={selections!r}\n"
            """
import json,os,sys
args=sys.argv[1:]
listing='--list' in args
if listing: args.remove('--list')
names=SELECTIONS[json.dumps(args)]
if listing:
    print(''.join(name+': test\\n' for name in names)+f'{len(names)} tests, 0 benchmarks')
else:
    mode=os.environ.get('EXECUTION_FAULT','')
    if mode=='missing': names=names[:-1]
    if mode=='duplicate': names=[names[0],names[0]]
    if mode=='zero': names=[]
    for name in names: print('test '+name+' ... ok')
    print(f'test result: ok. {len(names)} passed; 0 failed; 0 ignored;')
    if mode=='failure': sys.exit(37)
"""
        )
        binary.chmod(0o755)
        receipt["binaries"][target] = {
            "kind": kind,
            "features": ["default", "telemetry"],
            "sha256": execution.sha(binary),
            "profile": {
                "test": True,
                "opt_level": "0",
                "debuginfo": 2,
                "debug_assertions": True,
                "overflow_checks": True,
            },
        }
    (package / "build.json").write_text(json.dumps(receipt))
    nix = tmp_path / "nix"
    nix.write_text(
        f"#!{sys.executable}\nimport os,sys\n"
        "assert sys.argv[1:]==['eval','--raw','.#database-tests.outPath']\n"
        "print(os.environ['EXPECTED_PACKAGE'])\n"
    )
    nix.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path) + ":" + os.environ["PATH"])
    monkeypatch.setenv("EXPECTED_PACKAGE", str(package))
    plan_path = tmp_path / "plan.json"
    execution.discover(package, plan_path)
    plan = execution.load_plan(plan_path)
    results = tmp_path / "results"
    results.mkdir()
    return plan_path, plan, results


def complete_receipts(inventory):
    path, plan, results = inventory
    common = {
        "context": plan["context"],
        "plan_sha256": execution.sha(path),
        "build_sha256": plan["build_sha256"],
        "complete": True,
        "returncode": 0,
    }
    for name in (*plan["suites"], *plan["auxiliaries"]):
        row = {
            **common,
            "name": name,
            "command": execution.owned_command(plan, name),
            "cwd": str(execution.owned_cwd(name)),
            "process_cleanup_confirmed": True,
        }
        log = results / f"{name}.log"
        if name in plan["suites"]:
            row["tests"] = plan["suites"][name]["tests"]
            log.write_text(successful_output(row["tests"]))
        else:
            log.write_text("owned runner completed\n")
        row["log_sha256"] = execution.sha(log)
        (results / f"{name}.json").write_text(json.dumps(row))
    for index, lane in enumerate(execution.LANES):
        services = lanes.configuration(lane)["services"]
        row = {
            **common,
            "name": "lane-" + lane,
            "project": "aegaeon-db-" + "a" * 16 + "-" + lane,
            "cleanup": True,
            "suppliers": {
                name: {"container": f"{index * 2 + j + 1:064x}"} for j, name in enumerate(services)
            },
        }
        (results / f"lane-{lane}.json").write_text(json.dumps(row))


def collect(inventory):
    path, _, results = inventory
    output = results.parent / "aggregate.json"
    execution.aggregate(path, results, output)
    return json.loads(output.read_text())


def check_exact_occurrences_and_auxiliaries_are_required(inventory):
    complete_receipts(inventory)
    result = collect(inventory)
    assert result["complete"] is True
    assert result["occurrences"] == 14
    assert len(result["results"]) == 15
    with pytest.raises(ValueError, match="already exists"):
        collect(inventory)


def check_omission_fails_even_when_other_results_pass(inventory, missing):
    complete_receipts(inventory)
    (inventory[2] / f"{missing}.json").unlink()
    with pytest.raises(ValueError, match="missing or extra"):
        collect(inventory)


def check_duplicate_receipt_is_rejected(inventory):
    complete_receipts(inventory)
    (inventory[2] / "redis-copy.json").write_text((inventory[2] / "redis.json").read_text())
    with pytest.raises(ValueError, match="missing or extra"):
        collect(inventory)


def check_failed_cancelled_or_foreign_result_never_admits(inventory, field, value):
    complete_receipts(inventory)
    path = inventory[2] / "production.json"
    row = json.loads(path.read_text())
    row[field] = value
    path.write_text(json.dumps(row))
    with pytest.raises(ValueError, match=r"database|empty"):
        collect(inventory)


def check_isolation_and_cleanup_are_obligations(inventory, fault):
    complete_receipts(inventory)
    path = inventory[2] / "lane-mixed.json"
    row = json.loads(path.read_text())
    if fault == "cleanup":
        row["cleanup"] = False
    elif fault == "missing_supplier":
        del row["suppliers"]["postgres"]
    elif fault == "project":
        row["project"] = "unowned"
    else:
        row["suppliers"]["redis"]["container"] = f"{1:064x}"
    path.write_text(json.dumps(row))
    with pytest.raises(ValueError, match=r"database|empty"):
        collect(inventory)


def check_actual_child_cannot_report_a_partial_success(inventory, monkeypatch, fault):
    path, plan, results = inventory
    monkeypatch.setenv("EXECUTION_FAULT", fault)
    if fault == "failure":
        assert (
            execution.execute(
                path, results, "redis", execution.owned_command(plan, "redis"), test_suite=True
            )
            == 37
        )
    else:
        with pytest.raises(ValueError, match="omitted, duplicated"):
            execution.execute(
                path, results, "redis", execution.owned_command(plan, "redis"), test_suite=True
            )
    assert json.loads((results / "redis.json").read_text())["complete"] is False
    with pytest.raises(FileExistsError):
        execution.execute(
            path, results, "redis", execution.owned_command(plan, "redis"), test_suite=True
        )


def check_actual_child_completion_and_duplicate_guard(inventory):
    path, plan, results = inventory
    assert (
        execution.execute(
            path, results, "redis", execution.owned_command(plan, "redis"), test_suite=True
        )
        == 0
    )
    assert (
        json.loads((results / "redis.json").read_text())["tests"]
        == plan["suites"]["redis"]["tests"]
    )


def check_wrong_artifact_source_and_changed_log_are_rejected(inventory, monkeypatch):
    path, plan, results = inventory
    monkeypatch.setenv("EXPECTED_PACKAGE", "/other-source")
    with pytest.raises(ValueError, match="current source"):
        execution.discover(Path(plan["package"]), path.parent / "other.json")
    complete_receipts(inventory)
    (results / "redis.log").write_text("changed")
    with pytest.raises(ValueError, match="log changed"):
        collect(inventory)
    (Path(plan["package"]) / "libexec/aegaeon_server").write_text("changed")
    with pytest.raises(ValueError, match="does not match"):
        execution.bind_package(plan, Path(plan["package"]))


def check_empty_duplicated_or_incomplete_discovery_fails(text):
    with pytest.raises(ValueError, match=r"database|empty"):
        execution.listing(text)


def check_skipped_and_duplicated_runtime_occurrences_fail():
    for output in (
        "test x ... ignored\ntest result: ok. 0 passed; 0 failed; 1 ignored;\n",
        successful_output(["x", "x"]),
        successful_output(["y"]),
    ):
        with pytest.raises(ValueError, match=r"database|empty"):
            execution.completed_tests(output, ["x"])


def check_supplier_specs_do_not_share_names_or_host_ports():
    for lane in execution.LANES:
        config = lanes.configuration(lane)
        for service in config["services"].values():
            assert "container_name" not in service
            assert service["ports"][0]["published"] == "0"
            assert service["ports"][0]["host_ip"] == "127.0.0.1"
        assert not any(value and "name" in value for value in config["volumes"].values())


def check_build_trace_keeps_failure_and_post_test_tail(tmp_path):
    log = tmp_path / "observations.jsonl"
    command = [
        sys.executable,
        "-c",
        (
            "import sys; print('nextest complete',file=sys.stderr); "
            "print('building release.drv',file=sys.stderr); sys.exit(37)"
        ),
    ]
    with pytest.raises(subprocess.CalledProcessError) as error:
        run_observed(command, log)
    assert error.value.returncode == 37
    rows = [json.loads(line) for line in log.read_text().splitlines()]
    assert rows[0]["command"] == command
    assert rows[-1]["returncode"] == 37
    assert rows[-1]["truncated"] is False
    assert [x["text"] for x in rows if x["event"] == "output"] == [
        "nextest complete\n",
        "building release.drv\n",
    ]
    assert [x["elapsed_seconds"] for x in rows] == sorted(x["elapsed_seconds"] for x in rows)


def check_lane_lifecycle_keeps_cleanup_required(inventory, monkeypatch, fault):  # noqa: C901 - lifecycle fault matrix
    path, _, results = inventory
    cancelled = threading.Event()
    calls = []

    def fake_command(argv, env, log, event, *, timeout):  # noqa: PLR0911 - explicit fault outcomes
        calls.append(argv)
        if "up" in argv and fault == "startup":
            return 21
        if argv[0] == "bash":
            if fault == "cancelled":
                cancelled.set()
                raise InterruptedError
            if fault == "tests":
                return 37
        if "down" in argv:
            assert not event.is_set(), "teardown must survive cancellation"
            return 42 if fault == "cleanup" else 0
        return 0

    def fake_capture(argv, env):  # noqa: PLR0911 - distinct supplier commands
        if "--filter" in argv:
            return ""
        if "ps" in argv:
            return "" if fault == "supplier" else ("a" if argv[-1] == "postgres" else "b") * 64
        if "port" in argv:
            return "127.0.0.1:15432"
        assert argv[:2] == ["docker", "inspect"]
        return json.dumps(
            [
                {
                    "Image": "owned-image",
                    "Config": {
                        "Labels": {
                            "com.docker.compose.project": env["COMPOSE_PROJECT_NAME"],
                            "com.docker.compose.service": "postgres"
                            if argv[-1] == "a" * 64
                            else "redis",
                        }
                    },
                }
            ]
        )

    monkeypatch.setattr(lanes, "command", fake_command)
    monkeypatch.setattr(lanes, "capture", fake_capture)
    assert lanes.lane_run("postgres", path, results, results.parent / "suppliers", cancelled) == (
        0 if fault is None else 1
    )
    assert len([x for x in calls if "down" in x]) == 1
    row = json.loads((results / "lane-postgres.json").read_text())
    assert row["complete"] is (fault is None)
    assert row["cleanup"] is (fault != "cleanup")
    if fault in ("startup", "supplier"):
        assert not any(x[0] == "bash" for x in calls)


def check_cancellation_stops_the_owned_process(tmp_path):
    cancelled = threading.Event()
    pid_file = tmp_path / "pid"
    errors = []

    def worker():
        try:
            with (tmp_path / "child.log").open("wb") as log:
                lanes.command(
                    [
                        sys.executable,
                        "-c",
                        "import os,time,pathlib; pathlib.Path("
                        + repr(str(pid_file))
                        + ").write_text(str(os.getpid())); time.sleep(120)",
                    ],
                    dict(os.environ),
                    log,
                    cancelled,
                    timeout=10,
                )
        except InterruptedError as error:
            errors.append(str(error))

    thread = threading.Thread(target=worker)
    thread.start()
    try:
        deadline = time.monotonic() + 5
        while not pid_file.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert pid_file.exists()
    finally:
        cancelled.set()
        thread.join(timeout=15)
    assert not thread.is_alive()
    assert errors == ["database execution cancelled"]
    with pytest.raises(ProcessLookupError):
        os.kill(int(pid_file.read_text()), 0)


class DatabaseExecutionTests(unittest.TestCase):
    def test_interleaved_child_output_keeps_exact_serial_completions(self):
        text = (
            "test a::first ... CREATE DATABASE\nSELECT 1\nok\n"
            "test a::second ... CREATE ROLE\nALTER ROLE\nok\n"
            "test result: ok. 2 passed; 0 failed; 0 ignored;\n"
        )
        assert execution.completed_tests(text, ["a::first", "a::second"]) == [
            "a::first",
            "a::second",
        ]
        for broken in (
            text.replace("SELECT 1\nok", "SELECT 1"),
            text.replace("ALTER ROLE\nok", "ALTER ROLE"),
            text.replace("SELECT 1\nok", "SELECT 1\nok\nok"),
        ):
            with self.subTest(broken=broken), pytest.raises(ValueError, match="database"):
                execution.completed_tests(broken, ["a::first", "a::second"])

    def run_case(self, case, **arguments):
        temporary = Path(self.enterContext(tempfile.TemporaryDirectory()))
        monkeypatch = self.enterContext(pytest.MonkeyPatch.context())
        parameters = inspect.signature(case).parameters
        available = {"tmp_path": temporary, "monkeypatch": monkeypatch, **arguments}
        if "inventory" in parameters:
            available["inventory"] = make_inventory(temporary, monkeypatch)
        case(**{name: available[name] for name in parameters})

    def test_exact_occurrences_and_auxiliaries_are_required(self):
        self.run_case(check_exact_occurrences_and_auxiliaries_are_required)

    def test_omission_fails_even_when_other_results_pass(self):
        for missing in [*execution.selectors(), *execution.AUXILIARIES, "lane-mixed"]:
            with self.subTest(missing=missing):
                self.run_case(check_omission_fails_even_when_other_results_pass, missing=missing)

    def test_duplicate_receipt_is_rejected(self):
        self.run_case(check_duplicate_receipt_is_rejected)

    def test_failed_cancelled_or_foreign_result_never_admits(self):
        for field, value in [
            ("returncode", 37),
            ("returncode", -15),
            ("complete", False),
            ("context", {"GITHUB_RUN_ATTEMPT": "other"}),
            ("build_sha256", "wrong"),
            ("plan_sha256", "wrong"),
            ("command", ["true"]),
        ]:
            with self.subTest(field=field, value=value):
                self.run_case(
                    check_failed_cancelled_or_foreign_result_never_admits, field=field, value=value
                )

    def test_isolation_and_cleanup_are_obligations(self):
        for fault in ["cleanup", "missing_supplier", "shared_supplier", "project"]:
            with self.subTest(fault=fault):
                self.run_case(check_isolation_and_cleanup_are_obligations, fault=fault)

    def test_actual_child_cannot_report_a_partial_success(self):
        for fault in ["missing", "duplicate", "zero", "failure"]:
            with self.subTest(fault=fault):
                self.run_case(check_actual_child_cannot_report_a_partial_success, fault=fault)

    def test_actual_child_completion_and_duplicate_guard(self):
        self.run_case(check_actual_child_completion_and_duplicate_guard)

    def test_wrong_artifact_source_and_changed_log_are_rejected(self):
        self.run_case(check_wrong_artifact_source_and_changed_log_are_rejected)

    def test_empty_duplicated_or_incomplete_discovery_fails(self):
        for text in [
            "0 tests, 0 benchmarks\n",
            "x: test\nx: test\n2 tests, 0 benchmarks\n",
            "x: test\n2 tests, 0 benchmarks\n",
        ]:
            with self.subTest(text=text):
                self.run_case(check_empty_duplicated_or_incomplete_discovery_fails, text=text)

    def test_skipped_and_duplicated_runtime_occurrences_fail(self):
        self.run_case(check_skipped_and_duplicated_runtime_occurrences_fail)

    def test_supplier_specs_do_not_share_names_or_host_ports(self):
        self.run_case(check_supplier_specs_do_not_share_names_or_host_ports)

    def test_build_trace_keeps_failure_and_post_test_tail(self):
        self.run_case(check_build_trace_keeps_failure_and_post_test_tail)

    def test_lane_lifecycle_keeps_cleanup_required(self):
        for fault in [None, "startup", "supplier", "cancelled", "tests", "cleanup"]:
            with self.subTest(fault=fault):
                self.run_case(check_lane_lifecycle_keeps_cleanup_required, fault=fault)

    def test_cancellation_stops_the_owned_process(self):
        self.run_case(check_cancellation_stops_the_owned_process)
