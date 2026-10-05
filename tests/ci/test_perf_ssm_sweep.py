"""Controlled SSM and supervisor mechanics; no AWS calls or service operations."""

from __future__ import annotations

import base64
import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest
from test_perf_runtime_delivery import run_sweep_csv_fixture

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("ssm_sweep", ROOT / "scripts/perf/ssm_sweep.py")
assert SPEC is not None
assert SPEC.loader is not None
sweep = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(sweep)
UUID = "12345678-1234-4234-8234-123456789abc"


@pytest.mark.parametrize(
    ("rates", "expected"),
    [
        (" 1 ,\t2.50\t, 1e+2 , ,3,", ["1", "2.50", "1e+2", "3"]),
        (" , \t,", []),
        ("1 0, 1\t0 , 1 e2", ["1 0", "1\t0", "1 e2"]),
        ("1\n0,2", ["1\n0", "2"]),
        ("1,2\n3,4", ["1", "2\n3", "4"]),
        ("\n 1 , 2 \n", ["1", "2"]),
        (" \n,\t\n", []),
    ],
)
def test_sweep_rate_tokens_trim_only_edges_and_preserve_order(tmp_path, rates, expected):
    source = (ROOT / "scripts/perf/aws_sweep.sh").read_text()
    start = source.index("IFS=',' read -r -d '' -a rps_values")
    end = source.index("\tinvocation_index=$((invocation_index + 1))", start)
    # Execute the actual token loop before its first workload effect.
    script = "set -euo pipefail\n" + source[start:end] + "printf '%s\\0' \"$rps\"\ndone\n"
    result = subprocess.run(  # noqa: S603 -- extracted token loop only; no AWS/service operations
        [shutil.which("bash"), "-c", script],
        env={**os.environ, "RPS_LIST": rates},
        capture_output=True,
        check=False,
        timeout=2,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.split(b"\0")[:-1] == [rate.encode() for rate in expected]
    for rate in expected:
        if any(character.isspace() for character in rate):
            response = run_sweep_csv_fixture(tmp_path, rps=rate)
            assert response.returncode != 0
            assert b"RPS required" in response.stderr
            assert not response.stdout


def payload(run="1s", warmup="0"):
    return base64.b64encode(json.dumps({"RUN_TIME": run, "WARMUP": warmup}).encode()).decode()


@pytest.mark.parametrize("exit_code", [0, 7])
def test_ssm_shell_wrapper_executes_bash_and_preserves_exit(exit_code):
    script = (
        "set -euo pipefail\n"
        "value='literal $(exit 99)'\n"
        "[[ \"$value\" == 'literal $(exit 99)' ]]\n"
        ": <<'INNER'\nAEGAEON_SSM_BASH\nINNER\n"
        f"exit {exit_code}\n"
    )
    process = subprocess.run(  # noqa: S603 -- actual POSIX shell with controlled Bash payload
        [
            "/bin/sh",
            "-c",
            sweep.bash_script(script).replace("exec /bin/bash", f"exec {shutil.which('bash')}"),
        ],
        capture_output=True,
        check=False,
        timeout=2,
    )
    assert process.returncode == exit_code, process.stderr


def outcome(state="complete", cleanup="0", driver=0):
    return {
        "state": state,
        "cleanup_exit": cleanup,
        "stdout": base64.b64encode(
            f"RUN_ID=controlled\nEXIT_CODE={driver}\nDRIVER_EXIT_CODE={driver}\n".encode()
        ).decode(),
        "stderr": "",
    }


@pytest.mark.parametrize(
    ("run", "warmup", "budget"),
    [("300s", "10", 1210), ("86400", "86400", 173700), ("24h", "24h", 173700)],
)
def test_full_independent_duration_domain_is_supervised(tmp_path, run, warmup, budget):
    client = sweep.SSM("instance", tmp_path)
    scripts = []

    def command(script, comment, **kwargs):
        scripts.append(script)
        return {"Status": "Success"}

    with (
        patch.object(client, "command", command),
        patch.object(sweep, "snapshot", side_effect=[outcome(), outcome("stopped")]),
    ):
        assert sweep.loadtest(client, payload(run, warmup), "fixture")["Status"] == "Success"
    assert f"RuntimeMaxSec={budget}" in scripts[0]
    assert "--setenv=AEGAEON_SWEEP_ID=" in scripts[0]
    assert "ExecStopPost=/bin/bash" in scripts[0]


@pytest.mark.parametrize("value", ["86401", "01", "0", "$(touch forbidden)", "NaN"])
def test_invalid_run_duration_never_dispatches(tmp_path, value):
    client = sweep.SSM("instance", tmp_path)
    with patch.object(client, "command") as command, pytest.raises(ValueError, match="duration"):
        sweep.loadtest(client, payload(value), "fixture")
    command.assert_not_called()


def test_ssm_outlives_default_waiter_and_sends_explicit_timeouts(tmp_path):
    client = sweep.SSM("instance", tmp_path)
    responses = [subprocess.CompletedProcess([], 0, "command-id", "")]
    responses += [
        subprocess.CompletedProcess([], 0, '{"Status":"InProgress"}', "") for _ in range(25)
    ]
    responses += [
        subprocess.CompletedProcess(
            [], 0, '{"Status":"Success","StandardOutputContent":"","StandardErrorContent":""}', ""
        )
    ]
    with (
        patch.object(client, "call", side_effect=responses) as call,
        patch.object(sweep.time, "sleep"),
    ):
        assert client.command("exit 0", "fixture")["Status"] == "Success"
    args = call.call_args_list[0].args
    assert args[args.index("--timeout-seconds") + 1] == "60"
    assert json.loads(args[args.index("--parameters") + 1])["executionTimeout"] == ["120"]
    assert len(call.call_args_list) == 27
    assert not any("wait" in entry.args for entry in call.call_args_list)


@pytest.mark.parametrize("failure", ["failed", "unknown", "interrupted", "api"])
def test_failed_or_inconclusive_run_always_stops_and_retains_output(tmp_path, failure):
    client = sweep.SSM("instance", tmp_path)
    state = outcome("failed") if failure == "failed" else {"state": "unknown"}
    if failure == "interrupted":
        state = InterruptedError("fixture signal")
    if failure == "api":
        state = RuntimeError("fixture AWS failure")
    with (
        patch.object(client, "command", return_value={"Status": "Success"}),
        patch.object(
            sweep, "snapshot", side_effect=[state, outcome("stopped", driver=7)]
        ) as snapshot,
    ):
        response = sweep.loadtest(client, payload(), "fixture")
    assert response["Status"] == "Failed"
    assert "DRIVER_EXIT_CODE=7" in response["StandardOutputContent"]
    assert snapshot.call_args_list[-1].kwargs == {"stop": True}
    assert (tmp_path / "supervisor-final.json").is_file()


@pytest.mark.parametrize("cleanup", [None, "1"])
def test_unconfirmed_docker_cleanup_never_becomes_success(tmp_path, cleanup):
    client = sweep.SSM("instance", tmp_path)
    with (
        patch.object(client, "command", return_value={"Status": "Success"}),
        patch.object(sweep, "snapshot", side_effect=[outcome(), outcome("stopped", cleanup)]),
    ):
        assert sweep.loadtest(client, payload(), "fixture")["Status"] == "Failed"


def owned(script, directory):
    return (
        script.replace(f"/etc/aegaeon/.sweep-{UUID}", str(directory))
        .replace("== 0:700", f"== {os.getuid()}:700")
        .replace('[[ "$(id -u)" == 0 ]]', "true")
    )


@pytest.mark.parametrize("driver_exit", [0, 7])
def test_actual_runner_preserves_driver_exit_for_supervisor(tmp_path, driver_exit):
    control = tmp_path / "control"
    control.mkdir(mode=0o700)
    driver = tmp_path / "driver"
    driver.write_text(f"#!/bin/sh\necho RUN_ID=controlled\nexit {driver_exit}\n")
    driver.chmod(0o755)
    script = owned(sweep.runner_script(UUID), control).replace(
        "/usr/local/bin/aegaeon-run-loadtest", str(driver)
    )
    process = subprocess.run(  # noqa: S603 -- actual runner and controlled driver, no service operations
        [shutil.which("bash"), "-c", script],
        capture_output=True,
        check=False,
        timeout=2,
    )
    assert process.returncode == driver_exit
    assert (control / "completion").read_text() == f"{driver_exit}\n"
    assert f"DRIVER_EXIT_CODE={driver_exit}".encode() in process.stdout


def test_late_dispatch_cannot_pass_cancellation_tombstone(tmp_path):
    control = tmp_path / "control"
    control.mkdir(mode=0o700)
    (control / "cancelled").touch()
    result = subprocess.run(  # noqa: S603 -- controlled argv and fixture executables
        [shutil.which("bash"), "-c", owned(sweep.dispatch_script(UUID, payload(), 901), control)],
        capture_output=True,
        check=False,
        timeout=2,
    )
    assert result.returncode != 0
    assert not (control / "config.json").exists()
    assert not (control / "dispatched").exists()


@pytest.mark.parametrize(
    ("removal_exit", "listing_exit", "remaining", "expected"),
    [(1, 0, "", 0), (0, 1, "", 1), (0, 0, "aegaeon-sweep-" + UUID, 1)],
)
def test_cleanup_requires_positive_container_absence(
    tmp_path, removal_exit, listing_exit, remaining, expected
):
    control = tmp_path / "control"
    control.mkdir(mode=0o700)
    tools = tmp_path / "tools"
    tools.mkdir()
    docker = tools / "docker"
    docker.write_text(
        f"#!{sys.executable}\nimport sys\n"
        f"if sys.argv[1]=='rm':raise SystemExit({removal_exit})\n"
        f"print({remaining!r})\nraise SystemExit({listing_exit})\n"
    )
    docker.chmod(0o755)
    script = tmp_path / "runner"
    script.write_text(owned(sweep.runner_script(UUID), control))
    result = subprocess.run(  # noqa: S603 -- controlled argv and fixture executables
        [shutil.which("bash"), str(script), "cleanup"],
        env={**os.environ, "PATH": str(tools) + os.pathsep + os.environ["PATH"]},
        capture_output=True,
        check=False,
        timeout=2,
    )
    assert result.returncode == expected
    assert (control / "cleanup-exit").read_text().strip() == str(expected)


def test_timeout_preserves_partial_aws_output(tmp_path):
    client = sweep.SSM("instance", tmp_path)
    error = subprocess.TimeoutExpired(
        ["aws"], 45, output=b"partial stdout", stderr=b"partial stderr"
    )
    with (
        patch.dict(os.environ, AWS_REGION="us-east-1"),
        patch.object(sweep.subprocess, "run", side_effect=error),
        pytest.raises(RuntimeError, match="bounded AWS call"),
    ):
        client.call("send-command")
    assert (tmp_path / "00001-send-command.stdout").read_bytes() == b"partial stdout"
    assert (tmp_path / "00001-send-command.stderr").read_bytes() == b"partial stderr"


def test_local_expiry_cannot_accept_late_success_and_always_stops(tmp_path):
    client = sweep.SSM("instance", tmp_path)
    with (
        patch.object(client, "command", return_value={"Status": "Success"}),
        patch.object(sweep.time, "monotonic", side_effect=[0, 0, 1112]),
        patch.object(sweep, "snapshot", side_effect=[outcome(), outcome("stopped")]) as snapshot,
    ):
        response = sweep.loadtest(client, payload(), "fixture")
    assert response["Status"] == "Failed"
    assert "deadline expired" in response["StandardErrorContent"]
    assert snapshot.call_args_list[-1].kwargs == {"stop": True}


def test_cancel_api_error_still_runs_supervisor_cleanup(tmp_path):
    client = sweep.SSM("instance", tmp_path)
    with (
        patch.object(client, "command", return_value={"Status": "Success"}),
        patch.object(client, "cancel", side_effect=RuntimeError("cancel API disconnected")),
        patch.object(
            sweep, "snapshot", side_effect=[RuntimeError("status disconnected"), outcome("stopped")]
        ) as snapshot,
    ):
        assert sweep.loadtest(client, payload(), "fixture")["Status"] == "Failed"
    assert snapshot.call_args_list[-1].kwargs == {"stop": True}
    assert (tmp_path / "cancel-error.txt").is_file()


@pytest.mark.parametrize(
    "record",
    [
        [],
        {"Status": []},
        {"Status": "Success"},
        {"Status": "Success", "StandardOutputContent": 5, "StandardErrorContent": ""},
        {"Status": "Unexpected"},
    ],
)
def test_malformed_invocation_records_fail_closed(tmp_path, record):
    client = sweep.SSM("instance", tmp_path)
    responses = [
        subprocess.CompletedProcess([], 0, "command-id", ""),
        subprocess.CompletedProcess([], 0, json.dumps(record), ""),
    ]
    with (
        patch.object(client, "call", side_effect=responses),
        pytest.raises((ValueError, RuntimeError), match=r"SSM|status"),
    ):
        client.command("exit 0", "fixture")
    assert client.pending == "command-id"


@pytest.mark.parametrize(
    "record",
    [
        [],
        {"state": "complete"},
        {
            "state": "complete",
            "properties": {},
            "completed": True,
            "cleanup_exit": "0",
            "stdout": "!",
            "stderr": "",
            "stdout_truncated": False,
            "stderr_truncated": False,
        },
    ],
)
def test_malformed_supervisor_records_fail_closed(tmp_path, record):
    client = sweep.SSM("instance", tmp_path)
    with (
        patch.object(
            client,
            "command",
            return_value={"Status": "Success", "StandardOutputContent": json.dumps(record)},
        ),
        pytest.raises((TypeError, ValueError), match=r"supervisor|base64"),
    ):
        sweep.snapshot(client, UUID)


@pytest.mark.parametrize(
    ("active", "sub", "result", "completed", "expected"),
    [
        ("active", "exited", "success", True, "complete"),
        ("active", "exited", "success", False, "failed"),
        ("failed", "failed", "timeout", True, "failed"),
        ("active", "running", "success", False, "running"),
    ],
)
def test_actual_snapshot_checks_service_and_completion_and_caps_output(  # noqa: PLR0913, PLR0917 -- independent supervisor states
    tmp_path, active, sub, result, completed, expected
):
    control = tmp_path / "control"
    control.mkdir(mode=0o700)
    (control / "stdout.log").write_bytes(b"x" * 12000)
    (control / "stderr.log").write_bytes(b"e" * 4000)
    if completed:
        (control / "completion").write_text("0\n")
    tools = tmp_path / "tools"
    tools.mkdir()
    systemctl = tools / "systemctl"
    properties = (
        f"LoadState=loaded\nActiveState={active}\nSubState={sub}\n"
        f"Result={result}\nExecMainStatus=0\n"
    )
    systemctl.write_text(f"#!{sys.executable}\nprint({properties!r})\n")
    systemctl.chmod(0o755)
    process = subprocess.run(  # noqa: S603 -- actual bounded snapshot with owned systemctl substitute
        [shutil.which("bash"), "-c", owned(sweep.snapshot_script(UUID), control)],
        env={**os.environ, "PATH": str(tools) + os.pathsep + os.environ["PATH"]},
        capture_output=True,
        check=False,
        timeout=2,
    )
    assert process.returncode == 0, process.stderr
    assert len(process.stdout) < 20000
    record = json.loads(process.stdout)
    assert record["state"] == expected
    assert len(base64.b64decode(record["stdout"])) == 9000
    assert len(base64.b64decode(record["stderr"])) == 3000
    assert record["stdout_truncated"] is True
    assert record["stderr_truncated"] is True
    assert (control / "stdout.log").stat().st_size == 12000


def test_invalid_main_mode_does_not_start_transport():
    with (
        patch.object(sys, "argv", ["script", "typo", "instance", "comment", "evidence"]),
        patch.object(sweep, "SSM") as client,
    ):
        assert sweep.main() == 2
    client.assert_not_called()


def test_pending_command_local_deadline_retains_id_for_cancel(tmp_path):
    client = sweep.SSM("instance", tmp_path)
    clock = [0]
    calls = []

    def call(*args, **kwargs):
        calls.append(args)
        if args[0] == "send-command":
            return subprocess.CompletedProcess([], 0, "command-id", "")
        if args[0] == "cancel-command":
            return subprocess.CompletedProcess([], 0, "{}", "")
        clock[0] += 100
        return subprocess.CompletedProcess([], 0, '{"Status":"InProgress"}', "")

    def sleep(seconds):
        clock[0] += seconds

    with (
        patch.object(client, "call", call),
        patch.object(sweep.time, "monotonic", side_effect=lambda: clock[0]),
        patch.object(sweep.time, "sleep", sleep),
        pytest.raises(TimeoutError, match="SSM command deadline"),
    ):
        client.command("exit 0", "fixture")
    assert clock[0] == 210
    assert client.pending == "command-id"
    with patch.object(client, "call", call):
        client.cancel()
    assert calls[-1] == (
        "cancel-command",
        "--command-id",
        "command-id",
        "--instance-ids",
        "instance",
        "--output",
        "json",
    )


def test_aws_subprocess_uses_remaining_global_budget(tmp_path):
    client = sweep.SSM("instance", tmp_path)
    with (
        patch.dict(os.environ, AWS_REGION="us-east-1"),
        patch.object(sweep.time, "monotonic", return_value=200),
        patch.object(
            sweep.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "", "")
        ) as run,
    ):
        client.call("get-command-invocation", deadline=210)
    assert run.call_args.kwargs["timeout"] == 10
    assert run.call_args.kwargs["env"]["AWS_MAX_ATTEMPTS"] == "1"


@pytest.mark.parametrize(
    ("state", "active", "completed"),
    [("complete", "active", False), ("complete", "failed", True), ("stopped", "active", True)],
)
def test_inconsistent_supervisor_state_is_rejected(tmp_path, state, active, completed):
    client = sweep.SSM("instance", tmp_path)
    record = {
        **outcome(state),
        "properties": {
            "ActiveState": active,
            "SubState": "exited",
            "Result": "success",
            "ExecMainStatus": "0",
        },
        "completed": completed,
        "stdout_truncated": False,
        "stderr_truncated": False,
    }
    with (
        patch.object(
            client,
            "command",
            return_value={"Status": "Success", "StandardOutputContent": json.dumps(record)},
        ),
        pytest.raises(ValueError, match="inconsistent supervisor"),
    ):
        sweep.snapshot(client, UUID)


def test_late_ssm_terminal_success_is_not_accepted(tmp_path):
    client = sweep.SSM("instance", tmp_path)
    success = json.dumps(
        {"Status": "Success", "StandardOutputContent": "", "StandardErrorContent": ""}
    )
    with (
        patch.object(sweep.time, "monotonic", side_effect=[0, 0, 211]),
        patch.object(
            client,
            "call",
            side_effect=[
                subprocess.CompletedProcess([], 0, "command-id", ""),
                subprocess.CompletedProcess([], 0, success, ""),
            ],
        ),
        pytest.raises(TimeoutError, match="terminal acceptance"),
    ):
        client.command("exit 0", "fixture")
    assert client.pending == "command-id"


def test_failed_cancel_does_not_clear_pending_identity(tmp_path):
    client = sweep.SSM("instance", tmp_path)
    client.pending = "command-id"
    with (
        patch.object(
            client, "call", return_value=subprocess.CompletedProcess([], 1, "", "API failure")
        ),
        pytest.raises(RuntimeError, match="cancellation API failed"),
    ):
        client.cancel()
    assert client.pending == "command-id"


def test_actual_stop_tombstone_serializes_a_delayed_dispatch(tmp_path):
    control = tmp_path / "control"
    control.mkdir(mode=0o700)
    (control / "config.json").write_text("protected fixture")
    (control / "cleanup-exit").write_text("0\n")
    tools = tmp_path / "tools"
    tools.mkdir()
    systemctl = tools / "systemctl"
    systemctl.write_text(
        f"#!{sys.executable}\nimport sys,time\nfrom pathlib import Path\n"
        f"root=Path({str(control)!r})\n"
        "if sys.argv[1]=='stop':\n (root/'stop-observed').touch(); time.sleep(0.2)\n"
        "else:print('LoadState=not-found\\nActiveState=inactive\\nSubState=dead'\n"
        "           '\\nResult=success\\nExecMainStatus=0')\n"
    )
    systemctl.chmod(0o755)
    launch = tools / "systemd-run"
    launch.write_text(
        f"#!{sys.executable}\nfrom pathlib import Path\n"
        f"Path({str(control / 'unexpected-launch')!r}).touch()\n"
    )
    launch.chmod(0o755)
    env = {**os.environ, "PATH": str(tools) + os.pathsep + os.environ["PATH"]}
    with subprocess.Popen(  # noqa: S603 -- actual cleanup script, controlled systemctl substitute
        [shutil.which("bash"), "-c", owned(sweep.snapshot_script(UUID, stop=True), control)],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ) as stop:
        for _ in range(100):
            if (control / "stop-observed").exists():
                break
            sweep.time.sleep(0.01)
        assert (control / "stop-observed").exists()
        late = subprocess.run(  # noqa: S603 -- actual dispatch racing owned cleanup, no service operations
            [
                shutil.which("bash"),
                "-c",
                owned(sweep.dispatch_script(UUID, payload(), 901), control),
            ],
            env=env,
            capture_output=True,
            check=False,
            timeout=2,
        )
        stdout, stderr = stop.communicate(timeout=2)
    assert stop.returncode == 0, stderr
    assert json.loads(stdout)["state"] == "stopped"
    assert late.returncode != 0
    assert (control / "cancelled").is_file()
    assert not (control / "config.json").exists()
    assert not (control / "unexpected-launch").exists()
