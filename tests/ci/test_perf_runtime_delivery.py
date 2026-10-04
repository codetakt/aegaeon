"""Synthetic mechanics tests; credentials here establish no actual runtime supplier."""

from __future__ import annotations

import base64
import copy
import hashlib
import importlib
import json
import os
import shutil
import subprocess
import sys
import time
import types
from contextlib import nullcontext
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
import validate_infrastructure as infra

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "infra/tofu/perf-aws-ec2"


GUEST_MODULES = (
    "common",
    "filesystem",
    "credentials",
    "artifacts",
    "reports",
    "metrics",
    "orchestration",
)


@pytest.fixture
def helper(tmp_path):
    """Load the fixed trusted repository package; this is a synthetic mechanics fixture."""
    sections, _ = infra.template_sections(infra.source_template(MODULE, "server"))
    library = tmp_path / "fixture-library"
    package = library / "runtime_delivery"
    package.mkdir(parents=True)
    for name in infra.DELIVERY_PACKAGE_SHA256:
        body = sections["/usr/local/lib/aegaeon/runtime_delivery/" + name]
        (package / name).write_text(body)
    saved = {
        name: module
        for name, module in sys.modules.copy().items()
        if name == "runtime_delivery" or name.startswith("runtime_delivery.")
    }
    for name in saved:
        del sys.modules[name]
    sys.path.insert(0, str(library))
    try:
        scope = {}
        for name in GUEST_MODULES:
            scope.update(vars(importlib.import_module("runtime_delivery." + name)))
        yield types.SimpleNamespace(**scope)
    finally:
        sys.path.remove(str(library))
        for name in list(sys.modules):
            if name == "runtime_delivery" or name.startswith("runtime_delivery."):
                del sys.modules[name]
        sys.modules.update(saved)


@pytest.fixture
def supplies(helper):
    return {
        **dict.fromkeys(helper.REDIS_NAMES, "rediss://synthetic.invalid:6379/0"),
        "AEGAEON_DATABASE_URL": "postgresql://synthetic.invalid/db?sslmode=require",
        "AEGAEON_KEY_ENCRYPTION_KEY": base64.urlsafe_b64encode(bytes(32)).decode().rstrip("="),
    }


def config():
    return {
        "server_secret_arn": "arn:aws:secretsmanager:us-east-1:123456789012:secret:synthetic",
        "server_secret_version": "a" * 32,
        "region": "us-east-1",
        "issuer_url": "https://issuer.example.com",
        "issuer_host": "issuer.example.com",
        "trusted_proxies": "127.0.0.1/32",
    }


def test_all_twenty_surfaces_and_atomic_topology(helper, supplies):
    helper.validate_bundle("server", json.dumps(supplies), config()["issuer_url"])
    for name in helper.REDIS_NAMES:
        invalid = copy.deepcopy(supplies)
        del invalid[name]
        with pytest.raises(ValueError, match=r"."):
            helper.validate_bundle("server", json.dumps(invalid), config()["issuer_url"])
    for name in helper.ATOMIC_NAMES:
        invalid = copy.deepcopy(supplies)
        invalid[name] = "rediss://synthetic.invalid:6379/1"
        with pytest.raises(ValueError, match="topology"):
            helper.validate_bundle("server", json.dumps(invalid), config()["issuer_url"])


@pytest.mark.parametrize(
    "bad",
    [
        "",
        " \t",
        "value\n",
        "value\r",
        "value\x00",
        "value\x1b",
        "value\x85",
        "value\u2028",
        1,
        None,
    ],
)
def test_control_empty_and_type_failures(helper, supplies, bad):
    supplies["AEGAEON_PAR_REDIS_URL"] = bad
    with pytest.raises(ValueError, match=r"."):
        helper.validate_bundle("server", json.dumps(supplies), config()["issuer_url"])


def test_unknown_duplicate_removed_and_unsafe_urls(helper, supplies):
    raw = json.dumps(supplies)
    duplicate = raw[:-1] + ', "AEGAEON_PAR_REDIS_URL": "rediss://synthetic.invalid/0"}'
    with pytest.raises(ValueError, match="duplicate"):
        helper.validate_bundle("server", duplicate, config()["issuer_url"])
    for name in ("BASE_URL", "AEGAEON_EXPOSE_METRICS_ON_MAIN", "unknown"):
        with pytest.raises(ValueError, match=r"."):
            helper.validate_bundle(
                "server", json.dumps({**supplies, name: "synthetic"}), config()["issuer_url"]
            )
    for url in (
        "redis://synthetic.invalid/0",
        "rediss://synthetic.invalid/0?x=y",
        "rediss://synthetic.invalid/a",
        "rediss://synthetic.invalid/0#fragment",
    ):
        with pytest.raises(ValueError, match=r"."):
            helper.validate_bundle(
                "server",
                json.dumps({**supplies, "AEGAEON_PAR_REDIS_URL": url}),
                config()["issuer_url"],
            )
    for key, value in (
        ("AEGAEON_DATABASE_URL", "postgresql://synthetic.invalid/db"),
        ("AEGAEON_KEY_ENCRYPTION_KEY", "YQ"),
    ):
        with pytest.raises(ValueError, match=r"."):
            helper.validate_bundle(
                "server", json.dumps({**supplies, key: value}), config()["issuer_url"]
            )


def test_exact_secret_identity_version_and_denial(helper, supplies, monkeypatch):
    cfg = config()
    monkeypatch.setitem(helper.retrieve.__globals__, "aws_executable", lambda: Path("/fixture/aws"))
    response = {
        "ARN": cfg["server_secret_arn"],
        "VersionId": cfg["server_secret_version"],
        "SecretString": json.dumps(supplies),
    }
    for changes in ({}, {"ARN": "different"}, {"VersionId": "b" * 32}):
        with patch.object(
            helper.subprocess,
            "run",
            return_value=types.SimpleNamespace(stdout=json.dumps({**response, **changes}).encode()),
        ) as run:
            if changes:
                with pytest.raises(ValueError, match="identity"):
                    helper.retrieve(
                        "server",
                        cfg["server_secret_arn"],
                        cfg["server_secret_version"],
                        cfg["region"],
                        cfg["issuer_url"],
                    )
            else:
                helper.retrieve(
                    "server",
                    cfg["server_secret_arn"],
                    cfg["server_secret_version"],
                    cfg["region"],
                    cfg["issuer_url"],
                )
                argv = run.call_args.args[0]
                assert argv[0] == "/fixture/aws"
                assert argv[argv.index("--version-id") + 1] == cfg["server_secret_version"]
                assert run.call_args.kwargs["capture_output"] is True
    with (
        patch.object(
            helper.subprocess, "run", side_effect=subprocess.CalledProcessError(1, ["synthetic"])
        ),
        pytest.raises(subprocess.CalledProcessError),
    ):
        helper.retrieve(
            "server",
            cfg["server_secret_arn"],
            cfg["server_secret_version"],
            cfg["region"],
            cfg["issuer_url"],
        )
    with patch.object(helper.subprocess, "run") as run, pytest.raises(ValueError, match="version"):
        helper.retrieve("server", cfg["server_secret_arn"], "", cfg["region"], cfg["issuer_url"])
    run.assert_not_called()


def test_restart_failure_clears_stale_success_and_atomic_modes(helper, supplies, tmp_path):
    directory = tmp_path / "runtime"
    directory.mkdir(mode=0o700)
    # Test UID is unprivileged; production root-ownership check is tested separately.
    with patch.dict(
        helper.refresh.__globals__,
        prepare_directory=lambda _: None,
        retrieve=lambda *args: copy.deepcopy(supplies),
    ):
        helper.refresh("server", config(), directory)
    output = directory / "server.env"
    assert output.stat().st_mode & 0o777 == 0o600
    assert "AEGAEON_RUNTIME_ISSUER_HOST=issuer.example.com\n" in output.read_text()
    assert (directory / "server.version.json").exists()
    with (
        patch.dict(
            helper.refresh.__globals__,
            prepare_directory=lambda _: None,
            retrieve=lambda *args: (_ for _ in ()).throw(ValueError("synthetic denial")),
        ),
        pytest.raises(ValueError, match=r"."),
    ):
        helper.refresh("server", config(), directory)
    assert not output.exists()
    assert not (directory / "server.version.json").exists()
    assert not list(directory.glob(".delivery-*"))


def test_runtime_owner_mode_and_symlink_rejected(helper, tmp_path):
    directory = tmp_path / "runtime"
    directory.mkdir(mode=0o755)
    with pytest.raises(ValueError, match="unsafe"):
        helper.prepare_directory(directory)
    link = tmp_path / "link"
    link.symlink_to(directory, target_is_directory=True)
    with pytest.raises(ValueError, match="unsafe"):
        helper.prepare_directory(link)


def test_metric_absence_failure_and_no_redirect_credential_forwarding(helper, tmp_path):
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    cfg = {**config(), "metrics_secret_arn": "", "metrics_secret_version": ""}
    with patch.dict(helper.metrics.__globals__, prepare_directory=lambda _: None):
        helper.metrics(cfg, runtime, tmp_path)
    assert json.loads((tmp_path / "metrics-status.json").read_text())["status"] == "absent"
    (tmp_path / "server.metrics.prom").write_text("stale")
    cfg.update({"metrics_secret_arn": "synthetic", "metrics_secret_version": "a" * 32})
    with (
        patch.dict(
            helper.metrics.__globals__,
            prepare_directory=lambda _: None,
            retrieve=lambda *args: (_ for _ in ()).throw(ValueError("synthetic denial")),
        ),
        pytest.raises(ValueError, match=r"."),
    ):
        helper.metrics(cfg, runtime, tmp_path)
    assert not (tmp_path / "server.metrics.prom").exists()
    assert json.loads((tmp_path / "metrics-status.json").read_text())["status"] == "incomplete"
    assert (
        helper.NoRedirect().redirect_request(
            None, None, 302, "", {}, "https://different.example.com"
        )
        is None
    )


def test_strict_delivery_executable_and_launch_wiring():
    server = infra.source_template(MODULE, "server")
    loadgen = infra.source_template(MODULE, "loadgen")
    assert len(infra.performance_delivery_inputs(server, "server")) == 24
    assert len(infra.performance_delivery_inputs(loadgen, "client")) == 5
    for original, profile, before, after in (
        (server, "server", "capture_output=True", "capture_output=False"),
        (
            server,
            "server",
            "ExecStartPre=/usr/bin/python3 -I -B /usr/local/bin/aegaeon-deliver-supplies server",
            "# removed refresh",
        ),
        (
            loadgen,
            "client",
            (
                "/usr/bin/python3 -I -B /usr/local/bin/aegaeon-deliver-supplies"
                ' client "$SUPPLY_DIR" "$SOURCE_SHA256"\n'
            ),
            "# removed refresh\n",
        ),
        (
            server,
            "server",
            "server_secret_version = server_secret_version",
            'server_secret_version = ""',
        ),
    ):
        with pytest.raises(ValueError, match=r"."):
            infra.performance_delivery_inputs(original.replace(before, after, 1), profile)
    with pytest.raises(ValueError, match=r"."):
        infra.perf_server_environment_wiring(
            server.replace(
                "--env-file /run/aegaeon-supplies/server.env", "--env-file /tmp/stale.env"
            )
        )
    with pytest.raises(ValueError, match=r"."):
        infra.perf_loadgen_environment_wiring(
            loadgen.replace('--env-file "$${SUPPLY_DIR}/client.env"', "--env-file /tmp/stale.env"),
            rendered=False,
        )


def test_failed_refresh_blocks_executed_docker_workload(tmp_path):
    result, _, _, _ = run_driver_fixture(tmp_path, delivery_fail="client")
    assert result.returncode != 0
    assert (tmp_path / "docker.calls").read_text().splitlines() == ["pull"]
    assert (tmp_path / "delivery.calls").read_text().splitlines() == [
        "prepare-driver",
        "run-config",
        "client",
    ]
    assert list((tmp_path / "supplies").iterdir()) == [tmp_path / "supplies/driver.lock"]


@pytest.mark.parametrize(
    ("status", "content_type", "body"),
    [
        (200, "text/plain", b"aegaeon_requests 1\n"),
        (403, "text/plain", b"denied"),
        (200, "application/json", b"{}"),
        (200, "text/plain", b""),
    ],
)
def test_metrics_authenticated_response_and_status(helper, tmp_path, status, content_type, body):
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    cfg = {**config(), "metrics_secret_arn": "synthetic", "metrics_secret_version": "a" * 32}
    response = types.SimpleNamespace(
        status=status,
        headers=types.SimpleNamespace(get_content_type=lambda: content_type),
        read=lambda limit: body,
    )
    opener = Mock()
    opener.open.return_value = nullcontext(response)
    with patch.dict(
        helper.metrics.__globals__,
        prepare_directory=lambda _: None,
        retrieve=lambda *args: {"api_key": "aeg_synthetic"},
        build_opener=lambda *args: opener,
    ):
        if status == 200 and content_type == "text/plain" and body:
            helper.metrics(cfg, runtime, tmp_path)
            assert (tmp_path / "server.metrics.prom").read_bytes() == body
            assert json.loads((tmp_path / "metrics-status.json").read_text()) == {
                "status": "complete",
                "version": cfg["metrics_secret_version"],
            }
        else:
            with pytest.raises(ValueError, match="metrics response"):
                helper.metrics(cfg, runtime, tmp_path)
            assert not (tmp_path / "server.metrics.prom").exists()
            assert (
                json.loads((tmp_path / "metrics-status.json").read_text())["status"] == "incomplete"
            )
    request = opener.open.call_args.args[0]
    assert request.full_url == "https://issuer.example.com/api/v1/operations/metrics"
    assert request.get_header("Authorization") == "Bearer aeg_synthetic"
    assert not (runtime / "metrics.env").exists()


def test_role_supplier_and_iam_bindings(tmp_path):
    module = tmp_path / "perf-aws-ec2"
    shutil.copytree(MODULE, module)
    infra.resource_contract(module, {"aws": "6.66.0"})
    for filename, before, after in (
        (
            "instances.tf",
            "server_secret_version            = var.server_secret_version",
            "server_secret_version = var.client_secret_version",
        ),
        (
            "instances.tf",
            "server_image                     = var.loadgen_image",
            "server_image = var.server_image",
        ),
        (
            "instances.tf",
            "server_secret_arn                = var.server_secret_arn",
            (
                "server_secret_arn = var.server_secret_arn\n"
                "    server_secret_arn = var.client_secret_arn"
            ),
        ),
        ("locals.tf", "server  = [var.server_secret_arn]", "server = [var.client_secret_arn]"),
        ("iam.tf", "resources = each.value", 'resources = ["*"]'),
        (
            "iam.tf",
            'role   = aws_iam_role.perf_instance["server"].id',
            'role = aws_iam_role.perf_instance["loadgen"].id',
        ),
        (
            "iam.tf",
            "role     = each.value.name",
            'role = aws_iam_role.perf_instance["server"].name',
        ),
    ):
        path = module / filename
        original = path.read_text()
        assert before in original
        path.write_text(original.replace(before, after, 1))
        with pytest.raises(ValueError, match=r"."):
            infra.resource_contract(module, {"aws": "6.66.0"})
        path.write_text(original)


@pytest.mark.parametrize("health_ready", [False, True])
def test_driver_health_timeout_and_missing_report_fail(tmp_path, health_ready):
    result, _, _, _ = run_driver_fixture(tmp_path, health_ready=health_ready, report="missing")
    assert result.returncode != 0
    docker_calls = (
        (tmp_path / "docker.calls").read_text().splitlines()
        if (tmp_path / "docker.calls").exists()
        else []
    )
    assert docker_calls == (["pull", "run"] if health_ready else [])


def run_sweep_csv_fixture(tmp_path, rps="1", observation="absent", script=None):
    if script is None:
        script = (ROOT / "scripts/perf/aws_sweep.sh").read_text().split("python3 - <<'PY' >>", 1)[1]
        script = script.split("\n", 1)[1].split("\nPY\n", 1)[0]
    (tmp_path / "report.json").write_text("{}")
    (tmp_path / "metrics-status.json").write_text(
        json.dumps({"status": "complete" if observation == "missing" else observation})
    )
    if observation == "complete":
        (tmp_path / "server.metrics.prom").write_text(
            'oauth_request_latency_seconds_count{endpoint="/token",method="POST"} 24\n'
        )
    env = {
        **os.environ,
        "PERF_RPS_TARGET": rps,
        "PERF_WORKERS": "1",
        "PERF_RUN_TIME": "1s",
        "PERF_WARMUP": "0",
        "PERF_SCENARIO": "mixed",
        "PERF_RUN_ID": "synthetic",
        "PERF_EXIT_CODE": "0",
        "PERF_REPORT_PATH": str(tmp_path / "report.json"),
        "PERF_METRICS_PATH": str(tmp_path / "server.metrics.prom"),
        "PERF_SERVER_CPU_NS": "0",
        "PERF_SERVER_CPU_S": "0",
        "PERF_SERVER_MEM_CURRENT": "0",
        "PERF_SERVER_MEM_PEAK": "0",
    }
    return subprocess.run(  # noqa: S603 -- exact CSV heredoc only, never cloud orchestration
        [sys.executable, *(["-O"] if sys.flags.optimize else []), "-c", script],
        env=env,
        capture_output=True,
        check=False,
    )


def check_sweep_csv(condition, message):
    if not condition:
        pytest.fail(message)


@pytest.mark.parametrize("observation", ["absent", "complete", "missing", "incomplete", "failed"])
def test_sweep_distinguishes_absent_complete_and_failed_metrics(tmp_path, observation):
    result = run_sweep_csv_fixture(tmp_path, observation=observation)
    if observation in {"missing", "incomplete", "failed"}:
        check_sweep_csv(result.returncode != 0, "failed metrics emitted successful summary")
        check_sweep_csv(not result.stdout, "failed metrics emitted a CSV row")
    else:
        check_sweep_csv(result.returncode == 0, result.stderr.decode())
        columns = result.stdout.decode().strip().split(",")
        check_sweep_csv(columns[0] == "1", "integer CSV representation changed")
        check_sweep_csv(
            columns[20] == ("24" if observation == "complete" else ""), "metrics count changed"
        )
        check_sweep_csv(columns[-1] == observation, "metrics status changed")


@pytest.mark.parametrize(
    "rps",
    [
        "1",
        "200",
        "1000000000000000001",
        "0.125",
        "12.25",
        "1.0000000000000002",
        "1e3",
        "1.25e+2",
        "2e-3",
        "5e-324",
        "1.7976931348623157e308",
    ],
)
def test_sweep_csv_preserves_integer_fraction_and_finite_exponent_rps(tmp_path, rps):
    result = run_sweep_csv_fixture(tmp_path, rps=rps)
    check_sweep_csv(result.returncode == 0, result.stderr.decode())
    columns = result.stdout.decode().strip().split(",")
    check_sweep_csv(columns[0] == rps, "canonical RPS lexeme was truncated or reformatted")
    check_sweep_csv(len(columns) == 26, "CSV field count changed")
    check_sweep_csv(columns[-1] == "absent", "metrics absence semantics changed")


@pytest.mark.parametrize(
    "rps",
    [
        "",
        " ",
        "01",
        "00",
        ".5",
        "1.",
        "+1",
        "-1",
        "0",
        "0.0",
        "0e3",
        "1e",
        "1e01",
        "1e+01",
        "1E3",
        "nan",
        "NaN",
        "inf",
        "Infinity",
        "1e309",
        "1" + "0" * 309,
        "1e-324",
        "1e-999",
        "1,2",
        "1\n",
        "\uff11",
    ],
)
def test_sweep_csv_rejects_noncanonical_nonfinite_zero_and_f64_range_failures(tmp_path, rps):
    result = run_sweep_csv_fixture(tmp_path, rps=rps)
    check_sweep_csv(result.returncode != 0, "invalid RPS accepted")
    check_sweep_csv(not result.stdout, "invalid RPS emitted a CSV row")
    check_sweep_csv(
        b"RPS required" in result.stderr, "unrelated fixture failure masked RPS rejection"
    )


def run_driver_fixture(tmp_path, script=None, **settings):
    """Actual Bash orchestration with synthetic owned process substitutes; no suppliers/cloud."""
    if script is None:
        sections, _ = infra.template_sections(infra.source_template(MODULE, "loadgen"))
        script = sections["/usr/local/bin/aegaeon-run-loadtest"].replace("$${", "${")
    binpath = tmp_path / "bin"
    binpath.mkdir()
    outputs = tmp_path / "results"
    supply_root = tmp_path / "supplies"
    uploaded = tmp_path / "uploaded"
    uploaded.mkdir()
    envfile = tmp_path / "fixture-config.env"
    envfile.write_text(
        "SERVER_IMAGE=registry.example/aegaeon@sha256:"
        + "a" * 64
        + "\nSERVER_URL=https://issuer.example.com\nLOADTEST_BIN=/bin/aegaeon-loadtest\n"
        "SCENARIO=mixed\nWORKERS=1\nRPS=1\nRUN_TIME=1s\nWARMUP=0s\n"
        "ARTIFACT_BUCKET=synthetic-fixture\nARTIFACT_PREFIX=ci/\n"
        + "SOURCE_SHA256="
        + "b" * 64
        + "\nEXECUTABLE_SHA256="
        + "c" * 64
        + "\n"
    )
    programs = {
        "docker": """import json, os, sys, time
from pathlib import Path
with Path(os.environ['FIXTURE_DOCKER_CALLS']).open('a') as log:
    log.write(sys.argv[1] + '\\n')
if sys.argv[1] == 'pull':
    raise SystemExit(0)
out = Path(sys.argv[sys.argv.index('-v') + 1].split(':', 1)[0])
with Path(os.environ['FIXTURE_DOCKER_ARGV']).open('a') as log:
    log.write(json.dumps(sys.argv[1:]) + '\\n')
gate = os.environ.get('FIXTURE_GATE')
if gate:
    Path(gate + '.entered').touch()
    deadline = time.monotonic() + 10
    while Path(gate).exists():
        if time.monotonic() > deadline:
            raise SystemExit(90)
        time.sleep(0.01)
print('synthetic workload stdout')
print('synthetic workload stderr', file=sys.stderr)
if os.environ['FIXTURE_REPORT'] == 'present':
    (out / 'report.json').write_text(json.dumps({'synthetic': True}))
if os.environ['FIXTURE_LOG'] == 'missing':
    (out / 'loadtest.stdout.log').unlink()
if os.environ['FIXTURE_EXIT_FILE'] == 'directory':
    (out / 'exit_code.txt').mkdir()
raise SystemExit(int(os.environ['FIXTURE_EXIT']))
""",
        "deliver-supplies": """import json, os, sys
from pathlib import Path
command = sys.argv[1]
with Path(os.environ['FIXTURE_DELIVERY_CALLS']).open('a') as log:
    log.write(command + '\\n')
if command == os.environ['FIXTURE_DELIVERY_FAIL']:
    raise SystemExit(5)
if command == 'prepare-driver':
    Path(os.environ['FIXTURE_RESULTS']).mkdir(exist_ok=True)
    Path(os.environ['FIXTURE_SUPPLY_ROOT']).mkdir(exist_ok=True)
    raise SystemExit(0)
if command == 'run-config':
    out = Path(sys.argv[3])
    (out / 'validated-config.env').write_bytes(Path(os.environ['FIXTURE_CONFIG_ENV']).read_bytes())
    for name in ('driver-config.json', 'artifact-receipt.json', 'SOURCE-MANIFEST.json'):
        (out / name).write_text(json.dumps({'synthetic': True}))
    if os.environ['FIXTURE_REPORT_PREEXISTS'] == '1':
        (out / 'report.json').touch()
    raise SystemExit(0)
if command == 'client':
    generation = Path(sys.argv[2])
    generation.mkdir()
    for name in ('client.env', 'profile.json', 'session.txt', 'session-provenance.json'):
        (generation / name).write_text('synthetic')
    (generation / 'client.version.json').write_text(json.dumps({'synthetic': True}))
    raise SystemExit(0)
out = Path(sys.argv[2])
if command == 'verify-report':
    if not (out / 'report.json').is_file():
        raise SystemExit(6)
    (out / 'run-receipt.json').write_text(json.dumps({'synthetic': True}))
    raise SystemExit(0)
status = os.environ['FIXTURE_METRICS']
if status == 'missing':
    raise SystemExit(0)
recorded_status = 'incomplete' if status == 'failed' else status
(out / 'metrics-status.json').write_text(json.dumps({'status': recorded_status}))
if status == 'failed':
    raise SystemExit(3)
if status == 'complete':
    (out / 'server.metrics.prom').write_text('aegaeon_synthetic_metric 1\\n')
""",
        "aws": """import os, shutil, sys
from pathlib import Path
source = Path(sys.argv[3])
with Path(os.environ['FIXTURE_UPLOAD_CALLS']).open('a') as log:
    log.write(source.name + '\\n')
if source.name == os.environ['FIXTURE_UPLOAD_FAIL']:
    raise SystemExit(4)
shutil.copyfile(source, Path(os.environ['FIXTURE_UPLOADED']) / source.name)
""",
        "curl": """import os
raise SystemExit(0 if os.environ['FIXTURE_HEALTH'] == 'ready' else 7)
""",
    }
    for name, body in programs.items():
        command = binpath / name
        command.write_text(f"#!{sys.executable}\n" + body)
        command.chmod(0o755)
    login = binpath / "login"
    login.write_text("#!/bin/sh\nexit 0\n")
    login.chmod(0o755)
    script = (
        script.replace("/etc/aegaeon/loadtest.json", str(tmp_path / "boot.json"))
        .replace("/run/aegaeon-supplies", str(supply_root))
        .replace("/opt/aegaeon/results", str(outputs))
        .replace("/usr/local/bin/aegaeon-docker-login", str(login))
        .replace(
            "/usr/bin/python3 -I -B /usr/local/bin/aegaeon-deliver-supplies",
            str(binpath / "deliver-supplies"),
        )
        .replace("for _ in $(seq 1 120); do", "for _ in 1; do")
        .replace("  sleep 1\n", "  :\n")
    )
    env = {
        "PATH": str(binpath) + ":" + os.environ["PATH"],
        "FIXTURE_RESULTS": str(outputs),
        "FIXTURE_SUPPLY_ROOT": str(supply_root),
        "FIXTURE_CONFIG_ENV": str(envfile),
        "FIXTURE_REPORT": settings.get("report", "present"),
        "FIXTURE_EXIT": str(settings.get("exit_code", 0)),
        "FIXTURE_EXIT_FILE": settings.get("exit_file", "file"),
        "FIXTURE_LOG": settings.get("log", "present"),
        "FIXTURE_METRICS": settings.get("metrics", "complete"),
        "FIXTURE_UPLOAD_FAIL": settings.get("upload_fail", ""),
        "FIXTURE_UPLOAD_CALLS": str(tmp_path / "upload.calls"),
        "FIXTURE_UPLOADED": str(uploaded),
        "FIXTURE_DELIVERY_CALLS": str(tmp_path / "delivery.calls"),
        "FIXTURE_DELIVERY_FAIL": settings.get("delivery_fail", ""),
        "FIXTURE_DOCKER_CALLS": str(tmp_path / "docker.calls"),
        "FIXTURE_DOCKER_ARGV": str(tmp_path / "docker.argv"),
        "FIXTURE_REPORT_PREEXISTS": "1" if settings.get("report_preexists") else "0",
        "FIXTURE_HEALTH": "ready" if settings.get("health_ready", True) else "failed",
    }
    (tmp_path / "actual-driver.sh").write_text(script)
    (tmp_path / "fixture-environment.json").write_text(json.dumps(env))
    result = subprocess.run(  # noqa: S603 -- actual driver with owned local mechanics substitutes
        [shutil.which("bash"), "-c", script], env=env, capture_output=True, check=False
    )
    runs = list(outputs.iterdir()) if outputs.exists() else []
    calls = (
        (tmp_path / "upload.calls").read_text().splitlines()
        if (tmp_path / "upload.calls").exists()
        else []
    )
    return result, runs[0] if runs else None, uploaded, calls


@pytest.mark.parametrize(
    ("settings", "expected_exit"),
    [
        ({}, 0),
        ({"exit_code": 7}, 7),
        ({"report": "missing"}, 1),
        ({"report": "missing", "exit_code": 7}, 7),
        ({"exit_file": "directory"}, 1),
        ({"log": "missing"}, 1),
        ({"metrics": "failed"}, 1),
        ({"metrics": "missing"}, 1),
        ({"metrics": "absent"}, 0),
        ({"upload_fail": "report.json"}, 1),
        ({"upload_fail": "loadtest.stdout.log"}, 1),
        ({"upload_fail": "loadtest.stderr.log"}, 1),
        ({"upload_fail": "exit_code.txt"}, 1),
        ({"upload_fail": "metrics-status.json"}, 1),
        ({"upload_fail": "server.metrics.prom"}, 1),
        ({"exit_code": 7, "upload_fail": "report.json"}, 7),
    ],
)
def test_driver_preserves_outputs_and_propagates_workload_or_collection_failure(
    tmp_path, settings, expected_exit
):
    result, out, uploaded, calls = run_driver_fixture(tmp_path, **settings)
    assert result.returncode == expected_exit
    if settings.get("exit_file") != "directory":
        assert (out / "exit_code.txt").read_text().strip() == str(settings.get("exit_code", 0))
    required = {
        "report.json",
        "loadtest.stdout.log",
        "loadtest.stderr.log",
        "exit_code.txt",
        "metrics-status.json",
        "run-receipt.json",
        "client.version.json",
        "driver-config.json",
        "artifact-receipt.json",
        "SOURCE-MANIFEST.json",
    }
    available = {name for name in required | {"server.metrics.prom"} if (out / name).is_file()}
    assert set(calls) == available
    assert len(calls) == len(available)
    assert {file.name for file in uploaded.iterdir()} == available - {
        settings.get("upload_fail", "")
    }
    if expected_exit != 0:
        assert b"[perf] done;" not in result.stdout


def test_embedded_driver_syntax_is_checked_beyond_outer_userdata(tmp_path):
    source = infra.source_template(MODULE, "loadgen")
    sections, _ = infra.template_sections(source)
    driver = sections["/usr/local/bin/aegaeon-run-loadtest"]
    broken = source.replace(driver, driver + "\nif true; then\n", 1)
    commands = infra.Commands(tmp_path, os.environ.copy())
    commands.run([shutil.which("bash"), "-n"], tmp_path, broken)
    with pytest.raises(ValueError, match="Command failed"):
        infra.check_embedded_bash(broken, "loadgen", commands, shutil.which("bash"), tmp_path)


def client_bundle_fixture():
    """Synthetic bytes and receipts exercise mechanics, not genuine login/readback supply."""
    profile = {
        "issuer": config()["issuer_url"],
        "environment_id": "synthetic-environment",
        "configuration_version_id": "synthetic-version",
        "oauth_profile_id": "synthetic-profile",
        "activation": "ACTIVE",
        "client_id": "synthetic-client",
        "subject": "synthetic-subject",
        "redirect_uri": "https://client.example.com/callback?fixed=a%2Fb&second=2",
        "client_auth": "client_secret_basic",
        "scope": "api",
        "oidc_scope": "openid",
        "id_token_alg": "RS256",
        "sender_policy": "dpop",
        "par_policy": "required",
        "resource": "https://resource.example.com/",
    }
    profile_raw = json.dumps(profile, indent=2).encode() + b"\n"
    cookie = "aegaeon_auth_session=synthetic_cookie"
    provenance = {
        "issuer": profile["issuer"],
        "subject": profile["subject"],
        "method": "public-login",
        "producer": "synthetic-test-only",
        "profile_sha256": hashlib.sha256(profile_raw).hexdigest(),
        "session_sha256": hashlib.sha256(cookie.encode()).hexdigest(),
    }
    provenance_raw = json.dumps(provenance, indent=2).encode() + b"\n"
    bundle = {
        "schema_version": 2,
        "client_secret": "$(touch forbidden); literal",
        "profile_manifest_base64": base64.b64encode(profile_raw).decode(),
        "session_cookie": cookie,
        "session_provenance_base64": base64.b64encode(provenance_raw).decode(),
    }
    return bundle, profile_raw, provenance_raw


def test_client_bundle2_preserves_exact_profile_provenance_and_inert_secret(helper, tmp_path):
    bundle, profile, provenance = client_bundle_fixture()
    values = helper.validate_bundle("client", json.dumps(bundle), config()["issuer_url"])
    assert values["profile"] == profile
    assert values["provenance"] == provenance
    assert values["secret"] == bundle["client_secret"]
    directory = tmp_path / "inputs"
    cfg = {
        **config(),
        "client_secret_arn": "synthetic-client-reference",
        "client_secret_version": "b" * 32,
    }
    with (
        patch.dict(helper.protected_path.__globals__, OWNER_UID=os.getuid(), OWNED_ROOT=tmp_path),
        patch.dict(helper.refresh_client.__globals__, retrieve=lambda *_: values),
    ):
        helper.refresh_client(cfg, directory, "c" * 64)
    assert (directory / "profile.json").read_bytes() == profile
    assert (directory / "session-provenance.json").read_bytes() == provenance
    assert (directory / "session.txt").read_bytes() == bundle["session_cookie"].encode()
    assert directory.stat().st_mode & 0o777 == 0o700
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in directory.iterdir())
    env = dict(line.split("=", 1) for line in (directory / "client.env").read_text().splitlines())
    assert env == {
        "AEG_LOADTEST_CLIENT_SECRET": bundle["client_secret"],
        "AEG_LOADTEST_PROFILE_MANIFEST": "/run/aegaeon-inputs/profile.json",
        "AEG_LOADTEST_SESSION_FILE": "/run/aegaeon-inputs/session.txt",
        "AEG_LOADTEST_SESSION_PROVENANCE": "/run/aegaeon-inputs/session-provenance.json",
        "AEG_LOADTEST_SOURCE_SHA256": "c" * 64,
    }
    assert not (tmp_path / "forbidden").exists()
    assert helper.protected_path.__globals__["OWNER_UID"] == 0


@pytest.mark.parametrize(
    "change",
    [
        "old",
        "mixed",
        "unknown",
        "version",
        "boolean",
        "base64",
        "session-newline",
        "session-extra",
        "profile-issuer",
        "profile-policy",
        "profile-unknown",
        "profile-duplicate",
        "provenance-subject",
        "provenance-digest",
        "provenance-method",
        "provenance-producer",
    ],
)
def test_client_bundle2_rejects_shape_raw_bytes_policy_and_provenance(helper, change):
    bundle, profile, provenance = client_bundle_fixture()
    direct = {
        "mixed": ("AEG_LOADTEST_CLIENT_ID", "synthetic"),
        "unknown": ("unknown", "synthetic"),
        "version": ("schema_version", 1),
        "boolean": ("schema_version", True),
        "base64": ("profile_manifest_base64", bundle["profile_manifest_base64"] + "\n"),
        "session-newline": ("session_cookie", bundle["session_cookie"] + "\n"),
        "session-extra": ("session_cookie", bundle["session_cookie"] + "; second=cookie"),
    }
    if change == "old":
        bundle = {"AEG_LOADTEST_CLIENT_SECRET": "synthetic"}
    elif change in direct:
        key, replacement = direct[change]
        bundle[key] = replacement
    elif change.startswith("profile-"):
        value = json.loads(profile)
        if change != "profile-duplicate":
            key, replacement = {
                "profile-issuer": ("issuer", "https://different.example.com"),
                "profile-policy": ("client_auth", "none"),
                "profile-unknown": ("unknown", "synthetic"),
            }[change]
            value[key] = replacement
        modified = json.dumps(value).encode()
        if change == "profile-duplicate":
            modified = modified[:-1] + b',"activation":"ACTIVE"}'
        bundle["profile_manifest_base64"] = base64.b64encode(modified).decode()
    else:
        value = json.loads(provenance)
        key, replacement = {
            "provenance-subject": ("subject", "different"),
            "provenance-digest": ("profile_sha256", "d" * 64),
            "provenance-method": ("method", "fabricated"),
            "provenance-producer": ("producer", ""),
        }[change]
        value[key] = replacement
        bundle["session_provenance_base64"] = base64.b64encode(json.dumps(value).encode()).decode()
    with pytest.raises(ValueError, match=r"."):
        helper.validate_bundle("client", json.dumps(bundle), config()["issuer_url"])


def test_client_generation_failure_never_publishes_partial_or_reuses_stale(helper, tmp_path):
    bundle, _, _ = client_bundle_fixture()
    values = helper.validate_bundle("client", json.dumps(bundle), config()["issuer_url"])
    cfg = {
        **config(),
        "client_secret_arn": "synthetic-reference",
        "client_secret_version": "b" * 32,
    }
    directory = tmp_path / "inputs"
    writes = 0
    original_write = helper.atomic_write

    def failed_write(path, data):
        nonlocal writes
        writes += 1
        if writes == 3:
            message = "synthetic partial write"
            raise OSError(message)
        original_write(path, data)

    with (
        patch.dict(helper.protected_path.__globals__, OWNER_UID=os.getuid(), OWNED_ROOT=tmp_path),
        patch.dict(
            helper.refresh_client.__globals__,
            retrieve=lambda *_: values,
            atomic_write=failed_write,
        ),
        pytest.raises(OSError, match="synthetic partial write"),
    ):
        helper.refresh_client(cfg, directory, "c" * 64)
    assert not directory.exists()
    assert not list(tmp_path.glob(".generation-*"))
    directory.mkdir(mode=0o700)
    stale = directory / "stale"
    stale.write_text("previous immutable generation")
    retrieve = Mock(side_effect=OSError("synthetic denied retrieval"))
    with (
        patch.dict(helper.protected_path.__globals__, OWNER_UID=os.getuid(), OWNED_ROOT=tmp_path),
        patch.dict(
            helper.refresh_client.__globals__,
            retrieve=retrieve,
        ),
        pytest.raises(ValueError, match="already exists"),
    ):
        helper.refresh_client(cfg, directory, "c" * 64)
    retrieve.assert_not_called()
    assert stale.read_text() == "previous immutable generation"


def artifact_fixture(helper, tmp_path):
    """Strict synthetic metadata; no source/build/OCI acceptance is inferred."""
    files = {
        name: {
            "bytes": 1,
            "filesystem_mode": 33188,
            "git_blob": "a" * 40,
            "git_mode": "100644",
            "sha256": "b" * 64,
            "symlink": None,
        }
        for name in helper.REQUIRED_SOURCE_INPUTS
    }
    literal = b"result/bin/cargo-kani"
    files["crates/kani-harness/kani"] = {
        "bytes": len(literal),
        "filesystem_mode": 41471,
        "git_blob": hashlib.sha1(
            b"blob " + str(len(literal)).encode() + b"\0" + literal, usedforsecurity=False
        ).hexdigest(),
        "git_mode": "120000",
        "sha256": hashlib.sha256(literal).hexdigest(),
        "symlink": literal.decode(),
    }
    manifest = {
        "candidate_tree": "c" * 40,
        "source_base_commit": "d" * 40,
        "patch_sha256": "e" * 64,
        "files": files,
    }
    manifest_raw = json.dumps(manifest, indent=2).encode()
    manifest_path = tmp_path / "SOURCE-MANIFEST.json"
    manifest_path.write_bytes(manifest_raw)
    source_sha = hashlib.sha256(manifest_raw).hexdigest()
    image = "registry.example/aegaeon@sha256:" + "f" * 64
    entrypoint = "/bin/aegaeon-loadtest"
    receipt = {
        "schema_version": 1,
        "source_manifest_sha256": source_sha,
        "executable_sha256": "1" * 64,
        "image": image,
        "entrypoint": entrypoint,
        "build_binding": {
            "recipe_sha256": "2" * 64,
            "Cargo_lock_sha256": "b" * 64,
            "flake_lock_sha256": "b" * 64,
            "toolchain_sha256": "b" * 64,
            "target": "x86_64-unknown-linux-gnu",
            "features": [],
            "native_closure_sha256": "3" * 64,
        },
    }
    receipt_raw = json.dumps(receipt, indent=2).encode()
    receipt_path = tmp_path / "artifact-receipt.json"
    receipt_path.write_bytes(receipt_raw)
    cfg = {
        "SERVER_URL": config()["issuer_url"],
        "SERVER_IMAGE": image,
        "ARTIFACT_BUCKET": "synthetic-fixture",
        "ARTIFACT_PREFIX": "ci/",
        "WORKERS": "2",
        "RPS": "10",
        "RUN_TIME": "10s",
        "WARMUP": "1s",
        "SCENARIO": "mixed",
        "LOADTEST_BIN": entrypoint,
        "artifact": {
            "receipt_path": str(receipt_path),
            "receipt_sha256": hashlib.sha256(receipt_raw).hexdigest(),
            "source_manifest_path": str(manifest_path),
            "source_manifest_sha256": source_sha,
            "executable_sha256": receipt["executable_sha256"],
        },
    }
    return cfg, manifest, receipt


def test_artifact_inputs_preserve_raw_full_manifest_and_exact_binding(helper, tmp_path):
    cfg, _, _ = artifact_fixture(helper, tmp_path)
    with patch.dict(helper.protected_path.__globals__, OWNER_UID=os.getuid(), OWNED_ROOT=tmp_path):
        receipt, manifest = helper.validate_artifact(cfg)
    assert receipt == Path(cfg["artifact"]["receipt_path"]).read_bytes()
    assert manifest == Path(cfg["artifact"]["source_manifest_path"]).read_bytes()
    assert (
        helper.validate_source_manifest(manifest)["files"]["crates/kani-harness/kani"]["symlink"]
        == "result/bin/cargo-kani"
    )


@pytest.mark.parametrize(
    "change",
    [
        "manifest-unknown",
        "manifest-empty",
        "missing-core",
        "alias",
        "dot-path",
        "duplicate",
        "bool-bytes",
        "mode",
        "bool-mode",
        "link-bytes",
        "link-sha",
        "link-blob",
        "regular-link",
        "receipt-source",
        "receipt-image",
        "receipt-bin",
        "receipt-extra",
        "build-lock",
        "features",
        "target",
        "file-symlink",
        "parent-symlink",
        "writable-file",
        "writable-parent",
        "file-special",
        "digest",
    ],
)
def test_artifact_inputs_reject_schema_inventory_links_owners_aliases_and_bindings(
    helper, tmp_path, change
):
    cfg, manifest, receipt = artifact_fixture(helper, tmp_path)
    manifest_path = Path(cfg["artifact"]["source_manifest_path"])
    receipt_path = Path(cfg["artifact"]["receipt_path"])
    if change.startswith("manifest") or change in {
        "missing-core",
        "alias",
        "dot-path",
        "duplicate",
        "bool-bytes",
        "mode",
        "bool-mode",
        "link-bytes",
        "link-sha",
        "link-blob",
        "regular-link",
    }:
        raw = mutate_manifest_fixture(manifest, change)
        manifest_path.write_bytes(raw)
        cfg["artifact"]["source_manifest_sha256"] = hashlib.sha256(raw).hexdigest()
        receipt["source_manifest_sha256"] = cfg["artifact"]["source_manifest_sha256"]
    elif change.startswith("receipt") or change in {"build-lock", "features", "target"}:
        mutate_receipt_fixture(receipt, change)
    elif change == "digest":
        cfg["artifact"]["source_manifest_sha256"] = "0" * 64
    else:
        mutate_artifact_path_fixture(cfg, receipt_path, tmp_path, change)
    if change not in {"file-symlink", "file-special"}:
        raw = json.dumps(receipt).encode()
        receipt_path.write_bytes(raw)
        cfg["artifact"]["receipt_sha256"] = hashlib.sha256(raw).hexdigest()
    with (
        patch.dict(helper.protected_path.__globals__, OWNER_UID=os.getuid(), OWNED_ROOT=tmp_path),
        pytest.raises(ValueError, match=r"."),
    ):
        helper.validate_artifact(cfg)


def mutate_manifest_fixture(manifest, change):
    files = manifest["files"]
    if change == "manifest-unknown":
        manifest["unknown"] = "synthetic"
    elif change == "manifest-empty":
        manifest["files"] = {}
    elif change == "missing-core":
        del files["Cargo.lock"]
    elif change == "alias":
        files["alias/../Cargo.lock"] = files["Cargo.lock"]
    elif change == "dot-path":
        files["."] = files["Cargo.lock"]
    elif change in {"bool-bytes", "mode", "bool-mode", "regular-link"}:
        key, value = {
            "bool-bytes": ("bytes", True),
            "mode": ("filesystem_mode", 33261),
            "bool-mode": ("filesystem_mode", True),
            "regular-link": ("symlink", "Cargo.lock"),
        }[change]
        files["Cargo.lock"][key] = value
    elif change.startswith("link-"):
        key, value = {
            "link-bytes": ("bytes", 1),
            "link-sha": ("sha256", "a" * 64),
            "link-blob": ("git_blob", "a" * 40),
        }[change]
        files["crates/kani-harness/kani"][key] = value
    raw = json.dumps(manifest).encode()
    if change == "duplicate":
        raw = raw[:-1] + b',"candidate_tree":"' + b"c" * 40 + b'"}'
    return raw


def mutate_receipt_fixture(receipt, change):
    if change.startswith("receipt"):
        key = {
            "receipt-source": "source_manifest_sha256",
            "receipt-image": "image",
            "receipt-bin": "entrypoint",
            "receipt-extra": "unknown",
        }[change]
        receipt[key] = "synthetic-mismatch"
    else:
        key, value = {
            "build-lock": ("Cargo_lock_sha256", "a" * 64),
            "features": ("features", ["telemetry", "telemetry"]),
            "target": ("target", "unknown-target"),
        }[change]
        receipt["build_binding"][key] = value


def mutate_artifact_path_fixture(cfg, receipt_path, tmp_path, change):
    if change == "file-symlink":
        saved = receipt_path.with_name("saved-receipt")
        receipt_path.rename(saved)
        receipt_path.symlink_to(saved)
    elif change == "parent-symlink":
        folder = tmp_path / "alias-parent"
        folder.symlink_to(tmp_path, target_is_directory=True)
        cfg["artifact"]["receipt_path"] = str(folder / receipt_path.name)
    elif change == "writable-file":
        receipt_path.chmod(0o666)
    elif change == "writable-parent":
        tmp_path.chmod(0o777)
    elif change == "file-special":
        receipt_path.unlink()
        os.mkfifo(receipt_path)


def witness_fixture(helper, cfg):
    parsed = {
        "target_url": cfg["SERVER_URL"],
        "discovery_expected_issuer": None,
        "workers": int(cfg["WORKERS"]),
        "duration": {"secs": helper.duration_seconds(cfg["RUN_TIME"]), "nanos": 0},
        "target_rps": float(cfg["RPS"]),
        "warmup_duration": {
            "secs": helper.duration_seconds(cfg["WARMUP"], warmup=True),
            "nanos": 0,
        },
        "scenario": helper.SCENARIOS[cfg["SCENARIO"]],
        "debug": False,
    }
    raw = json.dumps(parsed, indent=2)
    return {"config_json": raw, "config_sha256": hashlib.sha256(raw.encode()).hexdigest()}, parsed


@pytest.mark.parametrize("rps", ["10", "2.5", "1.2e-5", "1e308", "1.7976931348623157e308"])
def test_config_witness_raw_bytes_semantic_f64_and_cli_bounds(helper, tmp_path, rps):
    cfg, _, _ = artifact_fixture(helper, tmp_path)
    cfg["WORKERS"] = "1"
    cfg["RPS"] = rps
    helper.validate_run_config(json.dumps(cfg), config()["issuer_url"])
    identity, _ = witness_fixture(helper, cfg)
    assert helper.validate_config_witness(identity, cfg) == identity["config_sha256"]
    compact = json.dumps(json.loads(identity["config_json"]), separators=(",", ":"))
    with pytest.raises(ValueError, match="digest"):
        helper.validate_config_witness({**identity, "config_json": compact}, cfg)


@pytest.mark.parametrize(
    "field",
    [
        "missing",
        "extra",
        "duplicate",
        "target_url",
        "workers",
        "duration",
        "target_rps",
        "warmup_duration",
        "scenario",
        "debug",
    ],
)
def test_config_witness_rejects_changed_seven_field_contract(helper, tmp_path, field):
    cfg, _, _ = artifact_fixture(helper, tmp_path)
    _identity, parsed = witness_fixture(helper, cfg)
    if field == "missing":
        del parsed["workers"]
    elif field == "extra":
        parsed["unknown"] = "synthetic"
    elif field != "duplicate":
        parsed[field] = {
            "target_url": "https://different.example.com",
            "workers": True,
            "duration": {"secs": 11, "nanos": 0},
            "target_rps": 10.0001,
            "warmup_duration": {"secs": 1, "nanos": 1},
            "scenario": "Smoke",
            "debug": True,
        }[field]
    raw = json.dumps(parsed)
    if field == "duplicate":
        raw = raw[:-1] + ',"workers":2}'
    changed = {"config_json": raw, "config_sha256": hashlib.sha256(raw.encode()).hexdigest()}
    with pytest.raises(ValueError, match=r"."):
        helper.validate_config_witness(changed, cfg)


@pytest.mark.parametrize("role", ["server", "loadgen"])
@pytest.mark.parametrize(
    "change",
    ["missing", "https-override", "empty", "bool", "number", "array", "object", "duplicate"],
)
def test_config_witness_required_null_discovery_issuer_rejects_recomputed_hash(
    helper, tmp_path, role, change
):
    sections, _ = infra.template_sections(infra.source_template(MODULE, role))
    for name, expected in infra.DELIVERY_PACKAGE_SHA256.items():
        body = sections["/usr/local/lib/aegaeon/runtime_delivery/" + name]
        assert hashlib.sha256(body.encode()).hexdigest() == expected
    output, generation, report = report_fixture(helper, tmp_path, "mixed")
    cfg = json.loads((output / "driver-config.json").read_bytes())
    assert (
        helper.validate_config_witness(report["identity"], cfg)
        == report["identity"]["config_sha256"]
    )
    parsed = json.loads(report["identity"]["config_json"])
    if change == "missing":
        del parsed["discovery_expected_issuer"]
    elif change != "duplicate":
        parsed["discovery_expected_issuer"] = {
            "https-override": "https://different.example.test",
            "empty": "",
            "bool": False,
            "number": 0,
            "array": [],
            "object": {},
        }[change]
    raw = json.dumps(parsed)
    if change == "duplicate":
        raw = raw[:-1] + ',"discovery_expected_issuer":null}'
    report["identity"].update(
        config_json=raw, config_sha256=hashlib.sha256(raw.encode()).hexdigest()
    )
    (output / "report.json").write_text(json.dumps(report))
    with (
        patch.dict(helper.protected_path.__globals__, OWNER_UID=os.getuid(), OWNED_ROOT=tmp_path),
        pytest.raises(ValueError, match=r"."),
    ):
        helper.verify_report(output, generation, "synthetic-run")
    assert not (output / "run-receipt.json").exists()


@pytest.mark.parametrize(
    ("role", "profile", "expected_fields"), [("server", "server", 24), ("loadgen", "client", 5)]
)
def test_driver_helper_exact_digest_and_one_byte_mutation_guard(role, profile, expected_fields):
    template = infra.source_template(MODULE, role)
    sections, _ = infra.template_sections(template)
    body = sections["/usr/local/bin/aegaeon-deliver-supplies"]
    assert hashlib.sha256(body.encode()).hexdigest() == infra.DELIVERY_BODY_SHA256
    assert len(infra.performance_delivery_inputs(template, profile)) == expected_fields
    changed_body = body.replace("package_sources", "package_sourcex", 1)
    assert changed_body != body
    assert len(changed_body.encode()) == len(body.encode())
    with pytest.raises(ValueError, match="Changed strict runtime supply executable"):
        infra.performance_delivery_inputs(template.replace(body, changed_body, 1), profile)


@pytest.mark.parametrize("phase", ["prepare-driver", "run-config", "client", "verify-report"])
def test_driver_rejects_failed_input_stages_and_cleans_generation(tmp_path, phase):
    result, _, _, _ = run_driver_fixture(tmp_path, delivery_fail=phase)
    assert result.returncode != 0
    calls = (
        (tmp_path / "docker.calls").read_text().splitlines()
        if (tmp_path / "docker.calls").exists()
        else []
    )
    assert (
        calls
        == (
            {
                "prepare-driver": [],
                "run-config": [],
                "client": ["pull"],
                "verify-report": ["pull", "run"],
            }[phase]
        )
    )
    if (tmp_path / "supplies").exists():
        assert all(path.name == "driver.lock" for path in (tmp_path / "supplies").iterdir())


def test_driver_rejects_preexisting_report_before_credentials_or_workload(tmp_path):
    result, _, _, _ = run_driver_fixture(tmp_path, report_preexists=True)
    assert result.returncode != 0
    assert not (tmp_path / "docker.calls").exists()
    assert (tmp_path / "delivery.calls").read_text().splitlines() == [
        "prepare-driver",
        "run-config",
    ]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("WORKERS", "0"),
        ("WORKERS", "01"),
        ("WORKERS", "4294967296"),
        ("WORKERS", True),
        ("RPS", "NaN"),
        ("RPS", "inf"),
        ("RPS", "1e309"),
        ("RPS", "0"),
        ("RPS", "0.0000001"),
        ("RPS", "01"),
        ("RUN_TIME", "0"),
        ("RUN_TIME", "24h"),
        ("RUN_TIME", "86401s"),
        ("RUN_TIME", "1.5s"),
        ("WARMUP", "-1"),
        ("WARMUP", "25h"),
        ("SERVER_URL", "https://different.example.com"),
        ("SERVER_IMAGE", "registry.example/aegaeon:latest"),
        ("LOADTEST_BIN", "/bin/../bin/aegaeon-loadtest"),
        ("SCENARIO", "oauth"),
        ("ARTIFACT_PREFIX", "../reports/"),
    ],
)
def test_run_config_rejects_schema_and_cli_bounds(helper, tmp_path, field, value):
    cfg, _, _ = artifact_fixture(helper, tmp_path)
    cfg[field] = value
    if (field, value) == ("RUN_TIME", "24h"):
        assert helper.validate_run_config(json.dumps(cfg), config()["issuer_url"]) == cfg
    else:
        with pytest.raises(ValueError, match=r"."):
            helper.validate_run_config(json.dumps(cfg), config()["issuer_url"])


def test_run_config_rejects_alias_unknown_missing_and_duplicate_keys(helper, tmp_path):
    cfg, _, _ = artifact_fixture(helper, tmp_path)
    for alias in ("BASE_URL", "LOADGEN_IMAGE", "SERVER"):
        changed = {**cfg, alias: cfg["SERVER_URL"]}
        with pytest.raises(ValueError, match="exact loadtest"):
            helper.validate_run_config(json.dumps(changed), config()["issuer_url"])
    for name in helper.LOADTEST_NAMES:
        changed = dict(cfg)
        del changed[name]
        with pytest.raises(ValueError, match="exact loadtest"):
            helper.validate_run_config(json.dumps(changed), config()["issuer_url"])
    raw = json.dumps(cfg)[:-1] + ',"WORKERS":"1"}'
    with pytest.raises(ValueError, match="duplicate"):
        helper.validate_run_config(raw, config()["issuer_url"])


def report_fixture(helper, tmp_path, scenario):
    cfg, _, _ = artifact_fixture(helper, tmp_path)
    cfg["SCENARIO"] = scenario
    output = tmp_path / "results"
    generation = tmp_path / "generation"
    output.mkdir(mode=0o700)
    generation.mkdir(mode=0o700)
    identity, _ = witness_fixture(helper, cfg)
    requires_profile = scenario not in {"smoke", "discovery", "jwks", "key-rotation"}
    identity.update(
        source_sha256=cfg["artifact"]["source_manifest_sha256"],
        artifact_sha256=cfg["artifact"]["executable_sha256"],
        report_id="12345678-1234-4567-8123-123456789abc",
        report_path="/results/report.json",
        profile_sha256="4" * 64 if requires_profile else None,
        session_provenance_sha256="5" * 64 if requires_profile else None,
    )
    report = {
        "schema_version": 2,
        "request_unit": "scenario_invocations",
        "memory_subject": "load_generator_process",
        "selected_scenario": helper.SCENARIOS[scenario],
        "identity": identity,
    }
    (output / "driver-config.json").write_text(json.dumps(cfg, indent=2))
    (generation / "client.version.json").write_text(
        json.dumps({"profile_sha256": "4" * 64, "provenance_sha256": "5" * 64})
    )
    (output / "report.json").write_text(json.dumps(report, indent=2))
    return output, generation, report


@pytest.mark.parametrize(
    "scenario",
    [
        "smoke",
        "auth-code",
        "introspection",
        "revocation",
        "dpop",
        "userinfo",
        "discovery",
        "jwks",
        "par",
        "mixed",
        "policy-mixed",
        "key-rotation",
    ],
)
def test_report_binds_all_selections_and_exact_raw_receipts(helper, tmp_path, scenario):
    output, generation, report = report_fixture(helper, tmp_path, scenario)
    report_raw = (output / "report.json").read_bytes()
    config_raw = (output / "driver-config.json").read_bytes()
    with patch.dict(helper.protected_path.__globals__, OWNER_UID=os.getuid(), OWNED_ROOT=tmp_path):
        helper.verify_report(output, generation, "synthetic-run")
    receipt = json.loads((output / "run-receipt.json").read_bytes())
    assert receipt["report_sha256"] == hashlib.sha256(report_raw).hexdigest()
    assert receipt["driver_config_sha256"] == hashlib.sha256(config_raw).hexdigest()
    assert receipt["producer_config_sha256"] == report["identity"]["config_sha256"]
    assert receipt["report_id"] == report["identity"]["report_id"]
    assert receipt["run_id"] == "synthetic-run"
    assert (output / "run-receipt.json").stat().st_mode & 0o777 == 0o600
    assert "performance acceptance is external" in receipt["qualification"]


@pytest.mark.parametrize(
    "field",
    [
        "schema_version",
        "request_unit",
        "memory_subject",
        "selected_scenario",
        "source_sha256",
        "artifact_sha256",
        "report_path",
        "report_id",
        "profile_sha256",
        "session_provenance_sha256",
        "config_sha256",
        "identity-extra",
    ],
)
def test_report_rejects_mismatched_identity_without_success_receipt(helper, tmp_path, field):
    output, generation, report = report_fixture(helper, tmp_path, "mixed")
    if field in report:
        report[field] = True if field == "schema_version" else "invalid"
    else:
        report["identity"]["extra" if field == "identity-extra" else field] = "invalid"
    (output / "report.json").write_text(json.dumps(report))
    with (
        patch.dict(helper.protected_path.__globals__, OWNER_UID=os.getuid(), OWNED_ROOT=tmp_path),
        pytest.raises(ValueError, match=r"."),
    ):
        helper.verify_report(output, generation, "synthetic-run")
    assert not (output / "run-receipt.json").exists()


def test_driver_serializes_two_invocations_and_limits_workload_mounts(tmp_path):
    initial, _, _, _ = run_driver_fixture(tmp_path)
    assert initial.returncode == 0
    script = (tmp_path / "actual-driver.sh").read_text()
    env = json.loads((tmp_path / "fixture-environment.json").read_text())
    gate = tmp_path / "gate"
    gate.touch()
    first_env = {**env, "FIXTURE_GATE": str(gate)}
    first = subprocess.Popen(  # noqa: S603 -- same owned actual-driver fixture
        [shutil.which("bash"), "-c", script],
        env=first_env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    second = None
    try:
        wait_for_fixture(lambda: gate.with_suffix(".entered").exists())
        second = subprocess.Popen(  # noqa: S603 -- same owned actual-driver fixture
            [shutil.which("bash"), "-c", script],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        wait_for_fixture(
            lambda: (
                (tmp_path / "delivery.calls").read_text().splitlines().count("prepare-driver") == 3
            )
        )
        calls = (tmp_path / "delivery.calls").read_text().splitlines()
        assert calls.count("run-config") == 2
        gate.unlink()
        first_output = first.communicate(timeout=10)
        second_output = second.communicate(timeout=10)
        assert first.returncode == second.returncode == 0, (first_output, second_output)
        assert len(list((tmp_path / "results").iterdir())) == 3
        assert not list((tmp_path / "supplies").glob("*/inputs"))
        assert_restricted_workload_mounts(tmp_path / "docker.argv")
    finally:
        gate.unlink(missing_ok=True)
        for process in (first, second):
            if process is not None and process.poll() is None:
                process.kill()
                process.communicate(timeout=5)


def assert_restricted_workload_mounts(path):
    for raw in path.read_text().splitlines():
        argv = json.loads(raw)
        assert argv[argv.index("--user") + 1] == "0:0"
        assert argv[argv.index("--cap-drop") + 1] == "ALL"
        assert argv[argv.index("--security-opt") + 1] == "no-new-privileges"
        mounts = [argv[index + 1] for index, value in enumerate(argv) if value == "--mount"]
        assert len(mounts) == 3
        assert all(value.endswith(",readonly") for value in mounts)
        assert {value.split("dst=", 1)[1].split(",", 1)[0] for value in mounts} == {
            "/run/aegaeon-inputs/profile.json",
            "/run/aegaeon-inputs/session.txt",
            "/run/aegaeon-inputs/session-provenance.json",
        }


def wait_for_fixture(predicate):
    deadline = time.monotonic() + 5
    while not predicate() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert predicate()


@pytest.mark.parametrize("change", ["symlink", "fifo", "owner", "writable"])
def test_run_config_protected_file_rejected_before_artifact_reads(helper, tmp_path, change):
    cfg, _, _ = artifact_fixture(helper, tmp_path)
    path = tmp_path / "run.json"
    path.write_text(json.dumps(cfg))
    if change == "symlink":
        saved = tmp_path / "saved.json"
        path.rename(saved)
        path.symlink_to(saved)
    elif change == "fifo":
        path.unlink()
        os.mkfifo(path)
    elif change == "writable":
        path.chmod(0o666)
    artifact = Mock(side_effect=AssertionError("must not read artifact"))
    with (
        patch.dict(helper.run_config.__globals__, validate_artifact=artifact),
        patch.dict(
            helper.protected_path.__globals__,
            OWNER_UID=os.getuid() + (change == "owner"),
            OWNED_ROOT=tmp_path,
        ),
        pytest.raises(ValueError, match="unsafe protected path"),
    ):
        helper.run_config(str(path), tmp_path / "output", config()["issuer_url"])
    artifact.assert_not_called()
    assert not (tmp_path / "output").exists()


def test_sweep_produces_exclusive_config_without_evaluating_values(tmp_path):
    source = (ROOT / "scripts/perf/aws_sweep.sh").read_text()
    start = source.index('\tconfig_payload="$(\n')
    end = source.index("\n\tlg_resp=", start)
    snippet = source[start:end]
    driver = tmp_path / "record-driver"
    driver.write_text(
        f"#!{sys.executable}\nimport json,sys\nfrom pathlib import Path\n"
        f"root=Path({str(tmp_path)!r})\np=Path(sys.argv[2])\n"
        "assert sys.argv[1]=='--config-file'\n"
        "assert p.stat().st_mode & 0o777 == 0o600\n"
        "(root/(p.name+'.captured')).write_bytes(p.read_bytes())\n"
    )
    driver.chmod(0o755)
    snippet = snippet.replace(
        "/etc/aegaeon/.loadtest-invocation-", str(tmp_path / ".loadtest-invocation-")
    )
    snippet = snippet.replace("/usr/local/bin/aegaeon-run-loadtest", str(driver))
    env = {
        **os.environ,
        "server_url": "https://issuer.example.com",
        "SERVER_IMAGE": "synthetic-image",
        "artifact_bucket": "synthetic-fixture",
        "artifact_prefix": "ci/",
        "WORKERS": "2",
        "rps": "2.5",
        "RUN_TIME": "1m",
        "WARMUP": "0",
        "SCENARIO": "mixed",
        "LOADTEST_BIN": "/bin/aegaeon-loadtest",
        "artifact_config": "{}",
    }
    for workers in ("2", "3", "$(touch " + str(tmp_path / "must-not-exist") + ")"):
        result = subprocess.run(  # noqa: S603 -- exact config-producing sweep snippet, no cloud calls
            [shutil.which("bash"), "-c", snippet + '\nbash -c "$loadgen_script"'],
            env={**env, "WORKERS": workers},
            capture_output=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr
    records = list(tmp_path.glob("*.captured"))
    assert len(records) == 3
    assert {json.loads(path.read_bytes())["WORKERS"] for path in records} == {
        "2",
        "3",
        "$(touch " + str(tmp_path / "must-not-exist") + ")",
    }
    assert not list(tmp_path.glob("*.json"))
    assert not (tmp_path / "must-not-exist").exists()
