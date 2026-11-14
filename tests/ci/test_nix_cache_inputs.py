"""Local-only cache diagnostics must not disclose credentials or bypass cleanup."""

from __future__ import annotations

import base64
import json
import os
import signal
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/ci"))
sys.path.insert(0, str(ROOT / "tests/ci"))
import observe_nix_cache_inputs as observer  # noqa: E402
from fixture_processes import run_fixture  # noqa: E402

PACKAGE = "/nix/store/" + "a" * 32 + "-aegaeon-database-tests-0.0.0"
DEPENDENCY = "/nix/store/" + "b" * 32 + "-dependency"
NAR_HASH = "sha256-" + base64.b64encode(bytes(32)).decode()
SECRET = "PRIVATE_TOKEN_MUST_NOT_ESCAPE"  # noqa: S105 - synthetic disclosure canary.


def metadata():
    return {
        path: {"narHash": NAR_HASH, "narSize": 100, "references": refs, "signatures": []}
        for path, refs in ((PACKAGE, [DEPENDENCY]), (DEPENDENCY, []))
    }


class CacheInputsTests(unittest.TestCase):
    def setUp(self):
        self.directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.tool = self.directory / "nix"
        self.log = self.directory / "commands.jsonl"
        self.configuration = {
            "substituters": "https://cache.nixos.org/ https://edge.cache.flakehub.com?trusted=1",
            "trusted-substituters": "http://127.0.0.1:12345/",
            "trusted-public-keys": "cache.nixos.org-1:" + base64.b64encode(bytes(32)).decode(),
            "require-sigs": "true",
            "netrc-file": "/nix/var/determinate/netrc",
            "fallback": "true",
            "narinfo-cache-negative-ttl": "0",
        }
        self.enterContext(
            patch.dict(
                os.environ,
                {
                    "PATH": f"{self.directory}:{os.environ['PATH']}",
                    "AEGAEON_TEST_NIX_SETTINGS": "{}",
                    "AEGAEON_TEST_NIX_ERROR": SECRET,
                },
            )
        )
        self.write_tool()

    def write_tool(self, body=None):
        os.environ["AEGAEON_TEST_NIX_SETTINGS"] = json.dumps(self.configuration)
        if body is None:
            body = f"""import json, os, pathlib, sys
args = sys.argv[1:]
with pathlib.Path({str(self.log)!r}).open('a') as log:
    log.write(json.dumps(args) + '\\n')
configuration = json.loads(os.environ["AEGAEON_TEST_NIX_SETTINGS"])
if args == ['--version']:
    print('nix (Determinate Nix 3.16.0) 2.34.9')
elif len(args) == 3 and args[:2] == ['config', 'show'] and args[2] in configuration:
    print(configuration[args[2]])
elif args == ['--offline', '--option', 'allow-import-from-derivation', 'false',
              'eval', '--no-write-lock-file', '--raw',
              '.#packages.x86_64-linux.database-tests.outPath']:
    print({PACKAGE!r})
elif args == ['--offline', '--store', 'daemon', 'path-info', '--json', '--recursive', {PACKAGE!r}]:
    print({json.dumps(metadata())!r})
else:
    raise SystemExit(91)
"""
        self.tool.write_text(f"#!{sys.executable}\n" + body)
        self.tool.chmod(0o755)

    def invoke(self, role="core", package=None):
        output = self.directory / f"report-{role}.json"
        arguments = ["observer", "--role", role, "--output", str(output)]
        if package is not None:
            arguments += ["--package", package]
        with patch.object(sys, "argv", arguments):
            status = observer.main()
        return status, json.loads(output.read_text())

    def check_stopped(self, report):
        for row in report["queries"]:
            assert row["cleanup_confirmed"], row
            if "pid" in row:
                assert not Path(f"/proc/{row['pid']}").exists(), row

    def test_core_and_database_only_query_selected_config_and_local_metadata(self):
        for role in ("core", "database"):
            status, report = self.invoke(role, PACKAGE if role == "database" else None)
            assert status == 0
            assert report["status"] == "observed"
            assert report["closure"]["path_count"] == 2
            assert report["closure"]["nar_bytes"] == 200
            assert report["nix_version"] == "2.34.9"
            assert report["determinate_nix_version"] == "3.16.0"
            assert report["settings_scope"] == "effective_client_config_only"
            assert report["daemon_auth_trust"] == "not_observed"
            assert report["collector_duration_seconds"] >= 0
            assert report["remote_availability"] == "not_observed"
            assert report["auth_validated"] is False
            assert report["closure"]["signatures_verified"] is False
            self.check_stopped(report)
        commands = [json.loads(line) for line in self.log.read_text().splitlines()]
        assert len(commands) == 19
        assert sum("eval" in command for command in commands) == 1
        assert sum("path-info" in command for command in commands) == 2
        assert not any(
            {"build", "copy", "store", "--refresh"}.intersection(command) for command in commands
        )
        assert all(len(command) == 3 for command in commands if command[0] == "config")

    def test_credentials_unknown_urls_fields_and_error_output_never_escape(self):
        self.configuration["substituters"] += (
            f" https://user:{SECRET}@cache.flakehub.com"
            f" https://edge.cache.flakehub.com?token={SECRET}"
            f" https://unknown.example/{SECRET}"
        )
        self.configuration["trusted-public-keys"] += f" {SECRET}"
        self.configuration["netrc-file"] = str(self.directory / SECRET)
        self.write_tool()
        assert SECRET not in self.tool.read_text()
        with patch.dict(os.environ, {"GITHUB_RUN_ID": SECRET, "GITHUB_TOKEN": SECRET}):
            status, report = self.invoke()
        assert status == 0
        assert report["status"] == "partial"
        assert SECRET not in json.dumps(report)
        assert report["settings"]["netrc-file"]["classification"] == "other_path_redacted"
        self.check_stopped(report)
        # A real command failure retains its status, never its potentially secret stderr.
        self.write_tool(
            "import os, sys\nsys.stderr.write(os.environ['AEGAEON_TEST_NIX_ERROR'])\nsys.exit(73)\n"
        )
        assert SECRET not in self.tool.read_text()
        status, report = self.invoke("database", PACKAGE)
        assert status == 0
        assert report["status"] == "partial"
        assert all(row["observed_returncode"] == 73 for row in report["queries"])
        assert SECRET not in json.dumps(report)
        self.check_stopped(report)

    def test_incomplete_unrelated_and_malformed_closures_are_not_complete(self):
        cases = [[], {}, {PACKAGE: metadata()[PACKAGE]}]
        unrelated = metadata()
        unrelated["/nix/store/" + "c" * 32 + "-unrelated"] = metadata()[DEPENDENCY]
        cases.append(unrelated)
        invalid_size = metadata()
        invalid_size[PACKAGE]["narSize"] = True
        cases.append(invalid_size)
        for value in cases:
            with pytest.raises(ValueError, match=r"local closure|local paths"):
                observer.closure(json.dumps(value).encode(), PACKAGE)
        valid = metadata()
        valid[PACKAGE]["ignored-secret-field"] = SECRET
        valid[PACKAGE]["signatures"] = [f"{SECRET}:value"]
        assert SECRET not in json.dumps(observer.closure(json.dumps(valid).encode(), PACKAGE))

    def test_invalid_package_and_exhausted_budget_do_not_start_work(self):
        with patch.object(observer, "WORK_SECONDS", 0):
            status, report = self.invoke("database", SECRET)
        assert status == 0
        assert report["status"] == "partial"
        assert report["closure"]["status"] == "package_unavailable"
        assert all(row["status"] == "budget_exhausted" for row in report["queries"])
        assert not self.log.exists()
        assert SECRET not in json.dumps(report)

    def test_real_child_output_limit_and_cancellation_keep_cleanup(self):
        self.write_tool("import os\nwhile True: os.write(1, b'x' * 4096)\n")
        report = {"queries": []}
        before = set(Path("/proc/self/fd").iterdir())
        assert observer.query([], report, time.monotonic() + 2, byte_limit=4096) is None
        assert report["queries"][0]["status"] == "output_limit"
        self.check_stopped(report)
        self.write_tool(
            "import os, signal, time\nos.kill(os.getppid(), signal.SIGTERM)\ntime.sleep(30)\n"
        )
        report = {"queries": []}
        with pytest.raises(SystemExit) as failure, observer.cancellation_scope():
            observer.query([], report, time.monotonic() + 2)
        assert failure.value.code == 128 + signal.SIGTERM
        assert report["queries"][0]["status"] == "interrupted"
        self.check_stopped(report)
        assert set(Path("/proc/self/fd").iterdir()) == before

    def test_real_held_writer_and_timeout_never_wait_for_eof(self):
        # The existing test supervisor reaps descendants after SOURCE group cleanup.
        controller = self.directory / "controller.py"
        controller.write_text(f"""import json, os, pathlib, sys, time
sys.path.insert(0, {str(ROOT / "scripts/ci")!r})
import observe_nix_cache_inputs as observer
from database_execution import group_running
tool = pathlib.Path({str(self.tool)!r})
records = []
for mode in ('leader_exit', 'timeout'):
    tool.write_text({f"#!{sys.executable}"!r} + '\\nimport os,time\\n' +
        'if os.fork() == 0: time.sleep(30)\\n' +
        ('time.sleep(30)\\n' if mode == 'timeout' else 'os._exit(0)\\n'))
    tool.chmod(0o755)
    report = {{'queries': []}}
    observer.query([], report, time.monotonic() + 0.5)
    row = report['queries'][0]
    if row['status'] != ('timeout' if mode == 'timeout' else 'ok'):
        raise RuntimeError('wrong query status')
    if not row['cleanup_confirmed'] or group_running(row['pid']):
        raise RuntimeError('source group still running')
    records.append(row)
pathlib.Path({str(self.directory / "held-result.json")!r}).write_text(json.dumps(records))
""")
        result = run_fixture([sys.executable, str(controller)], timeout=10)
        assert result.returncode == 0, result.stderr
        rows = json.loads((self.directory / "held-result.json").read_text())
        assert all(row["query_duration_seconds"] < 3 for row in rows)
        self.check_stopped({"queries": rows})

    def test_registration_and_stop_failures_cannot_report_confirmed_success(self):
        self.write_tool("import time\ntime.sleep(30)\n")
        report = {"queries": []}
        original = observer.cleanup_receipts.update

        def fail_registration(receipt, **kwargs):
            if "group" in kwargs:
                raise OSError(SECRET)
            return original(receipt, **kwargs)

        before = set(Path("/proc/self/fd").iterdir())
        with (
            patch.object(observer.cleanup_receipts, "update", fail_registration),
            pytest.raises(OSError, match=SECRET),
        ):
            observer.query([], report, time.monotonic() + 2)
        self.check_stopped(report)
        assert SECRET not in json.dumps(report)
        self.write_tool("raise SystemExit(0)\n")
        stop = observer.stop_process_group

        def stop_then_refuse(process, **kwargs):
            stop(process, **kwargs)
            raise OSError(SECRET)

        with patch.object(observer, "stop_process_group", stop_then_refuse):
            status, report = self.invoke("database", PACKAGE)
        assert status == 1
        assert report["status"] == "observer_failed"
        assert report["queries"][0]["cleanup_confirmed"] is False
        assert not Path(f"/proc/{report['queries'][0]['pid']}").exists()
        assert SECRET not in json.dumps(report)
        assert set(Path("/proc/self/fd").iterdir()) == before

    def test_workflow_keeps_full_build_and_db_execution_after_observation(self):
        workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
        jobs = workflow["jobs"]
        core = next(
            job
            for job in jobs.values()
            if any(step.get("id") == "core-checks" for step in job.get("steps", []))
        )
        steps = core["steps"]
        position = next(
            index for index, step in enumerate(steps) if step.get("id") == "core-checks"
        )
        assert "observe_nix_cache_inputs.py --role core" in steps[position - 1]["run"]
        assert "run_core_pr_checks.py --all-checks" in steps[position]["run"]
        database = next(
            step["run"]
            for job in jobs.values()
            for step in job.get("steps", [])
            if step.get("id") == "database-tests"
        )
        assert database.index("nix build .#database-tests") < database.index(
            "observe_nix_cache_inputs.py"
        )
        assert database.index("observe_nix_cache_inputs.py") < database.index(
            "database_execution.py discover"
        )
        assert "nix develop .#ci --command python3 scripts/ci/run_database_lanes.py" in database


if __name__ == "__main__":
    unittest.main()
