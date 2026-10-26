"""Preserve database selection, serial execution and service-backed test failures."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
PACKAGER = ROOT / "scripts/validation/database_test_package.py"
PROFILE = {
    "test": True,
    "opt_level": "0",
    "debuginfo": 2,
    "debug_assertions": True,
    "overflow_checks": True,
}


class DatabaseTestPackageTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        (self.root / "crates/server").mkdir(parents=True)
        (self.root / "crates/server/Cargo.toml").touch()
        self.rows = []
        for name, kind in (("aegaeon_server", "lib"), ("dcr_database_test", "test")):
            binary = self.root / "target/debug/deps" / name
            binary.parent.mkdir(parents=True, exist_ok=True)
            binary.write_text(
                f"#!{sys.executable}\nimport os,sys,json\n"
                f"with open({str(self.root / 'calls.jsonl')!r},'a') as f:\n"
                f" f.write(json.dumps({{'name':{name!r},'args':sys.argv[1:],'cwd':os.getcwd(),"
                "'redis':os.environ.get('AEGAEON_TEST_REDIS_URL')})+'\\n')\n"
                "print(os.environ.get('DB_OUTPUT',"
                "'test result: ok. 1 passed; 0 failed; 0 ignored;'))\n"
                "raise SystemExit(int(os.environ.get('DB_STATUS','0')))\n"
            )
            binary.chmod(0o755)
            self.rows.append(
                {
                    "reason": "compiler-artifact",
                    "executable": str(binary),
                    "manifest_path": str(self.root / "crates/server/Cargo.toml"),
                    "target": {"name": name, "kind": [kind], "test": True},
                    "profile": PROFILE,
                    "features": ["default", "telemetry"],
                }
            )
        self.rows.append({"reason": "build-finished", "success": True})

    def command(self, *arguments, environment=None):
        return subprocess.run(  # noqa: S603 - checked-in code, owned fixture executables
            [sys.executable, str(PACKAGER), *arguments],
            cwd=self.root,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )

    def install(self, rows=None):
        shutil.rmtree(self.root / "output", ignore_errors=True)
        rows = self.rows if rows is None else rows
        (self.root / "messages").write_text("".join(json.dumps(r) + "\n" for r in rows))
        (self.root / "identity").write_text('{"source":"owned-fixture"}')
        return self.command("install", "messages", "identity", "output")

    def test_all_four_selections_preserve_arguments_directory_and_environment(self):
        assert self.install().returncode == 0
        runtime = ["--ignored", "--test-threads=1"]
        cases = [
            (
                ["redis_", "--lib"],
                ["--skip", "shared_redis_", "--skip", "namespace::"],
                "aegaeon_server",
                ["redis_"],
            ),
            (["--lib"], ["--skip", "redis_", "--skip", "namespace::"], "aegaeon_server", []),
            (["--test", "dcr_database_test"], [], "dcr_database_test", []),
            (
                ["shared_redis_", "--lib"],
                ["--skip", "namespace::"],
                "aegaeon_server",
                ["shared_redis_"],
            ),
        ]
        expected = []
        for _ in range(2):
            for cargo, skips, name, filters in cases:
                result = self.command(
                    "run",
                    "output",
                    "-p",
                    "aegaeon-server",
                    *cargo,
                    "--",
                    *runtime,
                    *skips,
                    environment=dict(
                        os.environ, AEGAEON_TEST_REDIS_URL="redis://127.0.0.1:16379/0"
                    ),
                )
                assert result.returncode == 0, result.stderr
                expected.append(
                    {
                        "name": name,
                        "args": [*filters, *runtime, *skips],
                        "cwd": str(self.root / "crates/server"),
                        "redis": "redis://127.0.0.1:16379/0",
                    }
                )
        assert [
            json.loads(line) for line in (self.root / "calls.jsonl").read_text().splitlines()
        ] == expected

    def test_incomplete_failed_duplicate_and_mismatched_builds_are_rejected(self):
        invalid = [
            [],
            self.rows[:-1],
            self.rows[1:],
            self.rows * 2,
            [self.rows[0], self.rows[0], self.rows[-1]],
            [*self.rows[:-1], {"reason": "build-finished", "success": False}],
        ]
        invalid.extend(
            [self.rows[0] | change, *self.rows[1:]]
            for change in (
                {"features": ["default", "telemetry", "verified-claim"]},
                {"profile": PROFILE | {"test": False}},
                {"profile": PROFILE | {"opt_level": "3"}},
                {"executable": "/bin/sh"},
                {"manifest_path": "/other/Cargo.toml"},
            )
        )
        for rows in invalid:
            with self.subTest(rows=rows):
                result = self.install(rows)
                assert result.returncode != 0
                assert not (self.root / "output/build.json").exists()

    def test_non_test_binaries_are_build_evidence_not_runtime_selections(self):
        auxiliary = self.rows[0] | {
            "target": {"name": "server", "kind": ["bin"], "test": True},
            "profile": PROFILE | {"test": False},
        }
        result = self.install([auxiliary, *self.rows])
        assert result.returncode == 0, result.stderr
        receipt = json.loads((self.root / "output/build.json").read_text())
        assert receipt["auxiliary_build_targets"] == [auxiliary]
        assert set(receipt["binaries"]) == {"aegaeon_server", "dcr_database_test"}

    def test_modified_inventory_or_bytes_cannot_execute(self):
        for mutation in ("bytes", "missing", "symlink", "mode", "inventory", "profile"):
            with self.subTest(mutation=mutation):
                assert self.install().returncode == 0
                binary = self.root / "output/libexec/dcr_database_test"
                if mutation == "bytes":
                    binary.write_text("changed")
                elif mutation == "mode":
                    binary.chmod(0o644)
                elif mutation in ("missing", "symlink"):
                    binary.unlink()
                    if mutation == "symlink":
                        binary.symlink_to(self.rows[1]["executable"])
                else:
                    p = self.root / "output/build.json"
                    r = json.loads(p.read_text())
                    if mutation == "inventory":
                        del r["binaries"]["dcr_database_test"]
                    else:
                        r["binaries"]["aegaeon_server"]["profile"]["overflow_checks"] = False
                    p.write_text(json.dumps(r))
                result = self.command(
                    "run",
                    "output",
                    "-p",
                    "aegaeon-server",
                    "--lib",
                    "--",
                    "--ignored",
                    "--test-threads=1",
                )
                assert result.returncode != 0
                assert not (self.root / "calls.jsonl").exists()

    def test_unhandled_build_or_runtime_arguments_never_execute(self):
        assert self.install().returncode == 0
        good = ["-p", "aegaeon-server", "--lib", "--", "--ignored", "--test-threads=1"]
        for arguments in (
            [],
            ["--workspace"],
            good[:-2],
            [*good, "--list"],
            [*good, "--skip"],
            [*good, "--skip", ""],
            [*good, "--skip", "--list"],
            [*good[:3], "--features", "verified-claim", *good[3:]],
            [*good[:-1], "--test-threads=2"],
        ):
            with self.subTest(arguments=arguments):
                assert self.command("run", "output", *arguments).returncode != 0
        assert not (self.root / "calls.jsonl").exists()

    def test_real_required_guard_retains_failure_and_rejects_no_execution(self):
        assert self.install().returncode == 0
        scripts = self.root / "scripts/validation"
        scripts.mkdir(parents=True)
        for name in (
            "run_required_cargo_test.sh",
            "database_test_package.py",
            "jose_server_test_package.py",
        ):
            shutil.copy2(ROOT / "scripts/validation" / name, scripts / name)
        for output, status, expected in (
            ("test result: ok. 1 passed; 0 failed; 0 ignored;", "0", 0),
            ("test result: ok. 1 passed; 0 failed; 0 ignored;", "37", 37),
            ("test result: ok. 0 passed; 0 failed; 0 ignored;", "0", 1),
            ("test result: ok. 0 passed; 0 failed; 1 ignored;", "0", 1),
            ("running 1 test", "0", 1),
            ("test result: FAILED. 0 passed; 1 failed; 0 ignored;", "0", 1),
        ):
            env = dict(
                os.environ,
                AEGAEON_DATABASE_TEST_PACKAGE=str(self.root / "output"),
                DB_OUTPUT=output,
                DB_STATUS=status,
            )
            for key in ("BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS", "JOSE_SERVER_TEST_PACKAGE"):
                env.pop(key, None)
            bash = shutil.which("bash")
            assert bash
            result = subprocess.run(  # noqa: S603 - actual guard and owned fixture
                [
                    bash,
                    str(scripts / "run_required_cargo_test.sh"),
                    "-p",
                    "aegaeon-server",
                    "--lib",
                    "--",
                    "--ignored",
                    "--test-threads=1",
                ],
                cwd=self.root,
                env=env,
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )
            assert result.returncode == expected, result.stderr


class DatabaseWorkflowTests(unittest.TestCase):
    def test_compilation_failure_or_empty_output_stops_before_live_tests(self):
        workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
        step = next(
            s
            for s in workflow["jobs"]["db-integration"]["steps"]
            if s["name"] == "Run DB-gated ignored integration tests"
        )
        assert not step.get("continue-on-error", False)
        assert "if" not in step
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for tool, body in (
                ("sudo", "pass"),
                (
                    "nix",
                    (
                        "import json,os,sys\n"
                        "with open('commands','a') as f: f.write(json.dumps(sys.argv[1:])+'\\n')\n"
                        "if sys.argv[1]=='build':\n"
                        " print(os.environ['BUILD_OUTPUT'])\n"
                        " raise SystemExit(int(os.environ['BUILD_EXIT']))\n"
                        "assert os.environ['AEGAEON_DATABASE_TEST_PACKAGE']=='/fixture/package'\n"
                        "raise SystemExit(29)"
                    ),
                ),
            ):
                p = root / tool
                p.write_text(f"#!{sys.executable}\n" + body + "\n")
                p.chmod(0o755)
            bash = shutil.which("bash")
            assert bash
            for output, code, expected, count in (
                ("/fixture/package", "17", 17, 1),
                ("", "0", 1, 1),
                ("/fixture/package", "0", 29, 2),
            ):
                (root / "commands").unlink(missing_ok=True)
                env = dict(
                    os.environ,
                    PATH=f"{root}:{os.environ['PATH']}",
                    BUILD_OUTPUT=output,
                    BUILD_EXIT=code,
                )
                for key in ("BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS"):
                    env.pop(key, None)
                result = subprocess.run(  # noqa: S603 - actual workflow with owned Nix/sudo
                    [bash, "-e", "-o", "pipefail", "-c", step["run"]],
                    cwd=root,
                    env=env,
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=10,
                )
                assert result.returncode == expected, result.stdout + result.stderr
                calls = [json.loads(line) for line in (root / "commands").read_text().splitlines()]
                assert len(calls) == count
                assert calls[0] == ["build", ".#database-tests", "--no-link", "--print-out-paths"]
                if count == 2:
                    assert calls[1] == [
                        "develop",
                        ".#ci",
                        "--command",
                        "./scripts/tests/run_server_container_integration.sh",
                        "all",
                    ]
