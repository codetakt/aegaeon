"""Preserve database selection, serial execution and service-backed test failures."""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import pytest
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
            # Added ownership preflight uses the same compiled package and
            # nonzero-execution guard as the original four runtime selections.
            (["pre_migration_", "--lib"], [], "aegaeon_server", ["pre_migration_"]),
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
            for selection in ([], ["pre_migration_"]):
                result = subprocess.run(  # noqa: S603 - actual guard and owned fixture
                    [
                        bash,
                        str(scripts / "run_required_cargo_test.sh"),
                        "-p",
                        "aegaeon-server",
                        *selection,
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

    def namespace_driver(self, filename):
        spec = importlib.util.spec_from_file_location(
            filename.removesuffix(".py"), ROOT / "scripts/validation" / filename
        )
        assert spec
        assert spec.loader
        driver = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(driver)
        return driver

    def namespace_main(self, filename, *, compiled=True, listing="selected: test\n", build_code=0):
        driver = self.namespace_driver(filename)
        package = self.root / "output"
        binary = str(package / "libexec/aegaeon_server") if compiled else "/original/server-test"
        arguments = [filename, "--sudo-netns"]
        if compiled:
            arguments += ["--compiled-package", str(package)]
        listing_results = [listing]
        if "fingerprint" in filename:
            listing_results.insert(0, "Redis server v=7.2.0\n")
        build_message = json.dumps(
            {
                "reason": "compiler-artifact",
                "target": {"name": "aegaeon_server"},
                "executable": binary,
            }
        )
        with (
            patch.object(sys, "argv", arguments),
            patch.object(sys, "path", [str(ROOT / "scripts/validation"), *sys.path]),
            patch.object(sys, "platform", "linux"),
            patch.object(driver.shutil, "which", side_effect=lambda x: f"/tools/{x}"),
            patch.object(driver.os, "getuid", return_value=1000),
            patch.object(driver.os, "geteuid", return_value=1000),
            patch.object(driver.os, "getgid", return_value=100),
            patch.object(driver.os, "readlink", return_value="net:[parent]"),
            patch.object(driver.subprocess, "check_output", side_effect=listing_results) as listed,
            patch.object(driver.subprocess, "run") as run,
        ):
            launched = subprocess.CompletedProcess([], 37)
            run.side_effect = (
                [launched]
                if compiled
                else [subprocess.CompletedProcess([], build_code, build_message), launched]
            )
            result = driver.main()
        return result, run.call_args_list, listed.call_args_list, binary

    def test_namespace_package_preserves_selection_identity_and_failure(self):
        assert self.install().returncode == 0
        for filename in ("test_client_jwks_cache.py", "test_jwks_fingerprint_ledger.py"):
            with self.subTest(driver=filename):
                result, calls, listings, binary = self.namespace_main(filename)
                assert result == 37
                assert len(calls) == 1  # No Cargo compilation before the fresh namespace.
                command = calls[0].args[0]
                assert calls[0].kwargs == {"cwd": ROOT, "check": False}
                assert command[0] == "/tools/sudo"
                assert "/tools/unshare" in command
                assert "--net" in command
                start = command.index("--inside")
                assert command[start + 1 : start + 3] == [binary, "net:[parent]"]
                identity = "--run-as" if "fingerprint" in filename else "--drop-identity"
                start = command.index(identity)
                assert command[start + 1 : start + 3] == ["1000", "100"]
                expected_filter = (
                    "client_registry::jwks_runtime_state::redis_kid::"
                    if "fingerprint" in filename
                    else "client_registry::jwks_"
                )
                assert command[command.index("--filter") + 1] == expected_filter
                expected = [binary, expected_filter]
                if "fingerprint" not in filename:
                    expected += [
                        "--include-ignored",
                        "--skip",
                        "client_registry::jwks_runtime_state::redis_kid::",
                    ]
                assert listings[-1].args[0] == [*expected, "--list"]

    def test_namespace_default_build_and_build_failure_are_retained(self):
        for filename in ("test_client_jwks_cache.py", "test_jwks_fingerprint_ledger.py"):
            for status in (0, 61):
                with self.subTest(driver=filename, status=status):
                    result, calls, listings, _ = self.namespace_main(
                        filename, compiled=False, build_code=status
                    )
                    assert result == (37 if status == 0 else 61)
                    assert len(calls) == (2 if status == 0 else 1)
                    assert calls[0].args[0][1:] == [
                        "test",
                        "--locked",
                        "-p",
                        "aegaeon-server",
                        "--lib",
                        "--no-run",
                        "--message-format=json",
                    ]
                    if status:
                        assert len(listings) == int("fingerprint" in filename)

    def test_namespace_rejects_modified_package_and_empty_selection(self):
        for filename in ("test_client_jwks_cache.py", "test_jwks_fingerprint_ledger.py"):
            with self.subTest(driver=filename):
                assert self.install().returncode == 0
                with pytest.raises(RuntimeError, match="selected no tests"):
                    self.namespace_main(filename, listing="0 tests, 0 benchmarks\n")
                (self.root / "output/libexec/aegaeon_server").write_text("changed")
                with pytest.raises(ValueError, match="does not match"):
                    self.namespace_main(filename)


class DatabaseWorkflowTests(unittest.TestCase):
    def test_namespace_steps_require_the_same_compiled_package(self):
        workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
        steps = workflow["jobs"]["db-integration"]["steps"]
        build = next(s for s in steps if s["name"] == "Run DB-gated ignored integration tests")
        assert build["id"] == "database-tests"
        for script in ("test_client_jwks_cache.py", "test_jwks_fingerprint_ledger.py"):
            step = next(s for s in steps if script in s.get("run", ""))
            assert (
                step["env"]["DATABASE_TEST_PACKAGE"]
                == "${{ steps.database-tests.outputs.package }}"
            )
            assert 'test -n "$DATABASE_TEST_PACKAGE"' in step["run"]
            assert '--sudo-netns --compiled-package "$DATABASE_TEST_PACKAGE"' in step["run"]
            assert "if" not in step
            assert not step.get("continue-on-error", False)

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
                    GITHUB_OUTPUT=str(root / "step-output"),
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
                    assert (root / "step-output").read_text() == "package=/fixture/package\n"
                    assert calls[1] == [
                        "develop",
                        ".#ci",
                        "--command",
                        "./scripts/tests/run_server_container_integration.sh",
                        "all",
                    ]
