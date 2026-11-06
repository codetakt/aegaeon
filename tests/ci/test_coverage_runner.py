"""Coverage attempts retain workspace execution, database ownership and failures."""

from __future__ import annotations

# ruff: noqa: PT009, PT027 - run under unittest discovery and Python -O.
import json
import os
import runpy
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class CoverageRunnerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        for name in ("scripts/ci", "scripts/tests", "tests/docker", "bin"):
            (self.root / name).mkdir(parents=True)
        shutil.copy(ROOT / "scripts/ci/run_coverage.py", self.root / "scripts/ci/run_coverage.py")
        shutil.copy(
            ROOT / "tests/docker/docker-compose.yml", self.root / "tests/docker/docker-compose.yml"
        )
        fake = (
            "#!"
            + sys.executable
            + "\n"
            + r"""
import json, os, pathlib, shutil, sys
root = pathlib.Path.cwd()
name = pathlib.Path(sys.argv[0]).name
args = sys.argv[1:]
with (root / 'calls.jsonl').open('a') as stream:
    row = {'name': name, 'args': args, 'target': os.environ['CARGO_TARGET_DIR']}
    stream.write(json.dumps(row) + '\n')
target = pathlib.Path(os.environ['CARGO_TARGET_DIR'])
if name == 'cargo':
    if args == ['llvm-cov', 'clean', '--workspace']:
        if os.environ.get('INITIAL_CLEAN_FAIL'): sys.exit(43)
        shutil.rmtree(target / 'llvm-cov-target', ignore_errors=True)
    elif args == ['llvm-cov', '--workspace', '--no-report']:
        (target / 'llvm-cov-target').mkdir(parents=True)
        (target / 'llvm-cov-target/unit.profraw').write_text('fresh unit result')
        if os.environ.get('UNIT_FAIL'): sys.exit(17)
    elif args == ['llvm-cov', 'show-env', '--export-prefix']:
        if os.environ.get('SHOW_ENV_FAIL'): sys.exit(19)
        assert (target / 'unit.profraw').is_file()
        print('export CARGO_LLVM_COV=1')
        print('export LLVM_PROFILE_FILE=' + str(target / 'database.profraw'))
    elif args == ['llvm-cov', 'report', '--lcov', '--output-path', 'lcov.info']:
        if os.environ.get('REPORT_FAIL'): sys.exit(41)
        assert (target / 'llvm-cov-target/unit.profraw').is_file()
        hit = 50 if (target / 'llvm-cov-target/database.profraw').is_file() else 37
        (root / 'lcov.info').write_text('LF:100\nLH:' + str(hit) + '\n')
    else: raise AssertionError(args)
elif name == 'docker':
    if args[0] == 'compose':
        config = json.loads(pathlib.Path(args[args.index('-f') + 1]).read_text())
        assert set(config['services']) == {'postgres', 'redis'}
        for service in config['services'].values():
            assert 'container_name' not in service
            assert service['ports'][0]['published'] == '0'
        action = args[args.index('-f') + 2:]
        if action == ['up', '-d']:
            (root / 'suppliers').touch()
        elif action[0] == 'port':
            print('0.0.0.0:5432' if os.environ.get('BAD_PORT') else '127.0.0.1:15432')
        elif action == ['down', '--volumes', '--remove-orphans', '--timeout', '10']:
            if os.environ.get('CLEANUP_FAIL'): sys.exit(23)
            (root / 'suppliers').unlink()
        else: raise AssertionError(action)
    elif os.environ.get('REMAINING_SUPPLIER'):
        print('owned resource remains')
else: raise AssertionError(name)
"""
        )
        for name in ("cargo", "docker"):
            executable = self.root / "bin" / name
            executable.write_text(fake)
            executable.chmod(0o755)
        (self.root / "scripts/tests/run_server_container_integration.sh").write_text(
            r"""set -euo pipefail
test "$1" = all
test "$CARGO_LLVM_COV" = 1
test "$AEGAEON_SERVER_CONTAINER_SKIP_UP" = 1
test "$AEGAEON_SERVER_CONTAINER_DOWN" = 0
test -f "$CARGO_TARGET_DIR/unit.profraw"
test "$DATABASE_URL" = "$AEGAEON_DATABASE_URL"
test "$AEGAEON_TEST_ADMIN_DATABASE_URL" = "$AEGAEON_DATABASE_URL"
test "$AEGAEON_TEST_REDIS_URL" = redis://127.0.0.1:15432/0
if [ "${DB_FAIL:-0}" = 1 ]; then exit 29; fi
printf 'fresh database result\n' > "$LLVM_PROFILE_FILE"
"""
        )
        self.environment = {
            **os.environ,
            "PATH": str(self.root / "bin") + os.pathsep + os.environ["PATH"],
            "CARGO_TARGET_DIR": str(self.root / "target/coverage"),
        }
        for name in (
            "AEGAEON_DATABASE_TEST_PACKAGE",
            "AEGAEON_RFC_TEST_PACKAGE",
            "JOSE_SERVER_TEST_PACKAGE",
        ):
            self.environment.pop(name, None)

    def run_fixture(self, **values):
        return subprocess.run(  # noqa: S603 - actual runner and owned fake supplier commands
            [sys.executable, str(self.root / "scripts/ci/run_coverage.py")],
            cwd=self.root,
            env=self.environment | values,
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )

    def test_workspace_and_database_profiles_share_one_report_after_cleanup(self):
        result = self.run_fixture()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((self.root / "lcov.info").read_text(), "LF:100\nLH:50\n")
        self.assertFalse((self.root / "suppliers").exists())
        calls = [json.loads(line) for line in (self.root / "calls.jsonl").read_text().splitlines()]
        self.assertEqual(calls[0]["args"], ["llvm-cov", "clean", "--workspace"])
        self.assertEqual(calls[1]["args"], ["llvm-cov", "--workspace", "--no-report"])
        self.assertEqual(
            calls[-1]["args"], ["llvm-cov", "report", "--lcov", "--output-path", "lcov.info"]
        )

    def test_database_failure_retains_partial_report_but_rejects_attempt(self):
        stale = Path(self.environment["CARGO_TARGET_DIR"]) / "llvm-cov-target/database.profraw"
        stale.parent.mkdir(parents=True)
        stale.write_text("stale database counters from an earlier attempt")
        result = self.run_fixture(DB_FAIL="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("29", result.stderr)
        self.assertFalse((self.root / "suppliers").exists())
        self.assertEqual((self.root / "lcov.info").read_text(), "LF:100\nLH:37\n")

    def test_initial_cleanup_failure_cannot_execute_or_report_stale_counters(self):
        (self.root / "lcov.info").write_text("stale coverage from an earlier attempt")
        result = self.run_fixture(INITIAL_CLEAN_FAIL="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("returned non-zero exit status 43", result.stderr)
        self.assertFalse((self.root / "suppliers").exists())
        self.assertFalse((self.root / "lcov.info").exists())
        calls = [json.loads(line) for line in (self.root / "calls.jsonl").read_text().splitlines()]
        self.assertEqual([row["args"] for row in calls], [["llvm-cov", "clean", "--workspace"]])

    def test_workspace_failure_cannot_start_suppliers_or_be_replaced_by_database(self):
        (self.root / "lcov.info").write_text("stale coverage from an earlier attempt")
        result = self.run_fixture(UNIT_FAIL="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("returned non-zero exit status 17", result.stderr)
        self.assertFalse((self.root / "suppliers").exists())
        self.assertEqual((self.root / "lcov.info").read_text(), "LF:100\nLH:37\n")
        calls = [json.loads(line) for line in (self.root / "calls.jsonl").read_text().splitlines()]
        self.assertEqual([row["name"] for row in calls], ["cargo", "cargo", "cargo"])
        self.assertEqual(calls[-1]["args"][1], "report")

    def test_report_failure_preserves_the_original_workspace_failure(self):
        result = self.run_fixture(UNIT_FAIL="1", REPORT_FAIL="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("returned non-zero exit status 17", result.stderr)
        self.assertIn("Partial coverage report also failed:", result.stderr)
        self.assertIn("returned non-zero exit status 41", result.stderr)
        self.assertFalse((self.root / "lcov.info").exists())
        self.assertFalse((self.root / "suppliers").exists())

    def test_report_failure_after_passing_tests_rejects_attempt(self):
        result = self.run_fixture(REPORT_FAIL="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("returned non-zero exit status 41", result.stderr)
        self.assertFalse((self.root / "lcov.info").exists())
        self.assertFalse((self.root / "suppliers").exists())

    def test_external_supplier_address_is_refused_and_cleaned(self):
        result = self.run_fixture(BAD_PORT="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("owned loopback port", result.stderr)
        self.assertFalse((self.root / "suppliers").exists())

    def test_instrumentation_setup_failure_cannot_claim_database_coverage(self):
        result = self.run_fixture(SHOW_ENV_FAIL="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "suppliers").exists())
        self.assertEqual((self.root / "lcov.info").read_text(), "LF:100\nLH:37\n")

    def test_cleanup_failure_is_not_overridden_by_passing_report(self):
        result = self.run_fixture(CLEANUP_FAIL="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("23", result.stderr)
        self.assertEqual((self.root / "lcov.info").read_text(), "LF:100\nLH:50\n")

    def test_remaining_owned_resource_fails_after_successful_down(self):
        result = self.run_fixture(REMAINING_SUPPLIER="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("cleanup is incomplete", result.stderr)

    def test_uninstrumented_package_refused_before_any_execution(self):
        for name in (
            "AEGAEON_DATABASE_TEST_PACKAGE",
            "AEGAEON_RFC_TEST_PACKAGE",
            "JOSE_SERVER_TEST_PACKAGE",
        ):
            with self.subTest(name=name):
                result = self.run_fixture(**{name: "/unrelated/test-package"})
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("separately compiled test package", result.stderr)
                self.assertFalse((self.root / "calls.jsonl").exists())

    def test_foreign_profile_attempt_is_refused_before_execution(self):
        result = self.run_fixture(LLVM_PROFILE_FILE="/unrelated/attempt.profraw")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("another instrumentation attempt", result.stderr)
        self.assertFalse((self.root / "calls.jsonl").exists())

    def test_cancelled_command_stops_its_owned_process(self):
        runner = runpy.run_path(str(self.root / "scripts/ci/run_coverage.py"))
        cancelled = threading.Event()
        timer = threading.Timer(0.5, cancelled.set)
        timer.start()
        self.addCleanup(timer.join)
        pid_file = self.root / "child.pid"
        child = (
            "import os, pathlib, time; "
            "pathlib.Path('child.pid').write_text(str(os.getpid())); time.sleep(60)"
        )
        with self.assertRaises(InterruptedError):
            runner["command"]([sys.executable, "-c", child], self.environment, cancelled, 30)
        with self.assertRaises(ProcessLookupError):
            os.kill(int(pid_file.read_text()), 0)

    def test_deadline_stops_its_owned_process(self):
        runner = runpy.run_path(str(self.root / "scripts/ci/run_coverage.py"))
        pid_file = self.root / "child.pid"
        child = (
            "import os, pathlib, time; "
            "pathlib.Path('child.pid').write_text(str(os.getpid())); time.sleep(60)"
        )
        with self.assertRaises(TimeoutError):
            runner["command"]([sys.executable, "-c", child], self.environment, threading.Event(), 1)
        with self.assertRaises(ProcessLookupError):
            os.kill(int(pid_file.read_text()), 0)


if __name__ == "__main__":
    unittest.main()
