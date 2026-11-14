"""Initial DDL uses owned execution and retains private output on interruption."""

from __future__ import annotations

# ruff: noqa: PT009, PT027 - unittest assertions also work without pytest.
import ast
import importlib.util
import os
import signal
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/validation"))
import database_execution as execution  # noqa: E402 - fixed repository module.


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PrivateDdlTests(unittest.TestCase):
    def setUp(self):
        owner = tempfile.TemporaryDirectory(prefix="aeg-ddl-unit-")
        self.addCleanup(owner.cleanup)
        self.directory = Path(owner.name)
        self.process = load("ddl_current_process", ROOT / "tests/organizations/current_process.py")
        self.fixture = load("ddl_fixture", ROOT / "scripts/tests/subject_ownership_fixture.py")
        self.children = []
        self.real_popen = subprocess.Popen
        self.addCleanup(self.reclaim)

    def reclaim(self):
        for child in self.children:
            execution.stop_process_group(child, grace=0.1)

    def callback(self, run):
        path = ROOT / "tests/organizations/current_runtime.py"
        node = next(
            n
            for n in ast.walk(ast.parse(path.read_text()))
            if isinstance(n, ast.FunctionDef) and n.name == "execute_private"
        )
        namespace = {"run": run}
        exec(compile(ast.Module(body=[node], type_ignores=[]), str(path), "exec"), namespace)  # noqa: S102
        return namespace["execute_private"]

    def test_initial_ddl_uses_injected_private_callback_before_configuration(self):
        seen = []

        def callback(argv, *, data, env, log):
            self.assertTrue((self.directory / "owned-resources.json").is_file())
            self.assertEqual(argv, ["psql", "-X", "-v", "ON_ERROR_STOP=1"])
            self.assertIn("CREATE ROLE", data)
            self.assertNotIn(data, " ".join(argv))
            self.assertEqual(env["PGDATABASE"], "postgres")
            self.assertEqual(log, self.directory / "setup.log")
            seen.append(True)
            return 73

        with (
            mock.patch.object(self.fixture, "execute_private", side_effect=callback),
            mock.patch.object(self.fixture, "configure_database") as configure,
            mock.patch.object(self.fixture.subprocess, "run") as direct,
            self.assertRaisesRegex(RuntimeError, "private log"),
        ):
            self.fixture.prepare_runtime(self.directory, "postgresql://postgres@localhost/postgres")
        self.assertEqual(seen, [True])
        configure.assert_not_called()
        direct.assert_not_called()

    def test_runtime_callback_supplies_private_sink_and_owned_deadline(self):
        run = mock.Mock(return_value=subprocess.CompletedProcess([], 19))
        log = self.directory / "setup.log"
        result = self.callback(run)(
            ["psql", "-X"], data="private DDL", env={"PGUSER": "postgres"}, log=log
        )
        self.assertEqual(result, 19)
        run.assert_called_once_with(
            ["psql", "-X"],
            data="private DDL",
            environment={"PGUSER": "postgres"},
            timeout=180,
            private_log=log,
        )

    def test_owned_private_partial_output_survives_cancel_and_timeout(self):
        for cancel in (False, True):
            with self.subTest(cancel=cancel):
                self.process = load(
                    "ddl_current_process", ROOT / "tests/organizations/current_process.py"
                )
                log = self.directory / f"private-{cancel}.log"
                code = (
                    "import sys,time; print('private stdout',flush=True); "
                    "print('private stderr',file=sys.stderr,flush=True); time.sleep(10)"
                )

                def popen(*args, **kwargs):
                    child = self.real_popen(*args, **kwargs)
                    self.children.append(child)
                    return child

                original_check = self.process.check_cancellation

                def checked(cancel=cancel, log=log, original_check=original_check):
                    if cancel and log.exists() and "private stderr" in log.read_text():
                        self.process.interrupted(signal.SIGTERM, None)
                    original_check()

                with (
                    mock.patch.object(self.process.subprocess, "Popen", side_effect=popen),
                    mock.patch.object(self.process, "check_cancellation", side_effect=checked),
                    self.assertRaises(RuntimeError if cancel else subprocess.TimeoutExpired),
                ):
                    self.process.run_owned(
                        [str(Path("/proc/self/exe").resolve()), "-c", code],
                        root=self.directory,
                        env=dict(os.environ),
                        timeout=2,
                        private_log=log,
                    )
                self.assertIn("private stdout", log.read_text())
                self.assertIn("private stderr", log.read_text())
                self.assertEqual(self.process.unconfirmed_groups(), [])
                self.assertFalse(execution.group_running(self.children[-1].pid))


if __name__ == "__main__":
    unittest.main()
