# ruff: noqa: PT009 - directed unittest assertions remain active with Python -O
"""Selected interpreter/log opener composition with inert sanitizer observers."""

from __future__ import annotations

import json
import shlex
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_sanitizer_dispatch as dispatch

ROOT = Path(__file__).resolve().parents[2]


class SanitizerInterpreterCompositionTests(unittest.TestCase):
    # Reuse fixture construction, not the existing test suite.
    fixture = dispatch.SanitizerDispatchTests.fixture
    calls = dispatch.SanitizerDispatchTests.calls
    receipt = dispatch.SanitizerDispatchTests.receipt

    def selected_interpreter(self, fixture, entry):
        fixture.install(
            "git",
            "import os,sys\n"
            "if sys.argv[1:] == ['rev-parse', '--show-toplevel']:\n"
            " print(os.environ['FIXTURE_ROOT'])\n"
            "else: raise SystemExit(128)\n",
        )
        caller = fixture.root / "caller"
        caller.mkdir()
        directory = caller if entry == "" else caller / entry
        directory.mkdir(exist_ok=True)
        shadow_directory = fixture.root if entry == "" else fixture.root / entry
        shadow_directory.mkdir(exist_ok=True)
        log = Path(fixture.temporary) / "selected-python.jsonl"
        shadow = Path(fixture.temporary) / "shadow-python-called"
        bash = (fixture.bin / "bash").resolve()
        logger = (
            "import json,sys; from pathlib import Path; "
            "Path(sys.argv[1]).open('a').write(json.dumps(sys.argv[2:])+'\\n')"
        )
        selected = directory / "python3"
        selected.write_text(
            f"#!{bash}\n"
            f"{shlex.quote(sys.executable)} -I -c {shlex.quote(logger)} "
            f'{shlex.quote(str(log))} "$@"\n'
            # Preserve the original binding/cleanup/failure observer shim.
            f'exec {shlex.quote(str(fixture.bin / "python3"))} "$@"\n'
        )
        selected.chmod(0o755)
        trap = shadow_directory / "python3"
        trap.write_text(f"#!{bash}\nshadow=1 > {shlex.quote(str(shadow))}\nexit 87\n")
        trap.chmod(0o755)
        outer = fixture.root / "scripts/flake/security_suite.sh"
        outer.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / "scripts/flake/security_suite.sh", outer)
        outer.chmod(0o755)
        (fixture.root / "scripts/security/run_security_suite.sh").chmod(0o755)
        return caller, f"{entry}:{fixture.bin}", log, shadow

    def run_composed(self, fixture, entry, outer, **environment):
        caller, path, log, shadow = self.selected_interpreter(fixture, entry)
        script = fixture.root / (
            "scripts/flake/security_suite.sh" if outer else "scripts/security/run_security_suite.sh"
        )
        result = subprocess.run(  # noqa: S603 - owned exact wrappers/tools and fabricated env
            [str(fixture.bin / "bash"), str(script), "--stage", "sanitizers"],
            cwd=caller,
            env={**fixture.env, "CASE": "ok", "PATH": path, **environment},
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        self.assertFalse(shadow.exists(), result.stdout + result.stderr)
        calls = [json.loads(line) for line in log.read_text().splitlines()]
        self.assertTrue(all(call[0] == "-I" for call in calls))
        operations = [
            call[2]
            for call in calls
            if len(call) > 2 and call[1].endswith("/scripts/sanitizers/open_security_log.py")
        ]
        bootstrap = [call for call in calls if call[1] == "-c" and "BASH_FUNC_" in call[2]]
        return result, operations, len(bootstrap)

    def prepared_target(self, fixture):
        target = fixture.root / "target/sanitizers"
        target.mkdir(parents=True)
        (target / "prepared-sentinel").write_bytes(b"owned prepared output")
        return target

    def test_selected_python_validates_invalid_fd_with_relative_empty_direct_outer_paths(self):
        for entry in ("bin", ""):
            for outer in (False, True):
                with self.subTest(entry=entry, outer=outer):
                    fixture = self.fixture()
                    target = self.prepared_target(fixture)
                    result, operations, bootstraps = self.run_composed(
                        fixture, entry, outer, SANITIZER_SECURITY_LOG_FD="99999"
                    )
                    self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                    self.assertEqual(operations, ["validate"])
                    self.assertEqual(bootstraps, 2 if outer else 1)
                    self.assertEqual(self.calls(fixture, "sanitizer"), [])
                    self.assertEqual(len(self.calls(fixture, "cleanup")), 1)
                    self.assertFalse(target.exists())
                    summary = json.loads(
                        (fixture.artifacts / "sanitizers/run-summary.json").read_text()
                    )
                    self.assertEqual(summary["exit_code"], 1)
                    self.assertEqual(summary["cleanup_exit_code"], 0)

    def test_selected_python_recovers_bound_opener_alias_with_relative_empty_direct_outer_paths(
        self,
    ):
        for entry in ("bin", ""):
            for outer in (False, True):
                with self.subTest(entry=entry, outer=outer):
                    fixture = self.fixture()
                    target = self.prepared_target(fixture)
                    external = Path(fixture.temporary) / "external-log"
                    external.write_bytes(b"preserve external log")
                    result, operations, bootstraps = self.run_composed(
                        fixture, entry, outer, SANITIZER_OPENER_LOG_SYMLINK=str(external)
                    )
                    self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                    self.assertEqual(operations, ["open-exec-bound"])
                    self.assertEqual(bootstraps, 2 if outer else 1)
                    self.assertEqual(self.calls(fixture, "sanitizer"), [])
                    self.assertEqual(len(self.calls(fixture, "cleanup")), 1)
                    self.assertFalse(target.exists())
                    self.assertEqual(external.read_bytes(), b"preserve external log")
                    summary = json.loads(
                        (fixture.artifacts / "sanitizers/run-summary.json").read_text()
                    )
                    self.assertEqual(summary["exit_code"], 1)
                    self.assertEqual(summary["cleanup_exit_code"], 0)

    def test_selected_python_reexec_preserves_success_with_relative_empty_direct_outer_paths(self):
        for entry in ("bin", ""):
            for outer in (False, True):
                with self.subTest(entry=entry, outer=outer):
                    fixture = self.fixture()
                    target = self.prepared_target(fixture)
                    result, operations, bootstraps = self.run_composed(fixture, entry, outer)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertEqual(operations, ["open-exec-bound", "validate"])
                    self.assertEqual(bootstraps, 3 if outer else 2)
                    self.assertEqual(len(self.calls(fixture, "sanitizer")), 1)
                    self.assertEqual(len(self.calls(fixture, "cleanup")), 1)
                    self.assertFalse(target.exists())
                    self.assertEqual(self.receipt(fixture)["exit_code"], 0)
                    self.assertTrue((fixture.artifacts / "sanitizers/run-summary.json").is_file())


if __name__ == "__main__":
    unittest.main()
