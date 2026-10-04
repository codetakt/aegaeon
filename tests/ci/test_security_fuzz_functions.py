"""Imported-function controls for both security entrypoints with inert tools."""
# ruff: noqa: PT009 - unittest assertions remain active under Python -O

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

import test_security_fuzz as fixtures

ROOT = Path(__file__).resolve().parents[2]
FUNCTIONS = (
    "python3",
    "cargo",
    "timeout",
    "command",
    "type",
    "builtin",
    "declare",
    "read",
    "readonly",
    "unset",
    "exec",
    "set",
    "exit",
    "cd",
    "pwd",
    "dirname",
    "local",
    "echo",
    "export",
    "break",
    ":",
)


class SecurityFuzzFunctionsTests(unittest.TestCase):
    def fixture(self):
        fixture = fixtures.SecurityFuzzFixture()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        outer = fixture.root / "scripts/flake/security_suite.sh"
        outer.parent.mkdir(parents=True)
        shutil.copyfile(ROOT / "scripts/flake/security_suite.sh", outer)
        outer.chmod(0o755)
        (fixture.root / "scripts/security/run_security_suite.sh").chmod(0o755)
        return fixture

    def run_entry(self, fixture, *, outer=False, arguments=("--stage", "fuzz"), overrides=None):
        script = fixture.root / (
            "scripts/flake/security_suite.sh" if outer else "scripts/security/run_security_suite.sh"
        )
        return subprocess.run(  # noqa: S603 - explicit owned fixture route
            [str(fixture.bin / "bash"), str(script), *arguments],
            cwd=fixture.root,
            env={**fixture.env, "CASE": "ok", **(overrides or {})},
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )

    def test_imported_tools_and_builtins_reject_before_validator_git_or_effects(self):
        for outer in (False, True):
            for arguments in (("--stage", "fuzz"), (), ("--stage", "geiger")):
                for name in FUNCTIONS:
                    with self.subTest(outer=outer, arguments=arguments, function=name):
                        fixture = self.fixture()
                        receipts = fixture.artifacts / "fuzz"
                        receipts.mkdir(parents=True)
                        before = {}
                        for filename in ("collection.ok", "execution.json", "run_summary.json"):
                            before[filename] = b"preserved existing " + filename.encode()
                            (receipts / filename).write_bytes(before[filename])
                        fixture.install(
                            "git",
                            "import os,pathlib\n"
                            "pathlib.Path(os.environ['FIXTURE_ROOT']).parent.joinpath('git-call').write_text('called')\n"
                            "raise SystemExit(19)\n",
                        )
                        result = self.run_entry(
                            fixture,
                            outer=outer,
                            arguments=arguments,
                            overrides={
                                f"BASH_FUNC_{name}%%": (
                                    "() { printf '%s\\n' function-body-secret "
                                    '>> "$FIXTURE_ROOT/../function-call"; return 0; }'
                                )
                            },
                        )
                        self.assertNotEqual(result.returncode, 0)
                        self.assertIn("no inherited shell functions", result.stderr)
                        self.assertNotIn("function-body-secret", result.stdout + result.stderr)
                        owner = Path(fixture.temporary)
                        for filename in (
                            "git-call",
                            "function-call",
                            "calls.jsonl",
                            "cargo-home",
                            "target",
                        ):
                            self.assertFalse((owner / filename).exists(), filename)
                        self.assertEqual(
                            {p.name: p.read_bytes() for p in receipts.iterdir()}, before
                        )
                        self.assertEqual(list(fixture.artifacts.iterdir()), [receipts])

    def test_external_tools_keep_full_default_fuzz_inventory_on_both_routes(self):
        for outer in (False, True):
            with self.subTest(outer=outer):
                fixture = self.fixture()
                result = self.run_entry(fixture, outer=outer)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                summary = fixture.summary()
                self.assertEqual(summary["execution"]["selected_targets"], list(fixtures.TARGETS))
                self.assertTrue((fixture.artifacts / "fuzz/collection.ok").is_file())

    def test_outer_preserves_fuzz_long_selection_and_arguments(self):
        fixture = self.fixture()
        targets = "fuzz_bearer_token fuzz_pkce_verifier"
        result = self.run_entry(
            fixture,
            outer=True,
            arguments=("--fuzz-long", "--stage", "fuzz", "--", "preserved-trailing-argument"),
            overrides={"FUZZ_TARGETS": targets},
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        calls = [
            json.loads(line)
            for line in (Path(fixture.temporary) / "calls.jsonl").read_text().splitlines()
        ]
        runs = [args for args in calls if args[:2] == ["fuzz", "run"]]
        self.assertEqual(len(runs), 2)
        self.assertTrue(all(args[-1] == "-max_total_time=300" for args in runs))
        self.assertEqual(fixture.summary()["execution"]["selected_targets"], targets.split())

    def test_explicit_nonfuzz_preserves_ordinary_external_tools(self):
        for outer in (False, True):
            with self.subTest(outer=outer):
                fixture = self.fixture()
                result = self.run_entry(
                    fixture,
                    outer=outer,
                    arguments=("--stage", "geiger"),
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertFalse((fixture.artifacts / "fuzz").exists())

    def test_bootstrap_preserves_relative_and_empty_path_entries(self):
        fixture = self.fixture()
        first = Path(fixture.temporary) / "nonexecuting-bin"
        first.mkdir()
        (first / "python3").write_text("unselected nonexecutable fixture\n")
        result = self.run_entry(
            fixture,
            overrides={"PATH": ":../nonexecuting-bin:../bin:"},
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(fixture.summary()["execution"]["selected_targets"], list(fixtures.TARGETS))

    def test_imported_cd_or_export_cannot_promote_nonfuzz_into_fuzz(self):
        for outer in (False, True):
            for name in ("cd", "export"):
                with self.subTest(outer=outer, function=name):
                    fixture = self.fixture()
                    receipts = fixture.artifacts / "fuzz"
                    receipts.mkdir(parents=True)
                    marker = receipts / "collection.ok"
                    marker.write_bytes(b"preserved previous receipt\n")
                    result = self.run_entry(
                        fixture,
                        outer=outer,
                        arguments=("--stage", "geiger"),
                        overrides={
                            f"BASH_FUNC_{name}%%": (
                                f'() {{ SECURITY_STAGES=(fuzz); builtin {name} "$@"; }}'
                            )
                        },
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("no inherited shell functions", result.stderr)
                    self.assertFalse((Path(fixture.temporary) / "calls.jsonl").exists())
                    self.assertEqual(marker.read_bytes(), b"preserved previous receipt\n")
                    self.assertEqual(list(receipts.iterdir()), [marker])
                    self.assertEqual(list(fixture.artifacts.iterdir()), [receipts])

    def test_bootstrap_isolated_python_ignores_startup_environment(self):
        for outer in (False, True):
            with self.subTest(outer=outer):
                fixture = self.fixture()
                imports = Path(fixture.temporary) / "startup-imports"
                imports.mkdir()
                marker = Path(fixture.temporary) / "python-startup-called"
                (imports / "sitecustomize.py").write_text(
                    f"from pathlib import Path\nPath({str(marker)!r}).write_text('called')\n"
                )
                result = self.run_entry(
                    fixture,
                    outer=outer,
                    arguments=("--stage", "geiger"),
                    overrides={
                        "PYTHONPATH": str(imports),
                        "PYTHONHOME": str(Path(fixture.temporary) / "absent-python-home"),
                        "BASH_FUNC_set%%": "() { return 0; }",
                    },
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("no inherited shell functions", result.stderr)
                self.assertFalse(marker.exists())
                self.assertFalse(fixture.artifacts.exists())
                self.assertFalse((Path(fixture.temporary) / "calls.jsonl").exists())

    def shell_python(self, fixture, command="exec"):
        wrapper = fixture.bin / "python3"
        wrapper.unlink()
        if command != "exec":
            (fixture.bin / command).symlink_to(sys.executable)
        marker = Path(fixture.temporary) / "python-wrapper-started"
        wrapper.write_text(
            f"#!{(fixture.bin / 'bash').resolve()}\n"
            f"wrapper_started=1 > {str(marker)!r}\n"
            f'{command} {sys.executable if command == "exec" else ""} "$@"\n'
        )
        wrapper.chmod(0o755)
        return marker

    def test_shell_backed_python_rejects_exec_before_wrapper_or_effects(self):
        for outer in (False, True):
            for arguments in (("--stage", "fuzz"), (), ("--stage", "geiger")):
                with self.subTest(outer=outer, arguments=arguments):
                    fixture = self.fixture()
                    receipts = fixture.artifacts / "fuzz"
                    receipts.mkdir(parents=True)
                    before = {
                        name: b"previous " + name.encode()
                        for name in ("collection.ok", "execution.json", "run_summary.json")
                    }
                    for name, raw in before.items():
                        (receipts / name).write_bytes(raw)
                    wrapper_marker = self.shell_python(fixture)
                    result = self.run_entry(
                        fixture,
                        outer=outer,
                        arguments=arguments,
                        overrides={
                            "BASH_FUNC_exec%%": (
                                '() { function_called=1 > "$FIXTURE_ROOT/../function-call";'
                                " return 0; }"
                            )
                        },
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("no inherited shell functions", result.stderr)
                    self.assertFalse(wrapper_marker.exists())
                    self.assertFalse((Path(fixture.temporary) / "function-call").exists())
                    self.assertFalse((Path(fixture.temporary) / "calls.jsonl").exists())
                    self.assertEqual({p.name: p.read_bytes() for p in receipts.iterdir()}, before)
                    self.assertEqual(list(fixture.artifacts.iterdir()), [receipts])

    def test_posix_skipped_raw_keys_cannot_execute_in_shell_python(self):
        for outer in (False, True):
            for name in ("exec", "readonly", "builtin", "python-route", "if", "a/b", "malformed"):
                with self.subTest(outer=outer, name=name):
                    fixture = self.fixture()
                    self.shell_python(fixture, "python-route")
                    script = fixture.root / (
                        "scripts/flake/security_suite.sh"
                        if outer
                        else "scripts/security/run_security_suite.sh"
                    )
                    body = (
                        '() { function_called=1 > "$FIXTURE_ROOT/../function-call"; return 0; }'
                        if name != "malformed"
                        else "not a function"
                    )
                    result = subprocess.run(  # noqa: S603 - owned fixture and manufactured environment
                        [str(fixture.bin / "bash"), "--posix", str(script), "--stage", "geiger"],
                        cwd=fixture.root,
                        env={**fixture.env, f"BASH_FUNC_{name}%%": body},
                        capture_output=True,
                        text=True,
                        check=False,
                        timeout=30,
                    )
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertFalse((Path(fixture.temporary) / "function-call").exists())
                    self.assertFalse((Path(fixture.temporary) / "calls.jsonl").exists())
                    self.assertFalse(fixture.artifacts.exists())

    def test_bootstrap_restores_parent_posix_value_presence_export_and_option(self):
        for outer in (False, True):
            for mode in ([], ["--posix"], ["+o", "posix"]):
                for value in (None, "", "caller-value"):
                    with self.subTest(outer=outer, mode=mode, value=value):
                        fixture = self.fixture()
                        self.shell_python(fixture)
                        script = fixture.root / (
                            "scripts/flake/security_suite.sh"
                            if outer
                            else "scripts/security/run_security_suite.sh"
                        )
                        bootstrap = script.read_text().split("\nset -euo pipefail\n", 1)[0]
                        observation = (
                            'builtin printf "%s\\n" "$SHELLOPTS"\n'
                            "if [[ -v POSIXLY_CORRECT ]]; then\n"
                            " builtin declare -p POSIXLY_CORRECT\n"
                            'else builtin printf "%s\\n" absent; fi\n'
                            f"{sys.executable} -I -c 'import os; "
                            'print(repr(os.environ.get("POSIXLY_CORRECT")))\'\n'
                        )
                        baseline = fixture.root.parent / "baseline.sh"
                        candidate = fixture.root.parent / "bootstrap.sh"
                        baseline.write_text(observation)
                        candidate.write_text(bootstrap + "\n" + observation)
                        environment = dict(fixture.env)
                        environment.pop("POSIXLY_CORRECT", None)
                        if value is not None:
                            environment["POSIXLY_CORRECT"] = value
                        results = [
                            subprocess.run(  # noqa: S603 - owned fixture scripts
                                [str(fixture.bin / "bash"), *mode, str(path)],
                                cwd=fixture.root,
                                env=environment,
                                capture_output=True,
                                text=True,
                                check=False,
                                timeout=30,
                            )
                            for path in (baseline, candidate)
                        ]
                        self.assertEqual(results[0].returncode, 0, results[0].stderr)
                        self.assertEqual(results[1].returncode, 0, results[1].stderr)
                        self.assertEqual(results[0].stdout, results[1].stdout)

    def test_shell_backed_python_preserves_ordinary_nonfuzz_execution(self):
        for outer in (False, True):
            with self.subTest(outer=outer):
                fixture = self.fixture()
                marker = self.shell_python(fixture)
                result = self.run_entry(fixture, outer=outer, arguments=("--stage", "geiger"))
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertTrue(marker.exists())
                self.assertFalse((fixture.artifacts / "fuzz").exists())
