# ruff: noqa: PT009 - these controls run under unittest discovery
# ruff: noqa: S603 - all subprocess inputs are generated inert fixture programs
"""Exercise the security-only Nix entry wrapper with an inert Bash dispatch."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class SecurityAppLauncherTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        bash = shutil.which("bash")
        nix = shutil.which("nix")
        self.assertIsNotNone(bash)
        self.assertIsNotNone(nix)
        if bash is None or nix is None:
            self.fail("The supported test environment requires Bash and Nix")
        self.bash = bash
        self.nix = nix
        self.python = str(Path(sys.executable).resolve())
        self.record = self.directory / "record.py"
        self.record.write_text(
            "import json, os, sys\n"
            "print(json.dumps({'argv': [os.fsencode(a).hex() for a in sys.argv[1:]], "
            "'path': os.environ['PATH'], 'value': os.environ['AEG_FIXTURE_VALUE'], "
            "'raw': os.environb[b'AEG_FIXTURE_RAW'].hex()}))\n"
        )
        dispatch_root = self.directory / "dispatch"
        (dispatch_root / "bin").mkdir(parents=True)
        self.dispatch = dispatch_root / "bin" / "aegaeon-security"
        self.dispatch.write_text(
            f"#!{self.bash}\n"
            "set -o errexit\nset -o nounset\nset -o pipefail\n"
            'export PATH="/inert/runtime-one/bin:/inert/runtime-two/bin:$PATH"\n'
            f'exec {self.python} -I {self.record} "$@"\n'
        )
        # Evaluate the actual module with pure inert constructors: no builds,
        # flake resolution, package closure, or real security tools are needed.
        expression = """
          import MODULE {
            lib.unique = inputs: inputs;
            pkgs = {
              python3 = PYTHON;
              runtimeShell = BASH;
              bash = "/inert/bash-package";
              writeShellApplication = args: DISPATCH;
              writeTextFile = args: args;
            };
            name = "aegaeon-security";
            runtimeInputs = [ "/inert/runtime-one" "/inert/runtime-two" ];
            nativePkgConfigPath = "/inert/native/lib/pkgconfig";
            script = /inert/outer.sh;
          }
        """
        for key, value in {
            "MODULE": str(ROOT / "nix/flake/security-launcher.nix"),
            "PYTHON": str(Path(self.python).parent.parent),
            "BASH": self.bash,
            "DISPATCH": str(dispatch_root),
        }.items():
            expression = expression.replace(key, json.dumps(value))
        result = subprocess.run(
            [
                self.nix,
                "--extra-experimental-features",
                "nix-command",
                "eval",
                "--offline",
                "--impure",
                "--json",
                "--expr",
                expression,
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        self.launcher = self.directory / "entry"
        self.launcher.write_text(json.loads(result.stdout)["text"])
        self.launcher.chmod(0o755)

    def environment(self) -> dict[bytes, bytes]:
        return {
            b"PATH": b"/inert/inherited-path",
            b"AEG_FIXTURE_VALUE": b"fixture value with spaces",
            b"AEG_FIXTURE_RAW": b"\xff\xfe",
        }

    def test_inherited_functions_reject_before_bash_dispatch(self) -> None:
        for function in (b"set", b"export", b"exec", b"unused"):
            with self.subTest(function=function):
                environment = self.environment()
                environment[b"BASH_FUNC_" + function + b"%%"] = (
                    b'() { builtin printf "INERT_FUNCTION_BODY_SHOULD_NOT_RUN\\n"; }'
                )
                result = subprocess.run(
                    [str(self.launcher), "--stage", "geiger"],
                    env=environment,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stdout, b"")
                self.assertEqual(
                    result.stderr,
                    b"[security] inherited Bash functions are not supported\n",
                )

    def test_dispatch_preserves_missing_empty_and_present_path(self) -> None:
        arguments = [b"--stage", b"geiger", b"", b"space and quote'", b"line\nbreak", b"\xff"]
        for path in (None, b"", b"/inert/inherited-path"):
            with self.subTest(path=path):
                environment = self.environment()
                if path is None:
                    del environment[b"PATH"]
                else:
                    environment[b"PATH"] = path
                expected = subprocess.run(
                    [self.bash, str(self.dispatch), *arguments],
                    env=environment,
                    capture_output=True,
                    check=True,
                )
                observed = subprocess.run(
                    [str(self.launcher), *arguments],
                    env=environment,
                    capture_output=True,
                    check=True,
                )
                self.assertEqual(observed.stdout, expected.stdout)
                self.assertEqual(observed.stderr, expected.stderr)
                record = json.loads(observed.stdout)
                self.assertEqual(record["argv"], [argument.hex() for argument in arguments])
                self.assertEqual(record["value"], "fixture value with spaces")
                self.assertEqual(record["raw"], "fffe")

    def test_isolated_python_ignores_python_startup_injection(self) -> None:
        (self.directory / "sitecustomize.py").write_text(
            "raise RuntimeError('INERT_PYTHON_STARTUP_SHOULD_NOT_RUN')\n"
        )
        environment = self.environment()
        environment[b"PYTHONPATH"] = os.fsencode(self.directory)
        result = subprocess.run(
            [str(self.launcher), "--stage", "geiger"],
            env=environment,
            capture_output=True,
            check=True,
        )
        self.assertEqual(result.stderr, b"")
        self.assertEqual(json.loads(result.stdout)["argv"], [b"--stage".hex(), b"geiger".hex()])

    def test_ordinary_bash_startup_is_preserved_after_guard(self) -> None:
        startup = self.directory / "startup.sh"
        startup.write_text('export AEG_FIXTURE_VALUE="fixture set at Bash startup"\n')
        environment = self.environment()
        environment[b"BASH_ENV"] = os.fsencode(startup)
        expected = subprocess.run(
            [self.bash, str(self.dispatch)],
            env=environment,
            capture_output=True,
            check=True,
        )
        observed = subprocess.run(
            [str(self.launcher)],
            env=environment,
            capture_output=True,
            check=True,
        )
        self.assertEqual(observed.stdout, expected.stdout)
        self.assertEqual(json.loads(observed.stdout)["value"], "fixture set at Bash startup")
        startup.write_text('printf "INERT_BASH_STARTUP_SHOULD_NOT_RUN\\n"\n')
        environment[b"BASH_FUNC_unused%%"] = b"() { :; }"
        rejected = subprocess.run(
            [str(self.launcher)],
            env=environment,
            capture_output=True,
            check=False,
        )
        self.assertEqual(rejected.returncode, 1)
        self.assertEqual(rejected.stdout, b"")
        self.assertEqual(
            rejected.stderr, b"[security] inherited Bash functions are not supported\n"
        )


class SecurityAppLauncherProgramTests(unittest.TestCase):
    def test_generated_dispatch_overrides_inherited_native_provider_path(self) -> None:
        nix = shutil.which("nix")
        if nix is None:
            self.fail("The supported test environment requires Nix")
        expression = (
            "let flake = builtins.getFlake "
            + json.dumps(str(ROOT))
            + "; pkgs = import flake.inputs.nixpkgs { system = builtins.currentSystem; }; "
            "in import "
            + json.dumps(str(ROOT / "nix/flake/security-launcher.nix"))
            + ' { inherit pkgs; inherit (pkgs) lib; name = "provider-path-control"; '
            'runtimeInputs = []; nativePkgConfigPath = "/inert/pinned/lib/pkgconfig"; '
            'script = pkgs.writeText "record-provider-path.sh" '
            + json.dumps("printf '%s\\n' \"$PKG_CONFIG_PATH\"\n")
            + "; }"
        )
        build = subprocess.run(
            [
                nix,
                "--extra-experimental-features",
                "nix-command flakes",
                "build",
                "--offline",
                "--impure",
                "--no-link",
                "--json",
                "--expr",
                expression,
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        launcher = Path(json.loads(build.stdout)[0]["outputs"]["out"]) / "bin/provider-path-control"
        for inherited in (None, "", "/inert/inherited/lib/pkgconfig"):
            with self.subTest(inherited=inherited):
                environment = os.environ.copy()
                if inherited is None:
                    environment.pop("PKG_CONFIG_PATH", None)
                else:
                    environment["PKG_CONFIG_PATH"] = inherited
                observed = subprocess.run(
                    [str(launcher)],
                    env=environment,
                    capture_output=True,
                    text=True,
                    check=True,
                )
                self.assertEqual(observed.stdout, "/inert/pinned/lib/pkgconfig\n")
                self.assertEqual(observed.stderr, "")

    def test_actual_flake_program_matches_installed_wrapper_destination(self) -> None:
        nix = shutil.which("nix")
        if nix is None:
            self.fail("The supported test environment requires Nix")
        expression = (
            "let flake = builtins.getFlake "
            + json.dumps(str(ROOT))
            + "; app = flake.apps.${builtins.currentSystem}.security-suite; "
            "in { program = app.program; context = builtins.getContext app.program; }"
        )
        evaluation = subprocess.run(
            [
                nix,
                "--extra-experimental-features",
                "nix-command flakes",
                "eval",
                "--offline",
                "--impure",
                "--json",
                "--expr",
                expression,
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        app = json.loads(evaluation.stdout)
        self.assertEqual(len(app["context"]), 1)
        derivation_path = next(iter(app["context"]))
        result = subprocess.run(
            [
                nix,
                "--extra-experimental-features",
                "nix-command",
                "derivation",
                "show",
                derivation_path,
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        document = json.loads(result.stdout)
        derivation = next(iter(document.get("derivations", document).values()))
        # Nix v2 reports paths relative to its store; older JSON used absolute paths.
        output = str(Path(derivation_path).parent / derivation["outputs"]["out"]["path"])
        self.assertEqual(output, derivation["env"]["out"])
        # writeTextFile now uses structured attributes. Nix exposes them either
        # directly or as serialized JSON; older builders used environment fields.
        attributes = derivation.get("structuredAttrs")
        if attributes is None:
            environment = derivation["env"]
            attributes = (
                json.loads(environment["__json"]) if "__json" in environment else environment
            )
        self.assertEqual(app["program"], output + attributes["destination"])


if __name__ == "__main__":
    unittest.main()
