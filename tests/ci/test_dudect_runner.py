# ruff: noqa: PT009, S603 - unittest assertions and controlled tool argv
"""Exercise the required dudect wrapper and its actual caller with controlled tools."""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WRAPPER = ROOT / "scripts/flake/verify_dudect.sh"
BINARY = """import json
import os
import signal
from pathlib import Path

with Path(os.environ["DUDECT_EVENTS"]).open("a") as output:
    output.write(json.dumps({"tool": "binary", "stale": False}) + "\\n")
print("controlled dudect output", flush=True)
if os.environ.get("BINARY_SIGNAL"):
    os.kill(os.getpid(), signal.SIGTERM)
raise SystemExit(int(os.environ.get("BINARY_EXIT", "0")))
"""
TOOL = """import json
import os
import sys
from pathlib import Path

tool = Path(sys.argv[0]).name
with Path(os.environ["DUDECT_EVENTS"]).open("a") as output:
    output.write(json.dumps({"tool": tool, "args": sys.argv[1:]}) + "\\n")
if tool == "krml":
    raise SystemExit("krml is located, not executed, by this wrapper")
if tool == "dirname":
    if os.environ.get("DIRNAME_BAD_PATH"):
        print("/missing-dudect-control-directory")
    else:
        print(str(Path(sys.argv[1]).parent))
    raise SystemExit(int(os.environ.get("DIRNAME_EXIT", "0")))
if tool == "rm":
    status = int(os.environ.get("RM_EXIT", "0"))
    if status:
        raise SystemExit(status)
    os.execv(os.environ["DUDECT_REAL_RM"], ["rm", *sys.argv[1:]])
if tool == "clang":
    status = int(os.environ.get("COMPILER_EXIT", "0"))
    if status:
        raise SystemExit(status)
    if not os.environ.get("OMIT_BINARY"):
        target = Path(sys.argv[sys.argv.index("-o") + 1])
        if os.environ.get("DIRECTORY_BINARY"):
            target.mkdir()
            raise SystemExit(0)
        target.write_text(
            "" if os.environ.get("EMPTY_BINARY")
            else "#!" + sys.executable + "\\n" + os.environ["DUDECT_BINARY_SOURCE"]
        )
        target.chmod(0o600 if os.environ.get("NONEXECUTABLE_BINARY") else 0o755)
    raise SystemExit(0)
if tool == "tee":
    status = int(os.environ.get("TEE_EXIT", "0"))
    if status:
        sys.stdin.buffer.read()
        raise SystemExit(status)
    os.execv(os.environ["DUDECT_REAL_TEE"], ["tee", *sys.argv[1:]])
raise SystemExit("unexpected dudect fixture tool")
"""


class DudectRunnerTests(unittest.TestCase):
    def setUp(self):
        self.directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.fixture = self.directory / "source"
        (self.fixture / "c").mkdir(parents=True)
        for name in ("dudect_harness.c", "dudect.h"):
            (self.fixture / "c" / name).write_text("/* controlled source input */\n")
        self.bin = self.directory / "karamel/bin"
        self.bin.mkdir(parents=True)
        for name in ("clang", "krml", "dirname", "rm", "tee"):
            executable = self.bin / name
            executable.write_text(f"#!{sys.executable}\n{TOOL}")
            executable.chmod(0o755)
        self.out = self.directory / "out"
        self.out.mkdir()
        self.evercrypt = self.directory / "evercrypt"
        self.evercrypt.mkdir()
        self.events = self.directory / "events.jsonl"

    def environment(self, **changes):
        environment = {
            **os.environ,
            "PATH": str(self.bin),
            "OUT_DIR": str(self.out),
            "EVERCRYPT_DIST": str(self.evercrypt),
            "DUDECT_EVENTS": str(self.events),
            "DUDECT_BINARY_SOURCE": BINARY,
            "DUDECT_REAL_TEE": shutil.which("tee"),
            "DUDECT_REAL_RM": shutil.which("rm"),
        }
        for name in ("BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS"):
            environment.pop(name, None)
        for name, value in changes.items():
            if value is None:
                environment.pop(name, None)
            else:
                environment[name] = value
        return environment

    def invoke(self, **changes):
        return subprocess.run(
            [shutil.which("bash"), str(WRAPPER)],
            cwd=self.fixture,
            env=self.environment(**changes),
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )

    def recorded(self):
        return (
            [json.loads(line) for line in self.events.read_text().splitlines()]
            if self.events.exists()
            else []
        )

    def check_failure(self, result, *, before_compile=False):
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse((self.out / "success").exists())
        if before_compile:
            self.assertNotIn("clang", [event["tool"] for event in self.recorded()])
            self.assertNotIn("binary", [event["tool"] for event in self.recorded()])

    def test_each_required_input_must_be_a_file(self):
        for name in ("dudect_harness.c", "dudect.h"):
            for kind in ("missing", "directory", "dangling-symlink"):
                with self.subTest(input=name, kind=kind):
                    path = self.fixture / "c" / name
                    path.unlink()
                    if kind == "directory":
                        path.mkdir()
                    elif kind == "dangling-symlink":
                        path.symlink_to(self.directory / "missing")
                    result = self.invoke()
                    self.check_failure(result, before_compile=True)
                    self.assertIn(f"Required dudect input not found: c/{name}", result.stderr)
                    if kind == "directory":
                        path.rmdir()
                    elif kind == "dangling-symlink":
                        path.unlink()
                    path.write_text("/* controlled source input */\n")

    def test_mandatory_environment_cannot_be_missing_or_empty(self):
        for name in ("OUT_DIR", "EVERCRYPT_DIST"):
            for value in (None, ""):
                with self.subTest(variable=name, value=value):
                    self.check_failure(self.invoke(**{name: value}), before_compile=True)

    def test_missing_required_tools_fail(self):
        for tool in ("krml", "dirname", "rm", "clang", "tee"):
            with self.subTest(tool=tool):
                executable = self.bin / tool
                original = executable.read_bytes()
                executable.unlink()
                self.events.unlink(missing_ok=True)
                result = self.invoke()
                self.check_failure(result, before_compile=tool in ("krml", "dirname", "rm"))
                self.assertIn(tool, result.stderr)
                executable.write_bytes(original)
                executable.chmod(0o755)

    def test_failed_path_resolution_stops_before_compilation(self):
        for changes in ({"DIRNAME_EXIT": "37"}, {"DIRNAME_BAD_PATH": "1"}):
            with self.subTest(changes=changes):
                self.check_failure(self.invoke(**changes), before_compile=True)

    def create_stale_binary(self):
        stale = self.fixture / "dudect_test"
        stale.write_text(
            f"#!{sys.executable}\n"
            "import json, os\n"
            "from pathlib import Path\n"
            "with Path(os.environ['DUDECT_EVENTS']).open('a') as output:\n"
            "    output.write(json.dumps({'tool': 'binary', 'stale': True}) + '\\n')\n"
        )
        stale.chmod(0o755)
        return stale

    def test_failed_compiler_never_executes_a_stale_binary(self):
        stale = self.create_stale_binary()
        self.check_failure(self.invoke(COMPILER_EXIT="31"))
        self.assertEqual([event["tool"] for event in self.recorded()], ["dirname", "rm", "clang"])
        self.assertFalse(stale.exists())

    def test_successful_compiler_without_output_cannot_reuse_a_stale_binary(self):
        stale = self.create_stale_binary()
        result = self.invoke(OMIT_BINARY="1")
        self.check_failure(result)
        self.assertIn("Required dudect compiler output", result.stderr)
        self.assertEqual([event["tool"] for event in self.recorded()], ["dirname", "rm", "clang"])
        self.assertFalse(stale.exists())
        self.assertFalse((self.out / "dudect.log").exists())

    def test_failed_output_removal_prevents_compilation_and_execution(self):
        stale = self.create_stale_binary()
        result = self.invoke(RM_EXIT="39")
        self.check_failure(result, before_compile=True)
        self.assertIn("Unable to remove prior dudect compiler output", result.stderr)
        self.assertEqual([event["tool"] for event in self.recorded()], ["dirname", "rm"])
        self.assertTrue(stale.exists())
        self.assertFalse((self.out / "dudect.log").exists())

    def test_existing_directory_cannot_be_removed_as_prior_compiler_output(self):
        target = self.fixture / "dudect_test"
        target.mkdir()
        result = self.invoke()
        self.check_failure(result, before_compile=True)
        self.assertTrue(target.is_dir())
        self.assertIn("Unable to remove prior dudect compiler output", result.stderr)

    def test_missing_or_nonexecutable_compiler_output_fails(self):
        for changes in (
            {"OMIT_BINARY": "1"},
            {"NONEXECUTABLE_BINARY": "1"},
            {"EMPTY_BINARY": "1"},
        ):
            with self.subTest(changes=changes):
                self.events.unlink(missing_ok=True)
                (self.fixture / "dudect_test").unlink(missing_ok=True)
                self.check_failure(self.invoke(**changes))
                self.assertNotIn("binary", [event["tool"] for event in self.recorded()])

    def test_compiler_directory_output_cannot_count_as_an_executable(self):
        result = self.invoke(DIRECTORY_BINARY="1")
        self.check_failure(result)
        self.assertIn("Required dudect compiler output", result.stderr)
        self.assertNotIn("binary", [event["tool"] for event in self.recorded()])

    def test_binary_failure_and_signal_propagate_through_successful_tee(self):
        for changes in ({"BINARY_EXIT": "43"}, {"BINARY_SIGNAL": "1"}):
            with self.subTest(changes=changes):
                self.check_failure(self.invoke(**changes))
                self.assertEqual(
                    (self.out / "dudect.log").read_text(), "controlled dudect output\n"
                )

    def test_tee_and_output_write_failures_are_nonzero(self):
        self.check_failure(self.invoke(TEE_EXIT="41"))
        self.check_failure(self.invoke(OUT_DIR=str(self.directory / "absent-output-directory")))

    def test_success_preserves_compiler_route_and_captures_executed_output(self):
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.out / "dudect.log").read_text(), "controlled dudect output\n")
        self.assertEqual(
            [event for event in self.recorded() if event["tool"] == "rm"],
            [{"tool": "rm", "args": ["-f", "--", "dudect_test"]}],
        )
        compiler = [event for event in self.recorded() if event["tool"] == "clang"]
        self.assertEqual(len(compiler), 1)
        karamel = self.bin.parent
        self.assertEqual(
            compiler[0]["args"],
            [
                "-O2",
                "-Ic",
                "-I",
                str(self.evercrypt / "include"),
                "-I",
                str(karamel / "include"),
                "-I",
                str(karamel / "lib/krml/c"),
                "-I",
                str(karamel / "lib/krml/dist/generic"),
                "c/dudect_harness.c",
                "-L",
                str(self.evercrypt / "lib"),
                "-levercrypt",
                "-lm",
                "-o",
                "dudect_test",
            ],
        )
        self.assertIn({"tool": "binary", "stale": False}, self.recorded())

    def caller_script(self):
        source = (ROOT / "flake.nix").read_text().split("mkVerification =", 1)[1]
        source = source.split("mkLightVerification =", 1)[0]
        match = re.search(r"''\n(.*?)\n\s*'';", source, re.DOTALL)
        self.assertIsNotNone(match)
        script = match.group(1)
        substitutions = {
            "src": self.fixture,
            "haclStar": self.directory,
            "steel": self.directory,
            "evercryptDist": self.evercrypt,
            "pkgs.bash": Path(shutil.which("bash")).parents[1],
            "scriptPath": WRAPPER,
        }
        for name, value in substitutions.items():
            script = script.replace("${" + name + "}", shlex.quote(str(value)))
        self.assertNotIn("${", script)
        return script

    def test_actual_nix_caller_shell_creates_marker_only_after_success(self):
        for tool in ("cp", "chmod", "mkdir", "touch"):
            (self.bin / tool).symlink_to(shutil.which(tool))
        cases = ({"COMPILER_EXIT": "31"}, {"BINARY_EXIT": "43"}, {"TEE_EXIT": "41"}, {})
        for position, changes in enumerate(cases):
            with self.subTest(changes=changes):
                build = self.directory / f"build-{position}"
                build.mkdir()
                output = self.directory / f"caller-out-{position}"
                result = subprocess.run(
                    [shutil.which("bash"), "-e", "-o", "pipefail", "-c", self.caller_script()],
                    cwd=build,
                    env={**self.environment(**changes), "out": str(output), "TMPDIR": str(build)},
                    capture_output=True,
                    text=True,
                    timeout=15,
                    check=False,
                )
                self.assertEqual((output / "success").exists(), not changes)
                if changes:
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                else:
                    self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
