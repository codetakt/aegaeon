"""Exercise mandatory JOSE workflow shells with controlled tool failures."""

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
MANDATORY_STEPS = (
    "Run JOSE JSON/TLV compatibility tests",
    "Run strict claim-bearing profile tests",
    "Run TLV parity tests",
)
FAKE_TOOL = """import json
import os
import sys
from pathlib import Path

tool = Path(sys.argv[0]).name
args = sys.argv[1:]
if tool == "nix":
    if args[:5] != ["develop", ".#verification", "--command", "bash", "-c"]:
        raise SystemExit("unexpected nix command")
    os.execvpe(args[3], args[3:], os.environ)
if tool == "cat" and not args:
    os.execv(os.environ["REAL_CAT"], ["cat"])

trace = Path(os.environ["TRACE_DIR"]) / (tool + ".jsonl")
with trace.open("a") as stream:
    stream.write(json.dumps(args) + "\\n")
invocation = len(trace.read_text().splitlines())
if tool == "cargo":
    failed = invocation == int(os.environ["FAIL_CARGO_AT"])
    output = "synthetic cargo output"
    if failed:
        output = f"test synthetic_failure_{invocation} ... FAILED"
    print(output, flush=True)
    raise SystemExit(37 if failed else 0)
if tool == "tee":
    if invocation == int(os.environ["FAIL_TEE_AT"]):
        sys.stdin.buffer.read()
        raise SystemExit(41)
    os.execv(os.environ["REAL_TEE"], ["tee", *args])
if tool == "cat":
    if invocation == int(os.environ["FAIL_CAT_AT"]):
        raise SystemExit(43)
    os.execv(os.environ["REAL_CAT"], ["cat", *args])
raise SystemExit("unexpected fixture executable")
"""


def mandatory_scripts(text):
    steps = yaml.safe_load(text)["jobs"]["jose-vectors"]["steps"]
    scripts = {step["name"]: step["run"] for step in steps if step.get("name") in MANDATORY_STEPS}
    assert tuple(scripts) == MANDATORY_STEPS
    return scripts


def read_trace(directory, tool):
    path = directory / f"{tool}.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def run_script(script, *, cargo_failure=0, tee_failure=0, cat_failure=0):
    bash, tee, cat = shutil.which("bash"), shutil.which("tee"), shutil.which("cat")
    assert bash, "workflow fixtures require bash"
    assert tee, "workflow fixtures require tee"
    assert cat, "workflow fixtures require cat"
    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        binaries = directory / "bin"
        binaries.mkdir()
        for tool in ("nix", "cargo", "tee", "cat"):
            executable = binaries / tool
            executable.write_text(f"#!{sys.executable}\n{FAKE_TOOL}")
            executable.chmod(0o755)
        environment = {
            **os.environ,
            "PATH": f"{binaries}{os.pathsep}{os.environ['PATH']}",
            "TRACE_DIR": str(directory),
            "REAL_TEE": tee,
            "REAL_CAT": cat,
            "FAIL_CARGO_AT": str(cargo_failure),
            "FAIL_TEE_AT": str(tee_failure),
            "FAIL_CAT_AT": str(cat_failure),
        }
        for name in ("BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS"):
            environment.pop(name, None)
        result = subprocess.run(  # noqa: S603 - checked-in workflow with temporary fake tools
            [bash, "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", script],
            cwd=directory,
            env=environment,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        artifacts = {
            str(path.relative_to(directory / "artifacts")): path.read_text()
            for path in (directory / "artifacts").rglob("*.txt")
        }
        return result, read_trace(directory, "cargo"), read_trace(directory, "tee"), artifacts


class JoseWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.scripts = mandatory_scripts((ROOT / ".github/workflows/verification.yml").read_text())

    def test_strict_shell_preserves_successful_command_order_and_arguments(self):
        for name, script in self.scripts.items():
            with self.subTest(step=name):
                # The control differs only in shell options, not a copied command list.
                control = script.replace("set -euo pipefail\n", "")
                before, before_cargo, before_tee, before_artifacts = run_script(control)
                after, after_cargo, after_tee, after_artifacts = run_script(script)
                assert before.returncode == after.returncode == 0, (before.stderr, after.stderr)
                assert len(before_cargo) > 1
                assert after_cargo == before_cargo
                assert after_tee == before_tee
                assert after_artifacts == before_artifacts

    def test_first_and_middle_cargo_failure_stop_each_mandatory_shell(self):
        for name, script in self.scripts.items():
            success, expected, _, _ = run_script(script)
            assert success.returncode == 0, success.stderr
            for position in (1, len(expected) // 2):
                with self.subTest(step=name, failing_invocation=position):
                    result, cargo, _, _ = run_script(script, cargo_failure=position)
                    assert result.returncode == 37, result.stderr
                    assert cargo == expected[:position]

    def test_tee_failure_stops_the_tlv_profile_sweep(self):
        script = self.scripts["Run TLV parity tests"]
        success, expected_cargo, expected_tee, _ = run_script(script)
        assert success.returncode == 0, success.stderr
        # Each profile has a heading tee followed by the Cargo-output tee.
        for position in (2, 6):
            with self.subTest(failing_tee_invocation=position):
                result, cargo, tee, artifacts = run_script(script, tee_failure=position)
                assert result.returncode == 41, result.stderr
                assert tee == expected_tee[:position]
                assert cargo == expected_cargo[: position // 2]
                # Failed tee never creates the profile file; failed cat must not replace exit 41.
                assert len(artifacts) == position // 2

    def test_failed_tlv_profile_is_appended_before_stopping(self):
        script = self.scripts["Run TLV parity tests"]
        success, expected, _, _ = run_script(script)
        assert success.returncode == 0, success.stderr
        for position in (1, 3):
            with self.subTest(failing_invocation=position):
                result, cargo, _, artifacts = run_script(script, cargo_failure=position)
                assert result.returncode == 37, result.stderr
                assert cargo == expected[:position]
                aggregate = artifacts["jose/tlv-parity/test-output.txt"]
                failed_line = f"test synthetic_failure_{position} ... FAILED"
                assert failed_line in aggregate.splitlines()
                assert aggregate.count("=== TLV parity profile:") == position
                assert len(artifacts) == position + 1

    def test_append_failure_stops_and_preserves_primary_pipeline_status(self):
        script = self.scripts["Run TLV parity tests"]
        success, expected, _, _ = run_script(script)
        assert success.returncode == 0, success.stderr
        for position in (1, 3):
            for cargo_failure in (0, position):
                with self.subTest(failing_append=position, cargo_failure=cargo_failure):
                    result, cargo, _, artifacts = run_script(
                        script, cat_failure=position, cargo_failure=cargo_failure
                    )
                    assert result.returncode == (37 if cargo_failure else 43), result.stderr
                    assert cargo == expected[:position]
                    assert len(artifacts) == position + 1


if __name__ == "__main__":
    unittest.main()
