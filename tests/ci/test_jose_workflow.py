"""Exercise mandatory JOSE workflow shells with controlled tool failures."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from dataclasses import dataclass
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

# The helper owns a separate temporary capture; workflow logging faults
# below still target the original artifact-writing tee invocations.
if tool == "tee" and len(args) == 1 and Path(args[0]).parent == Path(os.environ["TMPDIR"]):
    os.execv(os.environ["REAL_TEE"], ["tee", *args])

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
    if not failed:
        print("test result: ok. 1 passed; 0 failed; 0 ignored;", flush=True)
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


RETAINED_PROFILES = (
    "default",
    "everparse-jose-header-entry",
    "ffi-jose-header-tlv",
    "ffi-jose-header-tlv-verified-claim",
)


@dataclass(frozen=True)
class ReportInputs:
    retained: bool = True
    damage: tuple[str, str] | None = None
    outcomes: tuple[str, str] = ("success", "success")


def prepare_reports(directory: Path, reports: ReportInputs):
    if not reports.retained:
        return
    for profile in RETAINED_PROFILES:
        path = directory / "artifacts/jose/tlv-parity" / f"{profile}.txt"
        path.parent.mkdir(parents=True, exist_ok=True)
        content = f"retained successful {profile} output\n".encode()
        path.write_bytes(content)
        digest = path.with_suffix(".txt.sha256")
        digest.write_text(f"{hashlib.sha256(content).hexdigest()}  {path.relative_to(directory)}\n")
        if reports.damage == (profile, "missing"):
            path.unlink()
        elif reports.damage == (profile, "changed"):
            path.write_text("changed\n")
        elif reports.damage == (profile, "empty"):
            path.write_bytes(b"")
        elif reports.damage == (profile, "missing-digest"):
            digest.unlink()
        elif reports.damage == (profile, "bad-digest"):
            digest.write_text("invalid digest\n")


def run_script(script, *, cargo_failure=0, tee_failure=0, cat_failure=0, reports=None):
    reports = reports or ReportInputs()
    bash, tee, cat = shutil.which("bash"), shutil.which("tee"), shutil.which("cat")
    assert bash, "workflow fixtures require bash"
    assert tee, "workflow fixtures require tee"
    assert cat, "workflow fixtures require cat"
    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        prepare_reports(directory, reports)
        helper = directory / "scripts/validation/run_required_cargo_test.sh"
        helper.parent.mkdir(parents=True)
        shutil.copy2(ROOT / "scripts/validation/run_required_cargo_test.sh", helper)
        (directory / "tmp").mkdir()
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
            "TMPDIR": str(directory / "tmp"),
            "REAL_TEE": tee,
            "REAL_CAT": cat,
            "FAIL_CARGO_AT": str(cargo_failure),
            "FAIL_TEE_AT": str(tee_failure),
            "FAIL_CAT_AT": str(cat_failure),
            "JOSE_COMPAT_OUTCOME": reports.outcomes[0],
            "JOSE_STRICT_OUTCOME": reports.outcomes[1],
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
                assert len(before_cargo) >= 1
                assert after_cargo == before_cargo
                assert after_tee == before_tee
                assert after_artifacts == before_artifacts

    def test_first_and_middle_cargo_failure_stop_each_mandatory_shell(self):
        for name, script in self.scripts.items():
            success, expected, _, _ = run_script(script)
            assert success.returncode == 0, success.stderr
            for position in sorted({1, max(1, len(expected) // 2)}):
                with self.subTest(step=name, failing_invocation=position):
                    result, cargo, _, _ = run_script(script, cargo_failure=position)
                    assert result.returncode == 37, result.stderr
                    assert cargo == expected[:position]

    def test_tee_failure_stops_the_tlv_profile_sweep(self):
        script = self.scripts["Run TLV parity tests"]
        success, expected_cargo, expected_tee, _ = run_script(script)
        assert success.returncode == 0, success.stderr
        # Four profiles retain logs; only verified-claim adds a serial invocation.
        for position, calls in ((1, 0), (4, 1), (5, 1)):
            with self.subTest(failing_tee_invocation=position):
                result, cargo, tee, _ = run_script(script, tee_failure=position)
                assert result.returncode == 41, result.stderr
                assert tee == expected_tee[:position]
                assert cargo == expected_cargo[:calls]

    def test_failed_tlv_profile_is_appended_before_stopping(self):
        script = self.scripts["Run TLV parity tests"]
        success, expected, _, _ = run_script(script)
        assert success.returncode == 0, success.stderr
        result, cargo, _, artifacts = run_script(script, cargo_failure=1)
        assert result.returncode == 37, result.stderr
        assert cargo == expected
        aggregate = artifacts["jose/tlv-parity/test-output.txt"]
        assert "test synthetic_failure_1 ... FAILED" in aggregate.splitlines()
        assert aggregate.count("=== TLV parity profile:") == 3

    def test_append_failure_stops_and_preserves_primary_pipeline_status(self):
        script = self.scripts["Run TLV parity tests"]
        for position, cargo_failure in ((1, 0), (3, 0), (3, 1)):
            with self.subTest(failing_append=position, cargo_failure=cargo_failure):
                result, cargo, _, _ = run_script(
                    script, cat_failure=position, cargo_failure=cargo_failure
                )
                assert result.returncode == (37 if cargo_failure else 43), result.stderr
                assert len(cargo) == (0 if position == 1 else 1)

    def test_report_reuses_four_logs_and_retains_the_distinct_serial_profile(self):
        result, cargo, _, artifacts = run_script(self.scripts["Run TLV parity tests"])
        assert result.returncode == 0, result.stderr
        assert cargo == [
            [
                "test",
                "-p",
                "aegaeon-jose",
                "--test",
                "tlv_parity",
                "--features",
                "verified-claim",
                "--",
                "--test-threads=1",
                "--nocapture",
            ]
        ]
        aggregate = artifacts["jose/tlv-parity/test-output.txt"]
        assert aggregate.count("=== TLV parity profile:") == 5
        for profile in RETAINED_PROFILES:
            assert f"retained successful {profile} output" in aggregate

    def test_missing_empty_changed_or_invalid_retained_output_is_fatal(self):
        for profile in RETAINED_PROFILES:
            for damage in ("missing", "changed", "empty", "missing-digest", "bad-digest"):
                with self.subTest(profile=profile, damage=damage):
                    result, cargo, _, _ = run_script(
                        self.scripts["Run TLV parity tests"],
                        reports=ReportInputs(damage=(profile, damage)),
                    )
                    assert result.returncode != 0
                    # No retry replaces the failed evidence.
                    assert all("verified-claim" in call for call in cargo)

    def test_unsuccessful_producer_cannot_be_replaced_by_retained_output(self):
        for outcome in ("failure", "cancelled", "skipped", ""):
            for outcomes in ((outcome, "success"), ("success", outcome)):
                with self.subTest(outcomes=outcomes):
                    result, cargo, tee, _ = run_script(
                        self.scripts["Run TLV parity tests"],
                        reports=ReportInputs(outcomes=outcomes),
                    )
                    assert result.returncode != 0
                    assert not cargo
                    assert not tee

    def test_actual_step_sequence_produces_complete_parity_reports(self):
        script = "\n".join(self.scripts.values())
        result, cargo, _, artifacts = run_script(script, reports=ReportInputs(retained=False))
        assert result.returncode == 0, result.stderr
        parity = [call for call in cargo if "tlv_parity" in call]
        assert len(parity) == 6
        assert len({tuple(call) for call in parity}) == 6
        strict = [call for call in parity if "verified-claim" in call]
        assert len(strict) == 2
        assert sum("--test-threads=1" in call for call in strict) == 1
        assert artifacts["jose/tlv-parity/test-output.txt"].count("=== TLV parity profile:") == 5

    def test_earlier_parity_failures_stop_the_sequence_and_retain_output(self):
        script = "\n".join(self.scripts.values())
        success, expected, _, _ = run_script(script, reports=ReportInputs(retained=False))
        assert success.returncode == 0, success.stderr
        positions = [index for index, call in enumerate(expected, 1) if "tlv_parity" in call]
        for position in positions:
            with self.subTest(position=position):
                result, cargo, _, artifacts = run_script(
                    script, reports=ReportInputs(retained=False), cargo_failure=position
                )
                assert result.returncode == 37, result.stderr
                assert cargo == expected[:position]
                # The default-thread strict call remains an ordinary required test.
                if "--test-threads=1" in expected[position - 1]:
                    assert any(
                        f"test synthetic_failure_{position} ... FAILED" in log
                        for log in artifacts.values()
                    )

    def test_original_capture_write_failure_stops_the_sequence(self):
        script = "\n".join(self.scripts.values())
        for position in range(1, 5):
            with self.subTest(capture=position):
                result, _, tee, _ = run_script(
                    script, reports=ReportInputs(retained=False), tee_failure=position
                )
                assert result.returncode == 41, result.stderr
                assert len(tee) == position

    def test_workflow_binds_reports_to_required_producer_outcomes(self):
        workflow = yaml.safe_load((ROOT / ".github/workflows/verification.yml").read_text())
        steps = {step.get("name"): step for step in workflow["jobs"]["jose-vectors"]["steps"]}
        for name, identity in (
            (MANDATORY_STEPS[0], "jose-compat"),
            (MANDATORY_STEPS[1], "jose-strict"),
        ):
            assert steps[name]["id"] == identity
            assert "if" not in steps[name]
            assert not steps[name].get("continue-on-error", False)
        assert steps[MANDATORY_STEPS[2]]["env"] == {
            "JOSE_COMPAT_OUTCOME": "${{ steps.jose-compat.outcome }}",
            "JOSE_STRICT_OUTCOME": "${{ steps.jose-strict.outcome }}",
        }
        assert "if" not in steps[MANDATORY_STEPS[2]]
        assert not steps[MANDATORY_STEPS[2]].get("continue-on-error", False)


if __name__ == "__main__":
    unittest.main()
