"""Exercise runner cleanup admission with synthetic disk and cleanup tools."""

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
SCRIPT = ROOT / ".github/actions/setup-nix-ci/prepare-disk.sh"
GIB = 1024**3
FAKE_TOOL = """import json
import os
import sys
from pathlib import Path

tool = Path(sys.argv[0]).name
args = sys.argv[1:]
with Path(os.environ["TRACE"]).open("a") as stream:
    stream.write(json.dumps([tool, *args]) + "\\n")
if tool == "sudo":
    os.execvpe(args[0], args, os.environ)
if tool == "df":
    if args == ["-h"]:
        print("synthetic disk observation")
        raise SystemExit(0)
    if args[:3] != ["-B1", "--output=avail", "--"]:
        raise SystemExit("unexpected df arguments")
    value = json.loads(os.environ["CAPACITY"])[args[3]]
    if value == "unreadable":
        raise SystemExit(1)
    print("Avail")
    print(value)
    raise SystemExit(0)
if tool in ("rm", "docker", "apt-get"):
    raise SystemExit(int(os.environ["CLEANUP_EXIT"]))
raise SystemExit("unexpected fixture tool")
"""
EXPECTED_CLEANUP = [
    [
        "rm",
        "-rf",
        "/usr/share/dotnet",
        "/opt/ghc",
        "/usr/local/lib/android",
        "/usr/local/share/boost",
        "/opt/hostedtoolcache/CodeQL",
    ],
    ["docker", "system", "prune", "-af"],
    ["apt-get", "clean"],
]


def run_cleanup(budget="80", *, capacities=None, absent_nix=False, sudo=True, cleanup_exit=0):
    bash = shutil.which("bash")
    dirname = shutil.which("dirname")
    assert bash
    assert dirname
    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        binaries = directory / "bin"
        binaries.mkdir()
        # Restrict PATH completely, so no real cleanup command or sudo is reachable.
        (binaries / "dirname").symlink_to(dirname)
        for tool in ["df", "rm", "docker", "apt-get", *(["sudo"] if sudo else [])]:
            executable = binaries / tool
            executable.write_text(f"#!{sys.executable}\n{FAKE_TOOL}")
            executable.chmod(0o755)
        paths = [directory / name for name in ("workspace", "temp", "nix-parent")]
        for path in paths:
            path.mkdir()
        arguments = [*paths[:2], paths[2] / "missing/nix" if absent_nix else paths[2]]
        values = capacities if capacities is not None else [81 * GIB] * 3
        environment = {
            **os.environ,
            "PATH": str(binaries),
            "TRACE": str(directory / "trace.jsonl"),
            "CAPACITY": json.dumps(dict(zip(map(str, paths), values, strict=True))),
            "CLEANUP_EXIT": str(cleanup_exit),
        }
        for name in ("BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS"):
            environment.pop(name, None)
        result = subprocess.run(  # noqa: S603 - checked-in script and isolated fake tool PATH
            [bash, str(SCRIPT), budget, *map(str, arguments)],
            env=environment,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        trace_path = directory / "trace.jsonl"
        trace = (
            [json.loads(line) for line in trace_path.read_text().splitlines()]
            if trace_path.exists()
            else []
        )
        return result, trace, list(map(str, paths))


class RunnerDiskCleanupTests(unittest.TestCase):
    def assert_cleanup(self, trace):
        assert [
            entry for entry in trace if entry[0] in ("rm", "docker", "apt-get")
        ] == EXPECTED_CLEANUP

    def test_above_and_equal_threshold_skip_after_measuring_all_paths(self):
        for capacity in (80 * GIB, 80 * GIB + 1, 81 * GIB):
            with self.subTest(capacity=capacity):
                result, trace, paths = run_cleanup(capacities=[capacity] * 3)
                assert result.returncode == 0, result.stderr
                assert "Skipping disk cleanup" in result.stdout
                assert [entry[-1] for entry in trace if entry[1] == "-B1"] == paths
                assert not any(entry[0] in ("sudo", "rm", "docker", "apt-get") for entry in trace)

    def test_each_separate_filesystem_can_require_cleanup(self):
        for index in range(3):
            with self.subTest(filesystem=index):
                values = [81 * GIB] * 3
                values[index] = 80 * GIB - 1
                result, trace, _ = run_cleanup(capacities=values)
                assert result.returncode == 0, result.stderr
                self.assert_cleanup(trace)

    def test_absent_nix_uses_nearest_existing_parent(self):
        result, trace, paths = run_cleanup(absent_nix=True)
        assert result.returncode == 0, result.stderr
        assert "Skipping disk cleanup" in result.stdout
        assert [entry[-1] for entry in trace if entry[1] == "-B1"] == paths

    def test_unreadable_or_malformed_capacity_falls_back_to_cleanup(self):
        for value in (
            "unreadable",
            "",
            "garbage",
            "-1",
            "1 2",
            "extra\n85899345920",
            "9223372036854775808",
        ):
            with self.subTest(value=value):
                result, trace, _ = run_cleanup(capacities=[81 * GIB, value, 81 * GIB])
                assert result.returncode == 0, result.stderr
                assert "measurement unavailable" in result.stdout
                self.assert_cleanup(trace)

    def test_zero_budget_always_cleans_without_capacity_admission(self):
        for budget in ("0", "000"):
            result, trace, _ = run_cleanup(budget, capacities=["unreadable"] * 3)
            assert result.returncode == 0, result.stderr
            self.assert_cleanup(trace)
            assert not any(entry[1] == "-B1" for entry in trace)

    def test_invalid_budget_fails_before_measurement_or_cleanup(self):
        for budget in ("", "-1", "+80", "80.0", "80 GiB", "$(false)", "8589934592"):
            with self.subTest(budget=budget):
                result, trace, _ = run_cleanup(budget)
                assert result.returncode == 2, result.stderr
                assert not trace

    def test_leading_zero_budget_is_decimal(self):
        result, trace, _ = run_cleanup("080", capacities=[80 * GIB] * 3)
        assert result.returncode == 0, result.stderr
        assert not any(entry[0] == "rm" for entry in trace)

    def test_cleanup_failures_remain_ignored_with_and_without_sudo(self):
        for sudo in (True, False):
            with self.subTest(sudo=sudo):
                result, trace, _ = run_cleanup("0", sudo=sudo, cleanup_exit=37)
                assert result.returncode == 0, result.stderr
                self.assert_cleanup(trace)
                assert "Disk capacity after cleanup decision" in result.stdout
                assert "Disk cleanup elapsed seconds:" in result.stdout

    def test_action_keeps_disabled_default_and_only_two_workflows_opt_in(self):
        action = yaml.safe_load((ROOT / ".github/actions/setup-nix-ci/action.yml").read_text())
        assert action["inputs"]["free-disk"]["default"] == "false"
        assert action["inputs"]["minimum-free-gib"]["default"] == "0"
        cleanup = action["runs"]["steps"][0]
        assert cleanup["if"] == "${{ inputs.free-disk == 'true' }}"
        assert cleanup["env"]["MINIMUM_FREE_GIB"] == "${{ inputs.minimum-free-gib }}"
        opted_in = []
        for path in (ROOT / ".github/workflows").glob("*.yml"):
            workflow = yaml.safe_load(path.read_text())
            for job_name, job in workflow.get("jobs", {}).items():
                for step in job.get("steps", []):
                    inputs = step.get("with", {})
                    if "minimum-free-gib" in inputs:
                        assert inputs["minimum-free-gib"] == "80"
                        assert inputs["free-disk"] == "true"
                        opted_in.append((path.name, job_name))
        assert sorted(opted_in) == [
            ("oidc-kms-parity.yml", "oidc-kms-parity"),
            ("verification.yml", "tamarin"),
        ]


if __name__ == "__main__":
    unittest.main()
