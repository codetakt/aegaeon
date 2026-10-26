"""Capacity diagnostics must retain partial/error data and stop independently."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/ci/observe_disk_capacity.py"
SPEC = importlib.util.spec_from_file_location("disk_observer", SCRIPT)
assert SPEC
assert SPEC.loader
observer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(observer)


class DiskCapacityTests(unittest.TestCase):
    def test_existing_and_not_yet_mounted_paths_retain_identity(self):
        with tempfile.TemporaryDirectory() as temp:
            existing = observer.observe(temp)
            missing = observer.observe(str(Path(temp) / "not-mounted" / "store"))
            assert missing["resolved"] == temp
            assert missing["device"] == existing["device"]
            assert existing["available_bytes"] > 0
            assert existing["total_bytes"] >= existing["available_bytes"]

    def test_failed_observation_is_not_zero_or_success(self):
        with patch.object(observer.os, "statvfs", side_effect=PermissionError("denied")):
            result = observer.observe("/")
        assert "error" in result
        assert "available_bytes" not in result

    def test_monitor_deadline_retains_last_sample(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            observer.monitor(directory, [temp], 0.01, 0.03)
            rows = [
                json.loads(line) for line in (directory / "samples.jsonl").read_text().splitlines()
            ]
            receipt = json.loads((directory / "completion.json").read_text())
            assert receipt["reason"] == "deadline"
            assert receipt["samples"] == len(rows)
            assert rows[-1]["elapsed_seconds"] >= 0.03

    def test_completion_is_not_visible_until_complete_json_is_written(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            original = Path.replace

            def publish(path, destination):
                assert not destination.exists()
                assert json.loads(path.read_text())["reason"] == "deadline"
                return original(path, destination)

            with patch.object(Path, "replace", publish):
                observer.monitor(directory, [temp], 0.01, 0.01)
            # A scheduling delay can exhaust the deadline before the first sample.
            assert json.loads((directory / "completion.json").read_text())["samples"] >= 1

    def test_actual_background_start_and_stop(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp) / "samples"
            command = [sys.executable, str(SCRIPT)]
            subprocess.run(  # noqa: S603 - fixed observer executable and owned temporary paths
                [
                    *command,
                    "start",
                    str(directory),
                    "--paths",
                    temp,
                    "--interval",
                    "60",
                    "--duration",
                    "60",
                ],
                check=True,
                timeout=5,
            )
            subprocess.run(  # noqa: S603 - fixed observer executable and owned temporary paths
                [*command, "stop", str(directory)], check=True, timeout=5, stdout=subprocess.PIPE
            )
            receipt = json.loads((directory / "completion.json").read_text())
            assert receipt["reason"] == "requested_stop"
            assert receipt["samples"] >= 2
            # Repeated stop reads the same completion; no PID-based killing.
            subprocess.run(  # noqa: S603 - fixed observer executable and owned temporary paths
                [*command, "stop", str(directory)], check=True, timeout=5, stdout=subprocess.PIPE
            )
            assert json.loads((directory / "completion.json").read_text()) == receipt

    def test_invalid_or_unbounded_intervals_are_rejected(self):
        for option, value in (
            ("--interval", "0"),
            ("--interval", "nan"),
            ("--duration", "inf"),
            ("--duration", "7201"),
        ):
            result = subprocess.run(  # noqa: S603 - fixed observer executable and owned temporary paths
                [sys.executable, str(SCRIPT), "start", "/unused", option, value],
                capture_output=True,
                check=False,
                timeout=5,
            )
            assert result.returncode == 2

    def test_workflow_keeps_cleanup_and_observes_failures(self):
        jobs = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())["jobs"]
        steps = jobs["ci"]["steps"]
        names = [step.get("name") for step in steps]
        assert names.index("Start disk capacity observation") < names.index("Setup Nix CI")
        setup = steps[names.index("Setup Nix CI")]["with"]
        assert setup["free-disk"] == "true"
        assert setup.get("minimum-free-gib", "0") == "0"
        for name in (
            "Start disk capacity observation",
            "Stop disk capacity observation",
            "Preserve disk capacity samples",
        ):
            assert steps[names.index(name)]["continue-on-error"] is True
        assert not steps[names.index("Setup Nix CI")].get("continue-on-error", False)
        for name in ("Stop disk capacity observation", "Preserve disk capacity samples"):
            assert steps[names.index(name)]["if"] == "always()"
        assert names.index("Stop disk capacity observation") > names.index("Upload server artifact")


if __name__ == "__main__":
    unittest.main()
