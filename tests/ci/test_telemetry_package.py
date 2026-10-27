"""Telemetry runtime must use both executables from the validated release package."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import tomllib
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


class TelemetryPackageTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.package = self.root / "package"
        (self.package / "bin").mkdir(parents=True)
        for name in ("aegaeon-server", "aegaeon-observability-seed"):
            path = self.package / "bin" / name
            path.write_text("#!/bin/sh\nexit 0\n")
            path.chmod(0o755)
        self.environment = self.root / "github-env"
        self.job = yaml.safe_load((ROOT / ".github/workflows/performance.yml").read_text())["jobs"][
            "observability-test"
        ]
        self.steps = {step.get("name"): step for step in self.job["steps"]}
        nix = self.root / "nix"
        nix.write_text('#!/bin/sh\nprintf "%s\\n" "$FIXTURE_PACKAGE"\nexit "${FIXTURE_EXIT:-0}"\n')
        nix.chmod(0o755)

    def build(self, **changes):
        bash = shutil.which("bash")
        assert bash
        return subprocess.run(  # noqa: S603 - repository step with owned fixture executables
            [bash, "-euo", "pipefail", "-c", self.steps["Build with telemetry"]["run"]],
            env={
                **os.environ,
                "PATH": f"{self.root}:{os.environ['PATH']}",
                "FIXTURE_PACKAGE": str(self.package),
                "GITHUB_ENV": str(self.environment),
                **changes,
            },
            capture_output=True,
            check=False,
            timeout=10,
        )

    def test_complete_package_is_passed_to_both_runtime_commands(self):
        assert self.build().returncode == 0
        assert self.environment.read_text() == f"AEGAEON_TELEMETRY_PACKAGE={self.package}\n"
        for step, binary in (
            ("Seed observability runtime configuration", "aegaeon-observability-seed"),
            ("Start server with telemetry", "aegaeon-server"),
        ):
            command = self.steps[step]["run"]
            assert f'"${{AEGAEON_TELEMETRY_PACKAGE}}/bin/{binary}"' in command
            assert "target/release" not in command

    def test_build_failure_or_missing_executable_cannot_publish_runtime_path(self):
        assert self.build(FIXTURE_EXIT="17").returncode != 0
        assert not self.environment.exists()
        assert self.build(FIXTURE_PACKAGE="").returncode != 0
        assert not self.environment.exists()
        for name in ("aegaeon-server", "aegaeon-observability-seed"):
            path = self.package / "bin" / name
            path.chmod(0o644)
            assert self.build().returncode != 0
            assert not self.environment.exists()
            path.chmod(0o755)

    def test_release_package_keeps_explicit_telemetry_feature_effect(self):
        manifest = tomllib.loads((ROOT / "crates/server/Cargo.toml").read_text())
        assert "telemetry" in manifest["features"]["default"]
        assert manifest["features"]["telemetry"] == []
        assert (
            "nix build .#server --no-link --print-out-paths"
            in self.steps["Build with telemetry"]["run"]
        )

    def test_runtime_checks_still_execute_after_seed_and_start(self):
        names = list(self.steps)
        for earlier, later in (
            ("Build with telemetry", "Seed observability runtime configuration"),
            ("Seed observability runtime configuration", "Start server with telemetry"),
            ("Start server with telemetry", "Generate traffic for metrics"),
            ("Generate traffic for metrics", "Verify metrics exported"),
        ):
            assert names.index(earlier) < names.index(later)
        assert self.steps["Stop server"]["if"] == "always()"
        for name in ("Build with telemetry", "Verify metrics exported"):
            assert not self.steps[name].get("continue-on-error", False)
        assert "/api/v1/operations/metrics" in self.steps["Verify metrics exported"]["run"]
        assert (
            "curl -f http://localhost:8080/health" in self.steps["Verify metrics exported"]["run"]
        )
