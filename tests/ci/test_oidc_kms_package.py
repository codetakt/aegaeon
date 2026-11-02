"""Exercise Cargo artifact selection and installed KMS test integrity."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PACKAGER = ROOT / "scripts/validation/oidc_kms_test_package.py"


class KmsPackageTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.executable = self.root / "target/debug/deps/aegaeon_server-fixture"
        self.executable.parent.mkdir(parents=True)
        self.executable.write_text("#!/bin/sh\nexit 0\n")
        self.executable.chmod(0o755)
        self.row = {
            "reason": "compiler-artifact",
            "executable": str(self.executable),
            "manifest_path": str(self.root / "crates/server/Cargo.toml"),
            "target": {"name": "aegaeon_server", "kind": ["lib"], "test": True},
            "profile": {"test": True, "opt_level": "0", "debug_assertions": True},
            "features": ["default", "kms-aws", "telemetry"],
        }
        (self.root / "identity.json").write_text('{"source":"fixture"}')

    def command(self, *arguments):
        return subprocess.run(  # noqa: S603 - checked-in tool and owned fixture paths
            [sys.executable, str(PACKAGER), *arguments],
            cwd=self.root,
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )

    def install(self, rows=None):
        rows = (
            rows if rows is not None else [self.row, {"reason": "build-finished", "success": True}]
        )
        (self.root / "messages.jsonl").write_text("".join(json.dumps(row) + "\n" for row in rows))
        return self.command("install", "messages.jsonl", "identity.json", "output")

    def test_installed_bytes_and_build_identity_survive_validation(self):
        result = self.install()
        assert result.returncode == 0, result.stderr
        assert (
            self.root / "output/libexec/oidc-kms-test"
        ).read_bytes() == self.executable.read_bytes()
        result = self.command("validate", "output")
        assert result.returncode == 0, result.stderr
        receipt = json.loads(result.stdout)
        assert receipt["scope"] == "compilation-only"
        assert receipt["build"] == {"source": "fixture"}
        assert receipt["features"] == ["default", "kms-aws", "telemetry"]

    def test_missing_duplicate_failed_and_incomplete_builds_are_rejected(self):
        for rows in (
            [],
            [self.row],
            [{"reason": "build-finished", "success": True}],
            [self.row, self.row, {"reason": "build-finished", "success": True}],
            [self.row, {"reason": "build-finished", "success": False}],
            [self.row, {"reason": "build-finished", "success": True}] * 2,
        ):
            with self.subTest(rows=rows):
                assert self.install(rows).returncode != 0
                assert not (self.root / "output/build.json").exists()

    def test_wrong_target_profile_features_and_executable_are_rejected(self):
        changes = (
            {"manifest_path": "/another/crates/server/Cargo.toml"},
            {"target": {"name": "aegaeon_server", "kind": ["bin"], "test": True}},
            {"target": {"name": "another", "kind": ["lib"], "test": True}},
            {"profile": {"test": False, "opt_level": "0", "debug_assertions": True}},
            {"profile": {"test": True, "opt_level": "3", "debug_assertions": False}},
            {"features": ["default", "telemetry"]},
            {"features": ["default", "kms-aws", "telemetry", "verified-claim"]},
            {"executable": str(self.root / "target/missing")},
            {"executable": "/bin/sh"},
        )
        for change in changes:
            with self.subTest(change=change):
                rows = [self.row | change, {"reason": "build-finished", "success": True}]
                assert self.install(rows).returncode != 0
                assert not (self.root / "output/build.json").exists()

    def test_corrupt_missing_and_symlinked_installed_bytes_are_rejected(self):
        for mutation in ("corrupt", "missing", "symlink", "not-executable", "receipt"):
            with self.subTest(mutation=mutation):
                output = self.root / "output"
                if output.exists():
                    shutil.rmtree(output)
                assert self.install().returncode == 0
                executable = output / "libexec/oidc-kms-test"
                if mutation == "corrupt":
                    executable.write_text("changed")
                elif mutation in ("missing", "symlink"):
                    executable.unlink()
                    if mutation == "symlink":
                        executable.symlink_to(self.executable)
                elif mutation == "not-executable":
                    executable.chmod(0o644)
                else:
                    (output / "build.json").write_text("{}")
                result = self.command("validate", "output")
                assert result.returncode != 0
                assert result.stdout == ""


if __name__ == "__main__":
    unittest.main()
