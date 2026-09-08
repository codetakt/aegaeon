"""Reject stale or invented executable subjects before main-only publication."""

from __future__ import annotations

import copy
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import pytest
from check_release_subjects import check_native_configuration, read_workflow, step, validate

ROOT = Path(__file__).resolve().parents[2]
COMPLIANCE = read_workflow(ROOT / ".github/workflows/compliance.yml")
RELEASE = read_workflow(ROOT / ".github/workflows/release.yml")


class ReleaseSubjectTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        self.compliance = copy.deepcopy(COMPLIANCE)
        self.release = copy.deepcopy(RELEASE)
        self.metadata = {
            "workspace_root": str(self.root),
            "target_directory": str(self.root / "target"),
            "workspace_members": ["server-id", "client-id"],
            "packages": [
                {
                    "id": "server-id",
                    "name": "aegaeon-server",
                    "targets": [
                        {"name": "aegaeon-server", "kind": ["bin"]},
                        {"name": "aegaeon-hosted-bootstrap", "kind": ["bin"]},
                        {"name": "aegaeon-observability-seed", "kind": ["bin"]},
                    ],
                },
                {
                    "id": "client-id",
                    "name": "aegaeon-client",
                    "targets": [{"name": "aegaeon_client", "kind": ["lib"]}],
                },
            ],
        }

    def validate(self):
        return validate(self.compliance, self.release, self.metadata, self.root)

    def test_approved_server_only_not_every_workspace_executable(self):
        assert self.validate() == Path("target/release/aegaeon-server")

    def test_library_is_not_an_executable_even_when_named_in_policy(self):
        self.compliance["env"].update(
            RELEASE_PACKAGE="aegaeon-client",
            RELEASE_BIN="aegaeon_client",
            RELEASE_BINARY="target/release/aegaeon_client",
        )
        with pytest.raises(ValueError, match="one executable, not a library"):
            self.validate()

    def test_missing_wrong_or_nonworkspace_package_and_bin(self):
        for field, value in (
            ("RELEASE_PACKAGE", "unknown"),
            ("RELEASE_PACKAGE", "aegaeon-client"),
            ("RELEASE_BIN", "unknown"),
        ):
            self.compliance = copy.deepcopy(COMPLIANCE)
            self.compliance["env"][field] = value
            with self.subTest(field=field, value=value), pytest.raises(ValueError, match="one"):
                self.validate()
        self.compliance = copy.deepcopy(COMPLIANCE)
        self.metadata["workspace_members"] = ["client-id"]
        with pytest.raises(ValueError, match="workspace member"):
            self.validate()

    def test_duplicate_and_feature_gated_bins_require_resolution(self):
        targets = self.metadata["packages"][0]["targets"]
        targets.append(copy.deepcopy(targets[0]))
        with pytest.raises(ValueError, match="one executable"):
            self.validate()
        targets.pop()
        targets[0]["required-features"] = ["unselected-feature"]
        with pytest.raises(ValueError, match="feature-gated"):
            self.validate()

    def test_missing_or_extra_attestation_subjects_fail(self):
        for job, name in (
            ("slsa-provenance", "Generate build provenance"),
            ("sbom-generation", "Generate SBOM attestation"),
        ):
            for subjects in ("", "${{ env.RELEASE_BINARY }}\ntarget/release/aegaeon-client"):
                self.compliance = copy.deepcopy(COMPLIANCE)
                step(self.compliance, job, name)["with"]["subject-path"] = subjects
                with (
                    self.subTest(job=job, subjects=subjects),
                    pytest.raises(ValueError, match="extra, omitted or different"),
                ):
                    self.validate()

    def test_additional_attestation_job_does_not_expand_the_approved_set(self):
        self.compliance["jobs"]["extra-attestation"] = {
            "steps": [
                {
                    "uses": "actions/attest@fixture",
                    "with": {"subject-path": "target/release/aegaeon-hosted-bootstrap"},
                }
            ]
        }
        with pytest.raises(ValueError, match="unexpected attestation job"):
            self.validate()

    def test_output_directory_profile_and_workspace_drift_fail(self):
        for key, value in (
            ("target_directory", str(self.root / "build-output")),
            ("workspace_root", str(self.root / "another-workspace")),
        ):
            original = self.metadata[key]
            self.metadata[key] = value
            with self.subTest(key=key), pytest.raises(ValueError, match=r"output path|workspace"):
                self.validate()
            self.metadata[key] = original
        self.compliance["env"]["RELEASE_PROFILE"] = "dev"
        with pytest.raises(ValueError, match="release profile"):
            self.validate()

    def test_build_flag_changes_cannot_silently_change_output_selection(self):
        build = step(self.compliance, "build", "Build release server")
        build["run"] += " --all-features"
        with pytest.raises(ValueError, match="selection/flags"):
            self.validate()

    def test_subject_override_and_download_destination_drift_fail(self):
        self.compliance["env"]["CARGO_TARGET_DIR"] = "elsewhere"
        with pytest.raises(ValueError, match="Cargo output overrides"):
            self.validate()
        del self.compliance["env"]["CARGO_TARGET_DIR"]
        self.compliance["jobs"]["slsa-provenance"]["env"] = {"RELEASE_BINARY": "another-file"}
        with pytest.raises(ValueError, match="override"):
            self.validate()
        del self.compliance["jobs"]["slsa-provenance"]["env"]
        step(self.compliance, "slsa-provenance", "Download release binary")["with"]["path"] = (
            "elsewhere"
        )
        with pytest.raises(ValueError, match="different directory"):
            self.validate()

    def test_phantom_tag_copy_and_ignored_copy_failure_fail(self):
        package = step(self.release, "build-release", "Package artifacts")
        original = package["run"]
        package["run"] += "\ncp target/release/aegaeon-client release-artifacts/ || true\n"
        with pytest.raises(ValueError, match="exactly the approved binary"):
            self.validate()
        package["run"] = original.replace("release-artifacts/\n", "release-artifacts/ || true\n")
        with pytest.raises(ValueError, match="exactly the approved binary"):
            self.validate()

    def test_implicit_cross_target_is_rejected(self):
        with (
            patch.dict(os.environ, {"CARGO_BUILD_TARGET": "aarch64-unknown-linux-gnu"}),
            pytest.raises(ValueError, match="CARGO_BUILD_TARGET"),
        ):
            check_native_configuration(self.root)
        config = self.root / ".cargo/config.toml"
        config.parent.mkdir()
        config.write_text('[build]\ntarget = "aarch64-unknown-linux-gnu"\n')
        with (
            patch.dict(os.environ, {"CARGO_BUILD_TARGET": ""}),
            pytest.raises(ValueError, match="implicit target configuration"),
        ):
            check_native_configuration(self.root)

    def test_actual_metadata_check_is_wired_into_required_full_lint_lane(self):
        lint = read_workflow(ROOT / ".github/workflows/lint.yml")
        check = step(lint, "lint", "Check release subjects against Cargo targets")
        assert (
            check["run"]
            == "nix develop .#ci --command python3 scripts/ci/check_release_subjects.py"
        )
        assert "if" not in check
        assert not check.get("continue-on-error", False)


if __name__ == "__main__":
    unittest.main()
