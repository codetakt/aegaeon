"""Exercise the workflow's subject preflight and bundle-verification commands."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = yaml.safe_load((ROOT / ".github/workflows/compliance.yml").read_text())


def step(job, name):
    return next(item for item in WORKFLOW["jobs"][job]["steps"] if item.get("name") == name)


class ProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.subject = self.root / WORKFLOW["env"]["RELEASE_BINARY"]
        self.subject.parent.mkdir(parents=True)
        self.subject.write_bytes(b"fixture binary")
        self.bundle = self.root / "bundle.jsonl"
        self.bundle.write_text("fixture bundle\n")
        self.calls = self.root / "gh-args.json"
        gh = self.root / "gh"
        gh.write_text(
            f"#!{sys.executable}\n"
            "import json, os, pathlib, sys\n"
            "pathlib.Path(os.environ['GH_ARGS']).write_text(json.dumps(sys.argv[1:]))\n"
            "sys.exit(int(os.environ.get('GH_EXIT', '0')))\n"
        )
        gh.chmod(0o755)

    def run_step(self, job, name, **extra_env):
        return subprocess.run(  # noqa: S603 - repository command, isolated fixture directory
            ["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", step(job, name)["run"]],  # noqa: S607
            cwd=self.root,
            env={
                **os.environ,
                "PATH": f"{self.root}:{os.environ['PATH']}",
                "RELEASE_BINARY": WORKFLOW["env"]["RELEASE_BINARY"],
                "ATTESTATION_BUNDLE": str(self.bundle),
                "GITHUB_REPOSITORY": "fixture/repository",
                "GH_ARGS": str(self.calls),
                "GH_EXIT": "0",
                **extra_env,
            },
            capture_output=True,
            text=True,
            check=False,
        )

    def verify(self, **extra_env):
        return self.run_step(
            "slsa-provenance", "Verify provenance bundle against the release binary", **extra_env
        )

    def test_attestations_consume_the_uploaded_binary(self):
        upload = step("build", "Upload release binary")["with"]
        subject_input = "${{ env.RELEASE_BINARY }}"
        assert upload["path"] == subject_input
        assert upload["if-no-files-found"] == "error"
        for job in ("slsa-provenance", "sbom-generation"):
            with self.subTest(job=job):
                assert WORKFLOW["jobs"][job]["needs"] == "build"
                download = step(job, "Download release binary")["with"]
                assert download["name"] == upload["name"]
                assert Path(download["path"]) / self.subject.name == Path(
                    WORKFLOW["env"]["RELEASE_BINARY"]
                )
                attest = next(
                    item
                    for item in WORKFLOW["jobs"][job]["steps"]
                    if item.get("uses", "").startswith("actions/attest@")
                )
                assert attest["with"]["subject-path"] == subject_input
        bundle_upload = step("slsa-provenance", "Upload provenance")["with"]
        bundle_input = "${{ steps.provenance.outputs.bundle-path }}"
        assert bundle_upload["path"] == bundle_input
        assert bundle_upload["if-no-files-found"] == "error"
        verify = step("slsa-provenance", "Verify provenance bundle against the release binary")
        assert verify["env"]["ATTESTATION_BUNDLE"] == bundle_input

    def test_subject_preflight_rejects_missing_empty_and_directory(self):
        # A different output must not rescue an absent expected server binary.
        self.subject.with_name("aegaeon-client").write_bytes(b"unrelated output")
        self.subject.unlink()
        for state in ("missing", "empty", "directory"):
            if state == "empty":
                self.subject.touch()
            elif state == "directory":
                self.subject.unlink()
                self.subject.mkdir()
            for job, name in (
                ("build", "Validate release binary"),
                ("slsa-provenance", "Validate provenance subject"),
            ):
                with self.subTest(state=state, job=job):
                    assert self.run_step(job, name).returncode != 0

    def test_valid_subject_reaches_verifier_with_exact_bundle_and_identity(self):
        assert self.run_step("build", "Validate release binary").returncode == 0
        assert self.run_step("slsa-provenance", "Validate provenance subject").returncode == 0
        assert self.verify().returncode == 0
        assert json.loads(self.calls.read_text()) == [
            "attestation",
            "verify",
            WORKFLOW["env"]["RELEASE_BINARY"],
            "--bundle",
            str(self.bundle),
            "--repo",
            "fixture/repository",
            "--predicate-type",
            "https://slsa.dev/provenance/v1",
        ]

    def test_missing_or_empty_bundle_stops_before_verification(self):
        self.bundle.unlink()
        assert self.verify().returncode != 0
        assert not self.calls.exists()
        self.bundle.touch()
        assert self.verify().returncode != 0
        assert not self.calls.exists()

    def test_verification_failure_is_fatal(self):
        assert self.verify(GH_EXIT="17").returncode == 17


if __name__ == "__main__":
    unittest.main()
