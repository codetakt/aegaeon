# ruff: noqa: S603, S607 - fixed tools and isolated file fixtures, never shell evaluation
"""Deterministic manifests must retain drift failures and merge safety."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
CHECKER = ROOT / "scripts/validation/check_runtime_drift.py"
WRAPPER = ROOT / "scripts/ci/run_runtime_drift.py"
MANIFEST = Path("spec/runtime-link-manifest.json")


def sha(data):
    return hashlib.sha256(data).hexdigest()


class RuntimeDriftFixture(unittest.TestCase):
    def setUp(self):
        self.temporary = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.root = self.temporary / "source"
        self.root.mkdir()
        self.paths = ("a.rs", "middle.rs", "z.rs", "crates/ffi/src/critical.rs")
        for path in (*self.paths, "crates/crypto/src/monitored.rs"):
            self.write(path, "first\nmiddle\nlast\n")
        self.write(
            "spec/compliance-matrix.yaml",
            json.dumps(
                {
                    "requirements": [
                        {"id": path, "status": "verified", "runtime_link": path}
                        for path in self.paths
                    ]
                }
            ),
        )
        self.generate()

    def write(self, path, text):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)

    def invoke(self, mode):
        return subprocess.run(
            [sys.executable, str(CHECKER), mode],
            cwd=self.root,
            capture_output=True,
            text=True,
            check=False,
        )

    def generate(self):
        result = self.invoke("--generate")
        assert result.returncode == 0, result.stderr
        return (self.root / MANIFEST).read_bytes()

    def merge_file(self, base, left, right):
        for name, content in (("base", base), ("left", left), ("right", right)):
            (self.temporary / name).write_bytes(content)
        return subprocess.run(
            [
                "git",
                "merge-file",
                "-p",
                str(self.temporary / "left"),
                str(self.temporary / "base"),
                str(self.temporary / "right"),
            ],
            capture_output=True,
            check=False,
        )


class RuntimeDriftTests(RuntimeDriftFixture):
    def test_repeated_generation_is_identical_and_retains_record_metadata(self):
        first = self.generate()
        second = self.generate()
        assert first == second
        manifest = json.loads(first)
        assert set(manifest) == {"files", "monitored_files"}
        assert list(manifest["files"]) == sorted(self.paths)
        for path, record in manifest["files"].items():
            assert record == {
                "sha256": sha((self.root / path).read_bytes()),
                "entries": [path],
                "critical": path.startswith("crates/ffi/"),
            }
        assert manifest["monitored_files"]["crates/crypto/src/monitored.rs"] == {
            "sha256": sha((self.root / "crates/crypto/src/monitored.rs").read_bytes()),
            "sources": ["monitored:crates/crypto/src/**/*.rs"],
            "critical": True,
        }

    def test_historical_generated_metadata_does_not_affect_clean_or_drift(self):
        manifest = json.loads(self.generate())
        manifest["generated"] = "2000-01-01T00:00:00+00:00"
        self.write(str(MANIFEST), json.dumps(manifest))
        assert self.invoke("--check").returncode == 0
        self.write("a.rs", "changed\n")
        assert self.invoke("--check").returncode == 1

    def test_changed_and_missing_runtime_files_preserve_exit_classes(self):
        for path, expected in (("a.rs", 1), ("crates/ffi/src/critical.rs", 2)):
            for missing in (False, True):
                with self.subTest(path=path, missing=missing):
                    self.write(path, "baseline\n")
                    self.generate()
                    if missing:
                        (self.root / path).unlink()
                    else:
                        self.write(path, "changed\n")
                    result = self.invoke("--check")
                    assert result.returncode == expected, result.stdout
                    assert path in result.stdout
                    self.write(path, "baseline\n")

    def test_changed_missing_and_new_monitored_files_remain_critical(self):
        path = "crates/crypto/src/monitored.rs"
        for change in ("changed", "missing", "new"):
            with self.subTest(change=change):
                self.write(path, "baseline\n")
                self.generate()
                if change == "missing":
                    (self.root / path).unlink()
                else:
                    self.write(path if change == "changed" else "crates/crypto/src/new.rs", "new\n")
                assert self.invoke("--check").returncode == 2

    def test_disjoint_source_changes_merge_with_both_digests(self):
        base = self.generate()
        self.write("a.rs", "left change\n")
        left = self.generate()
        self.write("a.rs", "first\nmiddle\nlast\n")
        self.write("z.rs", "right change\n")
        right = self.generate()
        merged = self.merge_file(base, left, right)
        assert merged.returncode == 0, merged.stdout
        self.write("a.rs", "left change\n")
        (self.root / MANIFEST).write_bytes(merged.stdout)
        assert self.invoke("--check").returncode == 0
        result = json.loads(merged.stdout)
        assert result["files"]["a.rs"]["sha256"] == sha(b"left change\n")
        assert result["files"]["z.rs"]["sha256"] == sha(b"right change\n")
        # Migration preserves the actual ancestor, which still has a timestamp.
        old_base = (
            json.dumps({"generated": "2000-01-01", **json.loads(base)}, indent=2) + "\n"
        ).encode()
        migrated = self.merge_file(old_base, left, right)
        assert migrated.returncode == 0
        assert migrated.stdout == merged.stdout

    def test_old_timestamp_conflicts_when_source_and_new_manifests_do_not(self):
        current = self.generate()
        historical = [
            json.dumps({"generated": stamp, **json.loads(current)}, indent=2).encode()
            for stamp in ("2000-01-01", "2000-01-02", "2000-01-03")
        ]
        assert self.merge_file(*historical).returncode == 1
        merged = self.merge_file(current, current, self.generate())
        assert merged.returncode == 0
        assert merged.stdout == current

    def test_combined_source_rejects_either_stale_branch_hash(self):
        base_source = b"one\ntwo\nthree\nfour\nfive\nsix\nseven\n"
        left_source = base_source.replace(b"one", b"left")
        right_source = base_source.replace(b"seven", b"right")
        for path, expected in (("a.rs", 1), ("crates/ffi/src/critical.rs", 2)):
            with self.subTest(path=path):
                self.write(path, left_source.decode())
                left_manifest = self.generate()
                self.write(path, right_source.decode())
                right_manifest = self.generate()
                merged = self.merge_file(base_source, left_source, right_source)
                assert merged.returncode == 0
                self.write(path, merged.stdout.decode())
                for stale in (left_manifest, right_manifest):
                    (self.root / MANIFEST).write_bytes(stale)
                    assert self.invoke("--check").returncode == expected


class RuntimeEvidenceTests(RuntimeDriftFixture):
    def setUp(self):
        super().setUp()
        subprocess.run(
            [
                "git",
                "clone",
                "--quiet",
                "--shared",
                "--no-checkout",
                str(ROOT),
                str(self.temporary / "git"),
            ],
            check=True,
        )
        shutil.move(self.temporary / "git/.git", self.root / ".git")
        subprocess.run(["git", "read-tree", "HEAD"], cwd=self.root, check=True)
        for source in (CHECKER, WRAPPER):
            self.write(str(source.relative_to(ROOT)), source.read_text())

    def wrapped(self, evidence, **environment):
        env = {key: value for key, value in os.environ.items() if not key.startswith("GITHUB_")}
        return subprocess.run(
            [
                sys.executable,
                str(self.root / "scripts/ci/run_runtime_drift.py"),
                "--evidence-dir",
                str(evidence),
            ],
            cwd=self.root,
            env={**env, **environment},
            capture_output=True,
            text=True,
            check=False,
        )

    def test_wrapper_preserves_status_and_binds_unchanged_manifest(self):
        for expected, path in ((0, None), (1, "a.rs"), (2, "crates/crypto/src/monitored.rs")):
            with self.subTest(expected=expected):
                self.generate()
                if path:
                    self.write(path, "changed\n")
                before = (self.root / MANIFEST).read_bytes()
                evidence = self.temporary / f"evidence-{expected}"
                result = self.wrapped(
                    evidence,
                    GITHUB_RUN_ID="123",
                    GITHUB_RUN_ATTEMPT="2",
                    GITHUB_EVENT_NAME="merge_group",
                    UNRELATED_VALUE="not-in-receipt",
                )
                assert result.returncode == expected, result.stderr
                receipt = json.loads((evidence / "receipt.json").read_text())
                assert receipt["exit_code"] == receipt["checker_exit_code"] == expected
                assert receipt["source_before"] == receipt["source_after"]
                assert receipt["source_before"]["tracked_status"]
                assert (
                    receipt["source_before"]["commit"]
                    == subprocess.check_output(
                        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
                    ).strip()
                )
                assert receipt["source_before"]["sha256"][str(MANIFEST)] == sha(before)
                assert receipt["log_sha256"] == sha((evidence / "check.log").read_bytes())
                assert datetime.fromisoformat(receipt["checked_at"]).tzinfo is not None
                assert receipt["github"] == {
                    "GITHUB_RUN_ID": "123",
                    "GITHUB_RUN_ATTEMPT": "2",
                    "GITHUB_EVENT_NAME": "merge_group",
                }
                assert "not-in-receipt" not in (evidence / "receipt.json").read_text()
                assert (self.root / MANIFEST).read_bytes() == before

    def test_mismatched_commit_and_evidence_failures_cannot_succeed(self):
        evidence = self.temporary / "mismatch"
        result = self.wrapped(evidence, GITHUB_SHA="0" * 40)
        assert result.returncode == 3
        receipt = json.loads((evidence / "receipt.json").read_text())
        assert receipt["checker_exit_code"] is None
        assert "differs" in receipt["error"]
        assert self.wrapped(evidence).returncode == 3
        assert self.wrapped(self.root / "evidence").returncode == 3
        assert not (self.root / "evidence").exists()

    def test_source_mutation_and_unexpected_status_are_evidence_failures(self):
        checker = self.root / "scripts/validation/check_runtime_drift.py"
        cases = (
            (
                (
                    "from pathlib import Path\n"
                    "Path('spec/runtime-link-manifest.json').write_text('{}')\n"
                ),
                0,
            ),
            ("raise SystemExit(42)\n", 42),
        )
        for index, (program, status) in enumerate(cases):
            with self.subTest(status=status):
                checker.write_text(program)
                evidence = self.temporary / f"invalid-{index}"
                result = self.wrapped(evidence)
                assert result.returncode == 3
                receipt = json.loads((evidence / "receipt.json").read_text())
                assert receipt["checker_exit_code"] == status
                assert receipt["error"]

    def test_missing_checker_is_recorded_without_claiming_execution(self):
        (self.root / "scripts/validation/check_runtime_drift.py").unlink()
        evidence = self.temporary / "missing-checker"
        assert self.wrapped(evidence).returncode == 3
        receipt = json.loads((evidence / "receipt.json").read_text())
        assert receipt["checker_exit_code"] is None
        assert receipt["error"]

    def test_absent_and_malformed_manifest_preserve_direct_checker_failure(self):
        manifest = self.root / MANIFEST
        for contents in (None, b"{"):
            with self.subTest(contents=contents):
                if contents is None:
                    manifest.unlink()
                else:
                    manifest.write_bytes(contents)
                direct = self.invoke("--check")
                evidence = self.temporary / ("absent" if contents is None else "malformed")
                wrapped = self.wrapped(evidence)
                assert wrapped.returncode == direct.returncode == 1
                receipt = json.loads((evidence / "receipt.json").read_text())
                assert receipt["checker_exit_code"] == receipt["exit_code"] == 1
                assert receipt["source_before"] == receipt["source_after"]
                assert receipt["source_before"]["sha256"][str(MANIFEST)] == (
                    None if contents is None else sha(contents)
                )
                assert (manifest.read_bytes() if manifest.exists() else None) == contents

    def test_workflow_keeps_failures_and_uploads_only_executed_runtime_evidence(self):
        workflow = yaml.safe_load((ROOT / ".github/workflows/verification.yml").read_text())
        steps = workflow["jobs"]["validation-scripts"]["steps"]
        check = next(step for step in steps if step.get("id") == "runtime-drift")
        upload = steps[steps.index(check) + 1]
        assert "continue-on-error" not in check
        assert "if" not in check
        assert "--generate" not in check["run"]
        assert "run_runtime_drift.py" in check["run"]
        assert upload["if"] == (
            "${{ always() && steps.runtime-drift.outcome "
            "&& steps.runtime-drift.outcome != 'skipped' }}"
        )
        assert upload["with"]["if-no-files-found"] == "error"
        assert upload["with"]["path"].splitlines() == [
            "${{ runner.temp }}/runtime-drift/receipt.json",
            "${{ runner.temp }}/runtime-drift/check.log",
        ]
        assert "check_keygen_rng.py --check" in steps[steps.index(check) - 1]["run"]
        assert "check_crypto_calls.py --check" in steps[steps.index(check) - 2]["run"]
