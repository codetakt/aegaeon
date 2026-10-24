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
import textwrap
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

    def guarded_checker(self, program, status=0):
        original = CHECKER.read_text()
        guard = 'if __name__ == "__main__":\n    raise SystemExit(main())'
        assert original.count(guard) == 1
        replacement = 'if __name__ == "__main__":\n' + textwrap.indent(
            program + f"\nraise SystemExit({status})\n", "    "
        )
        self.write(str(CHECKER.relative_to(ROOT)), original.replace(guard, replacement))

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
                self.guarded_checker(program, status)
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
        invalid_manifests = (
            None,
            b"{",
            b"\xff",
            b"[]",
            b"null",
            manifest.read_text().encode("utf-16"),
            b'{"metadata": ' + b"9" * 5000 + b"}",
            b"[" * 10_000 + b"]" * 10_000,
        )
        for index, contents in enumerate(invalid_manifests):
            with self.subTest(contents=contents):
                if contents is None:
                    manifest.unlink()
                else:
                    manifest.write_bytes(contents)
                direct = self.invoke("--check")
                evidence = self.temporary / f"invalid-manifest-{index}"
                wrapped = self.wrapped(evidence)
                assert wrapped.returncode == direct.returncode == 2
                receipt = json.loads((evidence / "receipt.json").read_text())
                assert receipt["checker_exit_code"] == receipt["exit_code"] == 2
                assert receipt["source_before"] == receipt["source_after"]
                assert set(receipt["source_before"]["runtime_inputs"]) == {
                    *self.paths,
                    "crates/crypto/src/monitored.rs",
                }
                assert receipt["source_before"]["sha256"][str(MANIFEST)] == (
                    None if contents is None else sha(contents)
                )
                assert (manifest.read_bytes() if manifest.exists() else None) == contents

    def test_untracked_and_ignored_monitored_mutations_are_evidence_failures(self):
        path = "crates/crypto/src/observed.rs"
        cases = (
            (False, "create", 0),
            (False, "modify", 0),
            (True, "modify", 0),
            (True, "remove", 0),
            (False, "modify", 1),
            (True, "remove", 2),
        )
        for index, (ignored, action, status) in enumerate(cases):
            with self.subTest(ignored=ignored, action=action, status=status):
                (self.root / ".git/info/exclude").write_text(path + "\n" if ignored else "")
                self.write(path, "before\n")
                if action == "create":
                    (self.root / path).unlink()
                operation = "unlink()" if action == "remove" else "write_text('after\\n')"
                self.guarded_checker(f"pathlib.Path({path!r}).{operation}", status)
                evidence = self.temporary / f"mutation-{index}"
                assert self.wrapped(evidence).returncode == 3
                receipt = json.loads((evidence / "receipt.json").read_text())
                assert receipt["checker_exit_code"] == status
                before, after = receipt["source_before"], receipt["source_after"]
                assert before["tracked_status"] == after["tracked_status"]
                assert before["tracked_diff_sha256"] == after["tracked_diff_sha256"]
                assert before["runtime_inputs"] != after["runtime_inputs"]
                assert after["runtime_inputs"].get(path) == (
                    None if action == "remove" else sha(b"after\n")
                )

    def test_listed_untracked_symlink_target_changes_are_observed(self):
        self.write("data/target", "before\n")
        path = "outside.rs"
        (self.root / path).symlink_to(self.root / "data/target")
        manifest = json.loads((self.root / MANIFEST).read_bytes())
        manifest["files"][path] = {
            "sha256": sha(b"before\n"),
            "entries": ["outside"],
            "critical": False,
        }
        self.write(str(MANIFEST), json.dumps(manifest))
        self.guarded_checker("pathlib.Path('data/target').write_text('after\\n')")
        evidence = self.temporary / "symlink"
        assert self.wrapped(evidence).returncode == 3
        receipt = json.loads((evidence / "receipt.json").read_text())
        assert receipt["checker_exit_code"] == 0
        before, after = receipt["source_before"], receipt["source_after"]
        assert before["tracked_status"] == after["tracked_status"]
        assert before["tracked_diff_sha256"] == after["tracked_diff_sha256"]
        assert before["runtime_inputs"][path] == sha(b"before\n")
        assert after["runtime_inputs"][path] == sha(b"after\n")

    def test_stable_untracked_ignored_and_missing_inputs_preserve_checker_failures(self):
        path = "crates/crypto/src/new.rs"
        for ignored in (False, True):
            with self.subTest(ignored=ignored):
                (self.root / ".git/info/exclude").write_text(path + "\n" if ignored else "")
                self.write(path, "new\n")
                evidence = self.temporary / f"stable-{ignored}"
                assert self.wrapped(evidence).returncode == 2
                receipt = json.loads((evidence / "receipt.json").read_text())
                assert receipt["checker_exit_code"] == 2
                assert receipt["source_before"] == receipt["source_after"]
                assert receipt["source_before"]["runtime_inputs"][path] == sha(b"new\n")
                (self.root / path).unlink()
        for path, status in (("a.rs", 1), ("crates/crypto/src/monitored.rs", 2)):
            with self.subTest(path=path):
                original = (self.root / path).read_bytes()
                (self.root / path).unlink()
                evidence = self.temporary / f"missing-{status}"
                assert (
                    self.wrapped(evidence).returncode == self.invoke("--check").returncode == status
                )
                receipt = json.loads((evidence / "receipt.json").read_text())
                assert receipt["source_before"] == receipt["source_after"]
                assert receipt["source_before"]["runtime_inputs"][path] is None
                (self.root / path).write_bytes(original)

    def test_unmonitored_untracked_noise_does_not_change_the_input_inventory(self):
        self.guarded_checker("pathlib.Path('noise.txt').write_text('unrelated')")
        evidence = self.temporary / "noise"
        assert self.wrapped(evidence).returncode == 0
        receipt = json.loads((evidence / "receipt.json").read_text())
        assert receipt["source_before"] == receipt["source_after"]
        assert "noise.txt" not in receipt["source_after"]["runtime_inputs"]
        assert (self.root / "noise.txt").read_text() == "unrelated"

    def test_matrix_discovery_binds_unlisted_ignored_and_symlink_inputs(self):
        matrix = self.root / "spec/compliance-matrix.yaml"
        data = json.loads(matrix.read_text())
        path = "unlisted.rs"
        data["requirements"].append({"id": "new", "status": "verified", "runtime_link": path})
        matrix.write_text(json.dumps(data))
        self.write("target.rs", "before")
        (self.root / path).symlink_to(self.root / "target.rs")
        (self.root / ".git/info/exclude").write_text("unlisted.rs\ntarget.rs\n")
        self.guarded_checker("pathlib.Path('target.rs').write_text('after')")
        evidence = self.temporary / "discovery"
        assert self.wrapped(evidence).returncode == 3
        receipt = json.loads((evidence / "receipt.json").read_text())
        before, after = receipt["source_before"], receipt["source_after"]
        assert before["runtime_inputs"][path] == sha(b"before")
        assert after["runtime_inputs"][path] == sha(b"after")
        assert before["tracked_diff_sha256"] == after["tracked_diff_sha256"]
        assert before["sha256"]["spec/compliance-matrix.yaml"] == sha(matrix.read_bytes())

    def test_missing_and_malformed_matrix_retain_checker_failure_and_discovery_error(self):
        matrix = self.root / "spec/compliance-matrix.yaml"
        for index, contents in enumerate((None, b"{", b"{}", b"\xff")):
            with self.subTest(contents=contents):
                if contents is None:
                    matrix.unlink()
                else:
                    matrix.write_bytes(contents)
                evidence = self.temporary / f"matrix-invalid-{index}"
                assert self.wrapped(evidence).returncode == 2
                receipt = json.loads((evidence / "receipt.json").read_text())
                assert receipt["checker_exit_code"] == 2
                assert receipt["source_before"] == receipt["source_after"]
                assert receipt["source_before"]["discovery_errors"]["matrix"]
                assert receipt["source_before"]["sha256"]["spec/compliance-matrix.yaml"] == (
                    sha(contents) if contents is not None else None
                )

    def test_invalid_discovery_cannot_accept_a_successful_checker(self):
        self.write("spec/compliance-matrix.yaml", "{}")
        self.guarded_checker("pass")
        evidence = self.temporary / "invalid-discovery-success"
        assert self.wrapped(evidence).returncode == 3
        receipt = json.loads((evidence / "receipt.json").read_text())
        assert receipt["checker_exit_code"] == 0
        assert "invalid discovery" in receipt["error"]

    def test_matrix_only_mutation_cannot_keep_original_success(self):
        self.guarded_checker("pathlib.Path('spec/compliance-matrix.yaml').write_text('{}')")
        evidence = self.temporary / "matrix-mutated"
        assert self.wrapped(evidence).returncode == 3
        receipt = json.loads((evidence / "receipt.json").read_text())
        assert receipt["checker_exit_code"] == 0
        assert receipt["source_before"]["sha256"] != receipt["source_after"]["sha256"]

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


class RuntimeInputIntegrityTests(RuntimeDriftFixture):
    def matrix(self):
        return json.loads((self.root / "spec/compliance-matrix.yaml").read_text())

    def save_matrix(self, data):
        self.write("spec/compliance-matrix.yaml", json.dumps(data))

    def test_matrix_membership_and_ids_are_checked_even_when_bytes_match(self):
        original = self.matrix()
        variants = []
        for kind in ("added", "removed", "renamed", "demoted", "reattributed"):
            data = json.loads(json.dumps(original))
            rows = data["requirements"]
            if kind == "added":
                self.write("outside/new.rs", "new")
                rows.append({"id": "new", "status": "verified", "runtime_link": "outside/new.rs"})
            elif kind == "removed":
                rows.pop()
            elif kind == "renamed":
                rows[0]["runtime_link"] = "other.rs"
                self.write("other.rs", (self.root / "a.rs").read_text())
            elif kind == "demoted":
                rows[0]["status"] = "pending"
            else:
                rows[0]["id"] = "new-id"
            variants.append((kind, data))
        for kind, data in variants:
            with self.subTest(kind=kind):
                self.save_matrix(data)
                assert self.invoke("--check").returncode == 2

    def test_shared_files_symbols_and_unselected_rows_keep_existing_scope(self):
        data = self.matrix()
        data["requirements"] += [
            {"id": "another", "status": "verified", "runtime_link": "a.rs#symbol"},
            {"id": "unverified", "status": "pending", "runtime_link": "absent.rs"},
            {"id": "unlinked", "status": "verified"},
        ]
        self.save_matrix(data)
        self.generate()
        manifest = json.loads((self.root / MANIFEST).read_text())
        assert manifest["files"]["a.rs"]["entries"] == ["a.rs", "another"]
        assert "absent.rs" not in manifest["files"]
        manifest["files"]["a.rs"]["entries"].reverse()
        self.write(str(MANIFEST), json.dumps(manifest))
        assert self.invoke("--check").returncode == 0

    def test_bad_matrix_inputs_cannot_check_or_replace_manifest(self):
        original = (self.root / MANIFEST).read_bytes()
        invalid = (
            None,
            b"[",
            b"\xff",
            b"{}",
            b"[]",
            b"null",
            b"[" * 10000,
            b'{"requirements": {}}',
            b'{"requirements": [null]}',
            b'{"requirements": [], "requirements": []}',
            b"requirements: []\nrequirements: []\n",
        )
        for contents in invalid:
            with self.subTest(contents=contents):
                matrix = self.root / "spec/compliance-matrix.yaml"
                if contents is None:
                    matrix.unlink()
                else:
                    matrix.write_bytes(contents)
                for mode in ("--check", "--generate"):
                    result = self.invoke(mode)
                    assert result.returncode == 2, result.stderr
                    assert "ERROR: runtime drift input:" in result.stderr
                    assert "Traceback" not in result.stderr
                    assert (self.root / MANIFEST).read_bytes() == original

    def test_invalid_selected_links_and_ids_are_rejected(self):
        original = self.matrix()
        for field, values in (
            (
                "runtime_link",
                (
                    None,
                    1,
                    [],
                    "",
                    "#symbol",
                    "/a.rs",
                    "../a.rs",
                    "./a.rs",
                    "a//b",
                    "a/",
                    "a\\b",
                    "a\n",
                ),
            ),
            ("id", (None, 1, [], "", " ")),
        ):
            for value in values:
                with self.subTest(field=field, value=value):
                    data = json.loads(json.dumps(original))
                    data["requirements"][0][field] = value
                    self.save_matrix(data)
                    assert self.invoke("--check").returncode == 2
                    assert self.invoke("--generate").returncode == 2
        data = original
        data["requirements"].append(data["requirements"][0].copy())
        self.save_matrix(data)
        assert self.invoke("--generate").returncode == 2

    def test_missing_or_nonfile_link_does_not_write_partial_generation(self):
        before = (self.root / MANIFEST).read_bytes()
        data = self.matrix()
        data["requirements"].append(
            {"id": "missing", "status": "verified", "runtime_link": "absent.rs"}
        )
        self.save_matrix(data)
        self.write("a.rs", "changed but not ready for publication")
        for is_directory in (False, True):
            with self.subTest(is_directory=is_directory):
                if is_directory:
                    (self.root / "absent.rs").mkdir()
                assert self.invoke("--generate").returncode == 2
                assert (self.root / MANIFEST).read_bytes() == before

    def test_manifest_membership_and_attribution_are_required(self):
        original = json.loads((self.root / MANIFEST).read_text())
        for kind in (
            "missing",
            "stale",
            "missing_entries",
            "empty_entries",
            "duplicate",
            "wrong_id",
        ):
            with self.subTest(kind=kind):
                data = json.loads(json.dumps(original))
                record = data["files"]["a.rs"]
                if kind == "missing":
                    del data["files"]["a.rs"]
                elif kind == "stale":
                    data["files"]["old.rs"] = record
                elif kind == "missing_entries":
                    del record["entries"]
                else:
                    record["entries"] = {
                        "empty_entries": [],
                        "duplicate": ["a.rs", "a.rs"],
                        "wrong_id": ["wrong"],
                    }[kind]
                self.write(str(MANIFEST), json.dumps(data))
                assert self.invoke("--check").returncode == 2

    def test_invalid_manifest_groups_records_paths_and_fields_fail(self):
        original = json.loads((self.root / MANIFEST).read_text())
        for group in ("files", "monitored_files"):
            for invalid in (None, [], "", 1):
                with self.subTest(group=group, invalid=invalid):
                    data = dict(original, **{group: invalid})
                    self.write(str(MANIFEST), json.dumps(data))
                    assert self.invoke("--check").returncode == 2
        for record in (
            None,
            {},
            {"sha256": "bad"},
            {"sha256": 42},
            {"sha256": "0" * 64, "entries": [None]},
        ):
            with self.subTest(record=record):
                data = json.loads(json.dumps(original))
                data["files"]["a.rs"] = record
                self.write(str(MANIFEST), json.dumps(data))
                assert self.invoke("--check").returncode == 2
        data = json.loads(json.dumps(original))
        data["monitored_files"]["../escape"] = next(iter(data["monitored_files"].values()))
        self.write(str(MANIFEST), json.dumps(data))
        assert self.invoke("--check").returncode == 2

    def test_duplicate_manifest_keys_fail(self):
        path = self.root / MANIFEST
        original = path.read_text()
        for text in (
            original.replace('"files": {', '"files": {}, "files": {', 1),
            original.replace('"critical": false', '"critical": true, "critical": false', 1),
        ):
            with self.subTest(text=text[:80]):
                path.write_text(text)
                assert self.invoke("--check").returncode == 2

    def test_critical_policy_cannot_be_downgraded_or_mistyped(self):
        original = json.loads((self.root / MANIFEST).read_text())
        for group, path in (
            ("files", "crates/ffi/src/critical.rs"),
            ("monitored_files", "crates/crypto/src/monitored.rs"),
        ):
            for value in (False, 1, "true", None):
                with self.subTest(group=group, value=value):
                    data = json.loads(json.dumps(original))
                    data[group][path]["critical"] = value
                    self.write(str(MANIFEST), json.dumps(data))
                    assert self.invoke("--check").returncode == 2
        for group in original.values():
            for record in group.values():
                record.pop("critical")
        self.write(str(MANIFEST), json.dumps(original))
        assert self.invoke("--check").returncode == 0
        self.write("crates/ffi/src/critical.rs", "changed")
        assert self.invoke("--check").returncode == 2


class VerifiedReqsDriftDispatchTests(unittest.TestCase):
    def test_actual_script_only_allows_valid_noncritical_drift_as_advisory(self):
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        script = ROOT / "scripts/flake/verify_reqs.sh"
        helpers = root / "scripts/flake"
        helpers.mkdir(parents=True)
        shutil.copyfile(
            script.with_name("dudect_output_permissions.sh"),
            helpers / "dudect_output_permissions.sh",
        )
        binary = root / "bin"
        binary.mkdir()
        shim = binary / "python3"
        shim.write_text(
            "#!/usr/bin/env bash\n"
            'printf "%s\\n" "$*" >> "$DISPATCH_LOG"\n'
            'if [[ "$1" == "scripts/validation/check_runtime_drift.py" ]]; then\n'
            '  exit "$DRIFT_STATUS"\nfi\n'
        )
        shim.chmod(0o755)
        for status in (0, 1, 2, 3, 42, 127, 137):
            with self.subTest(status=status):
                log = root / f"calls-{status}.log"
                result = subprocess.run(
                    ["bash", str(script)],
                    cwd=root,
                    env={
                        **os.environ,
                        "PATH": f"{binary}:{os.environ['PATH']}",
                        "DISPATCH_LOG": str(log),
                        "DRIFT_STATUS": str(status),
                        "AEGAEON_ASSURANCE_SOURCE_DIR": str(root),
                        "OUT_DIR": str(root),
                    },
                    text=True,
                    capture_output=True,
                    check=False,
                )
                assert result.returncode == (0 if status in (0, 1) else 1), (
                    result.stdout + result.stderr
                )
                calls = log.read_text()
                assert "check_runtime_drift.py --check" in calls
                assert ("check_crypto_calls.py --check" in calls) == (status in (0, 1))
                assert ("with warnings" in result.stdout) == (status == 1)
