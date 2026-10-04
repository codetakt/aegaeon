"""Check actual workflow cleanup and reporting preserve incomplete fuzz evidence."""

# Existing unittest discovery runs these checks, including under Python -O.
# ruff: noqa: PT009
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

import test_security_fuzz
import yaml

ROOT = Path(__file__).resolve().parents[2]


class SecurityFuzzWorkflowEnvironmentTests(test_security_fuzz.SecurityFuzzFixture):
    def test_workflow_environment_archives_nonempty_successful_corpus(self):
        workflow = yaml.safe_load((ROOT / ".github/workflows/security.yml").read_text())
        environment = {name: str(value) for name, value in workflow["env"].items()}
        result = self.run_suite(CI="true", **environment)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        summary = self.summary()
        self.assertEqual(summary["status"], "passed")
        self.assertEqual(summary["execution"]["coverage"], "full")
        directory = self.artifacts / "fuzz"
        archive_path = directory / summary["corpus_archive"]
        with tarfile.open(archive_path) as archive:
            for target in test_security_fuzz.TARGETS:
                self.assertEqual(archive.extractfile(f"corpus/{target}/seed").read(), b"input")
        self.assertEqual(
            archive_path.read_bytes(),
            (Path(self.env["SECURITY_HISTORY_DIR"]) / archive_path.name).read_bytes(),
        )
        marker = json.loads((directory / "collection.ok").read_text())
        self.assertEqual(marker["run_id"], summary["execution"]["run_id"])
        self.assertEqual(
            marker["summary_sha256"],
            hashlib.sha256((directory / marker["summary_file"]).read_bytes()).hexdigest(),
        )
        self.assertFalse((self.root / "fuzz/corpus").exists())


class SecurityFuzzWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bash = shutil.which("bash")
        if cls.bash is None:
            message = "bash is required for workflow execution controls"
            raise RuntimeError(message)
        workflow = yaml.safe_load((ROOT / ".github/workflows/security.yml").read_text())
        cls.steps = workflow["jobs"]["security-stage"]["steps"]

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        tools = self.root / "tools"
        tools.mkdir()
        # Execute the workflow's actual shell, substituting only rm's filesystem
        # boundary. Absolute cache paths are observed without touching host state.
        remover = tools / "rm"
        remover.write_text(
            "#!/usr/bin/env python3\n"
            "import pathlib,shutil,sys\n"
            "for name in sys.argv[1:]:\n"
            " if name.startswith('-'): continue\n"
            " p=pathlib.Path(name)\n"
            " if p.is_absolute(): continue\n"
            " if p.is_dir(): shutil.rmtree(p)\n"
            " elif p.exists(): p.unlink()\n"
        )
        remover.chmod(0o755)
        self.env = os.environ.copy()
        self.env["PATH"] = str(tools) + os.pathsep + self.env["PATH"]
        self.env["GITHUB_STEP_SUMMARY"] = str(self.root / "summary.md")

    def step(self, name):
        return next(step for step in self.steps if step.get("name") == name)

    def execute(self, name, stage="fuzz", *, outcome="failure"):
        body = self.step(name)["run"]
        body = body.replace("${{ matrix.stage }}", stage)
        body = body.replace("${{ job.status }}", "failure")
        body = body.replace("${{ steps.run_security_stage.outcome }}", outcome)
        return subprocess.run(  # noqa: S603
            [self.bash, "-e", "-o", "pipefail", "-c", body],
            cwd=self.root,
            env=self.env,
            text=True,
            capture_output=True,
            check=False,
            timeout=10,
        )

    def seed(self):
        paths = ["target", "fuzz/target", "fuzz/corpus", "fuzz/corpus_archive", "fuzz/artifacts"]
        for path in paths:
            directory = self.root / path
            directory.mkdir(parents=True)
            (directory / "input").write_text("preserve incomplete evidence")
        return paths

    def test_missing_collection_receipt_preserves_corpus_and_crashes(self):
        paths = self.seed()
        process = self.execute("Cleanup transient outputs", outcome="success")
        self.assertEqual(process.returncode, 0, process.stderr)
        for path in paths[:2]:
            self.assertFalse((self.root / path).exists())
        for path in paths[2:]:
            self.assertEqual(
                (self.root / path / "input").read_text(), "preserve incomplete evidence"
            )

    def test_collected_outputs_can_be_cleaned(self):
        paths = self.seed()
        receipt = self.root / "artifacts/security/latest/fuzz/collection.ok"
        receipt.parent.mkdir(parents=True)
        receipt.write_text("checked by required collector")
        process = self.execute("Cleanup transient outputs", outcome="success")
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertTrue(receipt.is_file())
        for path in paths:
            self.assertFalse((self.root / path).exists())

    def test_failed_cancelled_and_skipped_stages_preserve_raw_inputs_with_stale_receipt(self):
        paths = self.seed()
        receipt = self.root / "artifacts/security/latest/fuzz/collection.ok"
        receipt.parent.mkdir(parents=True)
        receipt.write_text("stale receipt from an earlier stage invocation")
        for outcome in ("failure", "cancelled", "skipped"):
            with self.subTest(outcome=outcome):
                process = self.execute("Cleanup transient outputs", outcome=outcome)
                self.assertEqual(process.returncode, 0, process.stderr)
                for path in paths[:2]:
                    self.assertFalse((self.root / path).exists())
                for path in paths[2:]:
                    self.assertEqual(
                        (self.root / path / "input").read_text(),
                        "preserve incomplete evidence",
                    )
                self.assertEqual(
                    receipt.read_text(), "stale receipt from an earlier stage invocation"
                )

    def test_cleanup_outcome_refers_to_identified_security_step(self):
        self.assertEqual(self.step("Run security stage")["id"], "run_security_stage")

    def test_other_stage_cleanup_keeps_existing_policy(self):
        paths = self.seed()
        process = self.execute("Cleanup transient outputs", stage="runtime-tests")
        self.assertEqual(process.returncode, 0, process.stderr)
        for path in paths:
            self.assertFalse((self.root / path).exists())

    def test_upload_includes_raw_fallback_and_existing_evidence(self):
        expected = {
            "artifacts/security-upload/security-evidence.tar.gz",
            "artifacts/security-upload/manifest.json",
        }
        for name, condition in (
            (
                "Upload security metrics",
                (
                    "always() && steps.package_security_upload.outcome == 'success' "
                    "&& matrix.stage != 'sbom'"
                ),
            ),
            (
                "Upload SBOM metrics",
                (
                    "always() && steps.package_security_upload.outcome == 'success' "
                    "&& matrix.stage == 'sbom'"
                ),
            ),
        ):
            step = self.step(name)
            self.assertEqual(step["if"], condition)
            self.assertEqual(set(step["with"]["path"].splitlines()), expected)
            self.assertEqual(step["with"]["if-no-files-found"], "error")
        self.assertEqual(self.step("Package security upload")["if"], "always()")
        self.assertEqual(self.step("Package security upload")["id"], "package_security_upload")

    def prepare_packager(self):
        destination = self.root / "scripts/fuzz/manage_fuzz_corpus.py"
        destination.parent.mkdir(parents=True)
        shutil.copyfile(ROOT / "scripts/fuzz/manage_fuzz_corpus.py", destination)
        self.env.update(SECURITY_UPLOAD_STAGE="fuzz", SECURITY_UPLOAD_OUTCOME="failure")

    def test_upload_archives_complete_raw_recovery_history_sbom_and_literal_links(self):  # noqa: PLR0915 - complete evidence membership and link controls
        self.prepare_packager()
        sources = (
            "artifacts/security/latest/fuzz/cleanup-recovery/id/raw/corpus",
            "artifacts/security/latest/fuzz/full-logs",
            "artifacts/security/history",
            "fuzz/corpus",
            "fuzz/artifacts",
            "fuzz/corpus_archive",
            "fuzz/corpus_meta",
            "artifacts/sbom",
        )
        for source in sources:
            directory = self.root / source
            directory.mkdir(parents=True)
            (directory / "input").write_bytes(b"complete preserved evidence " + source.encode())
        external = self.root / "external-private"
        external.mkdir()
        (external / "private").write_bytes(b"never upload external bytes")
        for source in (sources[0], "fuzz/corpus", "fuzz/artifacts"):
            directory = self.root / source
            (directory / "external-dir").symlink_to(external, target_is_directory=True)
            (directory / "external-file").symlink_to(external / "private")
        status = self.root / "security-artifacts/security_status.jsonl"
        status.parent.mkdir()
        status.write_bytes(b'{"job_status":"failure"}\n')
        result = self.execute("Package security upload")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        output = self.root / "artifacts/security-upload"
        for path in output.iterdir():
            self.assertFalse(path.is_symlink())
            self.assertTrue(path.is_file())
            self.assertEqual(path.stat().st_uid, os.geteuid())
        manifest = json.loads((output / "manifest.json").read_text())
        self.assertEqual(manifest["stage_outcome"], "failure")
        archive = output / "security-evidence.tar.gz"
        self.assertEqual(
            manifest["archive"]["sha256"], hashlib.sha256(archive.read_bytes()).hexdigest()
        )
        with tarfile.open(archive) as tar:
            names = tar.getnames()
            for source in sources:
                self.assertEqual(
                    tar.extractfile(source + "/input").read(),
                    b"complete preserved evidence " + source.encode(),
                )
            for source in (sources[0], "fuzz/corpus", "fuzz/artifacts"):
                for suffix, target in (
                    ("external-dir", external),
                    ("external-file", external / "private"),
                ):
                    member = tar.getmember(source + "/" + suffix)
                    self.assertTrue(member.issym())
                    self.assertEqual(member.linkname, str(target))
                    self.assertFalse(
                        any(name.startswith(source + "/" + suffix + "/") for name in names)
                    )
            self.assertEqual(
                tar.extractfile("security-artifacts/security_status.jsonl").read(),
                status.read_bytes(),
            )
            self.assertFalse(any("external-private" in name for name in names))
        self.assertEqual((external / "private").read_bytes(), b"never upload external bytes")

    def test_upload_packaging_rejects_source_output_aliases_specials_and_overlap(self):  # noqa: PLR0915 - exact filesystem rejection controls
        self.prepare_packager()
        raw = self.root / "fuzz/corpus"
        raw.parent.mkdir()
        external = self.root / "outside"
        external.mkdir()
        sentinel = external / "private"
        sentinel.write_bytes(b"private external bytes")
        raw.symlink_to(external, target_is_directory=True)
        result = self.execute("Package security upload")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "artifacts/security-upload").exists())
        raw.unlink()
        raw.mkdir()
        fifo = raw / "special"
        os.mkfifo(fifo)
        result = self.execute("Package security upload")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "artifacts/security-upload").exists())
        fifo.unlink()
        output = self.root / "artifacts/security-upload"
        output.parent.mkdir()
        output.symlink_to(external, target_is_directory=True)
        result = self.execute("Package security upload")
        self.assertNotEqual(result.returncode, 0)
        output.unlink()
        os.mkfifo(output)
        result = self.execute("Package security upload")
        self.assertNotEqual(result.returncode, 0)
        output.unlink()
        result = subprocess.run(  # noqa: S603 - exact owned helper with unsafe output fixture
            [
                sys.executable,
                str(self.root / "scripts/fuzz/manage_fuzz_corpus.py"),
                "--package-upload",
                str(raw),
            ],
            cwd=self.root,
            env=self.env,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(sentinel.read_bytes(), b"private external bytes")
        self.assertFalse(any(external.glob("*.tar.gz")))

    def test_upload_records_absent_roots_skipped_stage_and_preserves_nonfuzz_dispatch(self):
        self.prepare_packager()
        self.env.update(
            SECURITY_UPLOAD_STAGE="sbom", SECURITY_UPLOAD_OUTCOME="skipped", CARGO_BUILD_RUSTC=""
        )
        result = self.execute("Package security upload", stage="sbom", outcome="skipped")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        output = self.root / "artifacts/security-upload"
        manifest = json.loads((output / "manifest.json").read_text())
        self.assertEqual(manifest["stage"], "sbom")
        self.assertEqual(manifest["stage_outcome"], "skipped")
        self.assertTrue(all(record == {"present": False} for record in manifest["roots"].values()))
        with tarfile.open(output / "security-evidence.tar.gz") as tar:
            self.assertEqual(tar.getnames(), [])

    def test_summary_distinguishes_corpus_from_all_execution_results(self):
        summary = self.root / "artifacts/security/latest/fuzz/run_summary.json"
        summary.parent.mkdir(parents=True)
        targets = [f"fuzz_control_{index}" for index in range(7)]
        summary.write_text(
            json.dumps(
                {
                    "status": "failed",
                    "targets": [{"name": name, "files": 1, "size_bytes": 5} for name in targets],
                    "execution": {
                        "coverage": "full",
                        "internal_seconds": 30,
                        "watchdog_seconds": 60,
                        "targets": [
                            {
                                "name": name,
                                "build": {"status": "failed"},
                                "run": {"status": "not-run"},
                            }
                            for name in targets
                        ],
                    },
                }
            )
        )
        process = self.execute("Generate job summary")
        self.assertEqual(process.returncode, 0, process.stderr)
        output = (self.root / "summary.md").read_text()
        self.assertIn("Fuzz corpus targets recorded: 7", output)
        self.assertIn("Fuzz execution status: failed", output)
        self.assertIn("Internal seconds per target: 30", output)
        self.assertIn("Watchdog seconds per target: 60", output)
        for name in targets:
            self.assertIn(f"`{name}` build=failed run=not-run exit=n/a", output)


if __name__ == "__main__":
    unittest.main()
