"""Check actual workflow cleanup and reporting preserve incomplete fuzz evidence."""

# Existing unittest discovery runs these checks, including under Python -O.
# ruff: noqa: PT009
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
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
        step = self.step("Upload security metrics")
        self.assertEqual(step["if"], "always() && matrix.stage != 'sbom'")
        paths = set(step["with"]["path"].splitlines())
        self.assertTrue(
            {
                "artifacts/security/latest",
                "artifacts/security/history",
                "fuzz/artifacts",
                "fuzz/corpus",
                "fuzz/corpus_archive",
                "fuzz/corpus_meta",
                "security-artifacts/security_status.jsonl",
            }.issubset(paths)
        )

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
