"""Check actual workflow cleanup and reporting preserve incomplete fuzz evidence."""

# Existing unittest discovery runs these checks, including under Python -O.
# ruff: noqa: PT009
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


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

    def execute(self, name, stage="fuzz"):
        body = self.step(name)["run"]
        body = body.replace("${{ matrix.stage }}", stage)
        body = body.replace("${{ job.status }}", "failure")
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
        process = self.execute("Cleanup transient outputs")
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
        process = self.execute("Cleanup transient outputs")
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertTrue(receipt.is_file())
        for path in paths:
            self.assertFalse((self.root / path).exists())

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
