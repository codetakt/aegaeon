# Preserve import/annotation behavior of the measured checkpoint.
# unittest checks must also run without pytest and under Python -O.
# ruff: noqa: I001, I002, PT009, PT027
import copy
import json
from pathlib import Path
import tempfile
import unittest

from recovery_status import publish_completion, recovery_action


class RecoveryStatusTests(unittest.TestCase):
    def setUp(self):
        self.generation = "aeg-c64-test"
        self.digest = "a" * 64
        self.status = {
            "generation": self.generation,
            "plan_sha256": self.digest,
            "campaign": {"LoadState": "loaded", "ActiveState": "inactive", "Result": "success"},
            "recovery": {
                "LoadState": "loaded",
                "ActiveState": "inactive",
                "Result": "success",
                "ExecMainStartTimestampMonotonic": "0",
            },
            "recovery_failure": None,
            "receipt_sha256": "b" * 64,
            "upload_progress_sha256": "c" * 64,
            "recovery_completion": {
                "schema": "dudect-recovery-completion/1",
                "generation": self.generation,
                "plan_sha256": self.digest,
                "complete": True,
                "receipt_sha256": "b" * 64,
                "upload_progress_sha256": "c" * 64,
            },
        }

    def action(self):
        return recovery_action(self.status, self.generation, self.digest)

    def test_completed_unit_with_zero_timestamp_recovers(self):
        self.assertEqual(self.action(), "RECOVER")

    def test_timestamp_alone_does_not_complete(self):
        self.status["recovery_completion"] = None
        self.status["recovery"]["ExecMainStartTimestampMonotonic"] = "123456"
        self.assertEqual(self.action(), "WAIT")

    def test_each_active_writer_blocks_readback(self):
        for name in ("campaign", "recovery"):
            for state in ("active", "activating", "deactivating"):
                with self.subTest(name=name, state=state):
                    self.status[name]["ActiveState"] = state
                    self.assertEqual(self.action(), "WAIT")
                    self.status[name]["ActiveState"] = "inactive"

    def test_partial_acquisition_is_recovered_not_qualified(self):
        self.status["campaign"].update(ActiveState="failed", Result="timeout")
        self.assertEqual(self.action(), "RECOVER")

    def test_failed_recovery_not_reclassified_by_marker(self):
        self.status["recovery"]["Result"] = "exit-code"
        self.assertEqual(self.action(), "FAILED")

    def test_failure_receipt_takes_precedence(self):
        self.status["recovery_failure"] = {"error": "upload interrupted"}
        self.assertEqual(self.action(), "FAILED")

    def test_failed_without_marker_is_failure(self):
        self.status["recovery_completion"] = None
        self.status["recovery"]["ActiveState"] = "failed"
        self.assertEqual(self.action(), "FAILED")

    def test_wrong_plan_or_generation_refused(self):
        for key in ("generation", "plan_sha256"):
            original = copy.deepcopy(self.status)
            self.status[key] = "wrong"
            with self.assertRaises(ValueError):
                self.action()
            self.status = original

    def test_stale_or_incomplete_marker_refused(self):
        for key in ("schema", "generation", "plan_sha256", "complete"):
            original = copy.deepcopy(self.status)
            self.status["recovery_completion"][key] = False
            with self.assertRaises(ValueError):
                self.action()
            self.status = original

    def test_changed_recovery_files_refused(self):
        for key in ("receipt_sha256", "upload_progress_sha256"):
            original = copy.deepcopy(self.status)
            self.status[key] = "d" * 64
            with self.assertRaises(ValueError):
                self.action()
            self.status = original

    def test_missing_units_not_success(self):
        for name in ("campaign", "recovery"):
            original = copy.deepcopy(self.status)
            self.status[name]["LoadState"] = "not-found"
            with self.assertRaises(ValueError):
                self.action()
            self.status = original

    def test_unknown_state_refused(self):
        self.status["campaign"]["ActiveState"] = "unknown"
        with self.assertRaises(ValueError):
            self.action()


class CompletionPublicationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.write("execution-plan.json", {"generation": "aeg-c64-test"})
        self.write(
            "recovery-receipt.json", {"generation": "aeg-c64-test", "complete": True, "chunks": 1}
        )
        self.progress = [
            {"key": "results/aeg-c64-test/" + name, "version": str(i)}
            for i, name in enumerate(
                ("manifest.age", "000000.age", "recovery-receipt.json", "recovery-file-index.json")
            )
        ]
        self.write("upload-progress.json", self.progress)

    def write(self, name, value):
        (self.root / name).write_text(json.dumps(value))

    def test_completed_upload_publishes_once(self):
        marker = publish_completion(self.root)
        self.assertTrue(marker["complete"])
        self.assertEqual(json.loads((self.root / "recovery-completion.json").read_bytes()), marker)
        with self.assertRaises(FileExistsError):
            publish_completion(self.root)

    def test_partial_receipt_cannot_publish(self):
        self.write(
            "recovery-receipt.json", {"generation": "aeg-c64-test", "complete": False, "chunks": 1}
        )
        with self.assertRaises(ValueError):
            publish_completion(self.root)
        self.assertFalse((self.root / "recovery-completion.json").exists())

    def test_missing_upload_cannot_publish(self):
        self.write("upload-progress.json", self.progress[:-1])
        with self.assertRaises(ValueError):
            publish_completion(self.root)

    def test_duplicate_upload_cannot_replace_missing_chunk(self):
        self.progress[1] = self.progress[0]
        self.write("upload-progress.json", self.progress)
        with self.assertRaises(ValueError):
            publish_completion(self.root)

    def test_versioned_upload_is_required(self):
        self.progress[1]["version"] = None
        self.write("upload-progress.json", self.progress)
        with self.assertRaises(ValueError):
            publish_completion(self.root)

    def test_failure_record_prevents_publication(self):
        self.write("recovery-failure.json", {"error": "stopped"})
        with self.assertRaises(ValueError):
            publish_completion(self.root)

    def test_wrong_generation_cannot_publish(self):
        self.write(
            "recovery-receipt.json", {"generation": "old-generation", "complete": True, "chunks": 1}
        )
        with self.assertRaises(ValueError):
            publish_completion(self.root)


if __name__ == "__main__":
    unittest.main()
