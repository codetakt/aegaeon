"""Exercise the real bound final receipt independently of native execution."""
# ruff: noqa: PT009 - unittest assertions remain active under Python -O

from __future__ import annotations

import io
import json
import runpy
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]


class ZeroStatusError(OSError):
    status = 0


def withdraw(artifacts, kind):
    held = artifacts.with_name("held")
    artifacts.rename(held)
    if kind == "missing":
        return
    if kind == "replacement":
        artifacts.mkdir()
    elif kind == "file":
        artifacts.write_bytes(b"unrelated evidence path\n")
    elif kind == "symlink":
        artifacts.symlink_to(held, target_is_directory=True)
    elif kind == "dangling":
        artifacts.symlink_to(artifacts.with_name("absent"), target_is_directory=True)
    else:
        shutil.rmtree(held)


class FinalizationTests(unittest.TestCase):
    def namespace(self):
        return runpy.run_path(str(ROOT / "scripts/sanitizers/sanitizer_runner.py"))

    def test_final_receipt_directory_withdrawal_fails_without_rebinding(self):
        runner = self.namespace()
        for kind in ("missing", "replacement", "file", "symlink", "dangling", "deleted"):
            for prior in (0, 71, 143):
                with self.subTest(kind=kind, prior=prior), tempfile.TemporaryDirectory() as tmp:
                    artifacts = Path(tmp) / "evidence"
                    artifacts.mkdir()
                    summary = {"status": "failed" if prior else "completed", "error": "primary"}
                    supervisor = runner["Supervisor"](artifacts, summary)
                    supervisor.save()
                    raw = (artifacts / "run-summary.json").read_bytes()
                    withdraw(artifacts, kind)
                    with (
                        patch("sys.stdout", io.StringIO()) as stdout,
                        patch("sys.stderr", io.StringIO()) as stderr,
                    ):
                        status = runner["finish"](supervisor, prior)
                    self.assertEqual(status, prior or 1)
                    self.assertEqual(summary["status"], "failed")
                    self.assertEqual(summary["exit_code"], status)
                    self.assertNotIn("Sanitizer-backed tests completed", stdout.getvalue())
                    self.assertIn("Sanitizer evidence write failed", stderr.getvalue())
                    if kind != "deleted":
                        self.assertEqual((Path(tmp) / "held/run-summary.json").read_bytes(), raw)
                    if kind == "replacement":
                        self.assertEqual(list(artifacts.iterdir()), [])
                    if kind == "file":
                        self.assertEqual(artifacts.read_bytes(), b"unrelated evidence path\n")
                    if kind in {"missing", "deleted"}:
                        self.assertFalse(artifacts.exists())

    def test_receipt_precedes_notification_and_is_rechecked_after_it(self):
        runner = self.namespace()
        for remove in (False, True):
            with self.subTest(remove=remove), tempfile.TemporaryDirectory() as tmp:
                artifacts = Path(tmp) / "evidence"
                artifacts.mkdir()
                summary = {"status": "completed"}
                supervisor = runner["Supervisor"](artifacts, summary)
                notifications = []

                def notify(
                    message,
                    *,
                    error=False,
                    notifications=notifications,
                    artifacts=artifacts,
                    remove=remove,
                ):
                    notifications.append((message, error))
                    if not error:
                        saved = json.loads((artifacts / "run-summary.json").read_text())
                        self.assertEqual(saved, {"status": "completed", "exit_code": 0})
                        if remove:
                            artifacts.rename(artifacts.with_name("held"))

                with patch.dict(runner["finish"].__globals__, report=notify):
                    status = runner["finish"](supervisor, 0)
                self.assertEqual(status, int(remove))
                self.assertEqual(summary["exit_code"], status)
                self.assertEqual(summary["status"], "failed" if remove else "completed")
                self.assertEqual(
                    [error for _, error in notifications], [False, True] if remove else [False]
                )
                if not remove:
                    self.assertEqual(
                        json.loads((artifacts / "run-summary.json").read_text()), summary
                    )

    def test_zero_failure_status_cannot_make_final_save_or_execution_successful(self):
        runner = self.namespace()
        with tempfile.TemporaryDirectory() as tmp:
            artifacts = Path(tmp)
            supervisor = runner["Supervisor"](artifacts, {"status": "completed"})
            with (
                patch.object(
                    supervisor, "save", side_effect=ZeroStatusError("controlled zero status")
                ),
                patch("sys.stdout", io.StringIO()),
                patch("sys.stderr", io.StringIO()),
            ):
                self.assertEqual(runner["finish"](supervisor, 0), 1)
            settings = [""] * len(runner["Settings"].__dataclass_fields__)
            settings[3] = str(artifacts)
            with (
                patch.object(
                    runner["Supervisor"],
                    "execute",
                    side_effect=ZeroStatusError("controlled zero status"),
                ),
                patch("signal.signal"),
                patch("sys.argv", ["sanitizer_runner.py", *settings]),
                patch("sys.stderr", io.StringIO()),
            ):
                self.assertEqual(runner["main"](), 1)
            self.assertEqual(
                json.loads((artifacts / "run-summary.json").read_text())["exit_code"], 1
            )


if __name__ == "__main__":
    unittest.main()
