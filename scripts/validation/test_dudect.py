"""CLI validation binds successful current observations to retained native evidence."""

from __future__ import annotations

import io
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

import check_dudect as validator


class DudectAdmissionTests(unittest.TestCase):
    def evaluate_path(self, path: Path) -> tuple[int, str]:
        output = io.StringIO()
        with (
            patch.object(sys, "argv", ["check_dudect.py", str(path)]),
            redirect_stderr(output),
            redirect_stdout(output),
        ):
            result = validator.main()
        return result, output.getvalue()

    def test_cli_delegates_to_bound_bundle_validation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            with patch.object(validator, "validate_report_file") as validate:
                status, output = self.evaluate_path(path)
            self.assertEqual(status, 0, output)
            validate.assert_called_once_with(Path(__file__).resolve().parents[2], path.resolve())
            self.assertIn("observation contract satisfied", output)
            self.assertIn("product assurance not established", output)

    def test_historical_malformed_duplicate_and_nonfinite_reports_fail(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            for content in (
                '{"state":1,"num_traces":20000}',
                '{"schema_version":2}',
                '{"schema_version":3}',
                '{"a":1,"a":2}',
                '{"a":NaN}',
                "{",
                "null",
            ):
                with self.subTest(content=content):
                    path.write_text(content)
                    self.assertEqual(self.evaluate_path(path)[0], 1)
            path.unlink()
            self.assertEqual(self.evaluate_path(path)[0], 1)


if __name__ == "__main__":
    unittest.main()
