# ruff: noqa: PT009, PT027 - assertions remain active under unittest and Python -O
"""Adversarial process and evidence controls for the native acknowledgment protocol."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from test_dudect_candidate import binding as candidate_binding, observation as candidate_observation
from test_dudect_statistics import observation

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "constant_time"))
from dudect_process import NativeError, run_native
from run_candidate import collect


class DudectProcessTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.binary = self.root / "native"

    def program(self, source):
        self.binary.write_text(f"#!{sys.executable}\n" + source)
        self.binary.chmod(0o755)

    def execute(self):
        return run_native(self.root, self.root, self.binary, ("compare",), "pr")

    def status(self):
        return json.loads((self.root / "native.process.json").read_text())

    def test_exit_and_signal_are_preserved(self):
        for source, code in (
            ("raise SystemExit(43)", 43),
            ("import os, signal\nos.kill(os.getpid(), signal.SIGTERM)", 143),
        ):
            self.program(source)
            with self.assertRaises(NativeError) as caught:
                self.execute()
            self.assertEqual(caught.exception.code, code)
            self.assertFalse(self.status()["accepted"])

    def test_empty_partial_and_non_json_output_cannot_succeed(self):
        for source in ("pass", "print('{}', end='')", "print('nan')"):
            self.program(source)
            with self.assertRaises(ValueError):
                self.execute()
            self.assertFalse(self.status()["accepted"])

    def test_failed_inspection_is_not_acknowledged(self):
        row = observation()
        row["statistics"][0][2] = 1000
        self.program(
            "import sys\n"
            f"print({json.dumps(row)!r}, flush=True)\n"
            "sys.stdin.buffer.read(1)\n"
            "from pathlib import Path\nPath('incorrect-ack').touch()\n"
        )
        with self.assertRaisesRegex(ValueError, "leakage_detected"):
            self.execute()
        self.assertFalse((self.root / "incorrect-ack").exists())
        self.assertIn("leakage_detected", (self.root / "native.decisions.json").read_text())

    def test_complete_schedule_requires_successful_process_exit(self):
        rows = [json.dumps(observation(look=look)) for look in range(1, 8)]
        self.program(
            "import sys\n"
            f"for row in {rows!r}:\n"
            " print(row,flush=True)\n sys.stdin.buffer.read(1)\n"
            "raise SystemExit(43)\n"
        )
        with self.assertRaises(NativeError):
            self.execute()
        self.assertFalse(self.status()["accepted"])

    def test_extra_observation_after_success_is_rejected(self):
        rows = [json.dumps(observation(look=look)) for look in range(1, 8)]
        self.program(
            "import sys\n"
            f"for row in {rows!r}:\n"
            " print(row,flush=True)\n sys.stdin.buffer.read(1)\n"
            "print('{}',flush=True)\n"
        )
        with self.assertRaisesRegex(ValueError, "extra native observation"):
            self.execute()

    def test_deadline_kills_owned_descendants_and_retains_failure(self):
        self.program(
            "import os, time\nfrom pathlib import Path\n"
            "child=os.fork()\n"
            "if child: Path('child.pid').write_text(str(child))\n"
            "time.sleep(60)\n"
        )
        with (
            patch.dict("dudect_process.PROFILES", {"pr": (tuple(range(1, 8)), 200000, 0.2)}),
            self.assertRaisesRegex(ValueError, "deadline"),
        ):
            self.execute()
        child = int((self.root / "child.pid").read_text())
        state = Path(f"/proc/{child}/status")
        if state.exists():
            self.assertIn("\nState:\tZ", state.read_text())
        self.assertFalse(self.status()["accepted"])

    def test_output_bound_retains_output_and_stops_process(self):
        self.program("import sys\nsys.stdout.write('x'*2000000)\nsys.stdout.flush()\n")
        with self.assertRaisesRegex(ValueError, "output exceeded"):
            self.execute()
        self.assertGreater((self.root / "native.stdout").stat().st_size, 0)

    def test_evidence_write_failure_cannot_publish_success(self):
        self.program("pass")
        (self.root / "native.observations.json").mkdir()
        with self.assertRaises(OSError):
            self.execute()
        self.assertFalse(self.status()["accepted"])


class DudectCandidateDeadlineTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.binary = self.root / "native"
        self.names = ("ct_eq_32", "ct_eq_64")
        self.bindings = {name: candidate_binding(name, suite="nix") for name in self.names}

    def program(self, delays=(0, 0), *, per_look=0, final_exit=0):
        rows = [
            [json.dumps(candidate_observation(name, look=look)) for look in range(1, 8)]
            for name in self.names
        ]
        self.binary.write_text(
            f"#!{sys.executable}\nimport sys, time\n"
            f"for delay, rows in zip({delays!r}, {rows!r}, strict=True):\n"
            " time.sleep(delay)\n"
            " for row in rows:\n"
            f"  time.sleep({per_look!r})\n"
            "  print(row, flush=True)\n  sys.stdin.buffer.read(1)\n"
            f"time.sleep({final_exit!r})\n"
        )
        self.binary.chmod(0o755)

    def execute(self):
        with patch.dict("run_candidate.PROFILES", {"pr": (tuple(range(1, 8)), 200000, 1.0)}):
            return collect(self.root, self.root, self.binary, "pr", self.bindings)

    def assert_deadline(self):
        with self.assertRaisesRegex(ValueError, "deadline"):
            self.execute()
        status = json.loads((self.root / "process.json").read_text())
        self.assertFalse(status["collection_complete"])
        self.assertFalse(status["accepted"])
        self.assertNotEqual(status["exit"], 0)
        self.assertTrue((self.root / "native.stdout").is_file())
        self.assertTrue((self.root / "observations.json").is_file())
        self.assertTrue((self.root / "decisions.json").is_file())

    def test_first_case_cannot_borrow_later_case_budget(self):
        self.program(delays=(1.5, 0))
        self.assert_deadline()

    def test_later_case_cannot_borrow_unused_earlier_budget(self):
        self.program(delays=(0, 1.5))
        self.assert_deadline()

    def test_completed_case_starts_a_fresh_individual_budget(self):
        self.program(delays=(0.6, 0.6))
        observed = self.execute()
        self.assertEqual(set(observed), set(self.names))
        self.assertTrue(json.loads((self.root / "process.json").read_text())["collection_complete"])

    def test_each_look_cannot_restart_the_case_budget(self):
        self.program(per_look=0.2)
        self.assert_deadline()

    def test_final_observation_does_not_renew_process_exit_budget(self):
        self.program(final_exit=1.5)
        self.assert_deadline()


if __name__ == "__main__":
    unittest.main()
