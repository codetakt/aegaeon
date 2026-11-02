# Use the standard-library unittest runner inside the Nix package.
# ruff: noqa: PT009, PT027
from __future__ import annotations

import copy
import io
import json
import os
import signal
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from analysis_contract import WORKER_ENVIRONMENT
from analysis_runtime import Stream, Worker
from dependencies import runtime_identity
from dudect_candidate import canonical
from fixture import capture
from run_analysis import HERE


class PackagedTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.storage = tempfile.TemporaryDirectory(prefix="dudect-fixture-")
        cls.addClassCleanup(cls.storage.cleanup)
        cls.saved = Path(cls.storage.name) / "zero"
        cls.binding, cls.analysis, cls.rows, cls.decisions, cls.role = capture(cls.saved)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="dudect-証跡-")
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name)
        self.raw = self.directory / "native.timing"
        proof = json.loads((self.saved / "sparse-prefixes.jsonl").read_text().splitlines()[0])[
            "proof"
        ]
        with (self.saved / "native.timing").open("rb") as source:
            self.raw.write_bytes(source.read(proof["prefix_end"]))
        self.errors = self.enterContext((self.directory / "errors").open("wb"))

    def worker(self, analysis=None):
        worker = Worker(
            self.raw, {"hmac_sha256": self.binding}, self.errors, analysis=analysis or self.analysis
        )
        self.addCleanup(worker.close)
        return worker

    def stream(self):
        worker = self.worker()
        stream = Stream(("hmac_sha256",), "pr", bindings={"hmac_sha256": self.binding})
        journal = self.enterContext((self.directory / "sparse-prefixes.jsonl").open("wb"))
        stream.attach(worker, journal)
        stream.deadline = time.monotonic() + 10
        return worker, stream

    def test_zero_signal_full_profile(self):
        self.assertTrue(self.role["requirement_satisfied"])
        self.assertEqual(len(self.decisions), 8)
        self.assertTrue(all(t["eligible"] for t in self.decisions[-1]["tests"]))
        original = json.loads((self.saved / "decisions.json").read_text())
        self.assertEqual(original[-1]["candidate_statistical_outcome"], "inconclusive")

    def test_clock_signals_and_maximum_support(self):
        for mode in (2, 3, 4, 5, 6):
            with self.subTest(mode=mode):
                _, _, _, decisions, role = capture(self.directory / f"mode-{mode}", mode)
                self.assertEqual(len(decisions), 8)
                self.assertFalse(decisions[-1]["numerically_unresolved_ever"])
                if mode != 6:
                    self.assertEqual(role["failure"], "leakage_detected")
                    self.assertTrue(any(1 <= i <= 100 for i in decisions[-1]["detected_ever"]))

    def test_four_exception_live_prefix_and_domain_boundaries(self):
        for mode, expected in ((7, True), (8, False), (9, True)):
            with self.subTest(mode=mode):
                directory = self.directory / f"sparse-{mode}"
                _, _, _, decisions, role = capture(directory, mode)
                self.assertEqual(role["requirement_satisfied"], expected)
                proofs = [
                    json.loads(line)["proof"]
                    for line in (directory / "analysis-prefixes.jsonl").read_text().splitlines()
                ]
                self.assertEqual(len(proofs), 8)
                self.assertEqual(decisions[-1]["detected_ever"], [])
                added = [a for p in proofs for a in p["four_exception_supplements"] if a["applied"]]
                self.assertEqual(bool(added), mode == 7)
                if mode == 7:
                    self.assertEqual(len(added), 8 * 102)
                    self.assertEqual(
                        proofs[-1]["original_sparse_proof"]["history"]["effective"][
                            "candidate_statistical_outcome"
                        ],
                        "inconclusive",
                    )
                if mode == 9:
                    self.assertEqual(
                        proofs[-1]["original_sparse_proof"]["history"]["effective"][
                            "candidate_statistical_outcome"
                        ],
                        "no_leakage_detected_within_budget",
                    )

    def test_ack_follows_both_journals(self):
        _, stream = self.stream()
        ack = io.BytesIO()
        stream.consume(canonical(self.rows[0]) + b"\n", ack)
        self.assertEqual(ack.getvalue(), b"c")
        for name in ("sparse-prefixes.jsonl", "analysis-prefixes.jsonl"):
            self.assertEqual(len((self.directory / name).read_text().splitlines()), 1)

    def test_dead_worker_no_ack(self):
        worker, stream = self.stream()
        os.kill(worker.process.pid, signal.SIGKILL)
        worker.process.wait()
        ack = io.BytesIO()
        with self.assertRaises((ValueError, OSError)):
            stream.consume(canonical(self.rows[0]) + b"\n", ack)
        self.assertEqual(ack.getvalue(), b"")

    def test_stalled_worker_respects_deadline(self):
        worker, stream = self.stream()
        os.kill(worker.process.pid, signal.SIGSTOP)
        stream.deadline = time.monotonic() + 0.05
        ack = io.BytesIO()
        start = time.monotonic()
        with self.assertRaises((ValueError, OSError)):
            stream.consume(canonical(self.rows[0]) + b"\n", ack)
        self.assertLess(time.monotonic() - start, 1)
        self.assertEqual(ack.getvalue(), b"")

    def test_future_row_and_truncated_prefix_rejected(self):
        worker = self.worker()
        with self.assertRaises(ValueError):
            worker.exchange({"row": self.rows[1]}, time.monotonic() + 10)
        worker.close()
        os.truncate(self.raw, 200)
        with self.assertRaises(ValueError):
            self.worker().exchange({"row": self.rows[0]}, time.monotonic() + 10)

    def test_disk_failure_no_ack(self):
        _, stream = self.stream()
        stream.analysis_journal.close()
        stream.analysis_journal = self.enterContext(Path("/dev/full").open("wb"))
        ack = io.BytesIO()
        with self.assertRaises((ValueError, OSError)):
            stream.consume(canonical(self.rows[0]) + b"\n", ack)
        self.assertEqual(ack.getvalue(), b"")

    def test_worker_locale_private_utf8_and_archive_free(self):
        with patch.dict(os.environ, {"LC_ALL": "en_US.UTF-8", "PYTHONUTF8": "0"}):
            previous = os.environ.copy()
            worker = self.worker()
            entries = Path(f"/proc/{worker.process.pid}/environ").read_bytes().split(b"\0")
            environment = dict(e.split(b"=", 1) for e in entries if b"=" in e)
            for key, value in WORKER_ENVIRONMENT.items():
                self.assertEqual(environment[key.encode()], value.encode())
            self.assertNotIn("locale-archive", Path(f"/proc/{worker.process.pid}/maps").read_text())
            self.assertEqual(os.environ, previous)

    def test_changed_analysis_dependency_rejected(self):
        wrong = copy.deepcopy(self.analysis)
        wrong["python_flint"]["version"] = "wrong"
        with self.assertRaises(ValueError):
            self.worker(wrong)

    def test_packaged_runtime_inventory_is_checked(self):
        actual = runtime_identity(HERE)
        self.assertEqual(actual["schema"], "dudect-nix-runtime/1")
        wrong = copy.deepcopy(actual)
        wrong["files"][next(iter(wrong["files"]))] = "0" * 64
        (self.directory / "runtime-dependencies.json").write_text(json.dumps(wrong))
        with self.assertRaises(ValueError):
            runtime_identity(self.directory)


if __name__ == "__main__":
    unittest.main()
