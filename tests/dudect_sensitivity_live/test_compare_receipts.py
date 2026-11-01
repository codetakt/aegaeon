# unittest checks must also run without pytest and under Python -O.
# ruff: noqa: PT009, PT027
"""Malformed compare capture fails with self-contained protocol fixtures."""

from __future__ import annotations

import json
import struct
import tempfile
import unittest
from pathlib import Path

import analysis_contract  # noqa: F401 -- install the native-proof module path first
import compare_receipts as receipts
from dudect_timing import BATCH, CASE_V4


class CompareReceiptsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.directory.cleanup)
        cls.root = Path(cls.directory.name)
        cls.bindings = {
            "compare": {
                "build_sha256": "1" * 64,
                "contract_sha256": "2" * 64,
                "numerical_sha256": "3" * 64,
            },
        }
        labels = bytes([0, 1]) * (receipts.N // 2)
        operands = (bytes(32) + b"\x01" + bytes(31)) * (receipts.N // 2)
        indices = struct.pack("<65536I", *range(receipts.N))
        iterations = struct.pack("<65536I", *([32] * receipts.N))
        messages = []
        with (
            (cls.root / "native.timing").open("wb") as timing,
            (cls.root / "signal.inputs").open("wb") as saved,
        ):
            timing.write(b"AEGTIM05" + b"1" * 64 + b"2" * 64 + b"3" * 64)
            timing.write(CASE_V4.pack(b"compare", 32, 0, 0, 0, 0, 0))
            saved.write(b"AEGCMP01")
            for batch in range(17):
                timing.write(BATCH.pack(batch, receipts.N, batch + 1, batch + 2, 1, 1, *([0] * 12)))
                ticks = (100 * (batch * receipts.N + i) for i in range(receipts.N))
                timing.write(struct.pack("<65536q", *ticks))
                timing.write(labels)
                saved.write(receipts.FRAME.pack(0, batch, receipts.N, 32, 0))
                saved.write(labels + operands + bytes(32) + indices + iterations)
                messages.append(
                    "SENSITIVITY_FRAME "
                    + json.dumps(
                        {
                            "target": 0,
                            "batch": batch,
                            "samples": receipts.N,
                            "profile": 0,
                        }
                    )
                )
            saved.write(b"AEGCEND1")
        messages.append(
            "SENSITIVITY_COMPLETE "
            + json.dumps(
                {
                    "target": 0,
                    "frames": 17,
                    "prepared": 17 * receipts.N,
                    "callbacks": 17 * receipts.N,
                }
            )
        )
        (cls.root / "native.stderr").write_text("\n".join(messages) + "\n")
        with (cls.root / "signal.inputs").open("rb") as saved:
            cls.prefix = saved.read(48 + receipts.N * 37 + 32 + receipts.N * 4)

    def damaged(self, offset, value, message):
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            (directory / "native.timing").symlink_to(self.root / "native.timing")
            data = bytearray(self.prefix)
            data[offset : offset + len(value)] = value
            (directory / "signal.inputs").write_bytes(data)
            with self.assertRaisesRegex(ValueError, message):
                receipts.verify(directory, self.bindings, "zero", "physical_diagnostic")

    def test_complete_fixture_is_valid_without_private_capture(self):
        result = receipts.verify(self.root, self.bindings, "zero", "physical_diagnostic")
        self.assertTrue(result["complete"])
        self.assertEqual(result["checked_frames"], 17)

    def test_wrong_magic(self):
        self.damaged(0, b"AEGSEN04", "Wrong sidecar header")

    def test_wrong_batch(self):
        self.damaged(16, struct.pack("<Q", 1), "Wrong signal frame")

    def test_wrong_stride(self):
        self.damaged(32, struct.pack("<Q", 64), "Wrong signal frame")

    def test_wrong_class(self):
        self.damaged(48, b"\x02", "Input/timing labels differ")

    def test_wrong_operand(self):
        self.damaged(48 + receipts.N + 1, b"\xff", "Actual compare operand mismatch")

    def test_wrong_secret(self):
        self.damaged(48 + receipts.N * 33, b"\x01", "Wrong comparison secret")

    def test_wrong_index(self):
        self.damaged(48 + receipts.N * 33 + 32, struct.pack("<I", 1), "Wrong sample indices")

    def test_wrong_iterations(self):
        self.damaged(
            48 + receipts.N * 37 + 32, struct.pack("<I", 48), "Wrong actual signal assignment"
        )

    def test_truncated(self):
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            (directory / "native.timing").symlink_to(self.root / "native.timing")
            (directory / "signal.inputs").write_bytes(b"AEGCMP01")
            with self.assertRaisesRegex(ValueError, "Truncated sensitivity evidence"):
                receipts.verify(directory, self.bindings, "zero", "physical_diagnostic")


if __name__ == "__main__":
    unittest.main()
