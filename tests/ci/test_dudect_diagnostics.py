# ruff: noqa: PT009, PT027 - assertions remain active under unittest and Python -O
"""Adversarial capture framing and telemetry failure behavior."""

from __future__ import annotations

import errno
import io
import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from test_dudect_candidate import binding

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "constant_time"))
from dudect_diagnostics import FRAME, RuntimeCapture, msr, speculation_policy, validate_trace
from dudect_process import ObservationStream
from dudect_timing import BATCH, CASE, validate_timing


class DiagnosticTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.path = self.root / "trace"
        self.binding = binding("ct_eq_128", suite="nix")
        self.header = b"AEGTRC01" + b"".join(
            self.binding[k].encode()
            for k in ("build_sha256", "contract_sha256", "numerical_sha256")
        )
        # Small structural fixture; native batch size remains fixed in production.
        self.enterContext(patch("dudect_diagnostics.BATCH_SIZE", 2))
        self.enterContext(patch.dict("dudect_diagnostics.PROFILES", {"pr": ((1,), 1, 1)}))
        self.frame = FRAME.pack(0, 2, 128, 32) + struct.pack("<2q", 100, 120)
        self.frame += bytes([0, 1]) + bytes(32) + bytes([7]) * 32
        self.good = self.header + self.frame + FRAME.pack(1, 2, 128, 32) + self.frame[32:]
        self.path.write_bytes(self.good)

    def test_complete_trace_binds_original_order_and_identity(self):
        result = validate_trace(self.path, self.binding, "pr")
        self.assertEqual(result["frames"], 2)
        self.assertEqual(result["bytes"], len(self.good))
        self.assertTrue(result["complete"])

    def test_truncation_append_binding_sequence_class_and_input_rejected(self):
        changes = [self.good[:-1], self.good + b"x"]
        for offset in (0, 8, 200, 200 + 48, 200 + 50):
            bad = bytearray(self.good)
            bad[offset] = 9
            changes.append(bytes(bad))
        for data in changes:
            with self.subTest(size=len(data)), self.assertRaises(ValueError):
                self.path.write_bytes(data)
                validate_trace(self.path, self.binding, "pr")

    def test_missing_privileged_counters_are_explicit(self):
        with patch(
            "dudect_diagnostics.os.open", side_effect=PermissionError(errno.EACCES, "denied")
        ):
            self.assertEqual(msr(0), {"unavailable_errno": errno.EACCES})

    def test_short_counter_read_is_not_a_valid_zero(self):
        with (
            patch("dudect_diagnostics.os.open", return_value=5),
            patch("dudect_diagnostics.os.pread", return_value=b""),
            patch("dudect_diagnostics.os.close"),
        ):
            self.assertEqual(msr(0), {"unavailable_errno": errno.EIO})

    def test_runtime_capture_avoids_environment_and_records_unavailability(self):
        output = io.BytesIO()
        with (
            patch("dudect_diagnostics.os.sched_getaffinity", return_value={3}),
            patch("dudect_diagnostics.read_optional", return_value={"unavailable_errno": 2}),
            patch("dudect_diagnostics.cpu_identity", return_value={"model": "test"}),
            patch("dudect_diagnostics.msr", return_value={"unavailable_errno": 13}),
        ):
            RuntimeCapture(output).snapshot("start")
        row = json.loads(output.getvalue())
        self.assertEqual(row["native_affinity"], [3])
        self.assertEqual(row["cpus"]["3"]["msr"]["unavailable_errno"], 13)
        self.assertNotIn("environment", row)
        self.assertEqual(row["platform"]["spec_store_bypass"], {"unavailable_errno": 2})

    def test_speculation_policy_filters_unrelated_process_fields(self):
        status = (
            "Name:\tprivate-process\nUid:\t1000\n"
            "Speculation_Store_Bypass:\tthread mitigated\n"
            "SpeculationIndirectBranch:\tconditional enabled\n"
            "NoNewPrivs:\t0\nSeccomp:\t2\nUnknown:\tprivate value\n"
        )
        with patch("dudect_diagnostics.read_optional", return_value={"value": status}) as read:
            result = speculation_policy(1234)
        read.assert_called_once_with("/proc/1234/status")
        self.assertEqual(
            result,
            {
                "fields": {
                    "Speculation_Store_Bypass": "thread mitigated",
                    "SpeculationIndirectBranch": "conditional enabled",
                    "NoNewPrivs": "0",
                    "Seccomp": "2",
                },
                "missing_fields": [],
            },
        )

    def test_missing_policy_is_explicit_and_not_inferred_from_seccomp(self):
        with patch("dudect_diagnostics.read_optional", return_value={"value": "Seccomp: 2"}):
            result = speculation_policy(1234)
        self.assertEqual(result["fields"], {"Seccomp": "2"})
        self.assertEqual(
            result["missing_fields"],
            ["Speculation_Store_Bypass", "SpeculationIndirectBranch", "NoNewPrivs"],
        )

    def test_policy_read_failures_and_size_limit_remain_unavailable(self):
        for result in (
            {"unavailable_errno": errno.ENOENT},
            {"unavailable_errno": errno.EACCES},
            {"unavailable": "size limit"},
        ):
            with (
                self.subTest(result=result),
                patch("dudect_diagnostics.read_optional", return_value=result),
            ):
                self.assertEqual(speculation_policy(1234), result)

    def test_failed_capture_cannot_acknowledge_next_native_batch(self):
        stream = ObservationStream(("compare",), "pr")
        stream.before_observation = lambda: (_ for _ in ()).throw(OSError("disk full"))
        ack = io.BytesIO()
        with self.assertRaises(OSError):
            stream.consume(b"{}\n", ack)
        self.assertEqual(ack.getvalue(), b"")

    def test_native_scheduler_context_uses_only_owned_process(self):
        output = io.BytesIO()
        with (
            patch("dudect_diagnostics.os.sched_getaffinity", return_value={1}),
            patch(
                "dudect_diagnostics.read_optional", return_value={"unavailable_errno": 2}
            ) as read,
            patch("dudect_diagnostics.msr", return_value={"unavailable_errno": 13}),
        ):
            RuntimeCapture(output).snapshot("observation", 1234, case="sha256", look=1)
        row = json.loads(output.getvalue())
        self.assertEqual(
            set(row["native_process"]), {"stat", "sched", "schedstat", "speculation_policy"}
        )
        for name in ("stat", "sched", "schedstat", "status"):
            read.assert_any_call(f"/proc/1234/{name}")
        self.assertEqual(row["native_process"]["speculation_policy"], {"unavailable_errno": 2})
        self.assertGreaterEqual(row["capture_finished_monotonic_ns"], row["monotonic_ns"])

    def timing_fixture(self):
        self.enterContext(patch("dudect_timing.BATCH_SIZE", 2))
        self.enterContext(patch.dict("dudect_timing.PROFILES", {"pr": ((1,), 1, 1)}))
        names = ("ct_eq_64", "sha256", "hmac_sha256_key")
        bindings = {name: binding(name, suite="nix") for name in names}
        data = b"AEGTIM03" + self.header[8:]
        stamp = 1
        for name in names:
            stride = 64 if name == "ct_eq_64" else 32
            width = 0 if name == "ct_eq_64" else 32
            data += CASE.pack(name.encode(), stride, width, 16, 32, 48)
            for batch in range(2):
                data += BATCH.pack(batch, 2, stamp, stamp + 1, *([0] * 14))
                stamp += 2
                data += struct.pack("<2q", 100, 110) + b"\0\1"
                if width:
                    data += bytes([0xAA if name == "sha256" else 0x42]) * 32 + bytes([7]) * 32
        return bindings, data

    def test_all_case_trace_retains_original_layout_and_input_cases(self):
        bindings, data = self.timing_fixture()
        self.path.write_bytes(data)
        validated = validate_timing(self.path, bindings, "pr")
        self.assertEqual(validated["cases"], list(bindings))
        self.assertEqual(validated["input_cases"], ["sha256", "hmac_sha256_key"])
        self.assertEqual(
            validated["buffer_offsets_mod4096"]["sha256"],
            {"inputs": 16, "ticks": 32, "classes": 48},
        )
        for name in bindings:
            for batch, clock in enumerate(validated["clock_batches"][name]):
                self.assertEqual(clock["batch"], batch)
                self.assertEqual(clock["delta_gcd"], 10)
                self.assertEqual(clock["timestamp_residue_mod_gcd"], 0)
                self.assertEqual(clock["backward_deltas"], 0)

    def repeated_timing_fixture(self, names=("sha256",)):
        self.enterContext(patch("dudect_timing.BATCH_SIZE", 16))
        self.enterContext(patch.dict("dudect_timing.PROFILES", {"pr": ((1,), 1, 1)}))
        bindings = {name: binding(name, suite="nix") for name in names}
        data = b"AEGTIM03" + self.header[8:]
        offsets = []
        for case, name in enumerate(names):
            data += CASE.pack(name.encode(), 32, 32, 16, 32, 48)
            for batch in range(2):
                stamp = 1 + case * 4 + batch * 2
                data += BATCH.pack(batch, 16, stamp, stamp + 1, *([0] * 14))
                offsets.append(len(data))
                data += struct.pack("<16q", *range(0, 160, 10))
                data += bytes(16) + bytes([0xAA]) * (16 * 32)
        return bindings, data, offsets

    def test_identical_payloads_keep_independent_context_and_results(self):
        bindings, data, _ = self.repeated_timing_fixture()
        self.path.write_bytes(data)
        result = validate_timing(self.path, bindings, "pr")
        first, second = result["distribution_batches"]["sha256"]
        self.assertIsNone(first["context"]["gap_before_ns"])
        self.assertEqual(second["context"]["gap_before_ns"], 1)
        self.assertEqual(first["classes"][0]["count"], 5)
        first["classes"][0]["order_statistics"]["min"] = -1
        self.assertEqual(second["classes"][0]["order_statistics"]["min"], 10)
        fresh = validate_timing(self.path, bindings, "pr")
        self.assertEqual(
            fresh["distribution_batches"]["sha256"][0]["classes"][0]["order_statistics"]["min"],
            10,
        )

    def test_later_timestamp_and_class_changes_are_recomputed(self):
        bindings, data, offsets = self.repeated_timing_fixture()
        changed = bytearray(data)
        changed[offsets[1] + 16 * 8 + 12] = 1
        struct.pack_into("<q", changed, offsets[1] + 14 * 8, 151)
        self.path.write_bytes(changed)
        result = validate_timing(self.path, bindings, "pr")
        first, second = result["distribution_batches"]["sha256"]
        self.assertEqual([group["count"] for group in first["classes"]], [5, 0])
        self.assertEqual([group["count"] for group in second["classes"]], [3, 1])
        self.assertEqual(second["negative_deltas"], 1)
        self.assertEqual(result["clock_batches"]["sha256"][1]["backward_deltas"], 1)

    def test_later_fixed_input_corruption_cannot_reuse_a_summary(self):
        bindings, data, offsets = self.repeated_timing_fixture()
        changed = bytearray(data)
        changed[offsets[1] + 16 * 9 + 12 * 32] ^= 1
        self.path.write_bytes(changed)
        with self.assertRaisesRegex(ValueError, "fixed-class"):
            validate_timing(self.path, bindings, "pr")

    def test_identical_payload_for_another_case_rechecks_its_fixed_input(self):
        bindings, data, _ = self.repeated_timing_fixture(("sha256", "hmac_sha256"))
        self.path.write_bytes(data)
        with self.assertRaisesRegex(ValueError, "fixed-class"):
            validate_timing(self.path, bindings, "pr")

    def test_all_case_trace_rejects_bad_context_layout_classes_and_inputs(self):
        bindings, data = self.timing_fixture()
        changes = [data[:-1], data + b"x", b"AEGTIM02" + data[8:]]
        first_batch = 200 + CASE.size
        sha_case = first_batch + 2 * (BATCH.size + 18)
        sha_inputs = sha_case + CASE.size + BATCH.size + 18
        key_case = sha_case + CASE.size + 2 * (BATCH.size + 18 + 64)
        key_inputs = key_case + CASE.size + BATCH.size + 18
        for offset in (
            0,
            8,
            200,
            264,
            272,
            first_batch,
            first_batch + 8,
            sha_inputs,
            key_inputs,
        ):
            bad = bytearray(data)
            bad[offset] = 9
            changes.append(bytes(bad))
        # Backwards clock and resource counters cannot describe a native batch.
        for field, value in ((2, 0), (2, 3), (6, 1)):
            bad = bytearray(data)
            struct.pack_into("<Q", bad, first_batch + field * 8, value)
            changes.append(bytes(bad))
        for offset, value in ((280, 4096), (sha_case + 72, 0), (key_case + 72, 0)):
            bad = bytearray(data)
            struct.pack_into("<Q", bad, offset, value)
            changes.append(bytes(bad))
        bad = bytearray(data)
        bad[first_batch + BATCH.size + 16] = 2
        changes.append(bytes(bad))
        for bad in changes:
            with self.subTest(size=len(bad)), self.assertRaises(ValueError):
                self.path.write_bytes(bad)
                validate_timing(self.path, bindings, "pr")


if __name__ == "__main__":
    unittest.main()
