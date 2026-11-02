# Preserve import/annotation behavior of the measured checkpoint.
# ruff: noqa: I001
"""Offline, separately bound six-case calibration candidate.

Import with the frozen analysis package on PYTHONPATH. Its native verifier and
mathematical kernels remain unchanged; this module is not an active CI gate.
"""

from __future__ import annotations

import copy
import json
import struct
from pathlib import Path

import analysis_runtime
from analysis_contract import History, interval_test
from distributed import (
    LOOKS,
    POLICY_SHA256,
    Partition,
    selectors,
    cutoffs,
    cropped_moments,
    test_moments,
)
from dudect_candidate import canonical, digest
from dudect_sparse_runtime import PrefixReader
from dudect_support import require
from dudect_timing import input_width
from sparse_four import augment as augment_four

HERE = Path(__file__).resolve().parent
CONTRACT = json.loads((HERE / "scope_contract.json").read_text())
CONTRACT_SHA256 = digest(canonical(CONTRACT))
CASES = frozenset(CONTRACT["cases"])


class ScopedPartition(Partition):
    def __init__(self, packet, unit, case_id):
        require(case_id in CASES, "Unsupported distributed case")
        super().__init__(packet, unit)
        self.case_id = case_id
        self.name = case_id.split("/")[1]
        self.width = input_width(self.name, b"AEGTIM05")

    def push(self, payload, batch, size=65536):
        require(batch == self.batch + 1 and batch <= 16, "Missing, future or reordered frame")
        require(len(payload) == size * (9 + self.width), "Wrong case frame width")
        selected = selectors(self.packet, self.unit, batch, size)
        ticks = struct.unpack_from(f"<{size}q", payload)
        labels = payload[8 * size : 9 * size]
        require(set(labels) <= {0, 1}, "Invalid class label")
        if batch:
            self.slot_digest.update(struct.pack("<II", batch, size) + bytes(selected))
            for i in range(10, size - 1):
                value = ticks[i + 1] - ticks[i]
                if value < 0:
                    self.rejected += 1
                    continue
                require(value < 2**63, "Native delta exceeds int64")
                label = labels[i]
                if i % 16 == selected[i // 16]:
                    self.calibration[value] += 1
                    self.reserved_by_class[label] += 1
                else:
                    self.testing[label][value] += 1
        self.batch = batch

    def evaluate(self, row, proof):
        require(
            row["profile"] == "pr"
            and row["case"] == self.name
            and row["binding"]["case_id"] == self.case_id,
            "Wrong case scope",
        )
        require(1 <= row["look"] <= 8, "Invalid look")
        require(row["batches"] == self.batch == LOOKS[row["look"] - 1], "Future prefix used")
        require(proof["row_sha256"] == digest(canonical(row)), "Wrong original row")
        require(
            proof["case"] == self.name
            and proof["look"] == row["look"]
            and proof["through_batch"] == self.batch,
            "Wrong proof prefix",
        )
        counts = [sum(h.values()) for h in self.testing]
        require(
            [counts[g] + self.reserved_by_class[g] for g in (0, 1)] == row["statistics"][0][:2],
            "Reserved/test/raw count mismatch",
        )
        require(self.rejected == row["rejected"], "Rejected count mismatch")
        thresholds = cutoffs(self.calibration)
        moments = [cropped_moments(h, thresholds) for h in self.testing]
        return {
            "analysis_binding": {
                "scope_sha256": CONTRACT_SHA256,
                "selector_policy_sha256": POLICY_SHA256,
                "packet": self.packet,
                "unit": self.unit,
                "case_id": self.case_id,
            },
            "native_binding": copy.deepcopy(row["binding"]),
            "row_sha256": proof["row_sha256"],
            "look": row["look"],
            "through_batch": self.batch,
            "prefix": {
                k: proof[k] for k in ("prefix_start", "prefix_end", "case_start", "prefix_sha256")
            },
            "slot_assignment_sha256": self.slot_digest.hexdigest(),
            "reserved_counts": self.reserved_by_class.copy(),
            "test_counts": counts,
            "calibration_count": sum(self.calibration.values()),
            "cutoffs": thresholds,
            "moments": [[moments[g][j] for g in (0, 1)] for j in range(100)],
            "tests": [test_moments([moments[g][j] for g in (0, 1)], j + 1) for j in range(100)],
        }


class Reader(PrefixReader):
    def __init__(self, path, bindings, analysis):
        super().__init__(path, bindings, "pr")
        require(analysis["mode"] == "distributed", "Explicit distributed baseline required")
        self.analysis = analysis
        self.partition = None
        self.histories = {name: History() for name in bindings}

    def read(self, size):
        payload = super().read(size)
        if self.index < len(self.names) and self.prefix is not None:
            name = self.names[self.index]
            cid = self.bindings[name]["case_id"]
            if cid in CASES and size == 65536 * (9 + input_width(name, b"AEGTIM05")):
                if self.partition is None or self.partition.case_id != cid:
                    self.partition = ScopedPartition(
                        self.analysis["packet"], self.analysis["unit"], cid
                    )
                self.partition.push(payload, self.prefix.batch + 1)
        return payload

    def push(self, row, deadline=None):
        factory = analysis_runtime.original_runtime.Prefix
        captured = [self.prefix]

        def create_prefix():
            captured[0] = analysis_runtime.CompactPrefix()
            return captured[0]

        analysis_runtime.original_runtime.Prefix = create_prefix
        try:
            original = super().push(row)
        finally:
            analysis_runtime.original_runtime.Prefix = factory
        base = original["history"]["effective"]
        replacement = row["binding"]["case_id"] in CASES
        require(captured[0] is not None, "Missing authenticated native prefix")
        tests, four = augment_four(
            row, base["tests"], captured[0], excluded=range(1, 101) if replacement else ()
        )
        distributed = None
        if replacement:
            distributed = self.partition.evaluate(row, original)
            tests[1:101] = distributed["tests"]
        tests = [interval_test(t, deadline) for t in tests]
        effective = self.histories[row["case"]].append(row, base, tests)
        if row["look"] == 8:
            self.partition = None  # No cross-case histograms or retained memory.
        return {
            "schema": "six-case-calibration-review/1",
            "scope_sha256": CONTRACT_SHA256,
            "original_sparse_proof": original,
            "four_exception_supplements": four,
            "distributed": distributed,
            "effective": effective,
        }
