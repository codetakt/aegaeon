"""Private prefix-only distributed calibration; never an adopted gate."""

from __future__ import annotations

import copy
import hashlib
import math
import struct
from collections import Counter

from dudect_candidate import ALPHA, canonical, digest, significant
from dudect_results import BATCH_SIZE, CANDIDATE_PROFILES, NONDETECTION, welch
from dudect_sparse_runtime import PrefixReader
from dudect_support import require

SEED = b"aegaeon-retained-hmac-calibration-design-20261016-v1"
LOOKS = CANDIDATE_PROFILES["pr"][0]
POLICY = {
    "schema": "hmac-distributed-calibration-experiment/1",
    "case": "nix/hmac_sha256",
    "profile": "pr",
    "seed_hex": SEED.hex(),
    "selector": "sha256(seed/packet/unit/<little-endian uint32 batch,block>)[0]&15",
    "slots": "16 original indices per block; reserve before index/delta admissibility",
    "sample_admission": "10<=i<65535 and nonnegative int64 delta",
    "pilot": "excluded from new calibration; original center and raw0/101 retained",
    "quantile": "floor(n*(1-pow(0.5,10*(j+1)/100))); inclusive ties",
    "moments": "exact integer sums of int(float(native_tick)); round mean and M2 once",
    "tail": "existing fractional-df Welch with both positive variances; no sparse transfer",
    "alpha_hex": ALPHA.hex(),
    "looks": list(LOOKS),
    "classification": "separate exploratory history, absorbing detections, no OR with original",
}
POLICY_SHA256 = digest(canonical(POLICY))


def selectors(packet: str, unit: str, batch: int, size: int = BATCH_SIZE):
    require(size % 16 == 0 and size > 16, "Invalid frame size")
    require(
        isinstance(packet, str) and isinstance(unit, str) and packet and unit,
        "Missing frozen split domain",
    )
    require("/" not in packet and "/" not in unit, "Ambiguous split domain")
    domain = SEED + b"/" + packet.encode() + b"/" + unit.encode() + b"/"
    return [
        hashlib.sha256(domain + struct.pack("<II", batch, block)).digest()[0] & 15
        for block in range(size // 16)
    ]


def cutoffs(hist):
    count = sum(hist.values())
    require(count > 0, "Empty distributed calibration prefix")
    targets = [int(count * (1 - math.pow(0.5, 10 * (j + 1) / 100))) for j in range(100)]
    result, accumulated, index = [], 0, 0
    for value in sorted(hist):
        frequency = hist[value]
        accumulated += frequency
        while index < 100 and targets[index] < accumulated:
            result.append(value)
            index += 1
    require(len(result) == 100, "Incomplete calibration quantiles")
    return result


def cropped_moments(hist, thresholds):
    """Exact cancellation-free moments of the original binary64 tick conversion."""
    values = iter(sorted(hist))
    tick = next(values, None)
    n = total = squares = 0
    result = []
    for threshold in thresholds:
        while tick is not None and tick <= threshold:
            count = hist[tick]
            value = int(float(tick))
            n += count
            total += value * count
            squares += value * value * count
            tick = next(values, None)
        result.append({"n": n, "sum": total, "sum2": squares})
    return result


def test_moments(pair, index):
    counts = [m["n"] for m in pair]
    means = [m["sum"] / m["n"] if m["n"] else 0.0 for m in pair]
    m2s = [(m["n"] * m["sum2"] - m["sum"] ** 2) / m["n"] if m["n"] else 0.0 for m in pair]
    result = welch(counts + means + m2s)
    if result["eligible"]:
        result["alpha"] = ALPHA
    return {"id": index, **result}


class Partition:
    def __init__(self, packet, unit):
        self.packet, self.unit = packet, unit
        self.batch = -1
        self.calibration = Counter()
        self.testing = [Counter(), Counter()]
        self.reserved_by_class = [0, 0]
        self.rejected = 0
        self.slot_digest = hashlib.sha256()

    def push(self, payload, batch, size=BATCH_SIZE):
        require(batch == self.batch + 1 and batch <= 16, "Missing, future or reordered frame")
        require(len(payload) == size * (9 + 32), "Truncated HMAC frame")
        # Selection is a function of fixed identifiers and original indices only.
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

    def evaluate(self, row, sparse_proof):
        require(
            row["case"] == "hmac_sha256"
            and row["binding"]["case_id"] == POLICY["case"]
            and row["profile"] == "pr",
            "Wrong distributed calibration scope",
        )
        require(row["batches"] == self.batch == LOOKS[row["look"] - 1], "Future prefix used")
        require(sparse_proof["row_sha256"] == digest(canonical(row)), "Wrong original row")
        counts = [sum(h.values()) for h in self.testing]
        require(
            [counts[g] + self.reserved_by_class[g] for g in (0, 1)] == row["statistics"][0][:2],
            "Reserved/test/raw count mismatch",
        )
        require(self.rejected == row["rejected"], "Wrong rejected count")
        thresholds = cutoffs(self.calibration)
        moments = [cropped_moments(h, thresholds) for h in self.testing]
        tests = [test_moments([moments[g][j] for g in (0, 1)], j + 1) for j in range(100)]
        return {
            "analysis_binding": {
                "policy_sha256": POLICY_SHA256,
                "packet": self.packet,
                "unit": self.unit,
                "seed_hex": SEED.hex(),
            },
            "native_binding": copy.deepcopy(row["binding"]),
            "row_sha256": sparse_proof["row_sha256"],
            "look": row["look"],
            "through_batch": self.batch,
            "prefix": {
                k: sparse_proof[k]
                for k in ("prefix_start", "prefix_end", "case_start", "prefix_sha256")
            },
            "slot_assignment_sha256": self.slot_digest.hexdigest(),
            "reserved_counts": self.reserved_by_class.copy(),
            "test_counts": counts,
            "calibration_count": sum(self.calibration.values()),
            "cutoffs": thresholds,
            "moments": [[moments[g][j] for g in (0, 1)] for j in range(100)],
            "tests": tests,
        }


class History:
    def __init__(self):
        self.next_look = 1
        self.detected = set()

    def append(self, row, sparse_proof, evaluated):
        require(row["look"] == evaluated["look"] == self.next_look, "Candidate look reordered")
        require(
            row["batches"] == evaluated["through_batch"] == LOOKS[self.next_look - 1],
            "Wrong candidate look prefix",
        )
        tests = copy.deepcopy(sparse_proof["history"]["effective"]["tests"])
        tests[1:101] = copy.deepcopy(evaluated["tests"])
        detected_now = [t["id"] for t in tests if significant(t)]
        self.detected.update(detected_now)
        final = self.next_look == len(LOOKS)
        outcome = (
            "leakage_detected"
            if self.detected
            else "collecting"
            if not final
            else NONDETECTION
            if min(row["statistics"][0][:2]) >= 200000 and all(t["eligible"] for t in tests)
            else "inconclusive"
        )
        self.next_look += 1
        return {
            "tests": tests,
            "detected_now": detected_now,
            "detected_ever": sorted(self.detected),
            "exploratory_outcome": outcome,
            "collection_complete": final,
            "adopted": False,
        }


class DistributedReader(PrefixReader):
    """Share original prefix validation and resource transaction, preserving its proof.

    This adapter is used only by offline replay. No gate/ACK code is changed.
    The base reader reads exactly one current payload, before Prefix.push consumes it.
    """

    def __init__(self, path, bindings, packet, unit):
        super().__init__(path, bindings, "pr")
        self.partition = Partition(packet, unit)
        self.candidate_history = History()

    def read(self, size):
        data = super().read(size)
        if (
            self.index < len(self.names)
            and self.names[self.index] == "hmac_sha256"
            and self.prefix is not None
            and size == BATCH_SIZE * 41
        ):
            self.partition.push(data, self.prefix.batch + 1)
        return data

    def push(self, row):
        original = super().push(row)
        candidate = None
        if row["case"] == "hmac_sha256":
            candidate = self.partition.evaluate(row, original)
            candidate["history"] = self.candidate_history.append(row, original, candidate)
        return {"original_sparse_proof": original, "distributed_candidate": candidate}
