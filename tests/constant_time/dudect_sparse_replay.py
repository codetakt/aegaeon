"""Prefix-only certificates and separate candidate histories for retained observations."""

from __future__ import annotations

import bisect
import copy
import itertools
import math
import struct
from collections import Counter
from fractions import Fraction

from dudect_candidate import CandidateAdmission, significant
from dudect_results import BATCH_SIZE, CANDIDATE_PROFILES, NONDETECTION
from dudect_sparse import settings, supplement
from dudect_support import binary64, require


class Prefix:
    """Consume frames in order; no future labels, modes or counts are consulted."""

    def __init__(self):
        self.histograms = [Counter(), Counter()]
        self.batch = -1
        self.rejected = 0
        self.pilot = None
        self.prepared_counts = [0, 0]
        self.sorted_support = None

    def push(self, payload: bytes, batch: int, size: int = BATCH_SIZE):
        require(batch == self.batch + 1, "Missing or reordered timing frame")
        require(len(payload) >= size * 9, "Truncated timestamp/label frame")
        ticks = struct.unpack_from(f"<{size}q", payload)
        labels = payload[size * 8 : size * 9]
        require(set(labels) <= {0, 1}, "Invalid class label")
        self.batch = batch
        self.prepared_counts[0] += labels.count(0)
        self.prepared_counts[1] += labels.count(1)
        self.sorted_support = None
        accepted = []
        for sample in range(10, size - 1):
            delta = ticks[sample + 1] - ticks[sample]
            if delta >= 0:
                require(delta < 2**63, "Native delta exceeds int64")
                if batch:
                    self.histograms[labels[sample]][delta] += 1
                else:
                    accepted.append(delta)
            elif batch:
                self.rejected += 1
        if not batch:
            require(bool(accepted), "Empty calibration frame")
            # Match the original ordered binary64 sum, independently of stored pilot data.
            total = 0.0
            for value in accepted:
                total += float(value)
            ordered = sorted(accepted)
            self.pilot = {
                "count": len(accepted),
                "center": total / len(accepted),
                "cutoffs": [
                    ordered[int(len(accepted) * (1 - math.pow(0.5, 10 * (i + 1) / 100)))]
                    for i in range(100)
                ],
            }

    def check_row(self, row):
        require(row["batch_size"] == BATCH_SIZE, "Unreviewed batch size")
        require(self.batch == row["batches"], "Look does not match current prefix")
        require(self.pilot == row["pilot"], "Calibration differs from original timestamps")
        require(self.rejected == row["rejected"], "Rejected delta count differs from raw prefix")
        require(
            [sum(h.values()) for h in self.histograms] == row["statistics"][0][:2],
            "Raw counts differ from original prefix",
        )

    def indexed(self):
        if self.sorted_support is None:
            self.sorted_support = []
            for histogram in self.histograms:
                values = sorted(histogram)
                counts = list(itertools.accumulate(histogram[t] for t in values))
                self.sorted_support.append((values, counts))
        return self.sorted_support

    def endpoints(self, row, index):
        limit = row["pilot"]["cutoffs"][index - 1] if 0 < index < 101 else None
        ends = [
            len(v) if limit is None else bisect.bisect_right(v, limit) for v, _ in self.indexed()
        ]
        counts = [
            c[end - 1] if end else 0 for (_, c), end in zip(self.indexed(), ends, strict=True)
        ]
        require(
            counts == row["statistics"][index][:2], "Cropped counts differ from original prefix"
        )
        return ends

    def selected(self, row, index, *, small_only=False):
        ends = self.endpoints(row, index)
        if small_only and any(end > 4 for end in ends):
            return None
        return [
            {v: self.histograms[g][v] for v in values[:end]}
            for g, ((values, _), end) in enumerate(zip(self.indexed(), ends, strict=True))
        ]


def check_moments(histogram, row, index, group):
    """Exact dyadic moments, allowing only the existing Welford forward-error budget."""
    count = sum(histogram.values())
    require(count > 0, "Empty histogram certificate")
    low, high = min(histogram), max(histogram)
    center = row["pilot"]["center"]
    values = {
        t: ((float(t) - center) * (float(t) - center) if index == 101 else float(t))
        for t in histogram
    }
    require(all(math.isfinite(v) for v in values.values()), "Nonfinite certificate value")
    vmin, vmax = min(values.values()), max(values.values())
    actual = {
        "count": count,
        "tick_min": low,
        "tick_max": high,
        "tick_min_count": histogram[low],
        "tick_max_count": histogram[high],
        "value_min_hex": vmin.hex(),
        "value_max_hex": vmax.hex(),
    }
    recorded_support = dict(row["support"][index][group])
    for key in ("value_min_hex", "value_max_hex"):
        recorded_support[key] = binary64(recorded_support[key]).hex()
    require(actual == recorded_support, "Histogram contradicts native support")
    exact = {t: Fraction(v) for t, v in values.items()}
    total = sum(exact[t] * n for t, n in histogram.items())
    squares = sum(exact[t] ** 2 * n for t, n in histogram.items())
    mean, m2 = total / count, squares - total * total / count
    recorded_mean = Fraction(float(row["statistics"][index][2 + group]))
    recorded_m2 = Fraction(float(row["statistics"][index][4 + group]))
    span = math.nextafter(vmax - vmin, math.inf)
    unit = math.ulp(vmax)
    mean_error = 4 * count * unit
    delta_error = mean_error + unit
    error = math.nextafter(
        8
        * count
        * (
            span * delta_error
            + delta_error**2
            + count * 2**-53 * (span + delta_error) ** 2
            + math.ulp(0.0)
        ),
        math.inf,
    )
    require(math.isfinite(error), "Unbounded certificate rounding error")
    require(
        abs(mean - recorded_mean) <= Fraction(mean_error),
        "Histogram contradicts native mean",
    )
    require(
        abs(m2 - recorded_m2) <= Fraction(error),
        "Histogram contradicts native squared deviations",
    )


def augment(row, original, prefix, prior_detected):
    """Preserve the complete original result; supplements only fill an unsupported test."""
    prefix.check_row(row)
    effective = copy.deepcopy(original)
    additions = []
    configuration = settings(row["binding"], row["profile"])
    for index, test in enumerate(original["tests"]):
        prefix.endpoints(row, index)
        if test.get("reason") != "degenerate_variance" or test["eligible"]:
            continue
        histograms = prefix.selected(row, index, small_only=True)
        if histograms is None:
            additions.append(
                {
                    "statistic": index,
                    "applied": False,
                    "reason": "outside_two_three_exception_domain",
                }
            )
            continue
        for group, histogram in enumerate(histograms):
            check_moments(histogram, row, index, group)
        result = supplement(test, histograms, index, row["pilot"]["center"], configuration)
        additions.append({"statistic": index, **result})
        if result["applied"]:
            effective["tests"][index] = result["decision"]
    old_detections = [t["id"] for t in original["tests"] if significant(t)]
    new_detections = [t["id"] for t in effective["tests"] if significant(t)]
    require(old_detections == new_detections, "Supplement changed an existing detection")
    detected = (
        prior_detected
        or bool(old_detections)
        or original["candidate_statistical_outcome"] == "leakage_detected"
    )
    if detected:
        effective["candidate_statistical_outcome"] = "leakage_detected"
    elif original["collection_complete"]:
        enough = min(original["raw_class_counts"]) >= CANDIDATE_PROFILES[row["profile"]][1]
        effective["candidate_statistical_outcome"] = (
            NONDETECTION
            if enough and all(t["eligible"] for t in effective["tests"])
            else "inconclusive"
        )
    return {
        "original": copy.deepcopy(original),
        "supplements": additions,
        "effective": effective,
        "detected": detected,
    }


def baseline_history(rows):
    first = rows[0]
    admission = CandidateAdmission(first["case"], first["profile"], binding=first["binding"])
    history = [admission.admit(row) for row in rows]
    require(history[-1]["collection_complete"], "Incomplete original case")
    return history
