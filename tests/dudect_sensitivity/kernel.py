# Preserve import/annotation behavior of the measured checkpoint.
# Inline validation reasons remain part of the evidence error protocol.
# ruff: noqa: EM101, I002, TRY003
"""Fixed design-1 synthetic timestamp fixtures; no native timing is performed."""

import argparse
import json
import resource
import struct
import time

from analysis_contract import interval_test, significant
from candidate import ScopedPartition
from dudect_candidate import canonical, digest
from requirements import OBLIGATIONS, TARGETS

N = 65536
LOOKS = [1, 2, 3, 4, 5, 6, 7, 16]
NEGATIVES = ("pilot_main_common_drift", "max_distinct_support", "identical_values", "absent_class")
PROFILES = (*OBLIGATIONS, *NEGATIVES)
PACKET = "scope-sensitivity-design1-kernel"


def frame(profile, batch, width):
    ticks, labels = [], bytearray()
    tick, state = 0, 0x6E624EB7 ^ batch
    for i in range(N):
        state = (state * 1664525 + 1013904223) & 0xFFFFFFFF
        group = state >> 31
        noise = (
            (((i * 2654435761) & 0xFFFFFFFF) ^ ((batch * 2246822519) & 0xFFFFFFFF)) >> 12
        ) % 1000
        delta = (50000 if batch else 1000) + noise
        if batch and group:
            if profile == "lower_tail" and noise < 90:
                delta += 30
            elif profile in OBLIGATIONS and profile != "lower_tail":
                start, stop = OBLIGATIONS[profile]["batches"]
                if start <= batch <= stop and (profile != "history" or (i and labels[-1] == 1)):
                    delta += 200
        if profile == "max_distinct_support" and batch:
            delta = 1000000 + batch * N + i
        if profile == "identical_values":
            delta = 1000
        if profile == "absent_class":
            group = 0
        ticks.append(tick)
        labels.append(group)
        tick += delta
    return struct.pack(f"<{N}q", *ticks) + labels + bytes(N * width)


def run(case, profile):  # noqa: C901, PLR0912, PLR0915 -- ordered evidence checks retain each rejection boundary
    if case not in TARGETS or profile not in PROFILES:
        raise ValueError("Unplanned kernel fixture")
    resource.setrlimit(resource.RLIMIT_AS, (268435456, 268435456))
    part = ScopedPartition(PACKET, profile, case)
    seen, rows, max_seconds = set(), [], 0
    first, presignal, unresolved = None, [], []
    obligation = OBLIGATIONS.get(profile)
    for batch in range(17):
        payload = frame(profile, batch, part.width)
        started = time.monotonic()
        part.push(payload, batch)
        if batch not in LOOKS:
            continue
        look = LOOKS.index(batch) + 1
        counts = [sum(h.values()) + part.reserved_by_class[g] for g, h in enumerate(part.testing)]
        row = {
            "case": part.name,
            "binding": {"case_id": case},
            "profile": "pr",
            "look": look,
            "batches": batch,
            "statistics": [counts],
            "rejected": part.rejected,
        }
        proof = {
            "row_sha256": digest(canonical(row)),
            "case": part.name,
            "look": look,
            "through_batch": batch,
            "prefix_start": 0,
            "prefix_end": batch,
            "case_start": 0,
            "prefix_sha256": "synthetic-kernel-not-native-proof",
        }
        value = part.evaluate(row, proof)
        tests = [interval_test(t, started + 10) for t in value["tests"]]
        now = [t["id"] for t in tests if significant(t)]
        seen.update(now)
        unresolved.extend(
            {"look": look, "statistic": t["id"]}
            for t in tests
            if t.get("reason") == "numerically_unresolved"
        )
        if obligation:
            if look in obligation["forbidden_presignal_looks"] and now:
                presignal.append({"look": look, "detected": now})
            if first is None and set(now).intersection(obligation["statistics"]):
                first = look
        seconds = time.monotonic() - started
        max_seconds = max(max_seconds, seconds)
        if seconds >= 10:
            raise TimeoutError("Kernel look exceeded shared worker budget")
        rows.append(
            {
                "look": look,
                "through_batch": batch,
                "raw_class_counts": counts,
                "cutoffs": value["cutoffs"],
                "moments": value["moments"],
                "tests": tests,
                "reserved_counts": value["reserved_counts"],
                "test_counts": value["test_counts"],
                "detected_now": now,
                "detected_ever": sorted(seen),
                "seconds": seconds,
            }
        )
    eligible = all(t["eligible"] for t in rows[-1]["tests"])
    common = eligible and not unresolved and min(rows[-1]["raw_class_counts"]) >= 200000
    if obligation:
        passed = common and first is not None and not presignal
    elif profile == "pilot_main_common_drift":
        passed = common and not seen
    elif profile == "max_distinct_support":
        passed = common
    else:
        passed = not eligible and not seen
    return {
        "case_id": case,
        "profile": profile,
        "passed": passed,
        "looks": rows,
        "first_required_detection_look": first,
        "presignal_detections": presignal,
        "max_look_seconds": max_seconds,
        "maxrss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        "execution_kind": "synthetic_timestamp_kernel",
        "physical_clock": False,
        "qualification_scope": "crop kernel only; full102 validity separately tested in evaluator and actual collector",  # noqa: E501 -- fixed protocol text retained byte for byte
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("case", choices=sorted(TARGETS))
    parser.add_argument("profile", choices=PROFILES)
    args = parser.parse_args()
    print(json.dumps(run(args.case, args.profile), allow_nan=False))
