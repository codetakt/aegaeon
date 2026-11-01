# Preserve import/annotation behavior of the measured checkpoint.
# ruff: noqa: I001, I002
"""Independent ordered input/signal receipts, compared to native timing frames."""

import json
import struct
from pathlib import Path  # noqa: F401 -- retain imported-module initialization in this measured checkpoint

from dudect_diagnostics import HEADER_SIZE, file_identity
from dudect_support import require
from dudect_timing import BATCH, validate_header, input_width, STRIDES

N = 65536
PROFILES = (
    "zero",
    "lower_tail",
    "full",
    "early_half",
    "late_half",
    "early_short",
    "late_short",
    "history",
)
TARGETS = ("ct_eq_32", "hmac_sha256", "hmac_sha256_key", "ct_eq_64", "ct_eq_128", "sha256")
FRAME = struct.Struct("<5Q")


def read_exact(f, n):
    value = f.read(n)
    require(len(value) == n, "Truncated sensitivity evidence")
    return value


def enabled(p, b, i, labels):
    if b == 0 or labels[i] == 0:
        return False
    return (
        p == "full"
        or (p == "early_half" and b <= 8)
        or (p == "late_half" and b >= 9)
        or (p == "early_short" and b <= 2)
        or (p == "late_short" and b >= 15)
        or (p == "history" and i > 0 and labels[i - 1] == 1)
    )


def verify(output, bindings, profile, kind):  # noqa: C901, PLR0912, PLR0915 -- ordered evidence checks retain each rejection boundary
    require(
        profile in PROFILES and kind in ("physical_diagnostic", "injected_clock"),
        "Unknown receipt protocol",
    )
    sidecar = output / "signal.inputs"
    timing = output / "native.timing"
    targets = [n for n in bindings if n in TARGETS]
    checked = 0
    clock_previous = 0
    with sidecar.open("rb") as saved, timing.open("rb") as raw:
        require(read_exact(saved, 8) == b"AEGSEN04", "Wrong sidecar header")
        magic, caseframe = validate_header(
            read_exact(raw, HEADER_SIZE), bindings, 17, timing.stat().st_size
        )
        for name in bindings:
            header = caseframe.unpack(read_exact(raw, caseframe.size))
            width = input_width(name, magic)
            require(
                header[0] == name.encode().ljust(64, b"\0")
                and header[1:3] == (STRIDES[name], width),
                "Wrong timing case",
            )
            for batch in range(17):
                context = BATCH.unpack(read_exact(raw, BATCH.size))
                require(context[0] == batch, "Wrong native frame order")
                payload = read_exact(raw, N * (9 + width))
                if name not in targets:
                    continue
                tid = TARGETS.index(name)
                stride = STRIDES[name]
                require(
                    FRAME.unpack(read_exact(saved, FRAME.size))
                    == (tid, batch, N, stride, PROFILES.index(profile)),
                    "Wrong signal frame",
                )
                labels = read_exact(saved, N)
                inputs = read_exact(saved, stride * N)
                counts = struct.unpack("<65536I", read_exact(saved, 4 * N))
                require(labels == payload[8 * N : 9 * N], "Input/timing labels differ")
                require(set(labels) <= {0, 1}, "Invalid labels")
                if width:
                    require(inputs == payload[9 * N :], "Saved/native actual inputs differ")
                ticks = struct.unpack_from("<65536q", payload) if kind == "injected_clock" else None
                state = 0x6E624EB7 ^ batch
                for i, label in enumerate(labels):
                    on = enabled(profile, batch, i, labels)
                    require(counts[i] == 32 + 16 * on, "Wrong actual signal assignment")
                    value = inputs[stride * i : stride * (i + 1)]
                    fixed = (
                        0 if tid in (0, 3, 4) else 0xAA if tid == 5 else 0xBB if tid == 1 else 0x42
                    )
                    if not label:
                        require(value == bytes([fixed]) * stride, "Fixed input mismatch")
                    if ticks is not None:
                        state = (state * 1664525 + 1013904223) & 0xFFFFFFFF
                        require(
                            label == state >> 31
                            and value == bytes([0xCC if label else fixed]) * stride,
                            "Fixture input mismatch",
                        )
                        noise = (
                            (((i * 2654435761) & 0xFFFFFFFF) ^ ((batch * 2246822519) & 0xFFFFFFFF))
                            >> 12
                        ) % 1000
                        delta = (50000 if batch else 1000) + noise
                        delta += (
                            30 * label
                            if batch and profile == "lower_tail" and noise < 90
                            else 200 * on
                        )
                        require(ticks[i] == clock_previous, "Fixture timer/callback mismatch")
                        clock_previous += delta
                checked += 1
        require(
            read_exact(saved, 8) == b"AEGSEND4" and not saved.read(1) and not raw.read(1),
            "Incomplete/trailing evidence",
        )
    frame_receipts = []
    completions = []
    for line in (output / "native.stderr").read_text().splitlines():
        if line.startswith("SENSITIVITY_FRAME "):
            frame_receipts.append(json.loads(line.split(" ", 1)[1]))
        if line.startswith("SENSITIVITY_COMPLETE "):
            completions.append(json.loads(line.split(" ", 1)[1]))
    verify_completion_records(targets, profile, frame_receipts, completions)
    return {
        "sidecar": file_identity(sidecar),
        "checked_frames": checked,
        "samples": checked * N,
        "kind": kind,
        "profile": profile,
        "targets": targets,
        "complete": True,
        "limits": "CT32/64/128 premeasurement bytes; callback immutability separately tested; no physical-state reconstruction",  # noqa: E501 -- fixed protocol text retained byte for byte
    }


def verify_completion_records(targets, profile, frame_receipts, completions):
    # Frame receipts follow execution order. The native end-of-process table
    # iterates stable target IDs; Stable IDs append CT64=3, CT128=4 and SHA256=5.
    require(
        len(targets) == len(set(targets)) and all(n in TARGETS for n in targets),
        "Invalid completion targets",
    )
    expected_frames = [
        {"target": TARGETS.index(n), "batch": b, "samples": N, "profile": PROFILES.index(profile)}
        for n in targets
        for b in range(17)
    ]
    expected_complete = [
        {"target": TARGETS.index(n), "frames": 17, "prepared": 17 * N, "callbacks": 17 * N}
        for n in sorted(targets, key=TARGETS.index)
    ]
    require(
        frame_receipts == expected_frames and completions == expected_complete,
        "Callback/frame completion mismatch",
    )
