"""Bounded framing of every original pilot and measured batch."""

from __future__ import annotations

import struct
from typing import TYPE_CHECKING, Any

from dudect_diagnostics import HEADER_SIZE, file_identity
from dudect_results import BATCH_SIZE, PROFILES
from dudect_support import require

if TYPE_CHECKING:
    from pathlib import Path
    from typing import BinaryIO

TIMING_NAME = "native.timing"
TIMING_ENV = "AEGAEON_DUDECT_TIMING_FD"
CASE = struct.Struct("<64s5Q")
BATCH = struct.Struct("<18Q")
INPUTS = {"sha256": 0xAA, "hmac_sha256": 0xBB}
STRIDES = {
    "compare": 32,
    "compare_product_32": 32,
    "hmac": 32,
    "rsa": 256,
    "jwe": 16,
    "ed25519": 64,
    "hmac_key_reject": 16,
    "jwe_key_reject": 64,
    "ct_eq_32": 32,
    "ct_eq_64": 64,
    "ct_eq_128": 128,
    "sha256": 32,
    "hmac_sha256": 32,
    "hmac_sha256_key": 32,
    "ed25519_verify": 128,
    "control_independent": 4,
    "control_mean_shift": 4,
    "control_variance_shift": 4,
}


def validate_samples(source: BinaryIO, name: str, width: int) -> None:
    source.seek(BATCH_SIZE * 8, 1)
    classes = source.read(BATCH_SIZE)
    require(set(classes) <= {0, 1}, "Invalid timing sample class")
    if width:
        inputs = source.read(BATCH_SIZE * width)
        require(
            all(
                inputs[i * width : (i + 1) * width] == bytes([INPUTS[name]]) * width
                for i, label in enumerate(classes)
                if label == 0
            ),
            "Invalid fixed-class synthetic timing input",
        )


def validate_timing(path: Path, bindings: dict[str, Any], profile: str) -> dict[str, Any]:
    """Reject missing cases, pilot, batches, order, context or binding."""
    identity = file_identity(path)
    frames = PROFILES[profile][0][-1] + 1
    size = HEADER_SIZE + sum(
        CASE.size + frames * (BATCH.size + BATCH_SIZE * (41 if name in INPUTS else 9))
        for name in bindings
    )
    require(identity["bytes"] == size, "Incomplete or extra all-case timing evidence")
    first = next(iter(bindings.values()))
    keys = ("build_sha256", "contract_sha256", "numerical_sha256")
    require(
        all(all(binding[key] == first[key] for key in keys) for binding in bindings.values()),
        "Timing file spans different native bindings",
    )
    with path.open("rb") as source:
        require(
            source.read(HEADER_SIZE)
            == b"AEGTIM02" + b"".join(first[key].encode("ascii") for key in keys),
            "All-case timing binding mismatch",
        )
        previous_end = 0
        previous_counters = [0] * 6
        layouts = {}
        for name in bindings:
            native_name, stride, width, *offsets = CASE.unpack(source.read(CASE.size))
            require(
                native_name == name.encode("ascii").ljust(64, b"\0")
                and stride == STRIDES[name]
                and width == (32 if name in INPUTS else 0),
                "Timing case identity, stride or input width mismatch",
            )
            require(all(offset < 4096 for offset in offsets), "Invalid timing buffer offset")
            layouts[name] = dict(zip(("inputs", "ticks", "classes"), offsets, strict=True))
            for batch in range(frames):
                values = BATCH.unpack(source.read(BATCH.size))
                require(values[:2] == (batch, BATCH_SIZE), "Timing batch order or size mismatch")
                begin, end = values[2:4]
                require(begin > 0 and previous_end <= begin <= end, "Invalid native batch clock")
                require(
                    all(cpu <= 2**31 - 1 or cpu == 2**64 - 1 for cpu in values[4:6]),
                    "Invalid native batch CPU",
                )
                require(
                    all(
                        previous <= before <= after
                        for previous, before, after in zip(
                            previous_counters, values[6::2], values[7::2], strict=True
                        )
                    ),
                    "Regressed native batch counters",
                )
                previous_end = end
                previous_counters = list(values[7::2])
                validate_samples(source, name, width)
        require(source.read(1) == b"", "Trailing all-case timing evidence")
    return {
        **identity,
        "format": "AEGTIM02",
        "cases": list(bindings),
        "input_cases": [name for name in bindings if name in INPUTS],
        "buffer_offsets_mod4096": layouts,
        "frames_per_case": frames,
        "complete": True,
    }
