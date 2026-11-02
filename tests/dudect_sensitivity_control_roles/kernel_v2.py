# Preserve import/annotation behavior of the measured checkpoint.
# ruff: noqa: I002
"""Generate the frozen design-1 population; assess under a distinct contract."""

import argparse
import hashlib
import json
from pathlib import Path

# The caller pins PYTHONPATH to the retained design-1 generator and base runtime.
import kernel as original
from contract import identity
from qualification import assess_kernel


def run(case, profile):
    data = original.run(case, profile)  # Fresh fixed population and tail computations.
    return {
        "schema": "dudect-sensitivity-kernel/2",
        "identity": identity(),
        "original_generator_sha256": hashlib.sha256(
            Path(original.__file__).read_bytes()
        ).hexdigest(),
        "design1_result": data,
        "design2_crop_result": assess_kernel(data),
        "execution_kind": "synthetic_timestamp_kernel",
        "physical_clock": False,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("case", choices=sorted(original.TARGETS))
    parser.add_argument("profile", choices=original.PROFILES)
    args = parser.parse_args()
    print(json.dumps(run(args.case, args.profile), allow_nan=False))
