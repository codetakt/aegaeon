#!/usr/bin/env python3
"""
Check that signing key generation still uses SystemRandom.

This enforces the documented RNG boundary: key generation is outside the
verified DRBG path and remains a host/OS dependency. If this boundary changes,
update the docs and this guard.
"""

from __future__ import annotations

import argparse
import pathlib
import sys

SIGNING_RS = pathlib.Path("crates/crypto/src/signing.rs")
NEEDLE = "SystemRandom::new()"


def run_check() -> int:
    if not SIGNING_RS.exists():
        print(f"error: expected {SIGNING_RS} to exist")
        return 2
    text = SIGNING_RS.read_text(encoding="utf-8")
    if NEEDLE not in text:
        print("error: SystemRandom usage not found in signing.rs")
        print(
            "note: update docs/verification/workplans/rng/README.md and "
            "docs/verification/claims/assumptions/current-register.md "
            "if keygen RNG boundary changes"
        )
        return 1
    print("OK: key generation uses SystemRandom (boundary preserved)")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--check",
        action="store_true",
        help="run keygen RNG boundary check",
    )
    args = parser.parse_args()
    if not args.check:
        parser.error("--check is required")
    return run_check()


if __name__ == "__main__":
    sys.exit(main())
