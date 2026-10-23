"""Run the frozen operation tests with explicitly pinned age executables.

Only the test module's dependency is injected. Measured sources and archived
tests are not edited, and no timing or external infrastructure is started.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import unittest
from pathlib import Path


def age_dependency(path: Path, age_sha256: str, keygen_sha256: str) -> Path:
    if not path.is_absolute():
        message = "An absolute pinned age path is required"
        raise ValueError(message)
    resolved = path.resolve(strict=True)
    for executable, expected in (
        (resolved, age_sha256),
        (resolved.parent / "age-keygen", keygen_sha256),
    ):
        if not executable.is_file() or not os.access(executable, os.X_OK):
            message = "Missing executable age dependency"
            raise ValueError(message)
        with executable.open("rb") as stream:
            actual = hashlib.file_digest(stream, "sha256").hexdigest()
        if actual != expected:
            message = "age dependency digest mismatch"
            raise ValueError(message)
    return resolved


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--age", type=Path, required=True)
    parser.add_argument("--age-sha256", required=True)
    parser.add_argument("--age-keygen-sha256", required=True)
    args = parser.parse_args()
    age = age_dependency(args.age, args.age_sha256, args.age_keygen_sha256)
    root = Path(__file__).resolve().parents[2]
    directory = root / "tests/dudect_sensitivity_operations"
    sys.path.insert(0, str(directory))
    suite = unittest.defaultTestLoader.discover(str(directory))
    # The archived module keeps its original bytes and source receipt. Inject the
    # test-only executable after discovery and before any Transport.setUp call.
    module = sys.modules["test_operations"]
    original = vars(module)["AGE"]
    vars(module)["AGE"] = age
    try:
        result = unittest.TextTestRunner(verbosity=2).run(suite)
    finally:
        vars(module)["AGE"] = original
    print(
        json.dumps(
            {
                "tests": result.testsRun,
                "successful": result.wasSuccessful(),
                "age_sha256": args.age_sha256,
                "age_keygen_sha256": args.age_keygen_sha256,
            }
        )
    )
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
