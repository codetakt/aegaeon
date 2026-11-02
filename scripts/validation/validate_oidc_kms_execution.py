#!/usr/bin/env python3
"""Require the focused KMS parity test to execute before accepting its log."""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

TEST_NAME = (
    "oidc::config::tests::kms_parity::"
    "test_oidc_aws_kms_runtime_key_material_issues_verifiable_rs256_jwt"
)
SUMMARY = re.compile(
    r"test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; \d+ filtered out"
    r"(?:; finished in \d+(?:\.\d+)?s)?"
)


def validate(data: bytes) -> dict[str, object]:
    """Check libtest completion, not just Cargo's successful process exit."""
    lines = data.decode("utf-8").splitlines()
    tests = [line for line in lines if line.startswith("test ") and " ... " in line]
    summaries = [line for line in lines if line.startswith("test result:")]
    starts = [line for line in lines if re.fullmatch(r"running \d+ tests?", line)]
    if (
        starts != ["running 1 test"]
        or tests != [f"test {TEST_NAME} ... ok"]
        or len(summaries) != 1
        or not SUMMARY.fullmatch(summaries[0])
        or any("skipping OIDC AWS KMS signing test" in line for line in lines)
    ):
        raise ValueError("expected exactly one completed, successful OIDC KMS parity test")
    return {
        "schema_version": 1,
        "test": TEST_NAME,
        "passed": 1,
        "log_sha256": hashlib.sha256(data).hexdigest(),
        "log_bytes": len(data),
    }


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: validate_oidc_kms_execution.py TEST_LOG", file=sys.stderr)
        return 2
    try:
        result = validate(Path(sys.argv[1]).read_bytes())
    except (OSError, UnicodeError, ValueError) as error:
        print(f"KMS parity execution evidence rejected: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
