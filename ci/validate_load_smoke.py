"""Check a nonempty functional load run; never admit latency or capacity SLOs."""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
from typing import Any


def validate(report: dict[str, Any]) -> None:  # noqa: PLR0912 -- independent accounting checks
    if report.get("acceptance_mode") != "functional":
        message = "Expected explicit functional-only acceptance mode"
        raise ValueError(message)
    counts: list[Any] = [
        report.get(k) for k in ("total_requests", "successful_requests", "failed_requests")
    ]
    if any(type(n) is not int or n < 0 for n in counts):
        message = "Request counts must be nonnegative integers"
        raise ValueError(message)
    total, success, failed = counts
    if total == 0 or success == 0 or total != success + failed:
        message = "Expected a nonempty, consistent successful request inventory"
        raise ValueError(message)
    for key in (
        "p50_latency_ms",
        "p99_latency_ms",
        "throughput",
        "attempted_throughput",
        "peak_memory_mb",
        "error_rate",
    ):
        value: Any = report.get(key)
        if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
            message = "Invalid observed metric: " + key
            raise ValueError(message)
    if report["p50_latency_ms"] > report["p99_latency_ms"]:
        message = "Latency percentiles are reversed"
        raise ValueError(message)
    if not math.isclose(report["error_rate"], failed / total, abs_tol=1e-9):
        message = "Error rate differs from request counts"
        raise ValueError(message)
    if failed:
        message = "Functional smoke contains failed requests"
        raise ValueError(message)
    if report["throughput"] <= 0 or report["attempted_throughput"] < report["throughput"]:
        message = "Invalid successful/attempted throughput accounting"
        raise ValueError(message)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    args = parser.parse_args()
    value = json.loads(args.report.read_text())
    if not isinstance(value, dict):
        message = "Expected a report object"
        raise TypeError(message)
    validate(value)
    print("Functional load smoke passed. Performance qualification: NOT EVALUATED.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
