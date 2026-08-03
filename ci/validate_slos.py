#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

EXPECTED_ARGC = 2
EXIT_USAGE = 2
EXIT_FAIL = 1
EXIT_OK = 0

SLO_P50_MS = float(os.environ.get("SLO_P50_MS", "50"))
SLO_P99_MS = float(os.environ.get("SLO_P99_MS", "200"))
SLO_THROUGHPUT = float(os.environ.get("SLO_TARGET_RPS", "100"))
SLO_MIN_THROUGHPUT_RATIO = float(os.environ.get("SLO_MIN_THROUGHPUT_RATIO", "0.9"))
SLO_PEAK_MEMORY_MB = float(os.environ.get("SLO_PEAK_MEMORY_MB", "500"))
SLO_MAX_ERROR_RATE = float(os.environ.get("SLO_MAX_ERROR_RATE", "0.01"))


def _require_number(obj: dict[str, object], key: str) -> float | None:
    value = obj.get(key)
    if not isinstance(value, (int, float)):
        return None
    return float(value)


def _load_report(report_path: Path) -> dict[str, object] | None:
    try:
        text = report_path.read_text(encoding="utf-8")
        data = json.loads(text)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"Failed to parse JSON report: {exc}", file=sys.stderr)
        return None
    if not isinstance(data, dict):
        print("Invalid report schema: top-level JSON must be an object", file=sys.stderr)
        return None
    return data


def _extract_metrics(
    data: dict[str, object],
) -> tuple[float, float, float, float, float, float, int, int, int] | None:
    p50_latency_ms = _require_number(data, "p50_latency_ms")
    p99_latency_ms = _require_number(data, "p99_latency_ms")
    throughput = _require_number(data, "throughput")
    attempted_throughput = _require_number(data, "attempted_throughput")
    peak_memory_mb = _require_number(data, "peak_memory_mb")
    error_rate = _require_number(data, "error_rate")
    total_requests = data.get("total_requests")
    successful_requests = data.get("successful_requests")
    failed_requests = data.get("failed_requests")
    if (
        p50_latency_ms is None
        or p99_latency_ms is None
        or throughput is None
        or attempted_throughput is None
        or peak_memory_mb is None
        or error_rate is None
        or not isinstance(total_requests, int)
        or not isinstance(successful_requests, int)
        or not isinstance(failed_requests, int)
    ):
        print("Invalid report schema: missing or non-numeric metrics", file=sys.stderr)
        return None
    return (
        p50_latency_ms,
        p99_latency_ms,
        throughput,
        attempted_throughput,
        peak_memory_mb,
        error_rate,
        total_requests,
        successful_requests,
        failed_requests,
    )


def main() -> int:
    exit_code = EXIT_OK
    if len(sys.argv) != EXPECTED_ARGC:
        print("Usage: validate_slos.py <load-test-report.json>", file=sys.stderr)
        exit_code = EXIT_USAGE
    else:
        report_path = Path(sys.argv[1])
        if not report_path.is_file():
            print(f"Report not found: {report_path}", file=sys.stderr)
            exit_code = EXIT_USAGE
        else:
            data = _load_report(report_path)
            if data is None:
                exit_code = EXIT_USAGE
            else:
                metrics = _extract_metrics(data)
                if metrics is None:
                    exit_code = EXIT_USAGE
                else:
                    (
                        p50_latency_ms,
                        p99_latency_ms,
                        throughput,
                        attempted_throughput,
                        peak_memory_mb,
                        error_rate,
                        total_requests,
                        successful_requests,
                        failed_requests,
                    ) = metrics

                    slo_p50_pass = p50_latency_ms <= SLO_P50_MS
                    slo_p99_pass = p99_latency_ms <= SLO_P99_MS
                    min_successful_throughput = max(
                        SLO_THROUGHPUT * SLO_MIN_THROUGHPUT_RATIO,
                        1.0,
                    )
                    slo_throughput_pass = throughput >= min_successful_throughput
                    slo_error_rate_pass = total_requests > 0 and error_rate <= SLO_MAX_ERROR_RATE
                    slo_memory_pass = peak_memory_mb <= SLO_PEAK_MEMORY_MB

                    print("SLO Validation")
                    print(
                        f"- p50 < {SLO_P50_MS:.0f}ms: "
                        f"{'PASS' if slo_p50_pass else 'FAIL'} (actual: {p50_latency_ms:.2f}ms)"
                    )
                    print(
                        f"- p99 < {SLO_P99_MS:.0f}ms: "
                        f"{'PASS' if slo_p99_pass else 'FAIL'} (actual: {p99_latency_ms:.2f}ms)"
                    )
                    print(
                        f"- throughput >= {min_successful_throughput:.0f} req/s "
                        f"({SLO_MIN_THROUGHPUT_RATIO * 100:.0f}% of target {SLO_THROUGHPUT:.0f}): "
                        f"{'PASS' if slo_throughput_pass else 'FAIL'} "
                        "(successful: "
                        f"{throughput:.2f} req/s; attempted: "
                        f"{attempted_throughput:.2f} req/s)"
                    )
                    print(
                        f"- error rate <= {SLO_MAX_ERROR_RATE * 100:.2f}%: "
                        f"{'PASS' if slo_error_rate_pass else 'FAIL'} "
                        "(actual: "
                        f"{error_rate * 100:.2f}% | ok={successful_requests} "
                        f"fail={failed_requests})"
                    )
                    print(
                        f"- peak memory < {SLO_PEAK_MEMORY_MB:.0f}MB: "
                        f"{'PASS' if slo_memory_pass else 'FAIL'} (peak: {peak_memory_mb:.2f}MB)"
                    )

                    all_pass = (
                        slo_p50_pass
                        and slo_p99_pass
                        and slo_throughput_pass
                        and slo_error_rate_pass
                        and slo_memory_pass
                    )
                    if all_pass:
                        print("Overall: PASS")
                        exit_code = EXIT_OK
                    else:
                        print("Overall: FAIL")
                        exit_code = EXIT_FAIL

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
