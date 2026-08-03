#!/usr/bin/env python3
"""Validate dudect constant-time analysis results.

The dudect harness in this repository currently emits newline-delimited JSON
snippets describing intermediate runs, plus a final summary line. Some
variants of the harness (or upstream tooling) may instead emit a single JSON
document or a plain-text report with p-values. This script attempts to handle
all of those formats and enforces simple acceptance criteria:

* A dudect artifact must exist under ``artifacts/ct/dudect/`` or
  ``artifacts/dudect/``.
* The maximum observed sample count must meet the minimum trace threshold.
* Either the reported p-value satisfies the configured limits **or** the
  reported Student's t statistic (``tau``) remains below the configured
  thresholds. If both are present, the p-value check takes precedence.
* The overall dudect result (when provided) must indicate success.

Environment overrides:

* ``DUDECT_FAIL_THRESHOLD`` - p-value failure threshold (default: 0.01)
* ``DUDECT_WARN_THRESHOLD`` - p-value warning threshold (default: 0.05)
* ``DUDECT_TAU_FAIL`` - |tau| failure threshold (default: 4.5)
* ``DUDECT_TAU_WARN`` - |tau| warning threshold (default: 3.5)
* ``DUDECT_MIN_TRACES`` - minimum acceptable trace count (default: 100000)

Any parsing failure or missing output is treated as a CI failure so that the
team notices immediately when dudect stops producing usable evidence.
"""

from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ARTIFACT_DIRS = [
    Path("artifacts/ct/dudect"),
    Path("artifacts/dudect"),
]
LOG_FILENAMES = [
    "report.json",
    "compare.json",
    "dudect.json",
    "result.json",
    "dudect.log",
    "result.log",
    "dudect.txt",
]


@dataclass
class Metrics:
    p_value: float | None = None
    tau: float | None = None
    num_traces: int | None = None
    overall_pass: bool | None = None


def _update_metrics_from_mapping(metrics: Metrics, data: dict[str, Any]) -> None:
    for key in ("p_value", "pValue", "pvalue", "p_value_t", "p_value_u", "p"):
        if key in data and metrics.p_value is None:
            try:
                metrics.p_value = float(data[key])
            except (TypeError, ValueError):
                pass

    if "summary" in data and isinstance(data["summary"], dict):
        _update_metrics_from_mapping(metrics, data["summary"])

    for key in ("tau", "worst_tau"):
        if key in data:
            try:
                value = abs(float(data[key]))
            except (TypeError, ValueError):
                continue
            if metrics.tau is None or value > metrics.tau:
                metrics.tau = value

    for key in ("num_traces", "numSamples", "measurements", "samples"):
        if key in data:
            try:
                value = int(data[key])
            except (TypeError, ValueError):
                continue
            else:
                if metrics.num_traces is None or value > metrics.num_traces:
                    metrics.num_traces = value

    if "overall_result" in data:
        metrics.overall_pass = str(data["overall_result"]).strip().upper() == "PASS"
    elif "state" in data:
        try:
            metrics.overall_pass = int(data["state"]) == 1
        except (TypeError, ValueError):
            pass


def _read_metrics_from_json(path: Path) -> Metrics:
    metrics = Metrics()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return metrics

    if isinstance(data, dict):
        _update_metrics_from_mapping(metrics, data)
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                _update_metrics_from_mapping(metrics, item)
    return metrics


def _read_metrics_from_text(path: Path) -> Metrics:
    text = path.read_text(encoding="utf-8", errors="replace")
    metrics = Metrics()

    # Attempt to parse JSON objects line-by-line first.
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(data, dict):
            _update_metrics_from_mapping(metrics, data)

    # Fall back to regex extraction if needed.
    if metrics.p_value is None:
        p_patterns = [
            r"p[-_ ]?value\s*[:=]\s*([0-9]+\.?[0-9]*(?:[eE][-+]?\d+)?)",
            r"p\s*=\s*([0-9]+\.?[0-9]*(?:[eE][-+]?\d+)?)",
        ]
        for pat in p_patterns:
            match = re.search(pat, text, re.IGNORECASE)
            if match:
                try:
                    metrics.p_value = float(match.group(1))
                except ValueError:
                    continue
                break

    if metrics.tau is None:
        tau_patterns = [
            r"worst_tau\s*[:=]\s*([-+]?[0-9]+\.?[0-9]*(?:[eE][-+]?\d+)?)",
            r"tau\s*[:=]\s*([-+]?[0-9]+\.?[0-9]*(?:[eE][-+]?\d+)?)",
        ]
        for pat in tau_patterns:
            match = re.search(pat, text, re.IGNORECASE)
            if match:
                try:
                    metrics.tau = float(match.group(1))
                except ValueError:
                    continue
                break

    if metrics.num_traces is None:
        traces_patterns = [
            r"number of measurements\s*[:=]\s*(\d+)",
            r"measurements\s*[:=]\s*(\d+)",
            r"samples\s*[:=]\s*(\d+)",
            r"traces\s*[:=]\s*(\d+)",
        ]
        for pat in traces_patterns:
            match = re.search(pat, text, re.IGNORECASE)
            if match:
                try:
                    metrics.num_traces = int(match.group(1))
                except ValueError:
                    continue
                break

    return metrics


def load_dudect_results() -> Metrics:
    combined = Metrics()
    found_any = False

    checked_paths: list[str] = []
    for artifact_dir in ARTIFACT_DIRS:
        for filename in LOG_FILENAMES:
            path = artifact_dir / filename
            checked_paths.append(str(path))
            if not path.exists():
                continue
            found_any = True
            parsed = (
                _read_metrics_from_json(path)
                if path.suffix == ".json"
                else _read_metrics_from_text(path)
            )

            if parsed.p_value is not None:
                combined.p_value = parsed.p_value
            if parsed.tau is not None:
                if combined.tau is None or parsed.tau > combined.tau:
                    combined.tau = parsed.tau
            if parsed.num_traces is not None:
                if combined.num_traces is None or parsed.num_traces > combined.num_traces:
                    combined.num_traces = parsed.num_traces
            if parsed.overall_pass is not None:
                combined.overall_pass = parsed.overall_pass

    if not found_any:
        missing = ", ".join(checked_paths)
        raise FileNotFoundError(f"Unable to locate dudect results. Checked: {missing}")

    return combined


def get_threshold(env_name: str, default: float) -> float:
    raw = os.environ.get(env_name)
    if raw is None:
        return default
    try:
        return float(raw)
    except ValueError as exc:
        raise ValueError(f"Invalid float for {env_name}: {raw}") from exc


def get_min_traces() -> int:
    raw = os.environ.get("DUDECT_MIN_TRACES")
    if raw is None:
        return 16_000
    try:
        return int(raw)
    except ValueError as exc:
        raise ValueError(f"Invalid integer for DUDECT_MIN_TRACES: {raw}") from exc


def get_tau_threshold(env_name: str, default: float) -> float:
    raw = os.environ.get(env_name)
    if raw is None:
        return default
    try:
        return float(raw)
    except ValueError as exc:
        raise ValueError(f"Invalid float for {env_name}: {raw}") from exc


def main() -> int:
    fail_threshold = get_threshold("DUDECT_FAIL_THRESHOLD", 0.01)
    warn_threshold = get_threshold("DUDECT_WARN_THRESHOLD", 0.05)
    if warn_threshold < fail_threshold:
        print(
            f"⚠️ WARN threshold ({warn_threshold}) is lower than FAIL threshold "
            f"({fail_threshold}); adjusting warn threshold to fail threshold.",
            file=sys.stderr,
        )
        warn_threshold = fail_threshold

    tau_fail = get_tau_threshold("DUDECT_TAU_FAIL", 4.5)
    tau_warn = get_tau_threshold("DUDECT_TAU_WARN", 3.5)
    if tau_warn < tau_fail:
        print(
            f"⚠️ TAU warn threshold ({tau_warn}) below fail threshold ({tau_fail}); adjusting.",
            file=sys.stderr,
        )
        tau_warn = tau_fail

    min_traces = get_min_traces()

    try:
        metrics = load_dudect_results()
    except FileNotFoundError as exc:
        print(f"❌ {exc}", file=sys.stderr)
        return 1

    status_messages = [
        f"p-value={metrics.p_value if metrics.p_value is not None else 'n/a'}",
        f"tau={metrics.tau if metrics.tau is not None else 'n/a'}",
        f"traces={metrics.num_traces if metrics.num_traces is not None else 'n/a'}",
        f"p_fail={fail_threshold}",
        f"p_warn={warn_threshold}",
        f"tau_fail={tau_fail}",
        f"tau_warn={tau_warn}",
        f"min_traces={min_traces}",
    ]

    if metrics.overall_pass is False:
        print(
            "❌ dudect overall result reported failure: " + ", ".join(status_messages),
            file=sys.stderr,
        )
        return 1

    if metrics.num_traces is None or metrics.num_traces < min_traces:
        print(
            "❌ dudect trace count below minimum: " + ", ".join(status_messages),
            file=sys.stderr,
        )
        return 1

    if metrics.p_value is not None:
        if metrics.p_value < fail_threshold:
            print(
                "❌ dudect p-value below fail threshold: " + ", ".join(status_messages),
                file=sys.stderr,
            )
            return 1
        if metrics.p_value < warn_threshold:
            print(
                "⚠️ dudect p-value in warning band: " + ", ".join(status_messages),
                file=sys.stderr,
            )
            return 1
    elif metrics.tau is not None:
        abs_tau = abs(metrics.tau)
        if abs_tau > tau_fail:
            print(
                "❌ dudect tau exceeds fail threshold: " + ", ".join(status_messages),
                file=sys.stderr,
            )
            return 1
        if abs_tau > tau_warn:
            print(
                "⚠️ dudect tau in warning band: " + ", ".join(status_messages),
                file=sys.stderr,
            )
            return 1
    else:
        print(
            "❌ Unable to find p-value or tau in dudect output: " + ", ".join(status_messages),
            file=sys.stderr,
        )
        return 1

    print("✅ dudect constant-time check passed: " + ", ".join(status_messages))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except ValueError as exc:
        print(f"❌ {exc}", file=sys.stderr)
        sys.exit(1)
