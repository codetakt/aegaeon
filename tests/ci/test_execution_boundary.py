"""Functional execution must not masquerade as timing/performance qualification."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/ci"))
sys.path.insert(0, str(ROOT / "ci"))
from check_dudect_functional import check_receipt  # noqa: E402

from validate_load_smoke import validate  # noqa: E402
from validate_slos import _extract_metrics  # noqa: E402


def sample():
    return {
        "acceptance_mode": "functional",
        "total_requests": 2,
        "successful_requests": 2,
        "failed_requests": 0,
        "p50_latency_ms": 1000000,
        "p99_latency_ms": 2000000,
        "throughput": 0.001,
        "attempted_throughput": 0.001,
        "peak_memory_mb": 1000000,
        "error_rate": 0,
    }


def test_functional_has_no_performance_threshold_and_cannot_admit_slo():
    validate(sample())
    assert _extract_metrics(sample()) is None


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("acceptance_mode", "performance_slo"),
        ("total_requests", 0),
        ("successful_requests", True),
        ("failed_requests", 1),
        ("error_rate", 0.5),
        ("throughput", float("nan")),
        ("peak_memory_mb", float("inf")),
        ("p99_latency_ms", 0),
        ("attempted_throughput", 0),
    ],
)
def test_broken_functional_result_rejected(key, value):
    data = sample()
    data[key] = value
    with pytest.raises(ValueError, match=r"Expected|Invalid|counts|inventory|reversed|differs"):
        validate(data)


def test_exact_callback_inventory_and_non_timing_receipts():
    good = {"case_id": "nix/hmac_sha256", "self_test": True, "timing_executed": False}
    assert check_receipt(json.dumps(good), [good["case_id"]]) == [good]
    for raw in (
        "",
        json.dumps(good) + "\n" + json.dumps(good),
        json.dumps({**good, "timing_executed": True}),
        json.dumps({**good, "self_test": 1}),
    ):
        with pytest.raises(ValueError, match=r"receipts|types"):
            check_receipt(raw, [good["case_id"]])


def test_transition_holds_are_explicit_and_not_timing_runs():
    pr = yaml.safe_load((ROOT / ".github/workflows/pr.yml").read_text())
    step = next(
        s
        for s in pr["jobs"]["required"]["steps"]
        if s.get("name", "").startswith("Hold qualification")
    )
    assert step["if"] == "needs.plan.outputs.scope == 'full'"
    assert "exit 1" in step["run"]
    assert "continue-on-error" not in step
    release = yaml.safe_load((ROOT / ".github/workflows/release.yml").read_text())
    step = next(
        s
        for s in release["jobs"]["validate-release"]["steps"]
        if s.get("name", "").startswith("Hold release")
    )
    assert "if" not in step
    assert "continue-on-error" not in step
    assert "exit 1" in step["run"]
    periodic = yaml.safe_load((ROOT / ".github/workflows/dudect-periodic.yml").read_text())
    assert "schedule" not in periodic[True]
    assert "run_contract.py" not in str(periodic)
    assert "dudect_check.sh" not in str(periodic)


def test_ordinary_entrypoints_have_no_physical_launch():
    for name in ("ci", "pr", "verification", "performance"):
        source = (ROOT / f".github/workflows/{name}.yml").read_text()
        assert "dudect_check.sh" not in source
        assert "Collect fresh" not in source
        assert "python3 ci/validate_slos.py" not in source
    for name in ("verify_dudect.sh", "verify_reqs.sh"):
        assert "run_contract.py" not in (ROOT / "scripts/flake" / name).read_text()
