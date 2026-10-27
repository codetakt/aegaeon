"""Functional execution must not masquerade as timing/performance qualification."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
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


def test_temporary_deferral_reports_scope_and_release_still_blocks(tmp_path):
    pr = yaml.safe_load((ROOT / ".github/workflows/pr.yml").read_text())
    step = next(
        s
        for s in pr["jobs"]["required"]["steps"]
        if s.get("name") == "Report temporary Dudect qualification deferral"
    )
    assert step["if"] == "needs.plan.outputs.scope == 'full'"
    assert "continue-on-error" not in step
    summary = tmp_path / "summary.md"
    bash = shutil.which("bash")
    assert bash is not None
    subprocess.run(  # noqa: S603 - execute the repository's fixed workflow step.
        [bash, "-e", "-c", step["run"]],
        env={**os.environ, "GITHUB_STEP_SUMMARY": str(summary)},
        check=True,
    )
    assert "Until the next release" in summary.read_text()
    assert "not fresh physical qualification" in summary.read_text()
    assert "Release remains blocked" in summary.read_text()
    release = yaml.safe_load((ROOT / ".github/workflows/release.yml").read_text())
    step = next(
        s
        for s in release["jobs"]["validate-release"]["steps"]
        if s.get("name", "").startswith("Hold release")
    )
    assert "if" not in step
    assert "continue-on-error" not in step
    assert "exit 1" in step["run"]
    result = subprocess.run(  # noqa: S603 - execute the repository's fixed release guard.
        [bash, "-e", "-c", step["run"]], capture_output=True, check=False
    )
    assert result.returncode != 0
    periodic = yaml.safe_load((ROOT / ".github/workflows/dudect-periodic.yml").read_text())
    assert "schedule" not in periodic[True]
    assert "run_contract.py" not in str(periodic)
    assert "dudect_check.sh" not in str(periodic)


def test_transition_preserves_historical_binding_and_does_not_attest_a_new_target():
    record = json.loads((ROOT / "ci/evidence/dudect-ci-transition-20261023.json").read_text())
    for ref in record["retained_evidence"].values():
        assert hashlib.sha256((ROOT / ref["path"]).read_bytes()).hexdigest() == ref["sha256"]
    assert record["expires_before"] == "next_release"
    assert record["current_revision_physically_qualified"] is False
    assert record["authenticated_external_admission"] is False
    assert record["release_authorized"] is False
    assert record["task3"] == "paused"
    results = json.loads((ROOT / "ci/ci-result-contract.json").read_text())
    ref = results["qualification_transition"]["owner_exception"]
    assert ref["path"] == "ci/evidence/dudect-ci-transition-20261023.json"
    assert hashlib.sha256((ROOT / ref["path"]).read_bytes()).hexdigest() == ref["sha256"]


def test_ordinary_entrypoints_have_no_physical_launch():
    for name in ("ci", "pr", "verification", "performance"):
        source = (ROOT / f".github/workflows/{name}.yml").read_text()
        assert "dudect_check.sh" not in source
        assert "Collect fresh" not in source
        assert "python3 ci/validate_slos.py" not in source
    for name in ("verify_dudect.sh", "verify_reqs.sh"):
        assert "run_contract.py" not in (ROOT / "scripts/flake" / name).read_text()
