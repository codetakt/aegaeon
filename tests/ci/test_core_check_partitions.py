"""Partition accounting rejects missing work, mixed events and incomplete cleanup."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/ci"))

from run_core_pr_checks import (  # noqa: E402
    DATABASE_CHECKS,
    FORMAL_PACKAGES,
    SHARDS,
    build_command,
    partition,
    split_core_checks,
)
from validate_core_check_partitions import aggregate, object_json  # noqa: E402

CONTEXT = {
    "GITHUB_REPOSITORY": "example/repository",
    "GITHUB_RUN_ID": "123",
    "GITHUB_RUN_ATTEMPT": "1",
    "GITHUB_SHA": "a" * 40,
    "GITHUB_EVENT_NAME": "merge_group",
}
RESULTS = {"ci": "success", "check-shards": "success", "db-integration": "success"}


def write_json(path, data):
    path.write_text(json.dumps(data) + "\n")


def change(path, mutation):
    row = json.loads(path.read_text())
    mutation(row)
    write_json(path, row)


def fixture(directory, *, all_checks=False):
    checks = {
        name: "/nix/store/" + "a" * 32 + f"-{name}.drv"
        for name in [
            *FORMAL_PACKAGES,
            *DATABASE_CHECKS,
            "tests",
            "verifyJose",
            "future-check",
            "verifyDudect",
        ]
    }
    packages = {k: checks[k] for k in FORMAL_PACKAGES}
    owners = partition(checks, packages)
    if all_checks:
        owners = {"core": checks, "verification": {}}
    shards = split_core_checks(owners["core"])
    context = {**CONTEXT, "GITHUB_EVENT_NAME": "push"} if all_checks else CONTEXT
    for shard in SHARDS:
        root = directory / f"core-check-shard-{shard}"
        root.mkdir()
        write_json(
            root / "ci-check-ownership.json",
            {
                "schema": "core-check-shard/3",
                "system": "x86_64-linux",
                "context": context,
                "all_checks": all_checks,
                "shard": shard,
                "checks": checks,
                "formal_packages": packages,
                "owners": owners,
                "shards": shards,
            },
        )
        trace = [
            {"event": "start", "command": build_command(shards[shard]), "context": context},
            {"event": "output", "text": "build or substitute checked output\n"},
            {"event": "finish", "returncode": 0, "truncated": False},
        ]
        (root / "core-build-observations.jsonl").write_text(
            "".join(json.dumps({**row, "invocation": shard}) + "\n" for row in trace)
        )
        command = ["python3", "scripts/ci/run_core_pr_checks.py"]
        if all_checks:
            command += ["--all-checks"]
        command += ["--shard", shard]
        write_json(
            root / "organization-userns-core.json",
            {
                "command": command,
                "command_returncode": 0,
                "unconfirmed_groups": [],
                "restriction_before": "1",
                "restriction_after": "1",
                "before": {"passed": True},
                "nested_cleanup_receipts": [{"confirmed": True}],
            },
        )
    return context


@pytest.mark.parametrize("all_checks", [False, True])
def test_full_accounting_preserves_all_checks_and_separate_invocations(tmp_path, all_checks):
    context = fixture(tmp_path, all_checks=all_checks)
    result = aggregate(tmp_path, context, RESULTS, all_checks=all_checks)
    assert result["schema"] == "core-check-partitions/3"
    assert set(result["shards"]) == set(SHARDS)
    assert result["shards"]["workspace"]["checks"].keys() == {"tests"}
    assert result["shards"]["database"]["checks"].keys() == DATABASE_CHECKS
    remaining = result["shards"]["remaining"]["checks"]
    assert {"verifyDudect", "future-check"} <= remaining.keys()
    assert (set(FORMAL_PACKAGES) <= remaining.keys()) is all_checks
    for row in result["shards"].values():
        assert len(row["sha256"]) == 3


@pytest.mark.parametrize("job", ["ci", "check-shards", "db-integration"])
@pytest.mark.parametrize("status", ["failure", "cancelled", "skipped", "", None])
def test_unsuccessful_job_never_passes_even_with_complete_artifacts(tmp_path, job, status):
    fixture(tmp_path)
    with pytest.raises(ValueError, match="producer job"):
        aggregate(tmp_path, CONTEXT, {**RESULTS, job: status}, all_checks=False)


@pytest.mark.parametrize(
    "mutation",
    [
        "missing_shard",
        "unknown_shard",
        "missing_trace",
        "extra_file",
        "wrong_shard",
        "wrong_sha",
        "wrong_attempt",
        "wrong_run",
        "wrong_event",
        "wrong_repository",
        "mode",
        "drop_check",
        "inconsistent_inventory",
        "different_recipe",
        "cross_shard_alias",
    ],
)
def test_missing_or_mismatched_partition_is_rejected(tmp_path, mutation):  # noqa: C901, PLR0912, PLR0915 - explicit corruption cases.
    fixture(tmp_path)
    root = tmp_path / "core-check-shard-workspace"
    path = root / "ci-check-ownership.json"
    if mutation == "missing_shard":
        root.rename(tmp_path / "absent")
    elif mutation == "unknown_shard":
        (tmp_path / "unknown").mkdir()
    elif mutation == "missing_trace":
        (root / "core-build-observations.jsonl").unlink()
    elif mutation == "extra_file":
        (root / "unknown.json").write_text("{}")
    else:
        row = json.loads(path.read_text())
        if mutation.startswith("wrong_") and mutation != "wrong_shard":
            key = {
                "wrong_sha": "GITHUB_SHA",
                "wrong_attempt": "GITHUB_RUN_ATTEMPT",
                "wrong_run": "GITHUB_RUN_ID",
                "wrong_event": "GITHUB_EVENT_NAME",
                "wrong_repository": "GITHUB_REPOSITORY",
            }[mutation]
            row["context"][key] = "different"
        elif mutation == "wrong_shard":
            row["shard"] = "jose"
        elif mutation == "mode":
            row["all_checks"] = True
        elif mutation == "drop_check":
            row["shards"]["remaining"].pop("future-check")
        elif mutation == "inconsistent_inventory":
            row["checks"].pop("future-check")
            row["owners"]["core"].pop("future-check")
            row["shards"]["remaining"].pop("future-check")
        elif mutation == "different_recipe":
            row["checks"]["tests"] = row["checks"]["future-check"]
        else:
            row["checks"]["verifyJose"] = row["checks"]["tests"]
        write_json(path, row)
    with pytest.raises((ValueError, FileNotFoundError)):
        aggregate(tmp_path, CONTEXT, RESULTS, all_checks=False)


@pytest.mark.parametrize(
    "mutation",
    [
        "missing_start",
        "missing_finish",
        "duplicate_invocation",
        "mixed_invocation",
        "failed",
        "boolean_status",
        "truncated",
        "wrong_targets",
        "wrong_capacity",
        "wrong_source",
        "wrong_attempt",
    ],
)
def test_incomplete_or_mixed_build_trace_is_rejected(tmp_path, mutation):  # noqa: PLR0912 - explicit corruption cases.
    fixture(tmp_path)
    path = tmp_path / "core-check-shard-workspace/core-build-observations.jsonl"
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    if mutation == "missing_start":
        rows.pop(0)
    elif mutation == "missing_finish":
        rows.pop()
    elif mutation == "duplicate_invocation":
        rows += rows
    elif mutation == "mixed_invocation":
        rows[1]["invocation"] = "other"
    elif mutation in {"failed", "boolean_status"}:
        rows[-1]["returncode"] = 1 if mutation == "failed" else False
    elif mutation == "truncated":
        rows[-1]["truncated"] = True
    elif mutation == "wrong_targets":
        rows[0]["command"].pop()
    elif mutation == "wrong_capacity":
        rows[0]["command"][5] = "4"
    else:
        rows[0]["context"]["GITHUB_SHA" if mutation == "wrong_source" else "GITHUB_RUN_ATTEMPT"] = (
            "2"
        )
    path.write_text("".join(json.dumps(row) + "\n" for row in rows))
    with pytest.raises(ValueError, match=r"build|invocation|truncated"):
        aggregate(tmp_path, CONTEXT, RESULTS, all_checks=False)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("error", "cleanup failed"),
        ("cancellation", "signal 15"),
        ("recovery", {}),
        ("nested_cleanup_unconfirmed", "unknown"),
        ("policy_recovery_error", "cannot inspect"),
        ("unconfirmed_groups", [123]),
        ("command_returncode", 1),
        ("restriction_after", "0"),
        ("nested_cleanup_receipts", []),
        ("nested_cleanup_receipts", [{"confirmed": False}]),
        ("command", ["true"]),
        ("before", {"passed": False}),
    ],
)
def test_successful_nix_exit_does_not_hide_namespace_failure(tmp_path, field, value):
    fixture(tmp_path)
    path = tmp_path / "core-check-shard-workspace/organization-userns-core.json"
    change(path, lambda row: row.update({field: value}))
    with pytest.raises(ValueError, match=r"namespace|cleanup"):
        aggregate(tmp_path, CONTEXT, RESULTS, all_checks=False)


def test_repaired_namespace_requires_actual_probe_and_profile_absence(tmp_path):
    fixture(tmp_path)
    path = tmp_path / "core-check-shard-workspace/organization-userns-core.json"
    change(
        path,
        lambda row: row.update(
            {
                "before": {"passed": False},
                "after": {"passed": True},
                "install_attempted": True,
                "profile_absent": True,
            }
        ),
    )
    aggregate(tmp_path, CONTEXT, RESULTS, all_checks=False)
    change(path, lambda row: row.update({"profile_absent": False}))
    with pytest.raises(ValueError, match="profile cleanup"):
        aggregate(tmp_path, CONTEXT, RESULTS, all_checks=False)


def test_duplicate_json_fields_are_rejected():
    with pytest.raises(ValueError, match="duplicate"):
        object_json(b'{"all_checks":false,"all_checks":true}')


def test_oversized_trace_is_rejected_without_reading_unbounded_lines(tmp_path, monkeypatch):
    fixture(tmp_path)
    monkeypatch.setattr("validate_core_check_partitions.TRACE_LIMIT", 64)
    with pytest.raises(ValueError, match="exceeds bound"):
        aggregate(tmp_path, CONTEXT, RESULTS, all_checks=False)


def test_workflow_requires_parallel_producers_and_fail_closed_aggregate():
    jobs = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())["jobs"]
    shards = jobs["check-shards"]
    assert "needs" not in shards
    assert shards["strategy"]["fail-fast"] is False
    assert shards["strategy"]["matrix"]["shard"] == ["workspace", "jose", "database"]
    assert not shards.get("continue-on-error", False)
    complete = jobs["core-check-complete"]
    assert set(complete["needs"]) == {"ci", "check-shards", "db-integration"}
    assert complete["if"] == "always()"
    assert not complete.get("continue-on-error", False)
    validation = next(s for s in complete["steps"] if "CORE_PRODUCER_RESULTS" in s.get("env", {}))
    assert "${{ needs.ci.result }}" in validation["env"]["CORE_PRODUCER_RESULTS"]
    assert "${{ needs.check-shards.result }}" in validation["env"]["CORE_PRODUCER_RESULTS"]
    assert "${{ needs.db-integration.result }}" in validation["env"]["CORE_PRODUCER_RESULTS"]
    assert "mode+=(--all-checks)" in validation["run"]
    assert "if" not in validation
    assert not validation.get("continue-on-error", False)
    download = next(s for s in complete["steps"] if "download-artifact@" in s.get("uses", ""))
    assert download["with"]["pattern"] == "core-check-shard-*"
    assert download["with"]["merge-multiple"] is False


def test_database_checks_follow_package_creation_and_keep_all_existing_db_steps():
    jobs = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())["jobs"]
    job = jobs["db-integration"]
    assert "needs" not in job
    assert not job.get("continue-on-error", False)
    assert job["timeout-minutes"] == 60
    steps = job["steps"]
    build = next(i for i, s in enumerate(steps) if s.get("id") == "database-tests")
    assert "nix build .#database-tests" in steps[build]["run"]
    assert "scripts/ci/run_database_lanes.py" in steps[build]["run"]
    assert not any("--shard database" in step.get("run", "") for step in steps)
    shard = jobs["check-shards"]
    assert shard["timeout-minutes"] == "${{ matrix.shard == 'database' && 60 || 120 }}"
    consumer = next(step for step in shard["steps"] if step.get("id") == "core-checks")
    assert consumer["env"]["CORE_SHARD"] == "${{ matrix.shard }}"
    assert '--all-checks --shard "$CORE_SHARD"' in consumer["run"]
    assert 'run_core_pr_checks.py --shard "$CORE_SHARD"' in consumer["run"]
    assert "with_organization_userns.py" in consumer["run"]
    assert "if" not in consumer
    assert not consumer.get("continue-on-error", False)
    upload = next(
        step for step in shard["steps"] if step.get("name") == "Preserve core shard evidence"
    )
    assert upload["with"]["name"] == "core-check-shard-${{ matrix.shard }}"
    assert upload["if"] == "always()"
    assert upload["with"]["if-no-files-found"] == "error"
    production = next(
        step["run"] for step in steps if "run --name production" in step.get("run", "")
    )
    assert production.index("run --name production") < production.index(
        'cp "$runtime_output/cleanup.json"'
    )
    assert "organizations-production-runtime.outPath" in production
    assert "sha256sum postgres.json" in production
    for name in ("models", "production", "recovery", "jwks", "fingerprint", "grant"):
        assert any(f"run --name {name}" in s.get("run", "") for s in steps)


@pytest.mark.parametrize("mutation", ["missing", "wrong_source", "failed", "cancelled_cleanup"])
def test_database_partition_cannot_pass_without_its_own_complete_evidence(tmp_path, mutation):
    fixture(tmp_path)
    root = tmp_path / "core-check-shard-database"
    if mutation == "missing":
        (root / "core-build-observations.jsonl").unlink()
    elif mutation == "wrong_source":
        change(
            root / "ci-check-ownership.json",
            lambda row: row["context"].update({"GITHUB_SHA": "b" * 40}),
        )
    elif mutation == "cancelled_cleanup":
        change(root / "organization-userns-core.json", lambda row: row.update(cancellation="15"))
    else:
        path = root / "core-build-observations.jsonl"
        rows = [json.loads(line) for line in path.read_text().splitlines()]
        rows[-1]["returncode"] = 1
        path.write_text("".join(json.dumps(row) + "\n" for row in rows))
    with pytest.raises((ValueError, FileNotFoundError)):
        aggregate(tmp_path, CONTEXT, RESULTS, all_checks=False)
