#!/usr/bin/env python3
"""Validate Phase 2 certification evidence bundles."""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
from typing import Any, cast

from jsonschema import Draft202012Validator, ValidationError

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
SCHEMA_PATH = REPO_ROOT / "spec/certification-evidence-bundle.schema.json"
CLAIM_SCHEMA_PATH = REPO_ROOT / "spec/certification-claim.schema.json"

RESULT_TO_COUNT_KEY = {
    "PASSED": "passed",
    "REVIEW": "review",
    "WARNING": "warning",
    "SKIPPED": "skipped",
    "FAILED": "failed",
}
NON_PASS_DISPOSITION_RESULTS = {"REVIEW", "WARNING", "SKIPPED"}
EXTERNAL_COMPLETE_FORMAL_STATUSES = {"approved", "publicly_listed"}


def load_json(path: pathlib.Path) -> object:
    try:
        return json.loads(path.read_text())
    except OSError as exc:
        raise SystemExit(f"Certification evidence file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Invalid JSON in {path}: {exc}") from exc


def repo_relative_path(repo_root: pathlib.Path, raw_path: str, label: str) -> pathlib.Path:
    if not raw_path:
        raise ValidationError(f"{label}: path must be non-empty")
    path = pathlib.Path(raw_path)
    if path.is_absolute():
        raise ValidationError(f"{label}: local path must be repository-relative")
    if ".." in path.parts:
        raise ValidationError(f"{label}: local path must not contain '..'")
    resolved_root = repo_root.resolve()
    resolved = (resolved_root / path).resolve()
    try:
        resolved.relative_to(resolved_root)
    except ValueError as exc:
        raise ValidationError(f"{label}: local path escapes repository root") from exc
    return resolved


def require_existing_path(
    repo_root: pathlib.Path,
    raw_path: str,
    label: str,
    *,
    require_dir: bool | None = None,
) -> pathlib.Path:
    path = repo_relative_path(repo_root, raw_path, label)
    if not path.exists():
        raise ValidationError(f"{label}: path does not exist: {raw_path}")
    if require_dir is True and not path.is_dir():
        raise ValidationError(f"{label}: path must be a directory: {raw_path}")
    if require_dir is False and not path.is_file():
        raise ValidationError(f"{label}: path must be a file: {raw_path}")
    return path


def is_external_uri(raw_uri: str) -> bool:
    return raw_uri.startswith(("http://", "https://", "s3://", "gs://"))


def validate_evidence_uri(repo_root: pathlib.Path, raw_uri: str | None, label: str) -> None:
    if raw_uri is None:
        return
    if is_external_uri(raw_uri):
        if raw_uri.startswith("http://"):
            raise ValidationError(f"{label}: external evidence_uri must not use http")
        return
    require_existing_path(repo_root, raw_uri, label, require_dir=None)


def validate_claim_gate(repo_root: pathlib.Path, bundle: dict[str, Any]) -> dict[str, Any]:
    claim_gate_path = require_existing_path(
        repo_root,
        cast("str", bundle["claim_gate_path"]),
        "claim_gate_path",
        require_dir=False,
    )
    claim_schema = load_json(CLAIM_SCHEMA_PATH)
    claim_gate = cast("dict[str, Any]", load_json(claim_gate_path))
    Draft202012Validator(
        claim_schema,
        format_checker=Draft202012Validator.FORMAT_CHECKER,
    ).validate(claim_gate)

    if claim_gate.get("claim_target") != "certification":
        raise ValidationError("claim_gate_path must point at the certification claim gate")
    if claim_gate.get("claim_active") is not False:
        raise ValidationError("certification evidence bundles must keep claim_active=false")

    bundle_scope = cast("dict[str, Any]", bundle["certification_scope"])
    claim_scope = claim_gate.get("certification_scope")
    if not isinstance(claim_scope, dict):
        raise ValidationError("certification claim gate requires certification_scope")
    if bundle_scope.get("selected") is not True:
        raise ValidationError("certification evidence bundle requires selected scope")
    if claim_scope.get("selected") is not True:
        raise ValidationError("certification claim gate must record selected=true")
    if claim_scope.get("target") != bundle_scope.get("target"):
        raise ValidationError("certification claim gate target must match evidence bundle target")

    return claim_gate


def count_results(results: list[Any], plan_name: str) -> tuple[dict[str, int], dict[str, str]]:
    counts: dict[str, int] = dict.fromkeys(RESULT_TO_COUNT_KEY.values(), 0)
    non_pass_modules: dict[str, str] = {}

    for index, raw_entry in enumerate(results):
        if not isinstance(raw_entry, dict):
            raise ValidationError(f"{plan_name}: results entry {index} must be an object")
        module = raw_entry.get("test_module")
        result = raw_entry.get("result")
        status = raw_entry.get("status")
        if not isinstance(module, str) or not module:
            raise ValidationError(f"{plan_name}: results entry {index} missing test_module")
        if result not in RESULT_TO_COUNT_KEY:
            raise ValidationError(f"{plan_name}: {module} has unsupported result {result!r}")
        if status != "FINISHED":
            raise ValidationError(f"{plan_name}: {module} is not FINISHED")

        counts[RESULT_TO_COUNT_KEY[cast("str", result)]] += 1
        if result in NON_PASS_DISPOSITION_RESULTS:
            non_pass_modules[module] = cast("str", result)

    return counts, non_pass_modules


def load_plan_results(
    repo_root: pathlib.Path,
    plan: dict[str, Any],
    plan_name: str,
) -> tuple[dict[str, int], dict[str, str]]:
    artifacts = cast("dict[str, Any]", plan["artifacts"])
    results_json = artifacts.get("results_json")
    if not isinstance(results_json, str):
        raise ValidationError(f"{plan_name}: included claim-bearing plan requires results_json")
    results_path = require_existing_path(
        repo_root,
        results_json,
        f"{plan_name}.artifacts.results_json",
        require_dir=False,
    )
    results = load_json(results_path)
    if not isinstance(results, list):
        raise ValidationError(f"{plan_name}: results_json must contain a result list")
    return count_results(results, plan_name)


def validate_plan_artifacts(repo_root: pathlib.Path, plan: dict[str, Any], plan_name: str) -> None:
    artifacts = cast("dict[str, Any]", plan["artifacts"])
    required_file_keys = ("plan_json", "export_zip", "suite_commit_txt")
    for key in required_file_keys:
        raw_path = artifacts.get(key)
        if not isinstance(raw_path, str):
            raise ValidationError(f"{plan_name}: included claim-bearing plan requires {key}")
        path = require_existing_path(
            repo_root,
            raw_path,
            f"{plan_name}.artifacts.{key}",
            require_dir=False,
        )
        if key == "suite_commit_txt" and not path.read_text().strip():
            raise ValidationError(f"{plan_name}: suite_commit_txt must be non-empty")
        if key == "plan_json":
            plan_json = load_json(path)
            if not isinstance(plan_json, dict):
                raise ValidationError(f"{plan_name}: plan_json must contain an object")

    screenshots_dir = artifacts.get("screenshots_dir")
    if screenshots_dir is not None:
        if not isinstance(screenshots_dir, str):
            raise ValidationError(f"{plan_name}: screenshots_dir must be null or string")
        require_existing_path(
            repo_root,
            screenshots_dir,
            f"{plan_name}.artifacts.screenshots_dir",
            require_dir=True,
        )


def expected_counts(plan: dict[str, Any], plan_name: str) -> dict[str, int]:
    raw_counts = plan["result_counts"]
    if not isinstance(raw_counts, dict):
        raise ValidationError(f"{plan_name}: result_counts must be an object")
    return {key: int(raw_counts[key]) for key in RESULT_TO_COUNT_KEY.values()}


def validate_dispositions(
    plan: dict[str, Any],
    plan_name: str,
    non_pass_modules: dict[str, str],
) -> list[dict[str, Any]]:
    dispositions = cast("list[Any]", plan["dispositions"])
    disposition_by_module: dict[str, dict[str, Any]] = {}
    for index, raw_disposition in enumerate(dispositions):
        if not isinstance(raw_disposition, dict):
            raise ValidationError(f"{plan_name}: disposition {index} must be an object")
        disposition = cast("dict[str, Any]", raw_disposition)
        module = disposition.get("test_module")
        result = disposition.get("result")
        if not isinstance(module, str):
            raise ValidationError(f"{plan_name}: disposition {index} missing test_module")
        if module in disposition_by_module:
            raise ValidationError(f"{plan_name}: duplicate disposition for {module}")
        if module not in non_pass_modules:
            raise ValidationError(f"{plan_name}: disposition for non-non-PASS module {module}")
        if result != non_pass_modules[module]:
            raise ValidationError(
                f"{plan_name}: disposition result for {module} does not match results_json",
            )
        disposition_by_module[module] = disposition

    missing = sorted(set(non_pass_modules) - set(disposition_by_module))
    if missing:
        raise ValidationError(
            f"{plan_name}: missing dispositions for non-PASS modules: {', '.join(missing)}",
        )
    return list(disposition_by_module.values())


def validate_plan(
    repo_root: pathlib.Path,
    plan: dict[str, Any],
    external_complete: bool,
) -> tuple[bool, list[dict[str, Any]]]:
    plan_name = cast("str", plan["plan_name"])
    claim_bearing = plan.get("claim_bearing") is True
    included = plan.get("scope_status") == "included"
    if not claim_bearing or not included:
        return False, []

    if plan.get("result_status") not in {"pass", "partial-with-dispositions"}:
        raise ValidationError(f"{plan_name}: included claim-bearing plan requires result evidence")

    validate_plan_artifacts(repo_root, plan, plan_name)
    actual_counts, non_pass_modules = load_plan_results(repo_root, plan, plan_name)
    declared_counts = expected_counts(plan, plan_name)
    if declared_counts != actual_counts:
        raise ValidationError(
            f"{plan_name}: result_counts mismatch: "
            f"declared {declared_counts}, actual {actual_counts}",
        )
    if actual_counts["failed"] != 0:
        raise ValidationError(f"{plan_name}: FAILED modules block certification evidence")
    if plan.get("result_status") == "pass" and non_pass_modules:
        raise ValidationError(f"{plan_name}: pass result_status cannot include non-PASS modules")

    dispositions = validate_dispositions(plan, plan_name, non_pass_modules)
    if external_complete:
        blockers = [
            cast("str", disposition["test_module"])
            for disposition in dispositions
            if disposition.get("public_claim_blocker") is True
        ]
        if blockers:
            raise ValidationError(
                f"{plan_name}: public-claim blockers remain: {', '.join(sorted(blockers))}",
            )

    return True, dispositions


def validate_phase_semantics(bundle: dict[str, Any]) -> None:
    phase2_status = bundle["phase2_status"]
    public_claim_ready = bundle["public_claim_ready"]
    formal_submission = cast("dict[str, Any]", bundle["formal_submission"])
    formal_status = formal_submission["status"]
    review = cast("dict[str, Any]", bundle["review"])

    if phase2_status == "internal-complete" and public_claim_ready is not False:
        raise ValidationError(
            "internal-complete certification evidence must keep public_claim_ready=false"
        )
    if phase2_status == "external-complete" and public_claim_ready is not True:
        raise ValidationError(
            "external-complete certification evidence requires public_claim_ready=true"
        )
    if (
        phase2_status == "external-complete"
        and formal_status not in EXTERNAL_COMPLETE_FORMAL_STATUSES
    ):
        raise ValidationError(
            "external-complete certification evidence requires approved or "
            "publicly listed formal evidence",
        )
    if phase2_status in {"internal-complete", "external-complete"}:
        if review.get("decision") != "approved":
            raise ValidationError(
                f"{phase2_status} certification evidence requires approved review"
            )
        if not review.get("reviewer"):
            raise ValidationError(f"{phase2_status} certification evidence requires reviewer")


def validate_formal_submission(repo_root: pathlib.Path, bundle: dict[str, Any]) -> None:
    formal_submission = cast("dict[str, Any]", bundle["formal_submission"])
    status = formal_submission["status"]
    evidence_uri = formal_submission["evidence_uri"]
    if status in {"submitted", "approved", "publicly_listed"} and not evidence_uri:
        raise ValidationError(f"formal_submission status {status} requires evidence_uri")
    validate_evidence_uri(
        repo_root, cast("str | None", evidence_uri), "formal_submission.evidence_uri"
    )


def validate_bundle(path: pathlib.Path, repo_root: pathlib.Path | None = None) -> None:
    resolved_repo_root = (repo_root or REPO_ROOT).resolve()
    schema = load_json(SCHEMA_PATH)
    bundle = cast("dict[str, Any]", load_json(path))
    Draft202012Validator(
        schema,
        format_checker=Draft202012Validator.FORMAT_CHECKER,
    ).validate(bundle)

    validate_phase_semantics(bundle)
    validate_claim_gate(resolved_repo_root, bundle)
    validate_formal_submission(resolved_repo_root, bundle)

    external_complete = bundle["phase2_status"] == "external-complete"
    included_claim_bearing = 0
    for raw_plan in cast("list[Any]", bundle["plans"]):
        if not isinstance(raw_plan, dict):
            raise ValidationError("plans entries must be objects")
        was_included, _ = validate_plan(
            resolved_repo_root,
            cast("dict[str, Any]", raw_plan),
            external_complete,
        )
        if was_included:
            included_claim_bearing += 1

    if included_claim_bearing == 0:
        raise ValidationError("certification evidence bundle requires included claim-bearing plans")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", nargs="+", help="Certification evidence bundle JSON path(s)")
    args = parser.parse_args()

    failures = 0
    for raw_path in args.bundle:
        path = pathlib.Path(raw_path)
        try:
            validate_bundle(path)
        except (ValidationError, SystemExit) as exc:
            print(f"[invalid] {path}: {exc}", file=sys.stderr)
            failures += 1
            continue
        print(f"[ok] {path}")

    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
