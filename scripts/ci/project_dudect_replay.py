"""Project digest-bound ordinary replay reports, preserving their observation identity.

This projection is useful for real retained-data integration tests. It cannot
invent a fresh CI request, operator authentication or lifecycle verification.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from inspect_dudect_evidence import decode, digest, hash_value, read_bounded, require

CHECKS = [
    "package",
    "analysis_identity",
    "process",
    "diagnostics",
    "stdout",
    "raw_prefix_replay",
    "saved_assessments",
    "unchanged_inputs",
]


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def project_process(  # noqa: PLR0915 - ordered receipt binding checks
    report_bytes: bytes, expected_sha256: str, invocation_bytes: bytes
) -> list[dict[str, Any]]:
    hash_value(expected_sha256)
    require(digest(report_bytes) == expected_sha256, "replay report digest mismatch")
    report = decode(report_bytes)
    invocation = decode(invocation_bytes)
    require(report["schema"] == "ordinary-replay-report/1", "unknown replay report")
    require(invocation["kind"] == "ordinary", "diagnostic report not ordinary")
    require(report["ci_admission"] is False, "unexpected local admission claim")
    require(report["original_assessments_modified"] is False, "original evidence modified")
    require(report["new_physical_trials"] == 0, "replay is not a new observation")
    receipt = report["replay_receipt"]
    receipt_sha = digest(canonical(receipt))
    require(receipt_sha == report["replay_receipt_sha256"], "replay receipt digest mismatch")
    require(receipt["schema"] == "ordinary-local-replay-receipt/1", "unknown replay receipt")
    require(receipt["checks_completed"] == CHECKS, "replay checks incomplete")
    require(receipt["invocation_sha256"] == digest(invocation_bytes), "invocation mismatch")
    for field, inv_field in (
        ("native_package_sha256", "package_sha256"),
        ("native_elf_sha256", "binary_sha256"),
    ):
        require(receipt[field] == invocation[inv_field], "native identity mismatch")
    require(
        receipt["analysis_sha256"] == digest(canonical(invocation["analysis"])),
        "analysis identity mismatch",
    )
    order = [invocation["suite"] + "/" + name for name in invocation["case_order"]]
    require(receipt["case_order"] == invocation["case_order"], "receipt case order mismatch")
    require([row["case_id"] for row in report["cases"]] == order, "report case order mismatch")
    require(len(set(order)) == len(order), "duplicate case")
    files = receipt["files"]
    for key in (
        "native.timing",
        "decisions.json",
        "effective-decisions.json",
        "qualification.json",
    ):
        hash_value(files[key]["sha256"])
    require(
        report["qualification_passed"]
        is all(row["axes"]["qualification_passed"] for row in report["cases"]),
        "aggregate qualification mismatch",
    )
    result = []
    for row in report["cases"]:
        identity = row["expected_identity"]
        require(identity["replay_receipt_sha256"] == receipt_sha, "case replay binding mismatch")
        require(identity["analysis_sha256"] == receipt["analysis_sha256"], "case analysis mismatch")
        hash_value(identity["assessment_sha256"])
        hash_value(identity["contract_sha256"])
        require(type(row["axes"]["qualification_passed"]) is bool, "nonboolean case qualification")
        result.append(
            {
                "case_id": row["case_id"],
                "role": row["role"],
                "compiler": invocation["compiler"],
                "unit": invocation["unit"],
                "packet": invocation["packet"],
                "elf_sha256": receipt["native_elf_sha256"],
                "analysis_sha256": receipt["analysis_sha256"],
                "raw_manifest_sha256": digest(canonical(files)),
                "original_decisions_sha256": files["decisions.json"]["sha256"],
                "effective_decisions_sha256": files["effective-decisions.json"]["sha256"],
                "audit_sha256": receipt_sha,
                "report_sha256": expected_sha256,
                "assessment_sha256": identity["assessment_sha256"],
                "qualification": "observation_contract_satisfied"
                if row["axes"]["qualification_passed"]
                else "not_satisfied",
                "looks": 8,
                "collection": "complete",
                "prefix_verification": "complete",
                "numeric_validity": "complete"
                if row["axes"]["qualification_passed"]
                else "not_established",
                "original_retention": "complete",
                "original_detections": row["detection_changes"][
                    "original_detected_statistic_looks"
                ],
            }
        )
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--expected-report-sha256", required=True)
    parser.add_argument("--invocation", type=Path, required=True)
    args = parser.parse_args()
    try:
        rows = project_process(
            read_bounded(args.report),
            args.expected_report_sha256,
            read_bounded(args.invocation),
        )
    except (OSError, KeyError, ValueError, TypeError) as error:
        print(json.dumps({"status": "rejected", "reason": str(error), "ci_admission": False}))
        return 2
    print(
        json.dumps(
            {
                "schema": "ordinary-replay-projection/1",
                "results": rows,
                "ci_admission": False,
                "fresh_execution": False,
                "authentication_performed": False,
                "external_lifecycle_verified": False,
            },
            sort_keys=True,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
