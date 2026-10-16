"""Frozen hosted reliability opportunities; no statistical retry or CI adoption."""

from __future__ import annotations

import argparse
import json
import math
import os
import re
from fractions import Fraction
from pathlib import Path
from typing import Any

from verify_dudect_analysis_matrix import require, sha256, write_json

ROOT = Path(__file__).resolve().parents[2]
SPEC = ROOT / "scripts/ci/dudect-hosted-reliability.json"


def specification() -> dict[str, Any]:
    value = json.loads(SPEC.read_text())
    require(value["schema"] == "dudect-hosted-reliability/1", "Wrong campaign schema")
    require(value["maximum_opportunities"] == 299, "Unreviewed opportunity count")
    require(value["batch_size"] == 16, "Unreviewed concurrency")
    require(value["target_failure_rate"] == [1, 100], "Unreviewed target")
    require(value["one_sided_error"] == [1, 20], "Unreviewed confidence")
    require(value["replacements"] == 0, "Replacement trials are forbidden")
    # Exact integer/rational proof of the zero-failure design, not rounded logs.
    q = Fraction(*value["target_failure_rate"])
    error = Fraction(*value["one_sided_error"])
    n = value["maximum_opportunities"]
    require((1 - q) ** n <= error < (1 - q) ** (n - 1), "Wrong minimum sample size")
    return dict(value)


def slots(spec: dict[str, Any], batch: int) -> list[int]:
    count, size = spec["maximum_opportunities"], spec["batch_size"]
    require(type(batch) is int and 1 <= batch <= math.ceil(count / size), "Invalid batch")
    return list(range(1 + (batch - 1) * size, min(batch * size, count) + 1))


def invocation(
    spec: dict[str, Any], env: dict[str, str], slot: int | None = None
) -> dict[str, Any]:
    require(env.get("GITHUB_EVENT_NAME") == "push", "Campaign must be a frozen tag push")
    require(env.get("GITHUB_RUN_ATTEMPT") == "1", "Replacement workflow attempt")
    require(re.fullmatch(r"[0-9]+", env.get("GITHUB_RUN_ID", "")) is not None, "Missing run ID")
    require(
        re.fullmatch(r"[0-9a-f]{40}", env.get("GITHUB_SHA", "")) is not None, "Missing revision"
    )
    match = re.fullmatch(
        re.escape("refs/tags/" + spec["tag_prefix"]) + r"([0-9]{2})", env.get("GITHUB_REF", "")
    )
    require(match is not None, "Unexpected campaign tag")
    if match is None:
        raise ValueError("Missing batch")
    batch = int(match[1])
    inventory = slots(spec, batch)
    if slot is not None:
        require(type(slot) is int and slot in inventory, "Slot outside frozen batch")
    return {
        "schema": spec["schema"],
        "campaign": spec["campaign"],
        "batch": batch,
        "slot": slot,
        "batch_slots": inventory,
        "revision": env["GITHUB_SHA"],
        "run_id": env["GITHUB_RUN_ID"],
        "attempt": 1,
        "tag": env["GITHUB_REF"],
        "ci_admission": False,
        "prior_screen_included": False,
    }


def context(slot: int) -> dict[str, Any]:
    value = invocation(specification(), dict(os.environ), slot)
    value["spec_sha256"] = sha256(SPEC)
    return value


def check_packages(plan: dict[str, Any]) -> None:
    expected = specification()["packages"]
    for key in ("analysis_package", "native_packages", "case_contract_sha256"):
        require(plan[key] == expected[key], "Campaign package or numerical contract changed")


def assess_ledger(spec: dict[str, Any], records: list[dict[str, Any]]) -> dict[str, Any]:
    """Count opportunities, never cases/looks; partial stopping has no fixed-n CI."""
    identifiers = [r["slot"] for r in records]
    require(len(set(identifiers)) == len(identifiers), "Duplicate opportunity")
    require(
        all(type(s) is int and 1 <= s <= spec["maximum_opportunities"] for s in identifiers),
        "Unknown opportunity",
    )
    require(all(type(r["passed"]) is bool for r in records), "Invalid outcome")
    require(all(r.get("attempt") == 1 for r in records), "Replacement evidence")
    revisions = {r["revision"] for r in records}
    require(len(revisions) <= 1, "Mixed candidate revisions")
    failed = [r["slot"] for r in records if not r["passed"]]
    complete = len(records) == spec["maximum_opportunities"]
    qualified = complete and not failed
    return {
        "planned": spec["maximum_opportunities"],
        "recorded": len(records),
        "failures": failed,
        "stop_new_batches": bool(failed),
        "complete": complete,
        "zero_failure_criterion_met": qualified,
        "conditional_one_sided_upper_bound": -math.expm1(math.log(0.05) / 299)
        if qualified
        else None,
        "model": (
            "independent opportunities with a common failure probability; "
            "hosted allocation independence and long-term representativeness "
            "are not established by a fresh guest"
        ),
        "ci_admission": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("matrix", "receipt"))
    parser.add_argument("--slot", type=int)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    spec = specification()
    if args.action == "matrix":
        require(args.slot is None and args.output is None, "Unexpected matrix options")
        value = invocation(spec, dict(os.environ))
        print("matrix=" + json.dumps({"slot": value["batch_slots"]}, separators=(",", ":")))
    else:
        require(args.slot is not None and args.output is not None, "Missing receipt options")
        if args.slot is None or args.output is None:
            raise ValueError("Missing slot/output")
        value = context(args.slot)
        args.output.mkdir(parents=True, exist_ok=False)
        write_json(args.output / "opportunity.json", value)


if __name__ == "__main__":
    main()
