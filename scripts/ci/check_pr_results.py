#!/usr/bin/env python3
"""Fail unless every selected reusable workflow succeeded for the current PR run."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any

from pr_plan import unique_json_object, validate_policy


def result_context(
    needs: dict[str, Any], policy: dict[str, Any]
) -> tuple[str, set[str], set[str], dict[str, str]]:
    validate_policy(policy)
    if not isinstance(needs, dict):
        raise ValueError("aggregate results must be a JSON object")  # noqa: TRY004
    if any(not isinstance(value, dict) for value in needs.values()):
        raise ValueError("each aggregate dependency must have a result object")
    if needs.get("plan", {}).get("result") != "success":
        raise ValueError("change classification did not succeed")
    outputs = needs["plan"].get("outputs")
    if not isinstance(outputs, dict):
        raise ValueError("classification outputs must be a JSON object")  # noqa: TRY004
    scope = outputs.get("scope")
    if not isinstance(scope, str) or scope not in policy["scopes"]:
        raise ValueError("missing or unknown classification")
    selected = set(policy["scopes"][scope])
    all_lanes = set(policy["scopes"]["full"])
    supplemental = policy.get("supplemental_lanes", {})
    original = all_lanes | {"plan"}
    if not original <= set(needs) or set(needs) - original - set(supplemental):
        raise ValueError("aggregate dependencies differ from the check inventory")
    return scope, selected, all_lanes, supplemental


def check_results(needs: dict[str, Any], policy: dict[str, Any]) -> None:
    scope, selected, all_lanes, supplemental = result_context(needs, policy)
    for lane in sorted(all_lanes):
        result = needs[lane].get("result")
        allowed = {"success"} if lane in selected else {"success", "skipped"}
        if not isinstance(result, str) or result not in allowed:
            raise ValueError(f"{lane}: {result}; required={lane in selected}, scope={scope}")
        print(f"{lane}: {result}" + ("" if lane in selected else f" (not required for {scope})"))
    for lane, state in sorted(supplemental.items()):
        if lane not in needs:
            if state == "required":
                raise ValueError(f"{lane}: missing required supplemental check")
            continue
        if needs[lane].get("result") != "success":
            raise ValueError(f"{lane}: supplemental check must succeed whenever present")
        print(f"{lane}: success (supplemental)")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, required=True)
    args = parser.parse_args()
    try:
        check_results(
            json.loads(os.environ["PR_NEEDS_JSON"], object_pairs_hook=unique_json_object),
            json.loads(args.policy.read_text(), object_pairs_hook=unique_json_object),
        )
    except (KeyError, OSError, ValueError) as error:
        print(f"PR validation failed: {error}")
        return 1
    print("All required PR checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
