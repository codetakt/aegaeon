#!/usr/bin/env python3
"""Fail unless every selected reusable workflow succeeded for the current PR run."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any


def check_results(needs: dict[str, Any], policy: dict[str, Any]) -> None:
    if needs.get("plan", {}).get("result") != "success":
        raise ValueError("change classification did not succeed")
    scope = needs["plan"].get("outputs", {}).get("scope")
    if scope not in policy["scopes"]:
        raise ValueError("missing or unknown classification")
    selected = set(policy["scopes"][scope])
    all_lanes = set(policy["scopes"]["full"])
    if set(needs) != all_lanes | {"plan"}:
        raise ValueError("aggregate dependencies differ from the check inventory")
    for lane in sorted(all_lanes):
        result = needs[lane].get("result")
        allowed = {"success"} if lane in selected else {"success", "skipped"}
        if result not in allowed:
            raise ValueError(f"{lane}: {result}; required={lane in selected}, scope={scope}")
        print(f"{lane}: {result}" + ("" if lane in selected else f" (not required for {scope})"))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, required=True)
    args = parser.parse_args()
    try:
        check_results(json.loads(os.environ["PR_NEEDS_JSON"]), json.loads(args.policy.read_text()))
    except (KeyError, OSError, ValueError) as error:
        print(f"PR validation failed: {error}")
        return 1
    print("All required PR checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
