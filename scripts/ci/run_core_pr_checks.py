#!/usr/bin/env python3
"""Evaluate the full flake; run timing gates after other core-owned checks."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

from collect_dudect_nix_output import CORE_TIMING_CHECKS, store_output

SYSTEM = "x86_64-linux"
FORMAL_PACKAGES = {
    "verifyFstar": "verify-fstar",
    "verifyTamarin": "verify-tamarin",
    "verifyKani": "verify-kani",
}
DERIVATION = re.compile(r"/nix/store/[0-9a-z]{32}-[^/\s]+\.drv")
TIMING_RECORD = Path("artifacts/ci-dudect-outputs.json")


def evaluate(attribute: str, expression: str) -> dict[str, str]:
    output = subprocess.check_output(
        ["nix", "eval", "--json", attribute, "--apply", expression], text=True
    )
    value = json.loads(output)
    if not isinstance(value, dict) or not all(
        isinstance(name, str) and isinstance(drv, str) and DERIVATION.fullmatch(drv)
        for name, drv in value.items()
    ):
        raise ValueError(f"{attribute}: expected named derivation paths")
    return value


def partition(checks: dict[str, str], packages: dict[str, str]) -> dict[str, dict[str, str]]:
    """Names are exhaustive; aliases may not assign one derivation to two owners."""
    if set(packages) != set(FORMAL_PACKAGES):
        raise ValueError("formal package inventory differs from delegated checks")
    if not set(FORMAL_PACKAGES) <= set(checks):
        raise ValueError("a delegated formal check is missing")
    delegated = {name: checks[name] for name in FORMAL_PACKAGES}
    if delegated != packages:
        raise ValueError("formal packages do not build the delegated check derivations")
    if len(set(delegated.values())) != len(delegated):
        raise ValueError("delegated formal checks must have distinct derivations")
    core = {name: drv for name, drv in checks.items() if name not in delegated}
    if set(core.values()) & set(delegated.values()):
        raise ValueError("a derivation is assigned to both core and verification")
    return {"core": core, "verification": delegated}


def timing_outputs(checks: dict[str, str]) -> dict[str, dict[str, str]]:
    """Freeze output paths from the exact derivations before any check builds."""
    if not set(CORE_TIMING_CHECKS) <= set(checks):
        raise ValueError("a required core timing check is missing")
    timing = {name: checks[name] for name in CORE_TIMING_CHECKS}
    if len(set(timing.values())) != len(timing):
        raise ValueError("core timing checks must have distinct derivations")
    result = {}
    for name, drv in timing.items():
        # Query the evaluated derivation, without depending on Nix's versioned
        # `derivation show` JSON envelope or evaluating a separate package alias.
        path = subprocess.check_output(
            ["nix-store", "--query", "--outputs", drv], text=True
        ).strip()
        output = store_output(path)
        if output is None or not output.name.endswith("-" + CORE_TIMING_CHECKS[name]):
            raise ValueError("timing check has an unexpected output")
        result[name] = {
            "derivation": drv,
            "store_output": str(output),
            "build_step_outcome": "not_started",
        }
    return result


def save_timing_outputs(outputs: dict[str, dict[str, str]]) -> None:
    TIMING_RECORD.parent.mkdir(parents=True, exist_ok=True)
    temporary = TIMING_RECORD.with_suffix(".tmp")
    temporary.write_text(json.dumps(outputs, indent=2) + "\n")
    temporary.replace(TIMING_RECORD)


def build_checks(checks: dict[str, str], outputs: dict[str, dict[str, str]]) -> None:
    timing_drvs = {row["derivation"] for row in outputs.values()}
    ordinary = sorted(set(checks.values()) - timing_drvs)
    if ordinary:
        subprocess.run(
            ["nix", "build", "--no-link", "--print-build-logs"] + [drv + "^*" for drv in ordinary],
            check=True,
        )
    # Aliases of a timing derivation stay here too, never in the parallel build.
    # Both gates remain required. A failed gate stops admission without a retry.
    for row in outputs.values():
        row["build_step_outcome"] = "in_progress"
        save_timing_outputs(outputs)
        try:
            subprocess.run(
                [
                    "nix",
                    "build",
                    "--no-link",
                    "--print-build-logs",
                    "--keep-failed",
                    row["derivation"] + "^*",
                ],
                check=True,
            )
        except (OSError, subprocess.CalledProcessError):
            row["build_step_outcome"] = "failure"
            save_timing_outputs(outputs)
            raise
        row["build_step_outcome"] = "success"
        save_timing_outputs(outputs)


def run(*, all_checks: bool = False) -> None:
    if not all_checks and os.environ.get("GITHUB_EVENT_NAME") not in {
        "pull_request",
        "merge_group",
    }:
        raise ValueError("check delegation is only supported by full PR/group validation")
    # Preserve evaluation of every flake output, including packages, apps and shells.
    subprocess.run(["nix", "flake", "check", "--no-build", "--print-build-logs"], check=True)
    checks = evaluate(
        f".#checks.{SYSTEM}", "checks: builtins.mapAttrs (_: check: check.drvPath) checks"
    )
    aliases = " ".join(f'{name} = "{package}";' for name, package in FORMAL_PACKAGES.items())
    packages = evaluate(
        f".#packages.{SYSTEM}",
        "packages: builtins.mapAttrs (_: name: packages.${name}.drvPath) { " + aliases + " }",
    )
    owners = partition(checks, packages)
    if all_checks:
        owners = {"core": checks, "verification": {}}
    outputs = timing_outputs(owners["core"])
    save_timing_outputs(outputs)
    record = Path("artifacts/ci-check-ownership.json")
    record.parent.mkdir(parents=True, exist_ok=True)
    record.write_text(json.dumps({"system": SYSTEM, "owners": owners}, indent=2) + "\n")
    build_checks(owners["core"], outputs)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--all-checks", action="store_true", help="also own formal checks")
    args = parser.parse_args()
    try:
        run(all_checks=args.all_checks)
    except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError) as error:
        print(f"Core PR checks failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
