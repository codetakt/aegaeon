#!/usr/bin/env python3
"""Evaluate the full flake and build the checks owned by core in full PR validation."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

SYSTEM = "x86_64-linux"
FORMAL_PACKAGES = {
    "verifyFstar": "verify-fstar",
    "verifyTamarin": "verify-tamarin",
    "verifyKani": "verify-kani",
}
DERIVATION = re.compile(r"/nix/store/[0-9a-z]{32}-[^/\s]+\.drv")


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


def run() -> None:
    if os.environ.get("GITHUB_EVENT_NAME") not in {"pull_request", "merge_group"}:
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
    record = Path("artifacts/ci-check-ownership.json")
    record.parent.mkdir(parents=True, exist_ok=True)
    record.write_text(json.dumps({"system": SYSTEM, "owners": owners}, indent=2) + "\n")
    # Build exact evaluated derivations, including every new non-delegated check.
    if owners["core"]:
        subprocess.run(
            ["nix", "build", "--no-link", "--print-build-logs"]
            + [drv + "^*" for drv in sorted(set(owners["core"].values()))],
            check=True,
        )


def main() -> int:
    try:
        run()
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"Core PR checks failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
