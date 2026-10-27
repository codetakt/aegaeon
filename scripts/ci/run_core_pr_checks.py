#!/usr/bin/env python3
"""Evaluate the full flake and execute every owned non-timing check."""

from __future__ import annotations

import argparse
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


def build_checks(checks: dict[str, str]) -> None:
    if not checks:
        raise ValueError("No core checks selected")
    subprocess.run(
        ["nix", "build", "--no-link", "--print-build-logs"]
        + [drv + "^*" for drv in sorted(set(checks.values()))],
        check=True,
    )


def run(*, all_checks: bool = False) -> None:
    if not all_checks and os.environ.get("GITHUB_EVENT_NAME") not in {
        "pull_request",
        "merge_group",
    }:
        raise ValueError("check delegation is only supported by full PR/group validation")
    # Instantiate inventories first: import-from-derivation inputs (such as
    # Kani's patched Cargo.lock) may be absent on a fresh runner. The read-only
    # --no-build validation cannot prepare them and must not rely on a dev shell
    # having populated the store. This does not build the delegated checks.
    checks = evaluate(
        f".#checks.{SYSTEM}", "checks: builtins.mapAttrs (_: check: check.drvPath) checks"
    )
    aliases = " ".join(f'{name} = "{package}";' for name, package in FORMAL_PACKAGES.items())
    packages = evaluate(
        f".#packages.{SYSTEM}",
        "packages: builtins.mapAttrs (_: name: packages.${name}.drvPath) { " + aliases + " }",
    )
    # Still validate every output, including apps and shells, before execution.
    subprocess.run(["nix", "flake", "check", "--no-build", "--print-build-logs"], check=True)
    owners = partition(checks, packages)
    if all_checks:
        owners = {"core": checks, "verification": {}}
    record = Path("artifacts/ci-check-ownership.json")
    record.parent.mkdir(parents=True, exist_ok=True)
    record.write_text(json.dumps({"system": SYSTEM, "owners": owners}, indent=2) + "\n")
    build_checks(owners["core"])


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
