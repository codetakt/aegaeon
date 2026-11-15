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

from build_observations import run_observed
from core_resource_observations import observations

SYSTEM = "x86_64-linux"
# The 16 GiB core runner exhausted available memory/swap with simultaneous Rust
# derivations. Keep every target, but serialize derivations and bound build cores.
# These scheduling hints do not change derivations, test inputs or failure rules.
BUILD_CAPACITY = ["--max-jobs", "1", "--cores", "2"]
FORMAL_PACKAGES = {
    "verifyFstar": "verify-fstar",
    "verifyTamarin": "verify-tamarin",
    "verifyKani": "verify-kani",
}
DERIVATION = re.compile(r"/nix/store/[0-9a-z]{32}-[^/\s]+\.drv")
SHARDS = ("remaining", "workspace", "jose")
CONTEXT_KEYS = (
    "GITHUB_REPOSITORY",
    "GITHUB_RUN_ID",
    "GITHUB_RUN_ATTEMPT",
    "GITHUB_SHA",
    "GITHUB_EVENT_NAME",
)


def event_context() -> dict[str, str]:
    context = {key: os.environ[key] for key in CONTEXT_KEYS}
    if not all(context.values()):
        raise ValueError("missing GitHub event identity")
    if not re.fullmatch(r"[0-9a-f]{40}", context["GITHUB_SHA"]):
        raise ValueError("invalid source revision")
    if not all(
        re.fullmatch(r"[1-9][0-9]*", context[key])
        for key in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")
    ):
        raise ValueError("invalid run or attempt")
    actual = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    if actual != context["GITHUB_SHA"]:
        raise ValueError("checkout differs from GitHub source revision")
    return context


def split_core_checks(core: dict[str, str]) -> dict[str, dict[str, str]]:
    """Keep unknown checks; reject aliases that would cross runner ownership."""
    if not {"tests", "verifyJose"} <= set(core):
        raise ValueError("workspace or JOSE check is missing")
    groups = {
        "workspace": {"tests": core["tests"]},
        "jose": {"verifyJose": core["verifyJose"]},
        "remaining": {k: v for k, v in core.items() if k not in {"tests", "verifyJose"}},
    }
    assigned: set[str] = set()
    for selected in groups.values():
        if not selected or assigned.intersection(selected.values()):
            raise ValueError("empty shard or derivation assigned to multiple core shards")
        assigned.update(selected.values())
    return groups


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


def build_command(checks: dict[str, str]) -> list[str]:
    if not checks:
        raise ValueError("No core checks selected")
    return ["nix", "build", "--no-link", "--print-build-logs", *BUILD_CAPACITY] + [
        drv + "^*" for drv in sorted(set(checks.values()))
    ]


def build_checks(checks: dict[str, str]) -> None:
    run_observed(
        build_command(checks),
        Path("artifacts/core-build-observations.jsonl"),
    )


def run(*, all_checks: bool = False, shard: str | None = None) -> None:
    if not all_checks and os.environ.get("GITHUB_EVENT_NAME") not in {
        "pull_request",
        "merge_group",
    }:
        raise ValueError("check delegation is only supported by full PR/group validation")
    context = event_context() if shard is not None else None
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
    selected = owners["core"]
    if shard is None:
        record.write_text(json.dumps({"system": SYSTEM, "owners": owners}, indent=2) + "\n")
    else:
        shards = split_core_checks(selected)
        selected = shards[shard]
        record.write_text(
            json.dumps(
                {
                    "schema": "core-check-shard/1",
                    "system": SYSTEM,
                    "context": context,
                    "all_checks": all_checks,
                    "shard": shard,
                    "checks": checks,
                    "formal_packages": packages,
                    "owners": owners,
                    "shards": shards,
                },
                indent=2,
            )
            + "\n"
        )
    build_checks(selected)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--all-checks", action="store_true", help="also own formal checks")
    parser.add_argument("--shard", choices=SHARDS, help="build one exhaustive core partition")
    args = parser.parse_args()
    try:
        with observations():
            run(all_checks=args.all_checks, shard=args.shard)
    except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError) as error:
        print(f"Core PR checks failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
