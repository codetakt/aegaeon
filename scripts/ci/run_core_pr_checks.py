#!/usr/bin/env python3
"""Evaluate the full flake and execute every owned non-timing check."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, TypedDict

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
# These checks consume the package also built by the parallel DB job. Start
# their build invocation later, so it can discover outputs published meanwhile.
# This is a scheduling hint, never authority to omit any check or dependency.
DATABASE_CONSUMERS = {
    "lti-browser-consent",
    "lti-packaged-runtime",
    "organizations-production-runtime",
}
DERIVATION = re.compile(r"/nix/store/[0-9a-z]{32}-[^/\s]+\.drv")


class DependencyNode(TypedDict):
    outputs: list[str]
    inputs: dict[str, list[str]]


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


def build_phases(checks: dict[str, str]) -> list[dict[str, str]]:
    """Keep every name; aliases of one derivation must share its invocation."""
    if not checks:
        raise ValueError("No core checks selected")
    deferred = {drv for name, drv in checks.items() if name in DATABASE_CONSUMERS}
    return [
        phase
        for phase in (
            {name: drv for name, drv in checks.items() if drv not in deferred},
            {name: drv for name, drv in checks.items() if drv in deferred},
        )
        if phase
    ]


def dependency_graph(value: dict[str, Any]) -> dict[str, DependencyNode]:
    """Accept the observed Nix v4 static graph; unknown edges cannot authorize work."""
    if value.get("version") != 4 or not isinstance(value.get("derivations"), dict):
        raise ValueError("unsupported derivation graph")
    graph: dict[str, DependencyNode] = {}
    for name, row in value["derivations"].items():
        path = "/nix/store/" + name
        if not DERIVATION.fullmatch(path) or row.get("version") != 4:
            raise ValueError("invalid derivation graph node")
        outputs = row["outputs"]
        inputs = row["inputs"]["drvs"]
        if not isinstance(outputs, dict) or not outputs or not isinstance(inputs, dict):
            raise ValueError("invalid derivation inputs or outputs")
        edges = {}
        for dependency, edge in inputs.items():
            selected = edge["outputs"]
            if (
                edge["dynamicOutputs"] != {}
                or not isinstance(selected, list)
                or not selected
                or not all(isinstance(output, str) for output in selected)
                or len(selected) != len(set(selected))
            ):
                raise ValueError("unsupported derivation dependency outputs")
            edges["/nix/store/" + dependency] = sorted(selected)
        graph[path] = {"outputs": sorted(outputs), "inputs": edges}
    if any(
        dependency not in graph or not set(outputs) <= set(graph[dependency]["outputs"])
        for row in graph.values()
        for dependency, outputs in row["inputs"].items()
    ):
        raise ValueError("incomplete derivation dependency graph")
    return graph


def dependency_closure(graph: dict[str, DependencyNode], roots: set[str]) -> set[str]:
    pending, seen = list(roots), set()
    while pending:
        path = pending.pop()
        if path not in graph:
            raise ValueError("missing derivation graph root")
        if path not in seen:
            seen.add(path)
            pending.extend(graph[path]["inputs"])
    return seen


def distribution_prerequisite(
    owners: dict[str, dict[str, str]],
    phases: list[dict[str, str]],
    packages: dict[str, str],
    graph: dict[str, DependencyNode],
) -> dict[str, Any]:
    """An optional scheduling step may request only an already-required output."""
    if set(packages) != {"server-distribution", "database-tests"}:
        raise ValueError("prerequisite package inventory differs")
    dependency_closure(graph, {*owners["core"].values(), *packages.values()})
    distribution, database = packages["server-distribution"], packages["database-tests"]
    deferred = {drv for name, drv in owners["core"].items() if name in DATABASE_CONSUMERS}
    late = next(i for i, phase in enumerate(phases) if deferred & set(phase.values()))
    early = {drv for phase in phases[:late] for drv in phase.values()}
    required_by = [
        name
        for name, drv in phases[late].items()
        if distribution in dependency_closure(graph, {drv})
    ]
    distribution_inputs = dependency_closure(graph, {distribution})
    eligible = (
        bool(required_by)
        and graph[distribution]["outputs"] == ["out"]
        and database not in distribution_inputs
        and not set(owners["verification"].values()) & distribution_inputs
        and distribution not in set(owners["core"].values())
        and distribution not in dependency_closure(graph, early)
    )
    return {
        "before_phase": late if eligible else None,
        "derivations": {"server-distribution": distribution} if eligible else {},
        "packages": packages,
        "required_by": sorted(required_by),
        "dependency_graph": graph,
        "purpose": "already-required prerequisite only; no cache-hit or speedup guarantee",
    }


def prepare_prerequisite(
    owners: dict[str, dict[str, str]], phases: list[dict[str, str]]
) -> dict[str, Any] | None:
    if not DATABASE_CONSUMERS & owners["core"].keys():
        return None
    packages = evaluate(
        f".#packages.{SYSTEM}",
        "packages: { server-distribution = packages.server-distribution.drvPath; "
        "database-tests = packages.database-tests.drvPath; }",
    )
    roots = sorted({*owners["core"].values(), *packages.values()})
    command = ["nix", "derivation", "show", "--recursive", "--no-pretty", *roots]
    raw = subprocess.check_output(command)
    result = distribution_prerequisite(owners, phases, packages, dependency_graph(json.loads(raw)))
    result.update(graph_command=command, graph_sha256=hashlib.sha256(raw).hexdigest())
    return result


def build_checks(checks: dict[str, str]) -> None:
    if not checks:
        raise ValueError("No core checks selected")
    run_observed(
        ["nix", "build", "--no-link", "--print-build-logs", *BUILD_CAPACITY]
        + [drv + "^*" for drv in sorted(set(checks.values()))],
        Path("artifacts/core-build-observations.jsonl"),
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
    phases = [owners["core"]] if all_checks else build_phases(owners["core"])
    prerequisite = None if all_checks else prepare_prerequisite(owners, phases)
    record = Path("artifacts/ci-check-ownership.json")
    record.parent.mkdir(parents=True, exist_ok=True)
    record.write_text(
        json.dumps(
            {
                "system": SYSTEM,
                "owners": owners,
                "build_phases": phases,
                "prerequisite": prerequisite,
            },
            indent=2,
        )
        + "\n"
    )
    for index, phase in enumerate(phases):
        if prerequisite is not None and prerequisite["before_phase"] == index:
            build_checks(prerequisite["derivations"])
        build_checks(phase)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--all-checks", action="store_true", help="also own formal checks")
    args = parser.parse_args()
    try:
        with observations():
            run(all_checks=args.all_checks)
    except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError) as error:
        print(f"Core PR checks failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
