#!/usr/bin/env python3
"""Select PR checks from a complete Git diff, using the base revision's policy."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path, PurePosixPath
from typing import Any

SCOPES = ("docs", "integrity", "full")
ORIGINAL_LANES = (
    "docs",
    "integrity",
    "core",
    "lint",
    "security",
    "verification",
    "compliance",
    "kms",
    "container",
)
SUPPLEMENTAL_LANES = {"components"}
COMPONENTS = ("conformance", "development-tools", "infrastructure", "python-example")
INFRASTRUCTURE_MODULES = ("aegaeon-aws-staging", "oidc-aws-kms-parity", "perf-aws-ec2")
PYTHON_INPUTS = {
    "examples/minimal-rp/requirements.txt",
    "examples/minimal-rp/app.py",
    "tests/examples/minimal_rp/check_flow.py",
}
CONFORMANCE_INPUTS = {
    ".github/workflows/oidf-conformance.yml",
    ".github/workflows/conformance-validation.yml",
    "crates/server/tests/process_local_runtime_state_guard_test.rs",
    "tests/ci/test_conformance_runner.py",
    "tests/ci/test_conformance_results.py",
    "tests/ci/test_conformance_validation.py",
    "tests/ci/test_conformance_fixture.py",
    "tests/ci/test_conformance_https.py",
}
DEVELOPMENT_INPUTS = {
    "package.json",
    "package-lock.json",
    "tsconfig.json",
    "eslint.config.cjs",
    "spec/workflow-inventory.current.json",
    "spec/server-strict-types.current.json",
    "spec/strict-types.current.json",
    "scripts/check-strict-types.ts",
    "scripts/check-workflow-inventory.ts",
    "scripts/sdk/check_sdk_strict_types.ts",
    "scripts/sdk/tools-src/check-strict-types.ts",
    "tests/verified_core_wasm/root_strict_types_policy_test.ts",
    "tests/verified_core_wasm/strict_types_policy_test.ts",
    "tests/verified_core_wasm/workflow_inventory_policy_test.ts",
}


def unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Do not allow repeated policy/result keys to silently replace an earlier value."""
    result: dict[str, Any] = {}
    for name, value in pairs:
        if name in result:
            raise ValueError(f"duplicate JSON key: {name}")
        result[name] = value
    return result


def git(repo: Path, *args: str) -> bytes:
    return subprocess.check_output(["git", "-C", str(repo), *args], stderr=subprocess.PIPE)


def validate_policy(policy: dict[str, Any]) -> None:
    if not isinstance(policy, dict):
        raise ValueError("policy must be a JSON object")  # noqa: TRY004 - invalid policy
    scopes = policy.get("scopes")
    if (
        type(policy.get("version")) is not int
        or policy["version"] != 1
        or not isinstance(scopes, dict)
        or set(scopes) != set(SCOPES)
    ):
        raise ValueError("unsupported policy version or scopes")
    if scopes["docs"] != ["docs"] or scopes["integrity"] != ["docs", "integrity"]:
        raise ValueError("documentation and integrity checks cannot be omitted")
    if scopes["full"] != list(ORIGINAL_LANES):
        raise ValueError("invalid original full-check inventory")
    supplemental = policy.get("supplemental_lanes", {})
    if not isinstance(supplemental, dict):
        raise ValueError("malformed supplemental check inventory")  # noqa: TRY004
    if set(supplemental) & (set(ORIGINAL_LANES) | {"plan"}):
        raise ValueError("supplemental check inventory overlaps original checks")
    if set(supplemental) - SUPPLEMENTAL_LANES:
        raise ValueError("unknown supplemental check inventory")
    if any(state not in ("pending", "required") for state in supplemental.values()):
        raise ValueError("supplemental check state must be pending or required")

    validate_component_policy(policy)


def validate_component_policy(policy: dict[str, Any]) -> None:
    if "component_plan_version" in policy:
        if (
            type(policy["component_plan_version"]) is not int
            or policy["component_plan_version"] != 1
            or policy.get("components") != list(COMPONENTS)
            or policy.get("infrastructure_modules") != list(INFRASTRUCTURE_MODULES)
        ):
            raise ValueError("invalid component plan policy schema")
    elif "components" in policy or "infrastructure_modules" in policy:
        raise ValueError("component inventory requires a plan version")


def path_scope(path: str, policy: dict[str, Any]) -> tuple[str, str]:
    p = PurePosixPath(path)
    if p.is_absolute() or ".." in p.parts or any(ord(c) < 32 for c in path):
        return "full", "unrecognized path representation"
    if path in policy["runtime_document_paths"] or any(
        path.startswith(prefix) for prefix in policy["runtime_document_prefixes"]
    ):
        return "full", "document consumed by runtime regression tests"
    if path in policy["integrity_paths"] or any(
        path.startswith(prefix) for prefix in policy["integrity_prefixes"]
    ):
        if p.suffix in {".md", ".json", ".yaml", ".yml", ".py"}:
            return "integrity", "assurance, specification or validator input"
        return "full", "unrecognized integrity input type"
    if path in policy["documentation_paths"] or (path.startswith("docs/") and p.suffix == ".md"):
        return "docs", "documentation without a declared runtime dependency"
    return "full", "implementation, shared tooling or unclassified input"


def ambiguous_change(change: dict[str, str], policy: dict[str, Any]) -> bool:
    path = change["path"]
    p = PurePosixPath(path)
    modes = {change["old_mode"], change["new_mode"]} - {"000000"}
    scope, _ = path_scope(path, policy)
    return (
        not path
        or str(p) != path
        or "\\" in path
        or p.is_absolute()
        or ".." in p.parts
        or any(ord(c) < 32 for c in path)
        or change["status"] not in {"A", "D", "M", "T"}
        or not modes
        or not modes <= {"100644", "100755"}
        or len(modes) > 1
        or (scope == "docs" and "100755" in modes)
    )


def component_targets(
    change: dict[str, str], policy: dict[str, Any]
) -> tuple[list[str], list[str], str]:
    path = change["path"]
    p = PurePosixPath(path)
    scope, _ = path_scope(path, policy)
    if ambiguous_change(change, policy):
        return list(COMPONENTS), list(INFRASTRUCTURE_MODULES), "ambiguous path, change or file mode"
    if path.startswith("infra/tofu/"):
        if (
            len(p.parts) == 4
            and p.parts[2] in INFRASTRUCTURE_MODULES
            and (p.suffix in {".tf", ".tftpl"} or p.name == ".terraform.lock.hcl")
        ):
            return ["infrastructure"], [p.parts[2]], "registered OpenTofu module input"
        return (
            list(COMPONENTS),
            list(INFRASTRUCTURE_MODULES),
            "unregistered infrastructure input or module",
        )
    if path in PYTHON_INPUTS:
        return ["python-example"], [], "Python example dependency, application or flow test"
    if path.startswith("scripts/oidf_conformance/") or path in CONFORMANCE_INPUTS:
        return ["conformance"], [], "conformance suite or fixture guard input"
    if path in DEVELOPMENT_INPUTS:
        return ["development-tools"], [], "root development dependency or exact TypeScript consumer"
    if scope in {"docs", "integrity"}:
        return [], [], "document or integrity input without a declared component dependency"
    return (
        list(COMPONENTS),
        list(INFRASTRUCTURE_MODULES),
        "shared tooling, runner or unclassified input",
    )


def component_plan(
    changes: list[dict[str, str]], policy: dict[str, Any], fallback: str = ""
) -> dict[str, Any]:
    records = []
    components: set[str] = set()
    modules: set[str] = set()
    for change in sorted(
        changes, key=lambda item: (item["path"], item["status"], item["old_mode"], item["new_mode"])
    ):
        selected, selected_modules, reason = component_targets(change, policy)
        components.update(selected)
        modules.update(selected_modules)
        records.append(
            {
                **change,
                "components": selected,
                "infrastructure_modules": selected_modules,
                "reason": reason,
            }
        )
    if not changes or fallback:
        components.update(COMPONENTS)
        modules.update(INFRASTRUCTURE_MODULES)
    return {
        "version": 1,
        "components": sorted(components),
        "infrastructure_modules": sorted(modules),
        "changes": records,
        "fallback": fallback or ("empty diff" if not changes else ""),
    }


def parse_changes(raw: bytes) -> list[dict[str, str]]:
    """Parse --raw -z --no-renames; renames retain both deleted and added paths."""
    fields = raw.split(b"\0")
    if fields[-1] != b"" or (len(fields) - 1) % 2:
        raise ValueError("incomplete Git diff")
    changes = []
    for index in range(0, len(fields) - 1, 2):
        header = fields[index].decode("ascii").split()
        if (
            len(header) != 5
            or not header[0].startswith(":")
            or header[4] not in {"A", "D", "M", "T"}
            or not re.fullmatch(r":[0-7]{6}", header[0])
            or not re.fullmatch(r"[0-7]{6}", header[1])
            or any(not re.fullmatch(r"[0-9a-f]{7,64}", oid) for oid in header[2:4])
        ):
            raise ValueError("unsupported Git change record")
        changes.append(
            {
                "path": fields[index + 1].decode("utf-8"),
                "status": header[4],
                "old_mode": header[0][1:],
                "new_mode": header[1],
            }
        )
    if any(not change["path"] for change in changes):
        raise ValueError("empty Git change path")
    if len({change["path"] for change in changes}) != len(changes):
        raise ValueError("duplicate Git change path")
    return changes


def classify(changes: list[dict[str, str]], policy: dict[str, Any]) -> dict[str, Any]:
    validate_policy(policy)
    scope = "docs" if changes else "full"
    records = []
    for change in changes:
        kind, reason = path_scope(change["path"], policy)
        modes = {change["old_mode"], change["new_mode"]} - {"000000"}
        if (
            not modes <= {"100644", "100755"}
            or len(modes) > 1
            or (kind == "docs" and "100755" in modes)
        ):
            kind, reason = "full", "executable, symlink, submodule or other file mode"
        if "component_plan_version" in policy and ambiguous_change(change, policy):
            kind, reason = "full", "ambiguous path, change or file mode"
        if SCOPES.index(kind) > SCOPES.index(scope):
            scope = kind
        records.append({**change, "scope": kind, "reason": reason})
    result: dict[str, Any] = {
        "scope": scope,
        "selected": policy["scopes"][scope],
        "changes": records,
    }
    if "component_plan_version" in policy:
        result["component_plan"] = component_plan(changes, policy)
    return result


def build_plan(repo: Path, base: str, head: str, policy: dict[str, Any]) -> dict[str, Any]:
    for revision in (base, head):
        if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", revision):
            raise ValueError("base and head must be full commit IDs")
    merge_base = git(repo, "merge-base", base, head).decode().strip()
    raw = git(repo, "diff", "--raw", "-z", "--no-renames", "--no-ext-diff", merge_base, head, "--")
    return {
        "version": 1,
        "base": base,
        "head": head,
        "merge_base": merge_base,
        **classify(parse_changes(raw), policy),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--base", required=True)
    parser.add_argument("--head", required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    policy_bytes = args.policy.read_bytes()
    policy = json.loads(policy_bytes, object_pairs_hook=unique_json_object)
    validate_policy(policy)
    try:
        plan = build_plan(args.repo, args.base, args.head, policy)
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        plan = {
            "version": 1,
            "base": args.base,
            "head": args.head,
            "scope": "full",
            "selected": policy["scopes"]["full"],
            "changes": [],
            "fallback": str(error),
        }
    if "component_plan_version" in policy and "component_plan" not in plan:
        plan["component_plan"] = component_plan([], policy, plan["fallback"])
    plan["policy_sha256"] = hashlib.sha256(policy_bytes).hexdigest()
    plan["classifier_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    args.output.write_text(json.dumps(plan, indent=2) + "\n")
    if output := os.environ.get("GITHUB_OUTPUT"):
        with Path(output).open("a") as stream:
            stream.write(f"scope={plan['scope']}\n")
    print(json.dumps(plan, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
