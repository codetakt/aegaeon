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


def git(repo: Path, *args: str) -> bytes:
    return subprocess.check_output(["git", "-C", str(repo), *args], stderr=subprocess.PIPE)


def validate_policy(policy: dict[str, Any]) -> None:
    if policy["version"] != 1 or set(policy["scopes"]) != set(SCOPES):
        raise ValueError("unsupported policy version or scopes")
    scopes = policy["scopes"]
    if scopes["docs"] != ["docs"] or scopes["integrity"] != ["docs", "integrity"]:
        raise ValueError("documentation and integrity checks cannot be omitted")
    full = scopes["full"]
    if not {"docs", "integrity"} < set(full) or len(full) != len(set(full)):
        raise ValueError("invalid full-check inventory")


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
        if SCOPES.index(kind) > SCOPES.index(scope):
            scope = kind
        records.append({**change, "scope": kind, "reason": reason})
    return {"scope": scope, "selected": policy["scopes"][scope], "changes": records}


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
    policy = json.loads(policy_bytes)
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
