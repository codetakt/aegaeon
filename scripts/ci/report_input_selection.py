"""Compare immutable Git inputs using an advisory model; always retain full CI."""

from __future__ import annotations

import argparse
import base64
import hashlib
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, cast

from ci_shadow_inputs import (
    AUTHORITY_PATH,
    INVENTORY_PATH,
    MODEL_PATH,
    inventory_report,
    require,
    selection_report,
    validate_model,
)
from verify_ci_plan import decoded_path, encoded, git, load, tree_entries

MAX_SOURCE = 4 * 1024 * 1024


def commit(repo: Path, value: str) -> str:
    require(
        bool(re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", value)), "full commit identity required"
    )
    require(git(repo, "cat-file", "-t", value).strip() == b"commit", "identity is not a commit")
    return value


def source_blob(repo: Path, entries: dict[bytes, dict[str, Any]], path: str) -> bytes:
    entry = entries.get(path.encode("utf-8"))
    require(
        entry is not None and entry["type"] == "regular", "missing or nonregular source: " + path
    )
    entry = cast("dict[str, Any]", entry)
    oid = entry["object_id"]
    size = int(git(repo, "cat-file", "-s", oid))
    require(size <= MAX_SOURCE, "source exceeds diagnostic size limit: " + path)
    value = git(repo, "cat-file", "blob", oid)
    require(len(value) == size, "Git blob length changed")
    return value


def changed_entries(snapshots: dict[str, dict[bytes, dict[str, Any]]]) -> list[dict[str, Any]]:
    paths = sorted(set().union(*(set(entries) for entries in snapshots.values())))
    changes = []
    for path in paths:
        sides = {side: entries.get(path) for side, entries in snapshots.items()}
        signatures = {
            (item["mode"], item["object_id"]) if item else None for item in sides.values()
        }
        if len(signatures) > 1:
            changes.append(
                {
                    "raw_path_base64": base64.b64encode(path).decode("ascii"),
                    "decoded_path": decoded_path(path),
                    "snapshots": sides,
                }
            )
    return changes


def report(repo: Path, revisions: dict[str, str]) -> dict[str, Any]:
    require(set(revisions) == {"base", "head", "tested", "model"}, "incomplete revision binding")
    revisions = {side: commit(repo, sha) for side, sha in revisions.items()}
    for side in ("base", "head"):
        git(repo, "merge-base", "--is-ancestor", revisions[side], revisions["tested"])
    trees = {
        side: git(repo, "rev-parse", sha + "^{tree}").decode().strip()
        for side, sha in revisions.items()
    }
    snapshots = {side: tree_entries(repo, tree) for side, tree in trees.items()}
    inventory_bytes = source_blob(repo, snapshots["base"], INVENTORY_PATH)
    inventory = load(inventory_bytes)
    authority_bytes = source_blob(repo, snapshots["base"], AUTHORITY_PATH)
    authority = load(authority_bytes)
    model_bytes = source_blob(repo, snapshots["model"], MODEL_PATH)
    model = load(model_bytes)
    validate_model(model, inventory_bytes, inventory, authority)
    changes = changed_entries({side: snapshots[side] for side in ("base", "head", "tested")})
    result = selection_report(changes, model, authority)
    result.update(
        {
            "schema": "aegaeon-input-selection-shadow-v1",
            "revisions": revisions,
            "trees": trees,
            "model_sha256": hashlib.sha256(model_bytes).hexdigest(),
            "model_is_protected_base": revisions["model"] == revisions["base"],
            "inventory_sha256": hashlib.sha256(inventory_bytes).hexdigest(),
            "authority_sha256": hashlib.sha256(authority_bytes).hexdigest(),
            "implementation_sha256": {
                name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
                for name in (
                    "report_input_selection.py",
                    "ci_shadow_inputs.py",
                    "verify_ci_plan.py",
                    "pr_plan.py",
                )
            },
            "inventory": inventory_report(
                model, inventory, lambda path: source_blob(repo, snapshots["tested"], path)
            ),
        }
    )
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    for side in ("base", "head", "tested"):
        parser.add_argument("--" + side, required=True)
    parser.add_argument(
        "--model-revision", help="Unadopted model commit; defaults to the protected base"
    )
    args = parser.parse_args()
    try:
        revisions = {
            "base": args.base,
            "head": args.head,
            "tested": args.tested,
            "model": args.model_revision or args.base,
        }
        result = report(args.repo, revisions)
        sys.stdout.buffer.write(encoded(result))
    except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError) as error:
        print(f"input-selection diagnostic failed: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
