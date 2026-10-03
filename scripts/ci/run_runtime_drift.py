"""Run the existing drift gate and preserve evidence outside the checkout."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import runpy
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

CHECKER = Path("scripts/validation/check_runtime_drift.py")
MANIFEST = Path("spec/runtime-link-manifest.json")
WRAPPER = Path("scripts/ci/run_runtime_drift.py")
CONTEXT_KEYS = (
    "GITHUB_SHA",
    "GITHUB_REPOSITORY",
    "GITHUB_RUN_ID",
    "GITHUB_RUN_ATTEMPT",
    "GITHUB_EVENT_NAME",
    "GITHUB_REF",
)


def git(*args: str) -> str:
    return subprocess.check_output(["git", *args], text=True, stderr=subprocess.PIPE).rstrip("\n")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_manifest() -> bytes | None:
    try:
        return MANIFEST.read_bytes()
    except FileNotFoundError:
        # Missing manifests are an existing checker failure, not a wrapper failure.
        return None


def listed_paths(manifest: bytes | None) -> set[str]:
    try:
        data = json.loads(manifest.decode("utf-8")) if manifest is not None else None
    except (ValueError, RecursionError):
        # Let the existing checker decide invalid-manifest failures.
        return set()
    if not isinstance(data, dict):
        return set()
    return {
        path
        for group in (data.get("files"), data.get("monitored_files"))
        if isinstance(group, dict)
        for path, info in group.items()
        if isinstance(path, str) and isinstance(info, dict)
    }


def runtime_inputs(manifest: bytes | None) -> dict[str, str | None]:
    # Import only definitions; use the checker's discovery, including ignored files.
    checker = runpy.run_path(str(CHECKER), run_name="runtime_drift_snapshot")
    paths = listed_paths(manifest) | set(checker["_collect_monitored_files"]())
    inventory: dict[str, str | None] = {}
    for path in sorted(paths):
        try:
            inventory[path] = digest(Path(path).read_bytes())
        except FileNotFoundError:
            inventory[path] = None
    return inventory


def source_state() -> dict[str, Any]:
    """Bind dirty tracked bytes as well as the committed checkout identity."""
    commit = git("rev-parse", "HEAD")
    if os.environ.get("GITHUB_SHA", commit) != commit:
        raise ValueError("GITHUB_SHA differs from the checked out commit")
    manifest = read_manifest()
    return {
        "commit": commit,
        "tree": git("rev-parse", "HEAD^{tree}"),
        "tracked_status": git("status", "--porcelain=v1", "--untracked-files=no"),
        "tracked_diff_sha256": digest(subprocess.check_output(["git", "diff", "HEAD", "--binary"])),
        "sha256": {
            str(MANIFEST): digest(manifest) if manifest is not None else None,
            str(CHECKER): digest(CHECKER.read_bytes()),
            str(WRAPPER): digest(WRAPPER.read_bytes()),
        },
        "runtime_inputs": runtime_inputs(manifest),
    }


def validate_result(before: dict[str, Any], after: dict[str, Any], status: int) -> None:
    if before != after:
        raise ValueError("source changed during the runtime drift check")
    if status not in (0, 1, 2):
        raise ValueError("runtime drift checker returned an unexpected status")


def check(evidence: Path) -> dict[str, Any]:
    command = [sys.executable, str(CHECKER), "--check"]
    receipt: dict[str, Any] = {
        "checked_at": datetime.now(UTC).isoformat(),
        "command": command,
        "github": {key: os.environ[key] for key in CONTEXT_KEYS if key in os.environ},
        "checker_exit_code": None,
        "exit_code": 3,
    }
    output = b""
    try:
        before = source_state()
        receipt["source_before"] = before
        result = subprocess.run(
            command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False
        )
        output = result.stdout
        receipt["checker_exit_code"] = result.returncode
        after = source_state()
        receipt["source_after"] = after
        validate_result(before, after, result.returncode)
        receipt["exit_code"] = result.returncode
    except (
        OSError,
        ValueError,
        ImportError,
        LookupError,
        SyntaxError,
        TypeError,
        SystemExit,
        subprocess.SubprocessError,
    ) as error:
        receipt["error"] = str(error)
        output += f"\nRuntime drift evidence error: {error}\n".encode()
    receipt["finished_at"] = datetime.now(UTC).isoformat()
    receipt["log_sha256"] = digest(output)
    (evidence / "check.log").write_bytes(output)
    (evidence / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    sys.stdout.write(output.decode(errors="replace"))
    return receipt


def prepare_evidence(path: Path) -> Path:
    root = Path(git("rev-parse", "--show-toplevel")).resolve()
    evidence = path.resolve()
    if Path.cwd().resolve() != root or evidence.is_relative_to(root):
        raise ValueError("run at the checkout root with an evidence directory outside it")
    evidence.mkdir(parents=True, exist_ok=False)
    return evidence


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        evidence = prepare_evidence(args.evidence_dir)
        return int(check(evidence)["exit_code"])
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"Runtime drift evidence failed: {error}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
