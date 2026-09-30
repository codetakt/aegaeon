#!/usr/bin/env python3
"""Retain raw failed Kani records from this invocation's Nix build activity only."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import stat
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
KEPT = re.compile(r"""note: keeping build directory (['"])([^'"]+)\1""")
DRV = re.compile(r"/nix/store/[0-9a-z]{32}-([^/\s]+)\.drv")


def nix_event(line: str) -> dict[str, Any]:
    event = json.loads(line[5:])
    if not isinstance(event, dict):
        raise TypeError("invalid Nix structured event")
    return event


def retained_directory(log: str, requested_drv: str, build_root: Path) -> Path:
    active: dict[int, str] = {}
    candidates: list[Path] = []
    for line in log.splitlines():
        if not line.startswith("@nix "):
            continue
        event = nix_event(line)
        if event.get("action") == "start" and event.get("type") == 105:
            fields = event.get("fields")
            if not (
                isinstance(event.get("id"), int)
                and isinstance(fields, list)
                and fields
                and isinstance(fields[0], str)
            ):
                raise ValueError("invalid Nix build activity")
            active[event["id"]] = event["fields"][0]
        elif event.get("action") == "stop":
            active.pop(event["id"], None)
        elif event.get("action") == "msg":
            match = KEPT.fullmatch(ANSI.sub("", event.get("msg", "")))
            if (
                match
                and Path(match[2]).is_relative_to(build_root)
                and list(active.values()) == [requested_drv]
            ):
                candidates.append(Path(match[2]))
    if len(candidates) != 1:
        raise ValueError("expected one retained directory bound to the requested Nix build")
    return candidates[0]


def validate_directory(root: Path, requested_drv: str, build_root: Path) -> Path:
    match = DRV.fullmatch(requested_drv)
    if not match:
        raise ValueError("invalid requested derivation")
    old_layout = re.fullmatch(r"nix-build-" + re.escape(match[1]) + r"\.drv-\d+", root.name)
    new_layout = root.name == "build" and re.fullmatch(r"nix-\d+-\d+", root.parent.name)
    parent = root.parent if old_layout else root.parent.parent
    if root.resolve(strict=True) != root or parent != build_root or not (old_layout or new_layout):
        raise ValueError("unexpected or noncanonical Nix retained-directory layout")
    output = root / "source/artifacts/kani-evidence"
    if output.resolve(strict=True) != output or not output.is_dir():
        raise ValueError("Kani output is missing or escapes the retained source root")
    return output


def file_digests(output: Path) -> dict[str, str]:
    records = {}
    for path in output.rglob("*"):
        mode = path.lstat().st_mode
        if not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
            raise ValueError("failed Kani output contains a symlink or special file")
        if stat.S_ISREG(mode):
            records[path.relative_to(output).as_posix()] = hashlib.sha256(
                path.read_bytes()
            ).hexdigest()
    if not records:
        raise ValueError("no raw Kani records were retained")
    return records


def collect(evidence: Path) -> None:
    requested_drv = (evidence / "requested-drv").read_text().strip()
    # Builder messages can become top-level Nix events. Only the caller's
    # independent build-root record limits which paths may be inspected.
    build_root = Path((evidence / "build-root").read_text().strip())
    if (
        not build_root.is_absolute()
        or build_root.resolve(strict=True) != build_root
        or not build_root.is_dir()
        or build_root.stat().st_mode & 0o022
    ):
        raise ValueError("invalid caller build root")
    root = retained_directory((evidence / "build.log").read_text(), requested_drv, build_root)
    output = validate_directory(root, requested_drv, build_root)
    destination = evidence / "failed-output"
    records = copy_records(output, destination)
    (evidence / "failed-capture.json").write_text(
        json.dumps(
            {
                "status": "retained",
                "requested_drv": requested_drv,
                "build_root": str(build_root),
                "build_directory": str(root),
                "source": str(output),
                "files": records,
                "admission": False,
            },
            indent=2,
        )
        + "\n"
    )


def copy_records(output: Path, destination: Path) -> dict[str, str]:
    if destination.exists():
        raise FileExistsError("failed output already exists")
    records = file_digests(output)
    with TemporaryDirectory(prefix=".failed-staging-", dir=destination.parent) as scratch:
        staging = Path(scratch) / "records"
        # Do not follow a symlink introduced during collection. Validate before
        # exposing the copy to the artifact uploader.
        shutil.copytree(output, staging, symlinks=True)
        if (
            output.resolve(strict=True) != output
            or records != file_digests(staging)
            or records != file_digests(output)
        ):
            raise ValueError("raw Kani records changed during collection")
        staging.rename(destination)
    return records


def main() -> int:
    evidence = Path(sys.argv[1])
    try:
        collect(evidence)
    except (OSError, ValueError, KeyError, TypeError) as error:
        (evidence / "failed-capture.json").write_text(
            json.dumps({"status": "capture-failed", "reason": str(error), "admission": False})
            + "\n"
        )
        print(f"[FAIL] Raw Kani failure capture: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
