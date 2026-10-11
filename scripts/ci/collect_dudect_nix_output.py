"""Retain the requested Nix gate output after success, failure, or cancellation."""

from __future__ import annotations

import argparse
import json
import re
import shutil
from pathlib import Path

CORE_TIMING_CHECKS = {"verifyDudect": "verify-dudect", "verified-reqs": "verify-reqs"}


def store_output(value: str) -> Path | None:
    if not value:
        return None  # Evaluation failed before an output path was available.
    if not re.fullmatch(r"/nix/store/[a-z0-9]{32}-(?:verify-reqs|verify-dudect)", value):
        raise ValueError("Unexpected Dudect Nix output path")
    return Path(value)


def copy_output(source: Path | None, outcome: str, destination: Path) -> bool:
    if outcome == "not_started":
        return False
    if source is None or not source.exists():
        if outcome == "success":
            raise ValueError("Successful Nix step has no output to retain")
        return False
    if source.is_symlink() or not source.is_dir():
        raise ValueError("Expected a regular Nix output directory")
    if any(path.is_symlink() for path in source.rglob("*")):
        raise ValueError("Unexpected symlink in Dudect Nix output")
    shutil.copytree(source, destination / "nix-output")
    return True


def collect_output(source: Path | None, outcome: str, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=False)
    record: dict[str, object] = {
        "requested_store_output": str(source) if source else None,
        "build_step_outcome": outcome,
        "output_retained": False,
        "fresh_timing_asserted": False,
        "scope": "Build output retention only; cached output does not establish fresh timing.",
    }
    try:
        retained = copy_output(source, outcome, destination)
        record["output_retained"] = retained
        if outcome == "not_started":
            record["not_attempted"] = True
        elif not retained:
            record["missing_output"] = True
    except (OSError, ValueError) as error:
        record["collection_error"] = str(error)
        raise
    finally:
        (destination / "collection.json").write_text(json.dumps(record, indent=2) + "\n")


def collect_core_outputs(record: Path, destination: Path) -> None:
    rows = json.loads(record.read_text())
    if not isinstance(rows, dict) or set(rows) != set(CORE_TIMING_CHECKS):
        raise ValueError("Unexpected core timing output inventory")
    validated = []
    for name, row in rows.items():
        source = store_output(row["store_output"])
        outcome = row["build_step_outcome"]
        if source is None or not source.name.endswith("-" + CORE_TIMING_CHECKS[name]):
            raise ValueError("Unexpected core timing output")
        if outcome not in {"not_started", "in_progress", "success", "failure"}:
            raise ValueError("Unexpected core timing outcome")
        validated.append((name, source, outcome))
    errors = []
    for name, source, outcome in validated:
        try:
            collect_output(source, outcome, destination / name)
        except (OSError, ValueError) as error:
            errors.append(f"{name}: {error}")
    if errors:
        raise ValueError("; ".join(errors))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sources = parser.add_mutually_exclusive_group(required=True)
    sources.add_argument("--store-output")
    sources.add_argument("--core-record", type=Path)
    parser.add_argument("--outcome", choices=("success", "failure", "cancelled"))
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.core_record:
        if args.outcome is not None:
            parser.error("--outcome applies only to --store-output")
        collect_core_outputs(args.core_record, args.output)
    else:
        if args.outcome is None:
            parser.error("--store-output requires --outcome")
        collect_output(store_output(args.store_output), args.outcome, args.output)


if __name__ == "__main__":
    main()
