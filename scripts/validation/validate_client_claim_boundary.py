"""Validate client-claim boundary documents against the canonical schema."""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

from jsonschema import Draft202012Validator, ValidationError

SCHEMA_FILE = pathlib.Path("spec/client-claim-boundary.schema.json")


def load_json(path: pathlib.Path) -> object:
    try:
        return json.loads(path.read_text())
    except FileNotFoundError as exc:
        raise SystemExit(f"Boundary file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Invalid JSON in {path}: {exc}") from exc


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "boundary",
        nargs="+",
        help="Path(s) to client-claim boundary JSON files",
    )
    args = parser.parse_args()

    schema = json.loads(SCHEMA_FILE.read_text())
    validator = Draft202012Validator(
        schema,
        format_checker=Draft202012Validator.FORMAT_CHECKER,
    )

    failures = 0
    for raw_path in args.boundary:
        boundary_path = pathlib.Path(raw_path)
        try:
            boundary = load_json(boundary_path)
            validator.validate(boundary)
        except (ValidationError, SystemExit) as exc:
            print(f"[invalid] {boundary_path}: {exc}", file=sys.stderr)
            failures += 1
            continue

        print(f"[ok] {boundary_path}")

    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
