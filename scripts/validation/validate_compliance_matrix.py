#!/usr/bin/env python3
"""Validate compliance matrix schema and ensure referenced paths exist.

This utility validates ``spec/compliance-matrix.yaml`` against the
accompanying JSON schema and verifies that all referenced paths exist.
Missing paths fail closed by default. Use ``--write-stubs`` only for deliberate
bootstrap work, never as release evidence.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
from typing import Any, cast

import yaml
from jsonschema import ValidationError, validate

MATRIX_FILE = pathlib.Path("spec/compliance-matrix.yaml")
SCHEMA_FILE = pathlib.Path("spec/compliance-matrix.schema.json")


def collect_paths(obj: object) -> list[str]:
    paths: list[str] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if (k in ("module", "document", "artefact") and isinstance(v, str)) or (
                k in ("file", "spec") and isinstance(v, str)
            ):
                paths.append(v)
            elif k == "tests" and isinstance(v, list):
                for item in v:
                    if isinstance(item, str):
                        paths.append(item)
            else:
                paths.extend(collect_paths(v))
    elif isinstance(obj, list):
        for item in obj:
            paths.extend(collect_paths(item))
    return paths


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Deprecated no-op retained for CI compatibility; validation is check-only by default",
    )
    parser.add_argument(
        "--write-stubs",
        action="store_true",
        help="Create empty stubs for missing paths instead of failing",
    )
    args = parser.parse_args()

    data = yaml.safe_load(MATRIX_FILE.read_text())
    schema = cast("dict[str, Any]", json.loads(SCHEMA_FILE.read_text()))
    try:
        validate(instance=data, schema=schema)
    except ValidationError as exc:
        print(f"Schema validation failed: {exc.message}", file=sys.stderr)
        return 1

    paths = set(collect_paths(data))
    missing: list[pathlib.Path] = []
    for p in sorted(paths):
        path = pathlib.Path(p)
        if not path.exists():
            if not args.write_stubs:
                missing.append(path)
                continue
            path.parent.mkdir(parents=True, exist_ok=True)
            path.touch()
            print(f"Created stub {path}")
            continue
        print(f"Exists {path}")

    if missing:
        for m in missing:
            print(f"Missing {m}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
