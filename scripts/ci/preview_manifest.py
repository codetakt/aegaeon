"""Bind an internal preview to its source, published reference, and runtime closure."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any

from check_preview_ci import source_identity

REPOSITORY = "codetakt/aegaeon"
FLAKE_NAME = "codetakt-inc/aegaeon"
ATTRIBUTE = "packages.x86_64-linux.server"
EXECUTABLE = "bin/aegaeon-server"


def digest(path: Path) -> str:
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def closure(path: str) -> dict[str, str]:
    entries = json.loads(
        subprocess.check_output(
            ["nix", "path-info", "--recursive", "--json", "--json-format", "1", path]
        )
    )
    return {name: entry["narHash"] for name, entry in entries.items()}


def binary(path: Path) -> Path:
    executable = path / EXECUTABLE
    if not executable.is_file() or not os.access(executable, os.X_OK):
        raise ValueError("preview must contain an executable aegaeon-server")
    return executable


def record_build(build: list[dict[str, Any]], revision: str, root: Path) -> dict[str, Any]:
    if len(build) != 1 or set(build[0]["outputs"]) != {"out"}:
        raise ValueError("expected one server derivation with one out output")
    if re.fullmatch(r"[0-9a-f]{40}", revision) is None:
        raise ValueError("preview revision must be a full Git commit SHA")
    path = Path(build[0]["outputs"]["out"])
    executable = binary(path)
    subprocess.run([str(executable), "--help"], check=True, stdout=subprocess.DEVNULL)
    return {
        "version": 1,
        "distribution": "internal-preview",
        "repository": REPOSITORY,
        "revision": revision,
        "tooling_lock_sha256": digest(root / "flake.lock"),
        "distribution_lock_sha256": digest(root / ".flakehub/flake.lock"),
        "server_source": source_identity(root / ".flakehub/flake.lock"),
        "attribute": ATTRIBUTE,
        "derivation": build[0]["drvPath"],
        "store_path": str(path),
        "executable": EXECUTABLE,
        "binary_sha256": digest(executable),
        "closure": closure(str(path)),
    }


def bind_publication(record: dict[str, Any], reference: str) -> None:
    if re.fullmatch(r"[0-9a-f]{40}", record["revision"]) is None:
        raise ValueError("preview revision must be a full Git commit SHA")
    expected = rf"{re.escape(FLAKE_NAME)}/=0\.1\.[0-9]+\+rev-{record['revision']}"
    if re.fullmatch(expected, reference) is None:
        raise ValueError("publisher reference must pin the exact preview source revision")
    record["flakeref_exact"] = reference


def verify_fetch(record: dict[str, Any], link: Path) -> None:
    if record["distribution"] != "internal-preview":
        raise ValueError("unsupported distribution kind")
    identity = (record["version"], record["repository"], record["attribute"], record["executable"])
    if identity != (1, REPOSITORY, ATTRIBUTE, EXECUTABLE):
        raise ValueError("unsupported preview manifest identity")
    bind_publication(record, record["flakeref_exact"])
    if str(link.resolve(strict=True)) != record["store_path"]:
        raise ValueError("fetched store path differs from the built preview")
    if digest(binary(link)) != record["binary_sha256"]:
        raise ValueError("fetched executable digest differs from the built preview")
    if closure(record["store_path"]) != record["closure"]:
        raise ValueError("fetched runtime closure differs from the built preview")
    subprocess.run([str(link / EXECUTABLE), "--help"], check=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("build", "publish", "verify"))
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--build-json", type=Path)
    parser.add_argument("--revision")
    parser.add_argument("--reference")
    parser.add_argument("--link", type=Path)
    args = parser.parse_args()
    required = {
        "build": ("build_json", "revision"),
        "publish": ("reference",),
        "verify": ("link",),
    }
    missing = [
        f"--{name.replace('_', '-')}" for name in required[args.mode] if getattr(args, name) is None
    ]
    if missing:
        parser.error(f"{args.mode} requires {', '.join(missing)}")
    if args.mode == "build":
        record = record_build(
            json.loads(args.build_json.read_text()),
            args.revision,
            Path(__file__).resolve().parents[2],
        )
    else:
        record = json.loads(args.manifest.read_text())
        if args.mode == "publish":
            bind_publication(record, args.reference)
        else:
            verify_fetch(record, args.link)
            print("Fetched preview matches the build manifest and runs without compilation.")
            return
    args.manifest.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
