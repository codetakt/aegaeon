#!/usr/bin/env python3
"""Preserve the complete RFC Cargo target selection while reusing compilation."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from jose_server_test_package import digest, valid_profile

SCOPE = "rfc-test-compilation-v1"
FEATURES = {"server": ["default", "telemetry"], "jose": ["default"]}
KINDS = {"lib": 0, "bin": 1, "test": 2}


def target_key(target: dict[str, object]) -> str:
    kinds = target["kind"]
    name = target["name"]
    if not isinstance(kinds, list) or len(kinds) != 1:
        raise ValueError("unsupported RFC target kind")
    kind = kinds[0]
    if (
        not isinstance(kind, str)
        or not isinstance(name, str)
        or kind not in KINDS
        or not name
        or any(
            c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
            for c in name
        )
    ):
        raise ValueError("unsupported RFC test target")
    return kind + ":" + name


def install(directory: Path, identity: Path, destination: Path) -> None:
    metadata = json.loads((directory / "metadata.json").read_text())
    # --list only enumerates doctests; no test outcomes are reused. A new
    # matching doctest must not disappear from the compiled runtime path.
    if (directory / "doc-list.txt").read_text().strip() != "0 tests, 0 benchmarks":
        raise ValueError("matching RFC doctests require a fresh Cargo runtime path")
    groups = {}
    for group, features in FEATURES.items():
        manifest = Path(f"crates/{group}/Cargo.toml").resolve()
        (package,) = [
            p for p in metadata["packages"] if Path(p["manifest_path"]).resolve() == manifest
        ]
        expected = {
            target_key(t)
            for t in package["targets"]
            if t["test"] is True
            and t["kind"][0] in KINDS
            and (group == "server" or (t["kind"] == ["test"] and t["name"] == "rfc7520_vectors"))
        }
        if not expected:
            raise ValueError("empty RFC target inventory")
        rows = [
            json.loads(line) for line in (directory / f"{group}.jsonl").read_text().splitlines()
        ]
        finished = [r for r in rows if r.get("reason") == "build-finished"]
        if len(finished) != 1 or finished[0].get("success") is not True:
            raise ValueError("RFC Cargo build did not finish successfully")
        binaries = {}
        for row in rows:
            if row.get("reason") != "compiler-artifact" or not row.get("executable"):
                continue
            if Path(row["manifest_path"]).resolve() != manifest:
                raise ValueError("foreign RFC executable")
            if row["profile"].get("test") is False and row["target"]["kind"] == ["bin"]:
                continue  # Ordinary binary prerequisites are not libtest targets.
            key = target_key(row["target"])
            if (
                key not in expected
                or key in binaries
                or row["target"]["test"] is not True
                or not valid_profile(row["profile"])
                or sorted(row["features"]) != features
            ):
                raise ValueError("RFC build target, profile or features differ")
            executable = Path(row["executable"]).resolve(strict=True)
            executable.relative_to(Path("target").resolve())
            if not executable.is_file() or not os.access(executable, os.X_OK):
                raise ValueError("missing RFC executable")
            output = destination / "libexec" / group / key
            output.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(executable, output)
            binaries[key] = {
                "sha256": digest(output),
                "profile": row["profile"],
                "features": features,
            }
        if set(binaries) != expected:
            raise ValueError("incomplete RFC executable inventory")
        order = sorted(expected, key=lambda k: (KINDS[k.split(":")[0]], k.split(":")[1]))
        groups[group] = {"order": order, "binaries": binaries}
    (destination / "build.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "scope": SCOPE,
                "build": json.loads(identity.read_text()),
                "groups": groups,
                "matching_doctests": 0,
            },
            sort_keys=True,
        )
        + "\n"
    )


def run(package: Path, arguments: list[str]) -> int:
    if arguments == ["--package", "aegaeon-server", "rfc_tests", "--no-fail-fast"]:
        group, runtime = "server", ["rfc_tests"]
    elif arguments == ["--package", "aegaeon-jose", "--test", "rfc7520_vectors"]:
        group, runtime = "jose", []
    else:
        raise ValueError("unsupported RFC Cargo selection")
    receipt = json.loads((package / "build.json").read_text())
    if (
        receipt["schema_version"] != 1
        or receipt["scope"] != SCOPE
        or set(receipt["groups"]) != set(FEATURES)
        or receipt["matching_doctests"] != 0
    ):
        raise ValueError("invalid RFC package receipt")
    for name, features in FEATURES.items():
        entry = receipt["groups"][name]
        if (
            not entry["order"]
            or len(entry["order"]) != len(set(entry["order"]))
            or set(entry["order"]) != set(entry["binaries"])
        ):
            raise ValueError("invalid RFC executable order or inventory")
        for key in entry["order"]:
            kind, target = key.split(":")
            if target_key({"kind": [kind], "name": target}) != key:
                raise ValueError("invalid RFC target key")
            path = package / "libexec" / name / key
            record = entry["binaries"][key]
            if (
                not path.is_file()
                or path.is_symlink()
                or not os.access(path, os.X_OK)
                or not valid_profile(record["profile"])
                or record["features"] != features
                or digest(path) != record["sha256"]
            ):
                raise ValueError("RFC executable differs from its receipt")
    directory = Path(f"crates/{group}").resolve(strict=True)
    if not (directory / "Cargo.toml").is_file():
        raise ValueError("RFC crate directory is missing")
    failed = 0
    for key in receipt["groups"][group]["order"]:
        executable = (package / "libexec" / group / key).resolve(strict=True)
        print(f"Running compiled RFC target {group}/{key}", flush=True)
        result = subprocess.run([str(executable), *runtime], cwd=directory, check=False)
        if result.returncode:
            failed = result.returncode if result.returncode > 0 else 128 - result.returncode
        # Preserve server --no-fail-fast: later targets still run after failure.
    return failed


def main() -> int:
    try:
        if len(sys.argv) == 5 and sys.argv[1] == "install":
            install(*(Path(x) for x in sys.argv[2:]))
        elif len(sys.argv) >= 4 and sys.argv[1] == "run":
            return run(Path(sys.argv[2]), sys.argv[3:])
        else:
            raise ValueError("expected install DIRECTORY IDENTITY OUT or run PACKAGE CARGO_ARGS...")
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"RFC compiled test rejected: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
