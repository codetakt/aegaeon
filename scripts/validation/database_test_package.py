#!/usr/bin/env python3
"""Compile database test binaries once; execute each service-backed selection live."""

from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path

from jose_server_test_package import digest, valid_profile

SCOPE = "database-test-compilation-v1"
FEATURES = ["default", "telemetry"]
TARGETS = {"aegaeon_server": "lib", "dcr_database_test": "test"}


def install(messages: Path, identity: Path, destination: Path) -> None:
    rows = [json.loads(line) for line in messages.read_text().splitlines()]
    finished = [row for row in rows if row.get("reason") == "build-finished"]
    executable_rows = [
        row for row in rows if row.get("reason") == "compiler-artifact" and row.get("executable")
    ]
    # Cargo also builds ordinary server binaries as integration-test prerequisites.
    # They are build evidence, not additional libtest selections.
    artifacts = [row for row in executable_rows if row["profile"].get("test") is True]
    auxiliary = [row for row in executable_rows if row["profile"].get("test") is not True]
    for row in auxiliary:
        if (
            row["profile"].get("test") is not False
            or row["target"]["kind"] != ["bin"]
            or Path(row["manifest_path"]).resolve() != Path("crates/server/Cargo.toml").resolve()
        ):
            raise ValueError("unexpected auxiliary database build target")
    if len(finished) != 1 or finished[0].get("success") is not True or len(artifacts) != 2:
        raise ValueError("expected two test executables from a completed Cargo build")
    binaries = {}
    for artifact in artifacts:
        target = artifact["target"]
        name = target["name"]
        if (
            name not in TARGETS
            or name in binaries
            or target["kind"] != [TARGETS[name]]
            or target["test"] is not True
            or Path(artifact["manifest_path"]).resolve()
            != Path("crates/server/Cargo.toml").resolve()
            or sorted(artifact["features"]) != FEATURES
            or not valid_profile(artifact["profile"])
        ):
            raise ValueError("database target, build profile or features do not match")
        executable = Path(artifact["executable"]).resolve(strict=True)
        executable.relative_to(Path("target").resolve())
        if not executable.is_file() or not os.access(executable, os.X_OK):
            raise ValueError("database executable is missing or not executable")
        output = destination / "libexec" / name
        output.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(executable, output)
        binaries[name] = {
            "sha256": digest(output),
            "features": FEATURES,
            "profile": artifact["profile"],
            "kind": TARGETS[name],
        }
    if set(binaries) != set(TARGETS):
        raise ValueError("database executable inventory is incomplete")
    receipt = {
        "schema_version": 1,
        "scope": SCOPE,
        "build": json.loads(identity.read_text()),
        "binaries": binaries,
        "auxiliary_build_targets": auxiliary,
    }
    (destination / "build.json").write_text(json.dumps(receipt, sort_keys=True) + "\n")


def validate(package: Path) -> None:
    receipt = json.loads((package / "build.json").read_text())
    if (
        receipt["schema_version"] != 1
        or receipt["scope"] != SCOPE
        or set(receipt["binaries"]) != set(TARGETS)
    ):
        raise ValueError("database package inventory does not match")
    for name, kind in TARGETS.items():
        record = receipt["binaries"][name]
        path = package / "libexec" / name
        if (
            record["kind"] != kind
            or record["features"] != FEATURES
            or not valid_profile(record["profile"])
            or not path.is_file()
            or path.is_symlink()
            or not os.access(path, os.X_OK)
            or digest(path) != record["sha256"]
        ):
            raise ValueError("database executable does not match its receipt")


def selection(arguments: list[str]) -> tuple[str, list[str]]:
    if arguments[:2] != ["-p", "aegaeon-server"] or "--" not in arguments:
        raise ValueError("expected an explicit server database selection")
    separator = arguments.index("--")
    cargo, runtime = arguments[2:separator], arguments[separator + 1 :]
    filters = []
    if cargo == ["--test", "dcr_database_test"]:
        name = "dcr_database_test"
    elif cargo == ["--lib"]:
        name = "aegaeon_server"
    elif cargo in (["redis_", "--lib"], ["shared_redis_", "--lib"]):
        name = "aegaeon_server"
        filters = [cargo[0]]
    else:
        raise ValueError("unsupported database test build arguments")
    if runtime[:2] != ["--ignored", "--test-threads=1"]:
        raise ValueError("database tests must run ignored cases serially")
    skips = runtime[2:]
    if (
        len(skips) % 2
        or any(skips[i] != "--skip" for i in range(0, len(skips), 2))
        or any(not value or value.startswith("-") for value in skips[1::2])
        or (name == "dcr_database_test" and skips)
    ):
        raise ValueError("unsupported database test runtime arguments")
    return name, [*filters, *runtime]


def run(package: Path, arguments: list[str]) -> None:
    name, runtime = selection(arguments)
    validate(package)
    executable = (package / "libexec" / name).resolve(strict=True)
    directory = Path("crates/server").resolve(strict=True)
    if not (directory / "Cargo.toml").is_file():
        raise ValueError("server crate directory is missing")
    os.chdir(directory)
    os.execv(str(executable), [str(executable), *runtime])


def main() -> int:
    try:
        if len(sys.argv) == 5 and sys.argv[1] == "install":
            install(*(Path(argument) for argument in sys.argv[2:]))
        elif len(sys.argv) >= 4 and sys.argv[1] == "run":
            run(Path(sys.argv[2]), sys.argv[3:])
        else:
            raise ValueError("expected install MESSAGES IDENTITY OUT or run PACKAGE CARGO_ARGS...")
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"database compiled test rejected: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
