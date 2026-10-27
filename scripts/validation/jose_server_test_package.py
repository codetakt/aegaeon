#!/usr/bin/env python3
"""Compile-only server libtest packages; every selected test still runs live."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
from pathlib import Path

EXECUTABLE = "libexec/jose-server-test"
SCOPE = "jose-server-compilation-v1"
FEATURES = {
    "default": ["default", "telemetry"],
    "strict": ["default", "telemetry", "verified-claim"],
}


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def valid_profile(profile: dict[str, object]) -> bool:
    return (
        profile.get("test") is True
        and profile.get("opt_level") == "0"
        and profile.get("debuginfo") == 2
        and profile.get("debug_assertions") is True
        and profile.get("overflow_checks") is True
    )


def install(messages: Path, identity: Path, destination: Path) -> None:
    build = json.loads(identity.read_text())
    expected = FEATURES[build["profile"]]
    rows = [json.loads(line) for line in messages.read_text().splitlines()]
    finished = [row for row in rows if row.get("reason") == "build-finished"]
    artifacts = [
        row for row in rows if row.get("reason") == "compiler-artifact" and row.get("executable")
    ]
    if len(finished) != 1 or finished[0].get("success") is not True or len(artifacts) != 1:
        raise ValueError("expected one test executable from a completed Cargo build")
    artifact = artifacts[0]
    target = artifact["target"]
    if (
        Path(artifact["manifest_path"]).resolve() != Path("crates/server/Cargo.toml").resolve()
        or target["name"] != "aegaeon_server"
        or target["kind"] != ["lib"]
        or target["test"] is not True
        or not valid_profile(artifact["profile"])
        or sorted(artifact["features"]) != expected
    ):
        raise ValueError("server test target, build profile or features do not match")
    executable = Path(artifact["executable"]).resolve(strict=True)
    executable.relative_to(Path("target").resolve())
    if not executable.is_file() or not os.access(executable, os.X_OK):
        raise ValueError("server test executable is missing or not executable")
    output = destination / EXECUTABLE
    output.parent.mkdir(parents=True)
    shutil.copy2(executable, output)
    receipt = {
        "schema_version": 1,
        "scope": SCOPE,
        "executable": EXECUTABLE,
        "sha256": digest(output),
        "features": expected,
        "profile": artifact["profile"],
        "build": build,
    }
    (destination / "build.json").write_text(json.dumps(receipt, sort_keys=True) + "\n")


def validate(package: Path, profile: str) -> None:
    receipt = json.loads((package / "build.json").read_text())
    executable = package / EXECUTABLE
    if (
        receipt["schema_version"] != 1
        or receipt["scope"] != SCOPE
        or receipt["executable"] != EXECUTABLE
        or receipt["features"] != FEATURES[profile]
        or receipt["build"]["profile"] != profile
        or not valid_profile(receipt["profile"])
        or not executable.is_file()
        or executable.is_symlink()
        or not os.access(executable, os.X_OK)
        or digest(executable) != receipt["sha256"]
    ):
        raise ValueError("server test package does not match the requested profile or receipt")


def selection(arguments: list[str]) -> tuple[str, list[str]]:
    """Accept only the existing server-library Cargo shape, without dropping flags."""
    if arguments[:3] != ["-p", "aegaeon-server", "--lib"] or "--" not in arguments:
        raise ValueError("expected an explicit server-library selection")
    separator = arguments.index("--")
    cargo = arguments[3:separator]
    runtime = arguments[separator + 1 :]
    if not cargo or not cargo[0] or cargo[0].startswith("-"):
        raise ValueError("a nonempty test filter is required")
    if len(cargo) == 1:
        profile = "default"
    elif cargo[1:] == ["--features", "verified-claim"]:
        profile = "strict"
    else:
        raise ValueError("unsupported server-library build arguments")
    if runtime != ["--nocapture"]:
        raise ValueError("unsupported server-library runtime arguments")
    return profile, [cargo[0], *runtime]


def run(package: Path, arguments: list[str]) -> None:
    profile, runtime = selection(arguments)
    validate(package, profile)
    executable = (package / EXECUTABLE).resolve(strict=True)
    # Cargo executes a library test from its crate directory. Selected fixtures
    # are compiled into the binary; runtime code still sees the current checkout.
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
        print(f"JOSE compiled server test rejected: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
