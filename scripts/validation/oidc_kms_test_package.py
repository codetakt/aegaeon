#!/usr/bin/env python3
"""Install and verify a compile-only KMS test package; never certify execution."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
from pathlib import Path

from validate_oidc_kms_execution import TEST_NAME

EXECUTABLE = "libexec/oidc-kms-test"
FEATURES = ["default", "kms-aws", "telemetry"]


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def install(messages: Path, identity: Path, destination: Path) -> None:
    """Select the one server libtest artifact from a successful Cargo build."""
    rows = [json.loads(line) for line in messages.read_text().splitlines()]
    finished = [row for row in rows if row.get("reason") == "build-finished"]
    artifacts = [
        row for row in rows if row.get("reason") == "compiler-artifact" and row.get("executable")
    ]
    if len(finished) != 1 or finished[0].get("success") is not True or len(artifacts) != 1:
        raise ValueError("expected one test executable from a completed Cargo build")
    artifact = artifacts[0]
    target = artifact["target"]
    profile = artifact["profile"]
    if (
        Path(artifact["manifest_path"]).resolve() != Path("crates/server/Cargo.toml").resolve()
        or target["name"] != "aegaeon_server"
        or target["kind"] != ["lib"]
        or target["test"] is not True
        or profile["test"] is not True
        or profile["opt_level"] != "0"
        or profile["debug_assertions"] is not True
        or sorted(artifact["features"]) != FEATURES
    ):
        raise ValueError("KMS test package target, profile or features do not match")
    executable = Path(artifact["executable"]).resolve(strict=True)
    executable.relative_to(Path("target").resolve())
    if not executable.is_file() or not os.access(executable, os.X_OK):
        raise ValueError("KMS test executable is missing or not executable")
    output = destination / EXECUTABLE
    output.parent.mkdir(parents=True)
    shutil.copy2(executable, output)
    receipt = {
        "schema_version": 1,
        "scope": "compilation-only",
        "test": TEST_NAME,
        "executable": EXECUTABLE,
        "sha256": digest(output),
        "features": FEATURES,
        "profile": profile,
        "build": json.loads(identity.read_text()),
    }
    (destination / "build.json").write_text(json.dumps(receipt, sort_keys=True) + "\n")


def validate(package: Path) -> dict[str, object]:
    """Check installed bytes before passing them to the live execution wrapper."""
    receipt = json.loads((package / "build.json").read_text())
    executable = package / EXECUTABLE
    if (
        receipt["schema_version"] != 1
        or receipt["scope"] != "compilation-only"
        or receipt["test"] != TEST_NAME
        or receipt["executable"] != EXECUTABLE
        or receipt["features"] != FEATURES
        or receipt["profile"]["test"] is not True
        or receipt["profile"]["debug_assertions"] is not True
        or receipt["profile"]["opt_level"] != "0"
        or not executable.is_file()
        or executable.is_symlink()
        or not os.access(executable, os.X_OK)
        or digest(executable) != receipt["sha256"]
    ):
        raise ValueError("KMS compiled test package does not match its build receipt")
    return {"package": str(package), **receipt}


def main() -> int:
    try:
        if len(sys.argv) == 5 and sys.argv[1] == "install":
            install(*(Path(argument) for argument in sys.argv[2:]))
        elif len(sys.argv) == 3 and sys.argv[1] == "validate":
            print(json.dumps(validate(Path(sys.argv[2])), sort_keys=True))
        else:
            raise ValueError("expected install MESSAGES IDENTITY OUT or validate PACKAGE")
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"KMS compiled test rejected: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
