"""Fixed guest delivery artifacts responsibility."""

from __future__ import annotations

import hashlib
import re
from pathlib import PurePosixPath
from typing import Any

from runtime_delivery.common import absolute_path, digest, fail, json_object
from runtime_delivery.filesystem import protected_path

REQUIRED_SOURCE_INPUTS = (
    "Cargo.toml",
    "Cargo.lock",
    "flake.nix",
    "flake.lock",
    "rust-toolchain.toml",
    "nix/flake/packages.nix",
    "nix/schema-guarded-launch.nix",
    "crates/loadtest/src/generator.rs",
    "crates/loadtest/src/lib.rs",
    "crates/loadtest/src/main.rs",
    "crates/loadtest/src/metrics.rs",
    "crates/loadtest/src/scenarios.rs",
    "crates/loadtest/Cargo.toml",
    "crates/loadtest/src/profile.rs",
    "crates/loadtest/src/accounting.rs",
)


def manifest_entry(name: str, entry: dict[str, Any], modes: dict[str, int]) -> None:
    path = PurePosixPath(name)
    if (
        not name
        or not path.parts
        or str(path) != name
        or path.is_absolute()
        or (".." in path.parts)
        or any(not c.isprintable() for c in name)
    ):
        fail("noncanonical manifest path")
    if not isinstance(entry, dict) or set(entry) != {
        "bytes",
        "filesystem_mode",
        "git_blob",
        "git_mode",
        "sha256",
        "symlink",
    }:
        fail("source entry schema")
    if type(entry["bytes"]) is not int or entry["bytes"] < 0:
        fail("source byte length")
    digest(entry["git_blob"], 40)
    digest(entry["sha256"])
    if (
        type(entry["filesystem_mode"]) is not int
        or entry["git_mode"] not in modes
        or entry["filesystem_mode"] != modes[entry["git_mode"]]
    ):
        fail("source mode pair")
    if entry["git_mode"] == "120000":
        literal = entry["symlink"]
        if not isinstance(literal, str) or not literal or any(not c.isprintable() for c in literal):
            fail("source symlink literal")
        data = literal.encode()
        blob = b"blob " + str(len(data)).encode() + b"\x00" + data
        if (
            entry["bytes"] != len(data)
            or entry["sha256"] != hashlib.sha256(data).hexdigest()
            or entry["git_blob"] != hashlib.sha1(blob, usedforsecurity=False).hexdigest()
        ):
            fail("source symlink byte binding")
    elif entry["symlink"] is not None:
        fail("regular source link must be null")


def validate_source_manifest(raw: str | bytes | bytearray) -> dict[str, Any]:
    manifest = json_object(raw)
    if set(manifest) != {"candidate_tree", "files", "patch_sha256", "source_base_commit"}:
        fail("source manifest schema")
    digest(manifest["candidate_tree"], 40)
    digest(manifest["source_base_commit"], 40)
    digest(manifest["patch_sha256"])
    files = manifest["files"]
    if not isinstance(files, dict) or not files or (not set(REQUIRED_SOURCE_INPUTS) <= set(files)):
        fail("missing independently required source input")
    modes = {"100644": 33188, "100755": 33261, "120000": 41471}
    for name, entry in files.items():
        manifest_entry(name, entry, modes)
    return manifest


def artifact_receipt(
    receipt: dict[str, Any], artifact: dict[str, Any], config: dict[str, Any]
) -> None:
    expected_receipt = {
        "schema_version",
        "source_manifest_sha256",
        "executable_sha256",
        "image",
        "entrypoint",
        "build_binding",
    }
    if (
        set(receipt) != expected_receipt
        or type(receipt["schema_version"]) is not int
        or receipt["schema_version"] != 1
    ):
        fail("artifact receipt schema")
    if (
        receipt["source_manifest_sha256"] != artifact["source_manifest_sha256"]
        or receipt["executable_sha256"] != artifact["executable_sha256"]
        or receipt["image"] != config["SERVER_IMAGE"]
        or (receipt["entrypoint"] != config["LOADTEST_BIN"])
    ):
        fail("artifact receipt binding")


def artifact_build(receipt: dict[str, Any], manifest: dict[str, Any]) -> None:
    build = receipt["build_binding"]
    keys = {
        "recipe_sha256",
        "Cargo_lock_sha256",
        "flake_lock_sha256",
        "toolchain_sha256",
        "target",
        "features",
        "native_closure_sha256",
    }
    if not isinstance(build, dict) or set(build) != keys:
        fail("artifact build schema")
    for name in keys - {"target", "features"}:
        digest(build[name])
    if build["target"] not in {"x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"}:
        fail("unsupported loadgen target")
    features = build["features"]
    if (
        not isinstance(features, list)
        or any(
            not isinstance(v, str) or not re.fullmatch("[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)?", v)
            for v in features
        )
        or len(features) != len(set(features))
    ):
        fail("ordered unique features required")
    for name, path in (
        ("Cargo_lock_sha256", "Cargo.lock"),
        ("flake_lock_sha256", "flake.lock"),
        ("toolchain_sha256", "rust-toolchain.toml"),
    ):
        if build[name] != manifest["files"][path]["sha256"]:
            fail("build/source input mismatch")


def validate_artifact(config: dict[str, Any]) -> tuple[bytes, bytes]:
    artifact = config["artifact"]
    expected = {
        "receipt_path",
        "receipt_sha256",
        "source_manifest_path",
        "source_manifest_sha256",
        "executable_sha256",
    }
    if not isinstance(artifact, dict) or set(artifact) != expected:
        fail("artifact config schema")
    for name in ("receipt_sha256", "source_manifest_sha256", "executable_sha256"):
        digest(artifact[name])
    receipt_path = protected_path(absolute_path(artifact["receipt_path"]), regular=True)
    manifest_path = protected_path(absolute_path(artifact["source_manifest_path"]), regular=True)
    if receipt_path == manifest_path or (
        receipt_path.stat().st_dev,
        receipt_path.stat().st_ino,
    ) == (manifest_path.stat().st_dev, manifest_path.stat().st_ino):
        fail("artifact input alias")
    receipt_raw, source_raw = (receipt_path.read_bytes(), manifest_path.read_bytes())
    if (
        hashlib.sha256(receipt_raw).hexdigest() != artifact["receipt_sha256"]
        or hashlib.sha256(source_raw).hexdigest() != artifact["source_manifest_sha256"]
    ):
        fail("artifact raw digest mismatch")
    manifest = validate_source_manifest(source_raw)
    receipt = json_object(receipt_raw)
    artifact_receipt(receipt, artifact, config)
    artifact_build(receipt, manifest)
    return (receipt_raw, source_raw)
