"""Build and verify a source-bound native package, without timing admission."""

from __future__ import annotations

import os
import shutil
from typing import TYPE_CHECKING, Any

from dudect_candidate import CANDIDATE_CASES, CONTROL_CASES, NUMERICAL_SHA256, canonical, digest
from dudect_process import load_json
from dudect_support import require
from run import HARNESSES, discover_flags, write_json
from run_candidate import (
    ADDITIONS,
    CONTROLS,
    PROVIDER,
    BuildInputs,
    build,
    check_contract,
    freeze_sources,
)

if TYPE_CHECKING:
    from pathlib import Path

    from run import Adapter, Harness


def specs(suite: str) -> tuple[Harness, ...]:
    require(suite in CANDIDATE_CASES, "Unknown native package suite")
    return (CONTROLS, *HARNESSES, *ADDITIONS) if suite == "legacy" else (CONTROLS, PROVIDER)


def names_for(spec: Harness, suite: str) -> tuple[str, ...]:
    if spec.name == CONTROLS.name:
        return CONTROL_CASES
    return (spec.name,) if suite == "legacy" else CANDIDATE_CASES["nix"][: -len(CONTROL_CASES)]


def build_package(root: Path, output: Path, suite: str, adapter: Adapter) -> dict[str, Any]:
    output.mkdir(parents=True)
    snapshot, hashes = freeze_sources(root, output)
    contract = check_contract(snapshot)
    inputs = BuildInputs(snapshot, hashes, contract, discover_flags(snapshot, output), adapter)
    executables = []
    for spec in specs(suite):
        destination = output / "native" / spec.name
        destination.mkdir(parents=True)
        binary, identity = build(inputs, destination, spec, suite)
        executables.append(
            {
                "name": spec.name,
                "cases": list(names_for(spec, suite)),
                "relative_binary": binary.relative_to(output).as_posix(),
                "sha256": identity["sha256"],
                "build_sha256": identity["build_sha256"],
            }
        )
    index = {
        "schema": 1,
        "suite": suite,
        "contract_sha256": contract,
        "numerical_sha256": NUMERICAL_SHA256,
        "sources": hashes,
        "executables": executables,
    }
    write_json(output / "package.json", index)
    return index


def checked_package(package: Path, expected_sources: dict[str, Any], suite: str) -> dict[str, Any]:
    index: dict[str, Any] = load_json((package / "package.json").read_bytes())
    require(
        isinstance(index, dict)
        and set(index)
        == {"schema", "suite", "contract_sha256", "numerical_sha256", "sources", "executables"},
        "Invalid native package index",
    )
    require(type(index["schema"]) is int and index["schema"] == 1, "Unknown native package format")
    require(
        index["suite"] == suite and index["sources"] == expected_sources,
        "Native package/source mismatch",
    )
    require(index["numerical_sha256"] == NUMERICAL_SHA256, "Native package/numerics mismatch")
    for name, expected_hash in expected_sources.items():
        source = package / "sources" / name
        require(source.is_file() and not source.is_symlink(), "Missing packaged source")
        require(
            source.resolve().is_relative_to((package / "sources").resolve()),
            "Packaged source escaped root",
        )
        require(digest(source.read_bytes()) == expected_hash, "Packaged source digest mismatch")
    require(
        index["contract_sha256"]
        == expected_sources["tests/constant_time/contracts/case-contract-candidate.json"],
        "Native package/contract mismatch",
    )
    expected = specs(suite)
    require(
        isinstance(index["executables"], list) and len(index["executables"]) == len(expected),
        "Incomplete native package",
    )
    for spec, entry in zip(expected, index["executables"], strict=True):
        check_executable(package, entry, spec, index)
    return index


def check_executable(
    package: Path, entry: dict[str, Any], spec: Harness, index: dict[str, Any]
) -> None:
    require(
        isinstance(entry, dict)
        and set(entry) == {"name", "cases", "relative_binary", "sha256", "build_sha256"},
        "Invalid executable index",
    )
    require(
        entry["name"] == spec.name and entry["cases"] == list(names_for(spec, index["suite"])),
        "Executable case inventory mismatch",
    )
    require(
        entry["relative_binary"] == f"native/{spec.name}/{spec.name}",
        "Unexpected executable location",
    )
    binary = package / entry["relative_binary"]
    require(binary.is_file() and not binary.is_symlink(), "Missing real native executable")
    require(os.access(binary, os.X_OK), "Native artifact is not executable")
    require(binary.resolve().is_relative_to(package.resolve()), "Native executable escaped package")
    require(digest(binary.read_bytes()) == entry["sha256"], "Native executable digest mismatch")
    manifest = load_json((binary.parent / "build-manifest.json").read_bytes())
    require(digest(canonical(manifest)) == entry["build_sha256"], "Build manifest digest mismatch")
    require(
        manifest["sources"] == index["sources"] and manifest["suite"] == index["suite"],
        "Build manifest/source mismatch",
    )
    require(
        manifest["contract_sha256"] == index["contract_sha256"], "Build manifest/contract mismatch"
    )


def expected_bindings(index: dict[str, Any], profile: str) -> dict[str, Any]:
    bindings, binaries = {}, {}
    for entry in index["executables"]:
        for name in entry["cases"]:
            bindings[name] = {
                "case_id": f"{index['suite']}/{name}",
                "profile": profile,
                "contract_sha256": index["contract_sha256"],
                "build_sha256": entry["build_sha256"],
                "numerical_sha256": NUMERICAL_SHA256,
            }
            binaries[name] = {
                "path": "package/" + entry["relative_binary"],
                "sha256": entry["sha256"],
                "build_sha256": entry["build_sha256"],
            }
    return {"bindings": bindings, "binaries": binaries}


def import_package(
    source: Path, destination: Path, hashes: dict[str, Any], suite: str
) -> dict[str, Any]:
    checked_package(source, hashes, suite)
    shutil.copytree(source, destination)
    return checked_package(destination, hashes, suite)
