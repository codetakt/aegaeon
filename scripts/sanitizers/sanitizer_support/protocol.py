"""Admit complete Cargo artifacts and named libtest smoke execution."""

from __future__ import annotations

import os
import re
import tomllib
from pathlib import Path
from typing import Any

from sanitizer_support.core import failure, parse_json, require

# Required default-profile targets, independently frozen before this repair.
FFI_TARGETS = {
    "ffi",
    "aead_buffer_boundary_test",
    "dpop_header_test",
    "dpop_proof_test",
    "dpop_uri_test",
    "equivalence_pkce_test",
    "jose_header_runtime_test",
    "oidc_hash_runtime_test",
    "pkce_verifier_test",
}
LIBRARY_KINDS = {"lib", "rlib", "dylib", "cdylib", "staticlib", "proc-macro"}
TargetKey = tuple[str, tuple[str, ...]]
TargetInventory = dict[TargetKey, dict[str, Any]]


def target_key(target: dict[str, Any]) -> TargetKey:
    name, kinds = target.get("name"), target.get("kind")
    require(
        isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9_-]+", name),
        "Invalid Cargo target identity",
    )
    require(
        isinstance(kinds, list)
        and kinds
        and all(isinstance(kind, str) for kind in kinds)
        and len(kinds) == len(set(kinds)),
        "Invalid Cargo target kind",
    )
    return name, tuple(sorted(kinds))


def target_selector(key: TargetKey) -> list[str]:
    name, kinds = key
    if set(kinds) <= LIBRARY_KINDS:
        return ["--lib"]
    require(
        len(kinds) == 1 and kinds[0] in {"bin", "test", "example", "bench"},
        f"Unsupported test-enabled Cargo target kind: {kinds}",
    )
    return ["--" + kinds[0], name]


def target_inventory(package: dict[str, Any]) -> TargetInventory:
    targets = {}
    for target in package["targets"]:
        require(type(target.get("test")) is bool, "Invalid Cargo target test setting")
        if not target["test"]:
            continue
        key = target_key(target)
        target_selector(key)
        require(key not in targets, "Duplicate Cargo target identity")
        targets[key] = target
    require(targets, "Empty required sanitizer target inventory")
    require(
        sum(set(key[1]) <= LIBRARY_KINDS for key in targets) <= 1,
        "Multiple Cargo library targets cannot be selected independently",
    )
    if package["name"] == "ffi":
        baseline = {(name, ("lib" if name == "ffi" else "test",)) for name in FFI_TARGETS}
        require(set(targets) >= baseline, "Missing required baseline ffi target")
    validate_libtest_harnesses(package, targets)
    return targets


def validate_libtest_harnesses(package: dict[str, Any], targets: TargetInventory) -> None:
    # Cargo metadata omits `harness`. Inspect the selected package's manifest;
    # custom harnesses cannot supply the named libtest execution evidence.
    manifest = package.get("manifest_path")
    require(
        isinstance(manifest, str) and Path(manifest).is_absolute(),
        "Missing absolute Cargo package manifest",
    )
    document = tomllib.loads(Path(manifest).read_text())
    selected: dict[str, set[str]] = {}
    for name, kinds in targets:
        kind = "lib" if set(kinds) <= LIBRARY_KINDS else kinds[0]
        selected.setdefault(kind, set()).add(name)
    for kind, names in selected.items():
        declarations = [document.get(kind, {})] if kind == "lib" else document.get(kind, [])
        require(isinstance(declarations, list), "Malformed Cargo target declarations")
        for declaration in declarations:
            require(isinstance(declaration, dict), "Malformed Cargo target declaration")
            harness = declaration.get("harness", True)
            require(type(harness) is bool, "Invalid Cargo target harness setting")
            if harness:
                continue
            # Named non-library declarations are required by Cargo itself.
            name = declaration.get("name")
            require(kind == "lib" or isinstance(name, str), "Missing Cargo target name")
            require(
                kind != "lib" and name not in names,
                "Unsupported custom Cargo harness (harness = false): "
                f"{kind} {name or package['name']}",
            )


def listed(text: str) -> set[str]:
    names = []
    for line in text.splitlines():
        if not line.strip():
            continue
        name, separator, kind = line.rpartition(": ")
        require(
            separator and name and kind in {"test", "benchmark"} and line == line.strip(),
            f"Malformed libtest listing: {line!r}",
        )
        names.append(name)
    require(len(names) == len(set(names)), "Duplicate libtest identity")
    return set(names)


def completed_test(
    event: dict[str, Any],
    names: set[str],
    started: set[str],
    finished: dict[str, str],
    ignored: set[str],
) -> None:
    name = event.get("name")
    require(isinstance(name, str) and name in names, f"Unknown completed test: {name}")
    if event.get("event") == "started":
        require(name not in started and name not in finished, "Duplicate started test")
        started.add(name)
    else:
        require(name not in finished, "Duplicate completed test")
        require(name in ignored or name in started, "Test completed without starting")
        finished[name] = event.get("event")


SUITE_EVENTS = 2


def completed(text: str, names: set[str], ignored: set[str]) -> dict[str, list[str]]:
    started = set()
    finished = {}
    suites = []
    for line in text.splitlines():
        require(line.strip(), "Empty libtest event")
        event = parse_json(line)
        require(isinstance(event, dict), "Malformed libtest event")
        if event.get("type") == "suite":
            suites.append(event)
            require(len(suites) <= SUITE_EVENTS, "Duplicate libtest suite event")
            expected_event = "started" if len(suites) == 1 else "ok"
            require(event.get("event") == expected_event, "Missing normal libtest suite completion")
            if len(suites) == 1:
                require(
                    type(event.get("test_count")) is int and event["test_count"] == len(names),
                    "Libtest suite discovery count mismatch",
                )
            else:
                require(set(finished) == names, "Suite completed before named test execution")
        elif event.get("type") == "test":
            require(len(suites) == 1, "Test event outside active suite")
            completed_test(event, names, started, finished, ignored)
        else:
            failure("Unknown libtest event type")
    require(len(suites) == SUITE_EVENTS, "Missing normal libtest suite completion")
    require(set(finished) == names and started >= names - ignored, "Missing named test execution")
    require(
        all(finished[name] == ("ignored" if name in ignored else "ok") for name in names),
        "Failed or incorrectly ignored test",
    )
    result = suites[1]
    expected_counts = {
        "passed": len(names - ignored),
        "ignored": len(ignored),
        "failed": 0,
        "measured": 0,
        "filtered_out": 0,
    }
    require(
        all(
            type(result.get(key)) is int and result[key] == value
            for key, value in expected_counts.items()
        ),
        "Libtest totals do not match named execution",
    )
    return {
        "started": sorted(started),
        "completed": sorted(names - ignored),
        "ignored": sorted(ignored),
    }


def artifact_binary(record: dict[str, Any], expected: dict[str, Any], output_dir: Path) -> Path:
    target = record["target"]
    require(type(record.get("fresh")) is bool, "Malformed Cargo artifact freshness")
    features = record.get("features")
    require(
        isinstance(features, list)
        and all(isinstance(feature, str) for feature in features)
        and len(features) == len(set(features)),
        "Malformed Cargo artifact features",
    )
    require(
        target.get("kind") == expected["kind"]
        and Path(target.get("src_path", "")).resolve() == Path(expected["src_path"]).resolve(),
        "Cargo target identity mismatch",
    )
    require(isinstance(record.get("executable"), str), "Missing sanitizer test executable")
    binary = Path(record["executable"]).resolve()
    output_dir = output_dir / ("examples" if expected["kind"] == ["example"] else "deps")
    require(
        binary.is_relative_to(output_dir) and binary.is_file() and os.access(binary, os.X_OK),
        "Missing, stale or outside-target sanitizer executable",
    )
    require(
        isinstance(record.get("filenames"), list) and record["executable"] in record["filenames"],
        "Executable is not bound to Cargo artifact filenames",
    )
    return binary


def build_artifacts(
    output: str, package: dict[str, Any], targets: TargetInventory, output_dir: Path
) -> dict[TargetKey, tuple[Path, dict[str, Any]]]:
    found = {}
    binaries = set()
    build_finished = []
    for line in output.splitlines():
        if not line.strip():
            continue
        record = parse_json(line)
        require(
            isinstance(record, dict) and isinstance(record.get("reason"), str),
            "Malformed Cargo JSON record",
        )
        if record["reason"] == "build-finished":
            require(type(record.get("success")) is bool, "Malformed Cargo build-finished record")
            build_finished.append(record["success"])
            continue
        require(
            record["reason"] in {"compiler-artifact", "compiler-message", "build-script-executed"},
            "Unknown Cargo JSON record",
        )
        if record["reason"] != "compiler-artifact":
            continue
        profile = record.get("profile")
        require(
            isinstance(profile, dict) and type(profile.get("test")) is bool,
            "Malformed Cargo artifact profile",
        )
        if not profile["test"]:
            continue
        target = record.get("target", {})
        require(isinstance(target, dict), "Malformed Cargo artifact target")
        key = target_key(target)
        require(
            record.get("package_id") == package["id"] and key in targets,
            "Unrelated sanitizer test artifact",
        )
        require(key not in found, "Duplicate sanitizer test artifact")
        binary = artifact_binary(record, targets[key], output_dir)
        require(binary not in binaries, "Duplicate sanitizer executable")
        binaries.add(binary)
        found[key] = (binary, record)
    require(build_finished == [True], "Missing successful Cargo build-finished record")
    require(set(found) == set(targets), "Missing required sanitizer test artifacts")
    return found


def evidence_routes(inventories: dict[str, TargetInventory]) -> dict[tuple[str, TargetKey], str]:
    entries = [(package, key) for package, targets in inventories.items() for key in targets]
    names = [key[0] for _, key in entries]
    duplicates = len(names) != len(set(names))
    labels = [f"target-{index}-{name}" if duplicates else name for index, name in enumerate(names)]
    require(len(labels) == len(set(labels)), "Duplicate sanitizer evidence label")
    return dict(zip(entries, labels, strict=True))
