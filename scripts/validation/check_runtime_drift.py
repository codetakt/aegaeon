#!/usr/bin/env python3
"""Detect drift in runtime-linked files referenced by the compliance matrix.

Two modes:
    --generate  Compute SHA-256 hashes of all runtime_link files from
                status:verified entries and write spec/runtime-link-manifest.json.
                Also hashes files matched by MONITORED_PATHS independently.
    --check     Compare current file hashes against the manifest and report drift
                (0 clean, 10 noncritical drift, 2 critical drift or invalid inputs).

The manifest records which compliance-matrix entry IDs depend on each file,
so drift reports are actionable.

Crypto Fail-Close:
    Files matching CRITICAL_PATTERNS are marked ``critical: true`` in the manifest.
    When --check detects drift in a critical file, exit code is 2 (hard failure)
    instead of 1 (warning). This prevents crypto trust-boundary files from
    drifting silently.

Monitored Paths:
    MONITORED_PATHS lists glob patterns for files tracked independently of
    runtime_link entries. All monitored files are treated as critical (exit 2
    on drift). This covers source files (e.g. crates/crypto/src/) that have
    no compliance-matrix runtime_link but must not change unnoticed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sys
from collections import defaultdict
from typing import Any

import yaml

MATRIX_FILE = pathlib.Path("spec/compliance-matrix.yaml")
MANIFEST_FILE = pathlib.Path("spec/runtime-link-manifest.json")

# Files matching these patterns are crypto trust-boundary code.
# Drift in these files is a hard failure (exit 2) rather than a warning (exit 1).
#
# NOTE: For runtime_link files, only entries present in the compliance matrix are
# tracked.  Paths listed here that have no matrix entries will NOT be drift-checked
# via runtime_link (they are effectively no-ops).  However, MONITORED_PATHS (below)
# tracks files independently — crates/crypto/src/ is covered that way.
CRITICAL_PATTERNS: list[str] = [
    "fstar/crypto/",
    "fstar/jose/Jose.Jws.Verify.fst",
    "fstar/jose/Jose.Jws_signature.fst",
    "fstar/jose/Jose.Rsa_signatures.fst",
    "fstar/jose/Jose.SdJwt.fst",
    "fstar/jose/Jose.Federation.fst",
    "fstar/jose/Jose.Jwk_thumbprint_uri.fst",
    "fstar/dpop/Dpop.Signature.fst",
    "fstar/dpop/Dpop.Ath_validation.fst",
    "fstar/HashComputation.fst",
    "fstar/pkce/Pkce.fst",
    "fstar/pkce/Pkce.Verification.fst",
    # crates/crypto/src/ tracked via MONITORED_PATHS (below), not runtime_link.
    "crates/crypto/src/",  # Rust crypto crate (monitored independently)
    "crates/ffi/src/",  # FFI boundary layer
    "c/json_lowstar_runtime.c",
    "c/verified_core.c",
    "include/verified_core.h",
]


# Paths monitored independently of runtime_link entries.  Files matching
# these glob patterns are hashed and tracked for drift even if no
# compliance-matrix entry references them.  All monitored files are treated
# as critical (exit 2 on drift).
MONITORED_PATHS: list[str] = [
    "crates/crypto/src/**/*.rs",
]


def _is_critical(path_str: str) -> bool:
    """Return True if the file is a crypto trust-boundary file."""
    return any(path_str.startswith(pat) or path_str == pat for pat in CRITICAL_PATTERNS)


def _sha256(path: pathlib.Path) -> str:
    """Return the hex SHA-256 digest of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


ManifestRecord = dict[str, Any]


class InputError(ValueError):
    """Required drift-check input is invalid or incomplete."""


def _unique_mapping(pairs: list[tuple[Any, Any]]) -> dict[Any, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise InputError(f"duplicate mapping key: {key!r}")
        result[key] = value
    return result


# The pinned Python runtime has PyYAML but no loader type stubs.
class UniqueLoader(yaml.SafeLoader):  # type: ignore[misc]
    def construct_mapping(self, node: yaml.MappingNode, deep: bool = False) -> dict[Any, Any]:
        self.flatten_mapping(node)
        return _unique_mapping(self.construct_pairs(node, deep=deep))


def _has_surrogates(value: str) -> bool:
    return any(0xD800 <= ord(char) <= 0xDFFF for char in value)


def _runtime_path(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise InputError("runtime path must be a nonempty string")
    path = pathlib.PurePosixPath(value)
    if (
        path.is_absolute()
        or ".." in path.parts
        or str(path) != value
        or value == "."
        or "\\" in value
        or _has_surrogates(value)
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
    ):
        raise InputError(f"invalid runtime path: {value!r}")
    return value


def _collect_runtime_links(data: object) -> dict[str, list[str]]:
    """Discover the current verified file-to-ID inventory, not proof coverage."""
    if not isinstance(data, dict):
        raise InputError("matrix must be a mapping")
    links: dict[str, list[str]] = defaultdict(list)
    seen: set[str] = set()
    for key, entries in data.items():
        if key == "metadata":
            continue
        if not isinstance(entries, list):
            raise InputError(f"matrix section {key!r} must be a list")
        for entry in entries:
            if not isinstance(entry, dict):
                raise InputError(f"matrix section {key!r} contains a non-mapping row")
            if entry.get("status") != "verified" or "runtime_link" not in entry:
                continue
            entry_id = entry.get("id")
            if (
                not isinstance(entry_id, str)
                or not entry_id.strip()
                or _has_surrogates(entry_id)
                or entry_id in seen
            ):
                raise InputError(f"invalid or duplicate selected entry ID: {entry_id!r}")
            link = entry["runtime_link"]
            if not isinstance(link, str):
                raise InputError(f"invalid runtime_link for {entry_id}")
            # Symbol-form links monitor the containing file, not symbol existence.
            links[_runtime_path(link.split("#", 1)[0])].append(entry_id)
            seen.add(entry_id)
    if not links:
        raise InputError("matrix selects no verified runtime links")
    return dict(links)


def runtime_links(matrix: bytes | None) -> dict[str, list[str]]:
    """Shared discovery from the exact matrix bytes also bound by the wrapper."""
    try:
        if matrix is None:
            raise InputError(f"missing matrix: {MATRIX_FILE}")
        return _collect_runtime_links(yaml.load(matrix.decode("utf-8"), Loader=UniqueLoader))
    except (ValueError, TypeError, RecursionError, yaml.YAMLError) as error:
        raise InputError(f"invalid matrix: {error}") from error


def read_manifest(data: bytes) -> ManifestRecord:
    try:
        manifest = json.loads(data.decode("utf-8"), object_pairs_hook=_unique_mapping)
        if not isinstance(manifest, dict):
            raise InputError("manifest must be a mapping")
        return manifest
    except (ValueError, TypeError, RecursionError) as error:
        raise InputError(f"invalid manifest: {error}") from error


def _manifest_group(manifest: ManifestRecord, name: str) -> dict[str, ManifestRecord]:
    group = manifest.get(name)
    if not isinstance(group, dict):
        raise InputError(f"manifest {name} must be a mapping")
    for path, info in group.items():
        _runtime_path(path)
        if not isinstance(info, dict):
            raise InputError(f"invalid manifest record: {path}")
        digest = info.get("sha256")
        if not isinstance(digest, str) or re.fullmatch(r"[0-9a-fA-F]{64}", digest) is None:
            raise InputError(f"invalid digest: {path}")
        critical = name == "monitored_files" or _is_critical(path)
        if "critical" in info and (
            not isinstance(info["critical"], bool) or info["critical"] != critical
        ):
            raise InputError(f"critical policy mismatch: {path}")
    return group


def _validate_inventory(manifest: ManifestRecord, links: dict[str, list[str]]) -> None:
    files = _manifest_group(manifest, "files")
    _manifest_group(manifest, "monitored_files")
    if set(files) != set(links):
        raise InputError(
            f"runtime inventory mismatch: missing={sorted(set(links) - set(files))}, "
            f"stale={sorted(set(files) - set(links))}"
        )
    for path, info in files.items():
        entries = info.get("entries")
        if (
            not isinstance(entries, list)
            or not entries
            or any(not isinstance(entry, str) or not entry.strip() for entry in entries)
            or len(set(entries)) != len(entries)
            or set(entries) != set(links[path])
        ):
            raise InputError(f"invalid entry attribution: {path}")


def _collect_monitored_files() -> dict[str, list[str]]:
    """Glob MONITORED_PATHS and return {path_str: [source_pattern, ...]} mapping."""
    result: dict[str, list[str]] = defaultdict(list)
    for pattern in MONITORED_PATHS:
        for path in sorted(pathlib.Path(".").glob(pattern)):
            if path.is_file():
                result[_runtime_path(str(path))].append(f"monitored:{pattern}")
    return dict(result)


def generate(links: dict[str, list[str]]) -> ManifestRecord:
    """Build a manifest of file hashes and dependent entry IDs."""
    files: dict[str, ManifestRecord] = {}

    for path_str in sorted(links):
        path = pathlib.Path(path_str)
        files[path_str] = {
            "sha256": _sha256(path),
            "entries": sorted(links[path_str]),
            "critical": _is_critical(path_str),
        }

    # Monitored files (tracked independently of compliance matrix)
    monitored = _collect_monitored_files()
    monitored_files: dict[str, ManifestRecord] = {}
    for path_str in sorted(monitored):
        path = pathlib.Path(path_str)
        monitored_files[path_str] = {
            "sha256": _sha256(path),
            "sources": sorted(monitored[path_str]),
            "critical": True,
        }

    manifest: ManifestRecord = {
        "files": files,
        "monitored_files": monitored_files,
    }

    return manifest


def check(manifest: ManifestRecord, links: dict[str, list[str]]) -> tuple[int, int]:
    """Compare current hashes against manifest.

    Returns (total_drifted, critical_drifted).
    """
    _validate_inventory(manifest, links)
    files = manifest["files"]
    drifted = 0
    critical_drifted = 0

    for path_str, info in sorted(files.items()):
        path = pathlib.Path(path_str)
        is_crit = _is_critical(path_str)
        tag = " [CRITICAL]" if is_crit else ""

        if not path.exists():
            print(f"DRIFT{tag}: {path_str} — file missing (entries: {', '.join(info['entries'])})")
            drifted += 1
            if is_crit:
                critical_drifted += 1
            continue

        current_hash = _sha256(path)
        if current_hash != info["sha256"].lower():
            print(f"DRIFT{tag}: {path_str} — hash changed (entries: {', '.join(info['entries'])})")
            drifted += 1
            if is_crit:
                critical_drifted += 1

    # Check monitored files (always critical)
    monitored = manifest["monitored_files"]

    for path_str, info in sorted(monitored.items()):
        path = pathlib.Path(path_str)
        tag = " [CRITICAL]"

        if not path.exists():
            print(f"DRIFT{tag}: {path_str} — file missing (monitored)")
            drifted += 1
            critical_drifted += 1
            continue

        current_hash = _sha256(path)
        if current_hash != info["sha256"].lower():
            print(f"DRIFT{tag}: {path_str} — hash changed (monitored)")
            drifted += 1
            critical_drifted += 1

    # Detect NEW files matching MONITORED_PATHS not yet in the manifest.
    # Without this check, new crypto source files slip through until the
    # manifest is regenerated.
    current_monitored = _collect_monitored_files()
    for path_str in sorted(current_monitored):
        if path_str not in monitored:
            print(f"DRIFT [CRITICAL]: {path_str} — new file not in manifest (monitored)")
            drifted += 1
            critical_drifted += 1

    return drifted, critical_drifted


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--generate",
        action="store_true",
        help="Generate the runtime-link manifest",
    )
    group.add_argument(
        "--check",
        action="store_true",
        help="Check matrix inventory and current files against the manifest",
    )
    parser.add_argument(
        "--manifest",
        type=pathlib.Path,
        default=MANIFEST_FILE,
        help=f"Manifest file path (default: {MANIFEST_FILE})",
    )
    args = parser.parse_args()

    try:
        links = runtime_links(MATRIX_FILE.read_bytes())
        if args.generate:
            # Validate and read everything before opening the existing destination.
            manifest = generate(links)
            args.manifest.parent.mkdir(parents=True, exist_ok=True)
            args.manifest.write_text(json.dumps(manifest, indent=2) + "\n")
            print(
                f"Generated {args.manifest} "
                f"({len(manifest['files'])} files, {len(manifest['monitored_files'])} monitored)"
            )
            return 0
        manifest = read_manifest(args.manifest.read_bytes())
        drifted, critical_drifted = check(manifest, links)
    except (OSError, InputError) as error:
        print(f"ERROR: runtime drift input: {error}", file=sys.stderr)
        return 2

    if drifted:
        print(f"\n{drifted} file(s) have drifted since manifest was generated.")
        if critical_drifted:
            print(
                f"  {critical_drifted} CRITICAL (crypto trust-boundary) file(s) drifted — "
                f"fail-close triggered."
            )
        print("Run with --generate to update the manifest.")
    else:
        total = len(manifest.get("files", {}))
        monitored_total = len(manifest.get("monitored_files", {}))
        critical_total = (
            sum(1 for path in manifest["files"] if _is_critical(path)) + monitored_total
        )  # all monitored files are critical
        print(
            f"OK: all {total} runtime-linked + {monitored_total} monitored files "
            f"match manifest ({critical_total} critical)"
        )

    # Reserve 10 for completed noncritical drift; Python failures commonly exit 1.
    if critical_drifted:
        return 2
    return 10 if drifted else 0


if __name__ == "__main__":
    raise SystemExit(main())
