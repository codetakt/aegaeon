#!/usr/bin/env python3
"""Detect drift in runtime-linked files referenced by the compliance matrix.

Two modes:
    --generate  Compute SHA-256 hashes of all runtime_link files from
                status:verified entries and write spec/runtime-link-manifest.json.
                Also hashes files matched by MONITORED_PATHS independently.
    --check     Compare current file hashes against the manifest and report drift
                (exit 1 if drift detected, 0 otherwise).

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
import sys
from collections import defaultdict
from datetime import UTC, datetime
from typing import Any, cast

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


def _collect_runtime_links(data: dict[str, object]) -> dict[str, list[str]]:
    """Map runtime_link paths to the entry IDs that reference them."""
    links: dict[str, list[str]] = defaultdict(list)
    for key, entries in data.items():
        if key == "metadata" or not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            if entry.get("status") != "verified":
                continue
            rl = entry.get("runtime_link")
            entry_id = entry.get("id", "<unknown>")
            if isinstance(rl, str):
                # Symbol-form links ("path#symbol") monitor the containing file.
                links[rl.split("#", 1)[0]].append(str(entry_id))
    return dict(links)


def _collect_monitored_files() -> dict[str, list[str]]:
    """Glob MONITORED_PATHS and return {path_str: [source_pattern, ...]} mapping."""
    result: dict[str, list[str]] = defaultdict(list)
    for pattern in MONITORED_PATHS:
        for path in sorted(pathlib.Path(".").glob(pattern)):
            if path.is_file():
                result[str(path)].append(f"monitored:{pattern}")
    return dict(result)


def generate(data: dict[str, object]) -> ManifestRecord:
    """Build a manifest of file hashes and dependent entry IDs."""
    links = _collect_runtime_links(data)
    files: dict[str, ManifestRecord] = {}
    missing = 0

    for path_str in sorted(links):
        path = pathlib.Path(path_str)
        if not path.exists():
            print(f"WARNING: runtime_link file not found: {path_str}", file=sys.stderr)
            missing += 1
            continue
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
        "generated": datetime.now(UTC).isoformat(),
        "files": files,
        "monitored_files": monitored_files,
    }

    if missing:
        print(f"WARNING: {missing} runtime_link file(s) not found", file=sys.stderr)

    return manifest


def check(manifest: ManifestRecord) -> tuple[int, int]:
    """Compare current hashes against manifest.

    Returns (total_drifted, critical_drifted).
    """
    files = manifest.get("files", {})
    drifted = 0
    critical_drifted = 0

    if not isinstance(files, dict):
        files = {}

    for path_str, info in sorted(files.items()):
        if not isinstance(path_str, str) or not isinstance(info, dict):
            continue
        path = pathlib.Path(path_str)
        is_crit = info.get("critical", _is_critical(path_str))
        tag = " [CRITICAL]" if is_crit else ""

        if not path.exists():
            print(f"DRIFT{tag}: {path_str} — file missing (entries: {', '.join(info['entries'])})")
            drifted += 1
            if is_crit:
                critical_drifted += 1
            continue

        current_hash = _sha256(path)
        if current_hash != info["sha256"]:
            print(f"DRIFT{tag}: {path_str} — hash changed (entries: {', '.join(info['entries'])})")
            drifted += 1
            if is_crit:
                critical_drifted += 1

    # Check monitored files (always critical)
    monitored = manifest.get("monitored_files", {})
    if not isinstance(monitored, dict):
        monitored = {}

    for path_str, info in sorted(monitored.items()):
        if not isinstance(path_str, str) or not isinstance(info, dict):
            continue
        path = pathlib.Path(path_str)
        tag = " [CRITICAL]"

        if not path.exists():
            print(f"DRIFT{tag}: {path_str} — file missing (monitored)")
            drifted += 1
            critical_drifted += 1
            continue

        current_hash = _sha256(path)
        if current_hash != info["sha256"]:
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
        help="Check current files against the manifest (warning mode)",
    )
    parser.add_argument(
        "--manifest",
        type=pathlib.Path,
        default=MANIFEST_FILE,
        help=f"Manifest file path (default: {MANIFEST_FILE})",
    )
    args = parser.parse_args()

    if args.generate:
        if not MATRIX_FILE.exists():
            print(f"ERROR: {MATRIX_FILE} not found", file=sys.stderr)
            return 1

        data = cast("dict[str, object]", yaml.safe_load(MATRIX_FILE.read_text()))
        manifest = generate(data)

        args.manifest.parent.mkdir(parents=True, exist_ok=True)
        args.manifest.write_text(json.dumps(manifest, indent=2) + "\n")
        monitored_count = len(manifest.get("monitored_files", {}))
        print(
            f"Generated {args.manifest} "
            f"({len(manifest['files'])} files, {monitored_count} monitored)"
        )
        return 0

    # --check mode
    if not args.manifest.exists():
        print(
            f"ERROR: {args.manifest} not found (run with --generate first)",
            file=sys.stderr,
        )
        return 1

    manifest = cast("ManifestRecord", json.loads(args.manifest.read_text()))
    drifted, critical_drifted = check(manifest)

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
            sum(1 for f in manifest.get("files", {}).values() if f.get("critical", False))
            + monitored_total
        )  # all monitored files are critical
        print(
            f"OK: all {total} runtime-linked + {monitored_total} monitored files "
            f"match manifest ({critical_total} critical)"
        )

    # Exit 2 for critical drift (fail-close), 1 for non-critical drift, 0 for clean.
    if critical_drifted:
        return 2
    return 1 if drifted else 0


if __name__ == "__main__":
    raise SystemExit(main())
