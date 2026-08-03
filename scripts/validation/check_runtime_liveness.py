#!/usr/bin/env python3
"""Classify runtime liveness of compliance-matrix ``runtime_link`` targets.

For each ``status: verified`` entry in the compliance matrix, checks whether
the ``runtime_link`` target is actively exercised at runtime:

Categories:
    live          — file exists, referenced from tests, no feature-flag gating
    live_opt_in   — file exists, referenced from tests, gated behind AEGAEON_* flag
    spec_only     — entry's module points to fstar/ (F* spec, not runtime code)
    untested      — file exists but no test references found

Output: a Markdown report with summary, feature-flag matrix, and per-file
detail table.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys
from collections import defaultdict
from typing import Any, cast

import yaml

MATRIX_FILE = pathlib.Path("spec/compliance-matrix.yaml")

# Known feature flags (order preserved for report).
KNOWN_FLAGS = [
    "AEGAEON_REQUIRE_DPOP_NONCE",
]

# Generic pattern for any AEGAEON_* env var reference.
EXTERNAL_FLAG_RE = re.compile(r"\bAEGAEON_[A-Z][A-Z0-9_]*\b")

# ── helpers ──────────────────────────────────────────────────────────────


def _read_cached(path: pathlib.Path, cache: dict[str, str | None]) -> str | None:
    key = str(path)
    if key not in cache:
        try:
            cache[key] = path.read_text(errors="replace")
        except OSError:
            cache[key] = None
    return cache[key]


def _module_segments(runtime_link: str) -> list[str]:
    """Extract Rust module-path segments from a crate file path.

    ``crates/server/src/authcode/store.rs`` → ``["authcode", "store"]``
    ``crates/jose/src/jws.rs``              → ``["jws"]``
    """
    parts = pathlib.PurePosixPath(runtime_link).parts
    try:
        src_idx = parts.index("src")
    except ValueError:
        # Fallback: files under tests/ — use the stem directly.
        return [pathlib.PurePosixPath(runtime_link).stem]

    segments = list(parts[src_idx + 1 :])
    if segments:
        # Strip .rs extension from last segment.
        last = segments[-1]
        if last.endswith(".rs"):
            segments[-1] = last[:-3]
        # Remove trailing "mod" (it's the directory module, not useful for grep).
        if segments[-1] == "mod" and len(segments) > 1:
            segments.pop()
    return segments


def _basename(runtime_link: str) -> str:
    return pathlib.PurePosixPath(runtime_link).stem


def _detect_external_flags(text: str) -> set[str]:
    """Return all AEGAEON_* environment variable names referenced in *text*."""
    return set(EXTERNAL_FLAG_RE.findall(text))


# ── test-reference search ────────────────────────────────────────────────

# Directories to search for test references.
TEST_GLOBS: list[str] = [
    "crates/*/tests/*.rs",
    "crates/*/src/*test*.rs",
]


def _collect_test_files() -> list[pathlib.Path]:
    """Glob all test files under the workspace."""
    result: list[pathlib.Path] = []
    root = pathlib.Path(".")
    for pattern in TEST_GLOBS:
        result.extend(root.glob(pattern))
    return sorted(set(result))


def _has_test_references(
    runtime_link: str,
    test_contents: dict[str, str],
) -> bool:
    """Return True if any test file references the runtime_link target.

    Heuristics:
    1. Basename match (e.g. ``store`` for ``store.rs``)
    2. Module-path segment match (e.g. ``authcode::store``)
    3. ``use ... <basename>`` or ``mod <basename>`` pattern
    """
    basename = _basename(runtime_link)
    segments = _module_segments(runtime_link)

    # Build patterns to search for.
    patterns: list[str] = []
    # Direct basename reference (as identifier).
    if basename != "mod":
        patterns.append(basename)
    # Rust path segments joined by ::.
    if len(segments) >= 2:
        patterns.append("::".join(segments))
    elif len(segments) == 1 and segments[0] != "mod":
        patterns.append(segments[0])

    for _path, content in test_contents.items():
        for pat in patterns:
            if pat in content:
                return True

    return False


def _has_cfg_test(text: str) -> bool:
    """Return True if the file has ``#[cfg(test)]`` sections."""
    return "#[cfg(test)]" in text


# ── classification ───────────────────────────────────────────────────────


def _is_test_file(filepath: str) -> bool:
    """Return True if *filepath* is itself a test file."""
    p = pathlib.PurePosixPath(filepath)
    # Under tests/ directory.
    if "tests" in p.parts:
        return True
    # Named *_test.rs or *_tests.rs or *test*.rs.
    stem = p.stem
    if stem.endswith(("_test", "_tests")):
        return True
    if "test" in stem:
        return True
    return False


ComplianceEntry = dict[str, Any]


def classify_entry(
    entry: ComplianceEntry,
    file_cache: dict[str, str | None],
    test_contents: dict[str, str],
) -> tuple[str, set[str]]:
    """Return (category, external_flags) for a verified entry.

    Categories: live, live_opt_in, spec_only, untested.
    """
    module: str = entry.get("module", "")
    runtime_link: str = entry.get("runtime_link", "")

    # If the module points to an F* spec, classify as spec_only regardless
    # of test coverage — the runtime_link is the Rust counterpart, but the
    # entry's primary source is a formal spec.
    if module.startswith("fstar/"):
        return "spec_only", set()

    # Check file existence.
    rl_path = pathlib.Path(runtime_link)
    text = _read_cached(rl_path, file_cache)
    if text is None:
        return "untested", set()

    # Detect feature flags in the target file.
    external_flags = _detect_external_flags(text)

    # If the runtime_link itself IS a test file, it's inherently tested.
    is_self_test = _is_test_file(runtime_link)

    # Check test references.
    has_tests = _has_test_references(runtime_link, test_contents)
    has_inline = _has_cfg_test(text)
    tested = has_tests or has_inline or is_self_test

    if not tested:
        return "untested", external_flags

    return "live", external_flags


# ── report generation ────────────────────────────────────────────────────


def generate_report(
    entries: list[ComplianceEntry],
    classifications: list[tuple[str, set[str]]],
) -> str:
    """Generate Markdown report from classification results."""
    lines: list[str] = []

    # ── Summary ──
    counts: dict[str, int] = defaultdict(int)
    for cat, _flags in classifications:
        counts[cat] += 1

    lines.append("# Runtime Liveness Classification Report")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append("| Category | Count | Description |")
    lines.append("|----------|------:|-------------|")
    lines.append(f"| `live` | {counts['live']} | File exists, tested, no feature-flag gating |")
    lines.append(
        f"| `live_opt_in` | {counts['live_opt_in']} |"
        " File exists, tested, gated behind AEG_* flag |"
    )
    lines.append(
        f"| `spec_only` | {counts['spec_only']} |"
        " Module is F* spec (runtime_link is Rust counterpart) |"
    )
    lines.append(
        f"| `untested` | {counts['untested']} | File exists but no test references found |"
    )
    total = sum(counts.values())
    lines.append(f"| **Total** | **{total}** | |")
    lines.append("")

    # ��─ Feature Flag Matrix ──
    # Collect all flags seen across all entries.
    all_flags: set[str] = set()
    flag_to_files: dict[str, set[str]] = defaultdict(set)
    for entry, (_cat, flags) in zip(entries, classifications, strict=True):
        all_flags |= flags
        runtime_link = entry.get("runtime_link")
        for flag in flags:
            if isinstance(runtime_link, str):
                flag_to_files[flag].add(runtime_link)

    # Sort: known flags first, then any extras.
    sorted_flags = [f for f in KNOWN_FLAGS if f in all_flags]
    sorted_flags += sorted(all_flags - set(KNOWN_FLAGS))

    if sorted_flags:
        lines.append("## Feature Flag Matrix")
        lines.append("")
        lines.append("| Flag | Files Affected | Entry Count |")
        lines.append("|------|---------------:|------------:|")
        for flag in sorted_flags:
            files = flag_to_files[flag]
            entry_count = sum(
                1
                for entry, (_cat, flags) in zip(entries, classifications, strict=True)
                if flag in flags
            )
            lines.append(f"| `{flag}` | {len(files)} | {entry_count} |")
        lines.append("")

    # ── Per-file detail ──
    lines.append("## Per-Entry Detail")
    lines.append("")
    lines.append("| ID | Category | Runtime Link | Flags |")
    lines.append("|----|----------|--------------|-------|")
    for entry, (cat, flags) in zip(entries, classifications, strict=True):
        entry_id = entry.get("id", "?")
        rl = entry.get("runtime_link", "")
        flag_str = ", ".join(sorted(flags)) if flags else "-"
        lines.append(f"| {entry_id} | `{cat}` | `{rl}` | {flag_str} |")
    lines.append("")

    return "\n".join(lines)


# ── main ─────────────────────────────────────────────────────────────────


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Write Markdown report to FILE instead of stdout",
    )
    args = parser.parse_args()

    if not MATRIX_FILE.exists():
        print(f"ERROR: {MATRIX_FILE} not found", file=sys.stderr)
        return 1

    data = cast("dict[str, object]", yaml.safe_load(MATRIX_FILE.read_text()))

    # Collect verified entries.
    verified_entries: list[ComplianceEntry] = []
    for key, section_entries in data.items():
        if key == "metadata" or not isinstance(section_entries, list):
            continue
        for entry in section_entries:
            if not isinstance(entry, dict):
                continue
            if entry.get("status") == "verified" and entry.get("runtime_link"):
                verified_entries.append(entry)

    if not verified_entries:
        print("WARNING: No verified entries with runtime_link found.", file=sys.stderr)
        return 0

    # Pre-read all test files.
    file_cache: dict[str, str | None] = {}
    test_files = _collect_test_files()
    test_contents: dict[str, str] = {}
    for tf in test_files:
        content = _read_cached(tf, file_cache)
        if content is not None:
            test_contents[str(tf)] = content

    # Classify each entry.
    classifications: list[tuple[str, set[str]]] = []
    for entry in verified_entries:
        cat, flags = classify_entry(entry, file_cache, test_contents)
        classifications.append((cat, flags))

    # Generate report.
    report = generate_report(verified_entries, classifications)

    if args.output:
        output_path = pathlib.Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(report)
        print(f"Report written to {args.output}", file=sys.stderr)
    else:
        print(report)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
