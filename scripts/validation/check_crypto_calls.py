#!/usr/bin/env python3
"""Detect direct crypto library calls that bypass the verified abstraction layer.

Scans Rust source files under ``crates/`` for direct imports of low-level crypto
libraries (``ring``, ``aws_lc_rs``, ``ed25519_dalek``, ``p256``, ``sha2``, ``getrandom``,
``hmac``) that bypass the unified crypto layer (``crates/crypto/src/``) or verified
FFI layer (``crates/ffi/src/``).  Direct calls in production code may not be
covered by the project's formal F* proofs.

Two modes:
  --check   Print violations and exit 1 if any found, exit 0 if clean.
  --report  Print a Markdown report with all direct crypto usages and context.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys
from dataclasses import dataclass, field

# ��─ Constants ────────────────────────────────────────────────────────────

CRATES_DIR = pathlib.Path("crates")

# Directories where direct crypto calls are expected / acceptable.
EXCLUDED_DIRS = {
    pathlib.Path("crates/ffi/src"),  # FFI boundary layer
    pathlib.Path("crates/kani-harness"),  # Kani verification harnesses
    pathlib.Path("crates/crypto/src"),  # Unified crypto abstraction layer
    pathlib.Path("crates/loadtest"),  # Load test tooling (non-production)
}

# Patterns for crypto library imports/calls.
CRYPTO_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("ring", re.compile(r"\buse\s+ring::")),
    ("ring", re.compile(r"(?<!:)\bring::\w+")),
    ("aws_lc_rs", re.compile(r"\buse\s+aws_lc_rs::")),
    ("aws_lc_rs", re.compile(r"(?<!:)\baws_lc_rs::\w+")),
    ("ed25519_dalek", re.compile(r"\buse\s+ed25519_dalek::")),
    ("ed25519_dalek", re.compile(r"\bed25519_dalek::\w+")),
    ("p256", re.compile(r"\buse\s+p256::")),
    ("p256", re.compile(r"\bp256::\w+")),
    ("sha2", re.compile(r"\buse\s+sha2::")),
    ("sha2", re.compile(r"\bsha2::\w+")),
    ("getrandom", re.compile(r"\buse\s+getrandom::")),
    ("getrandom", re.compile(r"\bgetrandom::\w+")),
    ("hmac", re.compile(r"\buse\s+hmac::")),
    ("hmac", re.compile(r"\bhmac::\w+")),
]

# Sub-paths within artifacts/ that contain vendored dependency sources.
ARTIFACTS_SEGMENT = "artifacts"


# ─�� Data types ───────────────────────────────────────────────────────────


@dataclass
class Violation:
    file: pathlib.Path
    line_no: int
    line_text: str
    library: str
    in_test_context: bool


@dataclass
class FileReport:
    path: pathlib.Path
    violations: list[Violation] = field(default_factory=list)


# ── Helpers ──────────────────────────────────────────────────────────────


def _is_excluded_path(path: pathlib.Path) -> bool:
    """Return True if *path* should be entirely skipped."""
    for excluded in EXCLUDED_DIRS:
        try:
            path.relative_to(excluded)
            return True
        except ValueError:
            pass

    # Skip vendored dependency source in artifacts/ directories.
    if ARTIFACTS_SEGMENT in path.parts:
        return True

    # Skip test directories.
    if "tests" in path.parts:
        return True

    return False


def _compute_test_lines(lines: list[str]) -> set[int]:
    """Return the set of 0-based line indices inside #[cfg(test)] or #[cfg(kani)] blocks.

    Uses a brace-depth heuristic to track block scope.  This is imperfect for
    edge cases (string literals containing braces, etc.) but sufficient for
    the project's Rust style.
    """
    test_lines: set[int] = set()
    in_test_block = False
    test_brace_depth = 0
    brace_depth = 0
    next_is_test = False

    for i, line in enumerate(lines):
        stripped = line.strip()

        if "#[cfg(test)]" in stripped or "#[cfg(kani)]" in stripped:
            next_is_test = True

        open_braces = stripped.count("{")
        close_braces = stripped.count("}")

        if next_is_test and open_braces > 0:
            in_test_block = True
            test_brace_depth = brace_depth  # depth before entering block
            next_is_test = False

        brace_depth += open_braces - close_braces

        if in_test_block:
            test_lines.add(i)
            if brace_depth <= test_brace_depth:
                in_test_block = False

    return test_lines


def _scan_file(path: pathlib.Path) -> list[Violation]:
    """Scan a single Rust source file for direct crypto library calls."""
    try:
        text = path.read_text(errors="replace")
    except OSError:
        return []

    lines = text.splitlines()
    test_lines = _compute_test_lines(lines)
    violations: list[Violation] = []

    for i, line in enumerate(lines):
        stripped = line.strip()

        # Skip comments.
        if stripped.startswith("//"):
            continue

        for library, pattern in CRYPTO_PATTERNS:
            if pattern.search(stripped):
                in_test = i in test_lines
                violations.append(
                    Violation(
                        file=path,
                        line_no=i + 1,
                        line_text=stripped,
                        library=library,
                        in_test_context=in_test,
                    )
                )
                break  # One match per line is enough.

    return violations


# ── Scanning ─────────────────────────────────────────────────────────────


def scan_crates() -> list[Violation]:
    """Scan all Rust files under crates/ and return violations."""
    all_violations: list[Violation] = []

    if not CRATES_DIR.is_dir():
        print(f"ERROR: {CRATES_DIR} not found", file=sys.stderr)
        return all_violations

    rust_files = sorted(CRATES_DIR.rglob("*.rs"))
    scanned = 0
    skipped = 0

    for path in rust_files:
        if _is_excluded_path(path):
            skipped += 1
            continue

        scanned += 1
        violations = _scan_file(path)
        all_violations.extend(violations)

    print(
        f"Scanned {scanned} files, skipped {skipped} (excluded dirs/artifacts/tests)",
        file=sys.stderr,
    )
    return all_violations


# ── Output: --check mode ─────────────────────────────────────────────────


def check_mode(violations: list[Violation]) -> int:
    """Print violations and return exit code (1 if violations, 0 if clean)."""
    # Only report production violations (not in test context).
    prod_violations = [v for v in violations if not v.in_test_context]

    if not prod_violations:
        test_count = len([v for v in violations if v.in_test_context])
        print(
            f"OK: no direct crypto calls in production code "
            f"({test_count} in test context, excluded)"
        )
        return 0

    # Group by file.
    by_file: dict[pathlib.Path, list[Violation]] = {}
    for v in prod_violations:
        by_file.setdefault(v.file, []).append(v)

    for path in sorted(by_file):
        for v in by_file[path]:
            print(f"{v.file}:{v.line_no}: direct {v.library} call: {v.line_text}")

    print(
        f"\n{len(prod_violations)} direct crypto call(s) in "
        f"{len(by_file)} file(s) bypass the verified abstraction layer."
    )
    return 1


# ── Output: --report mode ────────────────────────────────────────────────


def report_mode(violations: list[Violation]) -> int:
    """Print a Markdown report with all crypto usages and context."""
    prod = [v for v in violations if not v.in_test_context]
    test = [v for v in violations if v.in_test_context]

    lines: list[str] = []
    lines.append("# Direct Crypto Library Call Report")
    lines.append("")

    # ── Summary ──
    lines.append("## Summary")
    lines.append("")

    # Count by library.
    lib_counts: dict[str, dict[str, int]] = {}
    for v in violations:
        ctx = "test" if v.in_test_context else "production"
        lib_counts.setdefault(v.library, {"production": 0, "test": 0})
        lib_counts[v.library][ctx] += 1

    lines.append("| Library | Production | Test Context | Total |")
    lines.append("|---------|----------:|-------------:|------:|")
    for lib in sorted(lib_counts):
        counts = lib_counts[lib]
        total = counts["production"] + counts["test"]
        lines.append(f"| `{lib}` | {counts['production']} | {counts['test']} | {total} |")
    grand_total = len(violations)
    lines.append(f"| **Total** | **{len(prod)}** | **{len(test)}** | **{grand_total}** |")
    lines.append("")

    # ── Production violations (actionable) ──
    lines.append("## Production Code (Actionable)")
    lines.append("")
    if prod:
        lines.append(
            "These calls bypass the verified FFI layer and may not be covered by formal proofs."
        )
        lines.append("")
        lines.append("| File | Line | Library | Code |")
        lines.append("|------|-----:|---------|------|")
        for v in sorted(prod, key=lambda v: (str(v.file), v.line_no)):
            code = v.line_text.replace("|", "\\|")
            lines.append(f"| `{v.file}` | {v.line_no} | `{v.library}` | `{code}` |")
        lines.append("")
    else:
        lines.append("No direct crypto calls found in production code.")
        lines.append("")

    # ── Test context (informational) ──
    lines.append("## Test Context (Informational)")
    lines.append("")
    if test:
        lines.append(
            "These calls are inside `#[cfg(test)]` or `#[cfg(kani)]` blocks "
            "and are acceptable for test setup."
        )
        lines.append("")
        lines.append("| File | Line | Library | Code |")
        lines.append("|------|-----:|---------|------|")
        for v in sorted(test, key=lambda v: (str(v.file), v.line_no)):
            code = v.line_text.replace("|", "\\|")
            lines.append(f"| `{v.file}` | {v.line_no} | `{v.library}` | `{code}` |")
        lines.append("")
    else:
        lines.append("No direct crypto calls found in test context.")
        lines.append("")

    # ── Excluded directories ──
    lines.append("## Excluded Directories")
    lines.append("")
    lines.append("The following directories are excluded from scanning:")
    lines.append("")
    for d in sorted(EXCLUDED_DIRS):
        lines.append(f"- `{d}/` — {_exclusion_reason(d)}")
    lines.append("- `**/artifacts/` — vendored dependency sources")
    lines.append("- `**/tests/` — test files (direct crypto calls expected)")
    lines.append("")

    print("\n".join(lines))
    return 0


def _exclusion_reason(d: pathlib.Path) -> str:
    reasons = {
        pathlib.Path("crates/ffi/src"): "verified FFI boundary layer",
        pathlib.Path("crates/kani-harness"): "Kani verification harnesses",
        pathlib.Path("crates/crypto/src"): "unified crypto abstraction layer",
        pathlib.Path("crates/loadtest"): "load test tooling (non-production)",
    }
    return reasons.get(d, "excluded")


# ── Main ─────────────────────────────────────────────────────────────────


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--check",
        action="store_true",
        help="Print violations and exit 1 if any found, exit 0 if clean",
    )
    group.add_argument(
        "--report",
        action="store_true",
        help="Print Markdown report with all direct crypto usages and context",
    )
    args = parser.parse_args()

    violations = scan_crates()

    if args.check:
        return check_mode(violations)
    return report_mode(violations)


if __name__ == "__main__":
    raise SystemExit(main())
