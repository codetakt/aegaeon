#!/usr/bin/env python3
"""Parse the same bounded Cargo options for preflight and actual execution."""

from __future__ import annotations

import re
import shlex
import sys

# Extra options may change features, scheduling or reporting. Package, native
# target, profile, compiler configuration and unstable options remain fixed.
SWITCHES = frozenset(
    {
        "--all-features",
        "--no-default-features",
        "--locked",
        "--offline",
        "--frozen",
        "--quiet",
        "--verbose",
        "--keep-going",
        "--no-run",
        "--future-incompat-report",
        "-q",
    }
)
VALUES = {
    "--features": "features",
    "-F": "features",
    "--jobs": "jobs",
    "-j": "jobs",
    "--color": "color",
}
BUILD_OPTIONS = ([], ["-Zbuild-std=std"], ["-Z", "build-std=std"])
ERROR = (
    "Cargo flags/build options cannot override required sanitizer selection, "
    "configuration or native target"
)


def valid_value(kind: str, value: str) -> bool:
    if kind == "features":
        return bool(value.split()) and all(
            not token.startswith("-") and re.fullmatch(r"[A-Za-z0-9_./?,-]+", token)
            for token in value.split()
        )
    if kind == "jobs":
        return re.fullmatch(r"-?[1-9][0-9]*", value) is not None
    return value in {"auto", "always", "never"}


def cargo_flags(extra_text: str, build_text: str) -> tuple[list[str], list[str]]:
    """Reject unknown options and positionals, including short-option bundles.

    Parse values explicitly so an option-looking value cannot become a selector.
    The dedicated build option is the only Cargo unstable-option channel.
    """
    extra, build = shlex.split(extra_text), shlex.split(build_text)
    if build not in BUILD_OPTIONS:
        raise ValueError(ERROR)
    pending = iter(extra)
    for token in pending:
        if token in SWITCHES or re.fullmatch(r"-v+", token):
            continue
        option, separator, value = token.partition("=")
        if option not in VALUES and token[:2] in {"-F", "-j"}:
            option, separator, value = token[:2], "attached", token[2:].removeprefix("=")
        kind = VALUES.get(option)
        if kind is None:
            raise ValueError(ERROR)
        if not separator:
            value = next(pending, "")
        if not valid_value(kind, value):
            raise ValueError(ERROR)
    return extra, build


def main() -> int:
    try:
        cargo_flags(*sys.argv[1:])
    except (ValueError, TypeError):
        print(f"[FAIL] {ERROR}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
