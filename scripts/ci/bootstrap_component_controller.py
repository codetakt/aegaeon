"""Check initial B custody after the fixed shell admits its first runtime.

Initial GitHub action resolution and platform/Nix trust are external premises.
This entrypoint installs no P package, calls no producer and grants no admission
by issuing a receipt. Its caller must verify its bytes before first execution.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import stat
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

if TYPE_CHECKING:
    from collections.abc import Mapping
    from os import stat_result

SOURCE_ROOT = Path("/trusted/component-bootstrap")
SOURCE_FILES = ("bootstrap_component_controller.py", "component-bootstrap-runtime.json")
MAX_JSON_BYTES = 1024 * 1024
JsonObject = dict[str, Any]


class BootstrapRejectedError(ValueError):
    """The concrete initial runtime or source custody differs."""


def require(condition: object, message: str) -> None:
    if not condition:
        raise BootstrapRejectedError(message)


def unique_object(pairs: list[tuple[str, Any]]) -> JsonObject:
    result: JsonObject = {}
    for key, value in pairs:
        require(key not in result, "duplicate bootstrap JSON key")
        result[key] = value
    return result


def load_object(path: Path) -> JsonObject:
    raw = path.read_bytes()
    require(len(raw) <= MAX_JSON_BYTES, "bootstrap JSON exceeds bound")
    value = json.loads(raw, object_pairs_hook=unique_object)
    require(type(value) is dict, "bootstrap JSON object required")
    return cast("JsonObject", value)


def verify_nar_map(expected: JsonObject, observed: JsonObject) -> None:
    """Recheck the same exact closure predicate as the pre-Python Nix gate."""
    require(len(expected) == 35 and set(observed) == set(expected), "NAR domain differs")
    for path, wanted in expected.items():
        actual = observed[path]
        require(type(wanted) is dict and type(actual) is dict, "NAR row differs")
        require(
            set(wanted) == {"narHash", "narSize", "references"}
            and all(actual.get(key) == value for key, value in wanted.items()),
            "NAR contents or references differ",
        )
        require(
            path.startswith("/nix/store/")
            and type(wanted["references"]) is list
            and all(reference in expected for reference in wanted["references"]),
            "NAR reference leaves the exact closure",
        )


def verify_owned_mode(info: stat_result, *, readonly: bool) -> None:
    require(info.st_uid == 0 and not info.st_mode & 0o022, "source custody is writable")
    if readonly:
        require(not info.st_mode & 0o222, "source payload is writable")


def verify_readonly_mount(root: Path, mountinfo: str) -> None:
    rows = []
    for line in mountinfo.splitlines():
        fields = line.split()
        require(len(fields) >= 10 and "-" in fields, "malformed mount observation")
        if fields[4] == str(root):
            rows.append(fields)
    require(len(rows) == 1 and "ro" in rows[0][5].split(","), "readonly source mount missing")


def verify_source_custody(root: Path, hashes: Mapping[str, str], mountinfo: str) -> None:
    require(root == SOURCE_ROOT and set(hashes) == set(SOURCE_FILES), "source root differs")
    require(root.is_dir() and not root.is_symlink(), "source directory differs")
    for ancestor in (root, *root.parents):
        info = ancestor.lstat()
        require(stat.S_ISDIR(info.st_mode), "source ancestor is not a directory")
        verify_owned_mode(info, readonly=ancestor == root)
    verify_readonly_mount(root, mountinfo)
    require({entry.name for entry in root.iterdir()} == set(SOURCE_FILES), "source set differs")
    for name, digest in hashes.items():
        path = root / name
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "source file differs")
        verify_owned_mode(info, readonly=True)
        require(hashlib.sha256(path.read_bytes()).hexdigest() == digest, "source bytes differ")


def verify_runtime(record: JsonObject) -> None:
    roots = record["nar_map"]
    require(type(roots) is dict and len(roots) == 35, "runtime closure differs")
    require(
        record["runtime_root"] in roots
        and record["ca_root"] in roots
        and sys.executable == record["interpreter"]
        and sys.flags.isolated == 1
        and sys.flags.dont_write_bytecode == 1,
        "explicit isolated runtime differs",
    )
    for entry in sys.path:
        require(
            bool(entry) and any(entry == root or entry.startswith(root + "/") for root in roots),
            "runtime import path leaves the admitted closure",
        )
    for root in roots:
        path = Path(root)
        require(path.is_dir() and not path.is_symlink(), "runtime root differs")
        verify_owned_mode(path.lstat(), readonly=True)
    ca = Path(record["ca_file"])
    require(
        ca.is_relative_to(Path(record["ca_root"])) and ca.name == "ca-bundle.crt",
        "literal public CA edge differs",
    )
    require(
        hashlib.sha256(ca.read_bytes()).hexdigest() == record["ca_sha256"],
        "public CA bytes differ",
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--script-sha256", required=True)
    parser.add_argument("--runtime-sha256", required=True)
    parser.add_argument("--observed-nar-map", type=Path, required=True)
    arguments = parser.parse_args()
    verify_source_custody(
        SOURCE_ROOT,
        dict(zip(SOURCE_FILES, (arguments.script_sha256, arguments.runtime_sha256), strict=True)),
        Path("/proc/self/mountinfo").read_text(),
    )
    record = load_object(SOURCE_ROOT / SOURCE_FILES[1])
    observed = load_object(arguments.observed_nar_map)
    verify_nar_map(record["nar_map"], observed)
    verify_runtime(record)
    sys.stdout.write("Initial B custody checks passed under external platform trust.\n")


if __name__ == "__main__":
    main()
