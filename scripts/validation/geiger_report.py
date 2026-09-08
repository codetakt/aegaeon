"""Validate cargo-geiger 0.13 JSON without mistaking partial metrics for success."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit


def members(metadata: dict[str, Any]) -> list[dict[str, Any]]:
    ids = metadata["workspace_members"]
    packages = {package["id"]: package for package in metadata["packages"]}
    if not ids or len(ids) != len(set(ids)):
        raise ValueError("empty or duplicate workspace membership")
    return [packages[package_id] for package_id in ids]


def identity(package: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": package["name"],
        "version": package["version"],
        "source": {"Path": Path(package["manifest_path"]).resolve().parent.as_uri()},
    }


def report_identities(package: dict[str, Any]) -> list[dict[str, Any]]:
    canonical = identity(package)
    # cargo-geiger 0.13 slices the Cargo package-ID string as if it were still
    # quoted. With modern Cargo, its Path URL includes a truncated #name@version.
    # Derive that exact spelling from metadata; never match by package name alone.
    raw_id = package["id"]
    if "+file://" not in raw_id:
        return [canonical]
    legacy_path = raw_id[1:-1].split("+file://", 1)[1]
    return [canonical, {**canonical, "source": {"Path": Path(legacy_path).as_uri()}}]


def metrics(entry: dict[str, Any]) -> None:
    unsafe = entry["unsafety"]
    if type(unsafe["forbids_unsafe"]) is not bool:
        raise ValueError("invalid forbids_unsafe metric")
    for usage in ("used", "unused"):
        for category in ("functions", "exprs", "item_impls", "item_traits", "methods"):
            for kind in ("safe", "unsafe_"):
                count = unsafe[usage][category][kind]
                if type(count) is not int or count < 0:
                    raise ValueError("invalid unsafe inventory count")


def identity_key(value: dict[str, Any]) -> str:
    if isinstance(value.get("source"), dict) and "Path" in value["source"]:
        url = urlsplit(value["source"]["Path"])
        if url.scheme != "file" or url.netloc or url.query or url.fragment:
            raise ValueError("invalid package source URI")
        value = {**value, "source": {"Path": unquote(url.path)}}
    return json.dumps(value, sort_keys=True)


def check_report(
    metadata: dict[str, Any], manifest: Path, report: dict[str, Any], diagnostics: str
) -> dict[str, Any]:
    workspace = members(metadata)
    selected = [p for p in workspace if Path(p["manifest_path"]).resolve() == manifest]
    if len(selected) != 1:
        raise ValueError("scan manifest is not a unique workspace member")
    expected = identity(selected[0])
    entries = report["packages"]
    missing = report["packages_without_metrics"]
    unscanned = report["used_but_not_scanned_files"]
    if not all(isinstance(items, list) for items in (entries, missing, unscanned)):
        raise ValueError("invalid Geiger report collections")
    keys = [identity_key(entry["package"]["id"]) for entry in entries]
    if len(keys) != len(set(keys)):
        raise ValueError("duplicate package metrics")
    expected_keys = [identity_key(item) for item in report_identities(selected[0])]
    roots = [entry for entry in entries if identity_key(entry["package"]["id"]) in expected_keys]
    if len(roots) != 1:
        raise ValueError("requested package metrics are missing or have the wrong identity")
    own_ids = [identity_key(item) for package in workspace for item in report_identities(package)]
    if any(identity_key(package) in own_ids for package in missing):
        raise ValueError("workspace package has no metrics")
    own_entries = [entry for entry in entries if identity_key(entry["package"]["id"]) in own_ids]
    for entry in own_entries:
        metrics(entry)
    source_roots = [Path(package["manifest_path"]).resolve().parent for package in workspace]
    if any(
        line.startswith(f"Failed to parse file: {root}/")
        for line in diagnostics.splitlines()
        for root in source_roots
    ):
        raise ValueError("workspace source was not scanned: parse failure")
    failed_paths = re.findall(r"^Failed to parse file: (.*?), .*$", diagnostics, re.MULTILINE)
    for filename in [*unscanned, *failed_paths]:
        path = Path(filename)
        if not path.is_absolute():
            raise ValueError("unattributed unscanned source file")
        if any(path.resolve().is_relative_to(root) for root in source_roots):
            raise ValueError(f"workspace source was not scanned: {filename}")
    return {
        "package": expected,
        "status": "complete",
        "workspace_metrics": own_entries,
        "dependency_packages_without_metrics": missing,
        "dependency_files_not_scanned": unscanned,
        "dependency_parse_failures": failed_paths,
    }


def main(argv: list[str]) -> None:
    command, metadata_path, manifest_arg, *paths = argv
    metadata = json.loads(Path(metadata_path).read_text())
    if command == "manifests":
        selected = members(metadata)
        if manifest_arg:
            manifest = Path(manifest_arg).resolve()
            selected = [p for p in selected if Path(p["manifest_path"]).resolve() == manifest]
        if not selected:
            raise ValueError("no workspace packages selected")
        for package in selected:
            path = str(Path(package["manifest_path"]).resolve())
            if any(char in path for char in "\t\n\r"):
                raise ValueError("unsupported manifest path characters")
            print(f"{package['name']}\t{path}")
        return
    if command != "check" or len(paths) != 2:
        raise ValueError("expected manifests or check command")
    report_path, diagnostic_path = map(Path, paths)
    result = check_report(
        metadata,
        Path(manifest_arg).resolve(),
        json.loads(report_path.read_text()),
        diagnostic_path.read_text(),
    )
    report_path.with_suffix(".gate.json").write_text(json.dumps(result, indent=2) + "\n")
    print(f"[geiger] {result['package']['name']}: scan complete")


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except (ValueError, KeyError, TypeError, OSError) as error:
        sys.exit(f"Geiger evidence rejected: {error}")
