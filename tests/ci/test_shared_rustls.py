"""Keep the rustls security-update sites and their distinct Cargo policies in sync."""

from __future__ import annotations

import re
import tomllib
import unittest
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
INHERITED = {("crates/client", "dependencies"), ("crates/crypto", "dependencies")}
PINNED = {("crates/server", "dependencies"), ("crates/loadtest", "dev-dependencies")}
KINDS = ("dependencies", "dev-dependencies", "build-dependencies")


def manifest(directory: Path) -> dict[str, Any]:
    return tomllib.loads((directory / "Cargo.toml").read_text())


def rustls_sites(workspace: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    sites = {}
    for directory in [*workspace["members"], *workspace["exclude"]]:
        doc = manifest(ROOT / directory)
        tables = [("", doc), *doc.get("target", {}).items()]
        for target, table in tables:
            for kind in KINDS:
                for name, value in table.get(kind, {}).items():
                    requirement = {"version": value} if isinstance(value, str) else value
                    if requirement.get("workspace"):
                        requirement_source = workspace["dependencies"][name]
                    else:
                        requirement_source = requirement
                    package = (
                        requirement_source.get("package", name)
                        if isinstance(requirement_source, dict)
                        else name
                    )
                    if package == "rustls":
                        key = ".".join(part for part in (target, kind, name) if part)
                        sites[directory, key] = requirement
    return sites


def stale_pins(sites: dict[tuple[str, str], dict[str, Any]], version: str) -> dict[str, Any]:
    return {
        path: sites[path, f"{kind}.rustls"].get("version")
        for path, kind in PINNED
        if sites[path, f"{kind}.rustls"].get("version") != f"={version}"
    }


class SharedRustlsTests(unittest.TestCase):
    def test_security_update_group(self) -> None:
        workspace = manifest(ROOT)["workspace"]
        baseline = workspace["dependencies"]["rustls"]
        version = baseline["version"]
        assert re.fullmatch(r"\d+\.\d+\.\d+", version)
        assert baseline == {"version": version, "default-features": False}
        sites = rustls_sites(workspace)
        assert set(sites) == {(path, f"{kind}.rustls") for path, kind in INHERITED | PINNED}
        for path, kind in INHERITED:
            with self.subTest(path=path, kind=kind):
                value = sites[path, f"{kind}.rustls"]
                assert value.get("workspace") is True
        stale = stale_pins(sites, version)
        assert not stale, f"expected ={version}, found {stale}"
        for lock in (ROOT / "Cargo.lock", ROOT / "fuzz/Cargo.lock"):
            with self.subTest(path=lock):
                packages = tomllib.loads(lock.read_text())["package"]
                assert ("rustls", version) in {(p["name"], p["version"]) for p in packages}

    def test_missed_loadtest_update(self) -> None:
        workspace = manifest(ROOT)["workspace"]
        current = workspace["dependencies"]["rustls"]["version"]
        line, patch = current.rsplit(".", 1)
        updated = f"{line}.{int(patch) + 1}"
        sites = rustls_sites(workspace)
        sites["crates/server", "dependencies.rustls"]["version"] = f"={updated}"
        assert stale_pins(sites, updated) == {"crates/loadtest": f"={current}"}
