"""Bind preview and consumer CLI closures to independent builds before executing them."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path

from preview_manifest import closure

OUTPUTS = {
    "server": ("./.flakehub#packages.x86_64-linux.server",),
    "fh": ("--inputs-from", ".", "nixpkgs#fh"),
}
UPSTREAM_KEY = "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY="


def output_path(path: str) -> str:
    if re.fullmatch(r"/nix/store/[0-9a-df-np-sv-z]{32}-[a-zA-Z0-9+._?=-]+", path) is None:
        raise ValueError("Expected one exact Nix store output")
    return path


def hosted_store() -> tuple[tuple[str, ...], str, dict[str, tuple[str, ...]]]:
    revision = os.environ["GITHUB_SHA"]
    if (
        re.fullmatch(r"[0-9a-f]{40}", revision) is None
        or subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip() != revision
    ):
        raise ValueError("Preview reference requires the checked-out event revision")
    # The hosted kernel restricts unprivileged namespaces. Keep the sandbox
    # and restrict the installed manager to the immutable upstream checkout.
    sudo = ("sudo", "-n", "--")
    store = subprocess.check_output(
        [*sudo, "/usr/bin/mktemp", "-d", "/var/lib/aegaeon-preview-store.XXXXXXXX"], text=True
    ).strip()
    if re.fullmatch(r"/var/lib/aegaeon-preview-store\.[a-zA-Z0-9]{8}", store) is None:
        raise ValueError("Unexpected preview reference store")
    subprocess.run([*sudo, "/usr/bin/chmod", "0711", store], check=True)
    flake = f"github:codetakt/aegaeon/{revision}"
    outputs = {
        "server": (f"{flake}?dir=.flakehub#packages.x86_64-linux.server",),
        "fh": ("--inputs-from", flake, "nixpkgs#fh"),
    }
    return ("sudo", "-n", "-H", "--", "/nix/var/nix/profiles/default/bin/nix"), store, outputs


def build_reference(destination: Path, *, hosted: bool = False) -> None:
    if hosted:
        executable, store, outputs = hosted_store()
    else:
        executable = ("nix",)
        store = tempfile.mkdtemp(prefix="preview-reference-", dir=os.environ["RUNNER_TEMP"])
        outputs = OUTPUTS
    nix = (
        *executable,
        "--store",
        f"local?root={store}",
        "--option",
        "sandbox",
        "true",
        "--option",
        "sandbox-fallback",
        "false",
        "--option",
        "accept-flake-config",
        "false",
        "--option",
        "builders",
        "",
        "--option",
        "substituters",
        "https://cache.nixos.org",
        "--option",
        "extra-substituters",
        "",
        "--option",
        "trusted-substituters",
        "",
        "--option",
        "trusted-public-keys",
        UPSTREAM_KEY,
        "--option",
        "extra-trusted-public-keys",
        "",
        "--option",
        "require-sigs",
        "true",
    )
    if subprocess.check_output([*nix, "path-info", "--all"]).strip():
        raise ValueError("Expected an empty preview reference store")
    result = {}
    for name, installable in outputs.items():
        path = output_path(
            subprocess.check_output(
                [
                    *nix,
                    "build",
                    "--no-update-lock-file",
                    "--no-link",
                    "--print-out-paths",
                    *installable,
                ],
                text=True,
            ).strip()
        )
        hashes = closure(path, nix)
        if path not in hashes:
            raise ValueError("Preview reference closure is missing its root")
        result[name] = {"path": path, "closure": hashes}
    with destination.open("x") as out:
        json.dump(result, out, sort_keys=True)


def verify_output(reference: Path, name: str, path: str) -> None:
    record = json.loads(reference.read_text())[name]
    if output_path(path) != record["path"]:
        raise ValueError("Preview build differs from the independent output path")
    hashes = closure(path)
    if path not in hashes or hashes != record["closure"]:
        raise ValueError("Preview build differs from the independent closure")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser("build")
    build.add_argument("--hosted", action="store_true")
    build.add_argument("reference", type=Path)
    verify = commands.add_parser("verify")
    verify.add_argument("reference", type=Path)
    verify.add_argument("name", choices=OUTPUTS)
    verify.add_argument("path")
    options = parser.parse_args()
    if options.command == "build":
        build_reference(options.reference, hosted=options.hosted)
    else:
        verify_output(options.reference, options.name, options.path)


if __name__ == "__main__":
    main()
