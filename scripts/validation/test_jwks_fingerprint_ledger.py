#!/usr/bin/env python3
"""Run JWKS fingerprint-ledger regressions against disposable Unix backends.

Usage: nix develop -c python3 scripts/validation/test_jwks_fingerprint_ledger.py
Linux user/network namespaces, unshare and ip are required. The default backend
is redis-server; use --server /path/to/valkey-server to test Valkey instead.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def inside_namespace(binary: str, filters: list[str], parent_namespace: str) -> int:
    namespace = os.readlink("/proc/self/ns/net")
    if namespace == parent_namespace:
        raise RuntimeError("network namespace was not isolated")
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
    links = json.loads(subprocess.check_output(["ip", "-j", "link", "show"]))
    if any(link["ifname"] != "lo" and "UP" in link["flags"] for link in links):
        raise RuntimeError("fixture namespace has an active non-loopback interface")
    for family in ("-4", "-6"):
        routes = json.loads(
            subprocess.check_output(["ip", family, "-j", "route", "show", "table", "all"])
        )
        if any(route.get("dev") != "lo" for route in routes):
            raise RuntimeError("fixture namespace contains a non-loopback route")
    with tempfile.TemporaryDirectory(prefix="aegaeon-ledger-", dir="/tmp") as directory:
        env = dict(os.environ, JWKS_LEDGER_TEST_NETNS=namespace, JWKS_LEDGER_TEST_DIR=directory)
        command = [binary, *filters, "--include-ignored", "--test-threads=1"]
        if env["JWKS_LEDGER_TEST_ENGINE"] == "redis-legacy":
            # Older Redis does not have the inspected base-time addition guards.
            print("Omitting newer-engine expiry arithmetic regression on legacy Redis.", flush=True)
            command += ["--skip", "integer_wire_and_remaining_time_overflow"]
        return subprocess.run(command, env=env, check=False).returncode


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--filter", action="append")
    parser.add_argument("--server", default="redis-server")
    parser.add_argument(
        "--inside", nargs=2, metavar=("BINARY", "PARENT_NETNS"), help=argparse.SUPPRESS
    )
    args = parser.parse_args()
    filters = args.filter or ["client_registry::jwks_runtime_state::redis_kid::"]
    if args.inside:
        return inside_namespace(args.inside[0], filters, args.inside[1])
    if sys.platform != "linux":
        parser.error("the contained backend fixtures require Linux")
    tool_paths: dict[str, str] = {}
    for tool in ("cargo", "unshare", "ip", args.server):
        resolved = shutil.which(tool)
        if resolved is None:
            parser.error(f"required executable not found: {tool}")
        tool_paths[tool] = resolved
    server = tool_paths[args.server]
    version = subprocess.check_output([server, "--version"], text=True).strip()
    parsed = re.search(r"v=(\d+)\.(\d+)", version)
    if parsed is None:
        parser.error(f"unrecognized backend version: {version}")
    release = tuple(map(int, parsed.groups()))
    if "valkey" in version.lower() and release >= (9, 1):
        engine = "valkey"
    else:
        engine = "redis-legacy" if release < (7, 0) else "redis"
    print(f"Backend: {version}; test profile: {engine}", flush=True)
    root = Path(__file__).resolve().parents[2]
    build = subprocess.run(
        [
            "cargo",
            "test",
            "--locked",
            "-p",
            "aegaeon-server",
            "--lib",
            "--no-run",
            "--message-format=json",
        ],
        cwd=root,
        stdout=subprocess.PIPE,
        text=True,
        check=False,
    )
    executable = None
    for line in build.stdout.splitlines():
        message = json.loads(line)
        if message.get("reason") == "compiler-message":
            print(message["message"].get("rendered", ""), file=sys.stderr, end="")
        if (
            message.get("reason") == "compiler-artifact"
            and message.get("target", {}).get("name") == "aegaeon_server"
            and message.get("executable")
        ):
            executable = message["executable"]
    if build.returncode:
        return build.returncode
    if executable is None:
        raise RuntimeError("Cargo did not report the server test executable")
    listing = subprocess.check_output([executable, *filters, "--list"], text=True)
    if not any(line.endswith(": test") for line in listing.splitlines()):
        raise RuntimeError("test filters selected no tests")
    env = dict(os.environ, JWKS_LEDGER_TEST_SERVER=server, JWKS_LEDGER_TEST_ENGINE=engine)
    command = [
        "unshare",
        "--user",
        "--map-root-user",
        "--net",
        sys.executable,
        str(Path(__file__).resolve()),
        "--inside",
        executable,
        os.readlink("/proc/self/ns/net"),
    ]
    for test_filter in filters:
        command += ["--filter", test_filter]
    return subprocess.run(command, cwd=root, env=env, check=False).returncode


if __name__ == "__main__":
    sys.exit(main())
