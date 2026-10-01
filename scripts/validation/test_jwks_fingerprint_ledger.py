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


def inside_namespace(
    binary: str,
    filters: list[str],
    parent_namespace: str,
    ip: str,
    server: str,
    engine: str,
    run_as: list[int] | None,
) -> int:
    namespace = os.readlink("/proc/self/ns/net")
    if namespace == parent_namespace:
        raise RuntimeError("network namespace was not isolated")
    subprocess.run([ip, "link", "set", "lo", "up"], check=True)
    links = json.loads(subprocess.check_output([ip, "-j", "link", "show"]))
    if any(link["ifname"] != "lo" and "UP" in link["flags"] for link in links):
        raise RuntimeError("fixture namespace has an active non-loopback interface")
    for family in ("-4", "-6"):
        routes = json.loads(
            subprocess.check_output([ip, family, "-j", "route", "show", "table", "all"])
        )
        if any(route.get("dev") != "lo" for route in routes):
            raise RuntimeError("fixture namespace contains a non-loopback route")
    if run_as is not None:
        uid, gid = run_as
        if os.geteuid() != 0 or uid <= 0 or gid <= 0:
            raise RuntimeError("privileged namespace must drop to the invoking non-root user")
        os.setgroups([])
        os.setgid(gid)
        os.setuid(uid)
        if (os.getuid(), os.geteuid(), os.getgid(), os.getegid()) != (uid, uid, gid, gid):
            raise RuntimeError("fixture privilege drop failed")
    print(f"Fixture namespace: {namespace}; uid={os.geteuid()}; gid={os.getegid()}", flush=True)
    with tempfile.TemporaryDirectory(prefix="aegaeon-ledger-", dir="/tmp") as directory:
        env = dict(
            os.environ,
            JWKS_LEDGER_TEST_NETNS=namespace,
            JWKS_LEDGER_TEST_DIR=directory,
            JWKS_LEDGER_TEST_SERVER=server,
            JWKS_LEDGER_TEST_ENGINE=engine,
        )
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
        "--sudo-netns",
        action="store_true",
        help="create the network namespace with sudo, then run fixtures as the invoking user",
    )
    parser.add_argument(
        "--inside", nargs=2, metavar=("BINARY", "PARENT_NETNS"), help=argparse.SUPPRESS
    )
    parser.add_argument("--ip-tool", help=argparse.SUPPRESS)
    parser.add_argument("--engine", help=argparse.SUPPRESS)
    parser.add_argument("--run-as", nargs=2, type=int, help=argparse.SUPPRESS)
    args = parser.parse_args()
    filters = args.filter or ["client_registry::jwks_runtime_state::redis_kid::"]
    if args.inside:
        if args.ip_tool is None or args.engine is None:
            parser.error("internal namespace invocation lacks resolved tools or backend profile")
        return inside_namespace(
            args.inside[0],
            filters,
            args.inside[1],
            args.ip_tool,
            args.server,
            args.engine,
            args.run_as,
        )
    if sys.platform != "linux":
        parser.error("the contained backend fixtures require Linux")
    if args.sudo_netns and os.geteuid() == 0:
        parser.error("--sudo-netns must be invoked by the non-root user who will run the tests")
    tool_paths: dict[str, str] = {}
    required_tools = ["cargo", "unshare", "ip", args.server]
    if args.sudo_netns:
        required_tools.append("sudo")
    for tool in required_tools:
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
            tool_paths["cargo"],
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
    if args.sudo_netns:
        command = [tool_paths["sudo"], "-n", "--", tool_paths["unshare"], "--net"]
    else:
        command = [tool_paths["unshare"], "--user", "--map-root-user", "--net"]
    command += [
        sys.executable,
        str(Path(__file__).resolve()),
        "--inside",
        executable,
        os.readlink("/proc/self/ns/net"),
        "--ip-tool",
        tool_paths["ip"],
        "--server",
        server,
        "--engine",
        engine,
    ]
    if args.sudo_netns:
        command += ["--run-as", str(os.getuid()), str(os.getgid())]
    for test_filter in filters:
        command += ["--filter", test_filter]
    return subprocess.run(command, cwd=root, check=False).returncode


if __name__ == "__main__":
    sys.exit(main())
