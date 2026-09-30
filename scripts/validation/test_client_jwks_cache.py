#!/usr/bin/env python3
"""Run client JWKS regressions in an isolated Linux network namespace.

Usage: nix develop -c python3 scripts/validation/test_client_jwks_cache.py
Requires unshare, ip, redis-server and redis-cli; no existing Redis is used.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def inside_namespace(binary: str, test_filter: str, parent_namespace: str) -> int:
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
    with tempfile.TemporaryDirectory(prefix="aegaeon-jwks-") as directory:
        socket = str(Path(directory) / "redis.sock")
        env = dict(
            os.environ,
            JWKS_TEST_NETNS=namespace,
            JWKS_TEST_DIR=directory,
            AEGAEON_TEST_REDIS_URL=f"redis+unix://{socket}",
        )
        with open(Path(directory) / "redis.log", "wb") as log:
            backend = subprocess.Popen(
                [
                    env["JWKS_LEDGER_TEST_SERVER"],
                    "--port",
                    "0",
                    "--unixsocket",
                    socket,
                    "--unixsocketperm",
                    "700",
                    "--save",
                    "",
                    "--appendonly",
                    "no",
                    "--dir",
                    directory,
                ],
                stdout=log,
                stderr=subprocess.STDOUT,
            )
            try:
                deadline = time.monotonic() + 10
                while not Path(socket).exists():
                    if backend.poll() is not None or time.monotonic() >= deadline:
                        raise RuntimeError("disposable Redis did not start")
                    time.sleep(0.01)
                subprocess.run(
                    [env["JWKS_LEDGER_TEST_CLI"], "-s", socket, "ping"],
                    check=True,
                    stdout=subprocess.DEVNULL,
                )
                return subprocess.run(
                    [binary, test_filter, "--include-ignored", "--test-threads=1"],
                    env=env,
                    check=False,
                ).returncode
            finally:
                backend.terminate()
                try:
                    backend.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    backend.kill()
                    backend.wait()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--filter", default="client_registry::jwks_")
    parser.add_argument(
        "--inside", nargs=2, metavar=("BINARY", "PARENT_NETNS"), help=argparse.SUPPRESS
    )
    args = parser.parse_args()
    if args.inside:
        return inside_namespace(args.inside[0], args.filter, args.inside[1])
    if sys.platform != "linux":
        parser.error("the contained HTTPS fixtures require Linux")
    tool_paths: dict[str, str] = {}
    for tool in ("cargo", "unshare", "ip", "redis-server", "redis-cli"):
        resolved = shutil.which(tool)
        if resolved is None:
            parser.error(f"required executable not found: {tool}")
        tool_paths[tool] = resolved
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
    listing = subprocess.check_output([executable, args.filter, "--list"], text=True)
    if not any(line.endswith(": test") for line in listing.splitlines()):
        raise RuntimeError("test filter selected no tests")
    env = dict(
        os.environ,
        JWKS_LEDGER_TEST_SERVER=tool_paths["redis-server"],
        JWKS_LEDGER_TEST_CLI=tool_paths["redis-cli"],
    )
    return subprocess.run(
        [
            "unshare",
            "--user",
            "--map-root-user",
            "--net",
            sys.executable,
            str(Path(__file__).resolve()),
            "--filter",
            args.filter,
            "--inside",
            executable,
            os.readlink("/proc/self/ns/net"),
        ],
        cwd=root,
        env=env,
        check=False,
    ).returncode


if __name__ == "__main__":
    sys.exit(main())
