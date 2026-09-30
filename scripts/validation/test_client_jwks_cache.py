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


def libtest_selection(binary: str, test_filter: str) -> list[str]:
    """Use the same selection for the nonempty check and fixture execution."""
    return [
        binary,
        test_filter,
        "--include-ignored",
        "--skip",
        # This module requires the separate fingerprint runner's backend context.
        "client_registry::jwks_runtime_state::redis_kid::",
    ]


def inside_namespace(
    binary: str,
    test_filter: str,
    parent_namespace: str,
    tools: list[str],
    drop_identity: list[int] | None,
) -> int:
    ip, redis_server, redis_cli = tools
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
    if drop_identity is not None:
        uid, gid = drop_identity
        if uid <= 0 or gid <= 0 or os.geteuid() != 0:
            raise RuntimeError("invalid unprivileged fixture identity")
        os.setgroups([])
        os.setgid(gid)
        os.setuid(uid)
        if (os.getuid(), os.geteuid(), os.getgid(), os.getegid()) != (uid, uid, gid, gid):
            raise RuntimeError("fixture privilege drop failed")
        if os.getgroups():
            raise RuntimeError("fixture retained supplementary groups")
        if os.readlink("/proc/self/ns/net") != namespace:
            raise RuntimeError("fixture left the isolated network namespace")
        print(f"namespace ready; fixtures run as uid={uid} gid={gid}", flush=True)
    with tempfile.TemporaryDirectory(prefix="aegaeon-jwks-") as directory:
        socket = str(Path(directory) / "redis.sock")
        env = dict(
            os.environ,
            JWKS_TEST_NETNS=namespace,
            JWKS_TEST_DIR=directory,
            JWKS_LEDGER_TEST_SERVER=redis_server,
            JWKS_LEDGER_TEST_CLI=redis_cli,
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
                    [*libtest_selection(binary, test_filter), "--test-threads=1"],
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
        "--sudo-netns",
        action="store_true",
        help="create the network namespace with sudo, then run fixtures as the caller",
    )
    parser.add_argument(
        "--inside", nargs=2, metavar=("BINARY", "PARENT_NETNS"), help=argparse.SUPPRESS
    )
    parser.add_argument("--inside-tools", nargs=3, help=argparse.SUPPRESS)
    parser.add_argument("--drop-identity", nargs=2, type=int, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.inside:
        if args.inside_tools is None:
            parser.error("namespace child requires resolved tool paths")
        return inside_namespace(
            args.inside[0], args.filter, args.inside[1], args.inside_tools, args.drop_identity
        )
    if sys.platform != "linux":
        parser.error("the contained HTTPS fixtures require Linux")
    if args.sudo_netns and os.getuid() == 0:
        parser.error("--sudo-netns must be started by the unprivileged fixture user")
    tool_paths: dict[str, str] = {}
    required_tools = ["cargo", "unshare", "ip", "redis-server", "redis-cli"]
    if args.sudo_netns:
        required_tools.append("sudo")
    for tool in required_tools:
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
    listing = subprocess.check_output(
        [*libtest_selection(executable, args.filter), "--list"], text=True
    )
    if not any(line.endswith(": test") for line in listing.splitlines()):
        raise RuntimeError("test filter selected no tests")
    namespace_command = [tool_paths["unshare"], "--user", "--map-root-user", "--net"]
    identity_args: list[str] = []
    if args.sudo_netns:
        namespace_command = [tool_paths["sudo"], "--", tool_paths["unshare"], "--net"]
        identity_args = ["--drop-identity", str(os.getuid()), str(os.getgid())]
    return subprocess.run(
        [
            *namespace_command,
            sys.executable,
            str(Path(__file__).resolve()),
            "--filter",
            args.filter,
            "--inside",
            executable,
            os.readlink("/proc/self/ns/net"),
            "--inside-tools",
            tool_paths["ip"],
            tool_paths["redis-server"],
            tool_paths["redis-cli"],
            *identity_args,
        ],
        cwd=root,
        check=False,
    ).returncode


if __name__ == "__main__":
    sys.exit(main())
