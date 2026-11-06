"""Start the fixed Organizations server from exact systemd credential copies."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import stat
import sys
from pathlib import Path

SERVER = Path("@selectedWorkerServer@")
MAX_INPUT = 1024 * 1024
MAX_PORT = 65535
MAX_CERTIFICATES = 9
PRIVATE_READ = 0o400
ROOT_GROUP_READ = 0o440
SHARED_STORES = json.loads(Path(__file__).with_name("organization_runtime_stores.json").read_text())
KEYS = {
    *SHARED_STORES,
    "AEGAEON_DATABASE_URL",
    "AEGAEON_RUNTIME_ISSUER_HOST",
    "AEGAEON_ORGANIZATION_RUNTIME_CONFIG",
    "AEGAEON_KEY_ENCRYPTION_KEY",
}


def require(condition: object) -> None:
    if not condition:
        message = "selected worker credential input refused"
        raise ValueError(message)


def read(path: Path) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as handle:
        info = os.fstat(handle.fileno())
        require(
            stat.S_ISREG(info.st_mode)
            and info.st_uid in (0, os.geteuid())
            # systemd can expose root:root 0440 plus an ACL for this unit's
            # user. Accept that exact read-only form, never arbitrary group
            # access, writes or world access. Protected directory custody is
            # checked by inputs before opening any credential.
            and (
                stat.S_IMODE(info.st_mode) == PRIVATE_READ
                or (
                    stat.S_IMODE(info.st_mode) == ROOT_GROUP_READ
                    and info.st_uid == info.st_gid == 0
                )
            )
            and info.st_nlink == 1
        )
        data = handle.read(MAX_INPUT + 1)
        require(0 < len(data) <= MAX_INPUT)
        return data


def inputs(directory: Path) -> tuple[list[str], dict[str, str]]:
    require(os.geteuid() != 0 and directory.is_absolute())
    require(
        str(directory.parent) == "/run/credentials"
        and re.fullmatch(r"aegaeon-organization-runtime-[a-z0-9-]{1,64}\.service", directory.name)
    )
    for parent in [directory, *directory.parents]:
        info = parent.lstat()
        require(
            stat.S_ISDIR(info.st_mode)
            and not info.st_mode & 0o022
            and info.st_uid in (0, os.geteuid())
        )
    launch = json.loads(read(directory / "launch.json"))
    raw = read(directory / "runtime.json")
    runtime = json.loads(raw)
    require(
        set(launch)
        == {
            "version",
            "unit",
            "environmentId",
            "host",
            "port",
            "runtimeSha256",
            "environment",
            "certificates",
        }
        and launch["version"] == 1
        and launch["unit"] == directory.name
    )
    require(hashlib.sha256(raw).hexdigest() == launch["runtimeSha256"])
    environment = launch["environment"]
    require(
        type(environment) is dict
        and set(environment) == KEYS
        and all(type(v) is str and v and "\0" not in v for v in environment.values())
    )
    require(environment["AEGAEON_ORGANIZATION_RUNTIME_CONFIG"] == str(directory / "runtime.json"))
    require(
        environment["AEGAEON_DATABASE_URL"] == runtime["primary"]["url"]
        and all(environment[name] == runtime["token"]["url"] for name in SHARED_STORES)
    )
    children = [row for row in runtime["environments"] if row["id"] == launch["environmentId"]]
    require(len(children) == 1)
    # The retained launcher input uses the native parser's selector. The
    # server checks it against this exact runtime document before connections;
    # repeating URL normalization in Python would disagree on IDNA and ports.
    certificates = launch["certificates"]
    require(type(certificates) is list and 1 <= len(certificates) <= MAX_CERTIFICATES)
    names = [row["name"] for row in certificates]
    require(names == ["root-cert", *[f"delivery-root-{i:02d}" for i in range(len(names) - 1)]])
    require(
        all(
            runtime[name]["root_cert"] == str(directory / "root-cert")
            for name in ["control", "primary", "token"]
        )
    )
    require(
        [row["root_cert"] for row in runtime["delivery_trust"]]
        == [str(directory / name) for name in names[1:]]
    )
    for row in certificates:
        require(
            set(row) == {"name", "sha256"}
            and hashlib.sha256(read(directory / row["name"])).hexdigest() == row["sha256"]
        )
    host, port = launch["host"], launch["port"]
    require(
        str(ipaddress.ip_address(host)) == host
        and "%" not in host
        and type(port) is int
        and 1 <= port <= MAX_PORT
    )
    require(SERVER.is_file() and str(SERVER).startswith("/nix/store/"))
    return [str(SERVER), "--host", host, "--port", str(port)], {
        "PATH": os.defpath,
        "LANG": "C.UTF-8",
        # Ordinary Redis clients use rustls-native-certs. Bind their CA input
        # to the same authenticated credential copy as the independent observer.
        "SSL_CERT_FILE": str(directory / "root-cert"),
        **environment,
    }


def main() -> None:
    require(len(sys.argv) == 1)
    argv, environment = inputs(Path(os.environ["CREDENTIALS_DIRECTORY"]))
    os.execve(SERVER, argv, environment)  # noqa: S606 — fixed Nix entry, bounded explicit argv/env


if __name__ == "__main__":
    try:
        main()
    except Exception:  # noqa: BLE001 — no secret, endpoint or parser detail in worker logs
        print("selected Organizations worker startup refused", file=sys.stderr)
        sys.exit(1)
