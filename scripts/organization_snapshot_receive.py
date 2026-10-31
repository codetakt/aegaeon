#!/usr/bin/env python3
"""Receive and durably retain one complete Organizations snapshot over verified TLS."""

from __future__ import annotations

import argparse
import fcntl
import http.client
import itertools
import json
import os
import signal
import ssl
import sys
import time
import uuid
from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO
from urllib.parse import urlsplit

from organization_audit_consumer import credentials, directory, private, refuse, source
from organization_snapshot import verify

if TYPE_CHECKING:
    from types import FrameType

LIFETIME = 3600
PROGRESS = 30
HTTP_OK = 200
MAX_FILES = 64


class Transfer:
    """Exact-byte tee with a whole-operation deadline and per-record progress."""

    def __init__(
        self, response: http.client.HTTPResponse, output: BinaryIO, deadline: float
    ) -> None:
        self.response = response
        self.output = output
        self.deadline = deadline

    def arm(self) -> None:
        remaining = min(PROGRESS, self.deadline - time.monotonic())
        if remaining <= 0:
            refuse("snapshot transfer deadline")
        signal.setitimer(signal.ITIMER_REAL, remaining)

    def readline(self, limit: int) -> bytes:
        self.arm()
        value = self.response.readline(limit)
        self.output.write(value)
        return value

    def read(self, limit: int) -> bytes:
        self.arm()
        value = self.response.read(limit)
        self.output.write(value)
        return value


def download(
    connection: http.client.HTTPSConnection,
    base: str,
    session: dict[str, str],
    fd: int,
    deadline: float,
) -> dict[str, object]:
    environment, domain = source(base)
    connection.request(
        "GET",
        urlsplit(base).path + "/snapshot",
        headers={"Cookie": session["cookie"], "Accept": "application/x-ndjson"},
    )
    response = connection.getresponse()
    if (
        response.status != HTTP_OK
        or len(response.headers.get_all("Content-Type", [])) != 1
        or response.headers.get_content_type() != "application/x-ndjson"
        or response.headers.get("Content-Encoding", "identity") != "identity"
    ):
        refuse("snapshot response refused; partial retained")
    with os.fdopen(fd, "wb", closefd=False) as output:
        transfer = Transfer(response, output, deadline)
        result = verify(transfer)
        if result["scope"] != {"environment_id": environment, "domain_id": domain}:
            refuse("snapshot scope differs from requested source")
        transfer.arm()
        output.flush()
        os.fsync(fd)
    return result


def receive(root: Path, base: str, session: dict[str, str]) -> dict[str, object]:
    source(base)
    deadline = time.monotonic() + LIFETIME
    url = urlsplit(base)
    connection = http.client.HTTPSConnection(
        url.hostname, url.port, timeout=PROGRESS, context=ssl.create_default_context()
    )
    try:
        with directory(root) as state:
            fcntl.flock(state, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with os.scandir(state) as entries:
                if sum(1 for _ in itertools.islice(entries, MAX_FILES)) >= MAX_FILES:
                    refuse("snapshot directory capacity; inspect retained artifacts")
            partial = f".partial-{uuid.uuid4()}.jsonl"
            fd = os.open(
                partial, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=state
            )
            try:
                private(fd)
                os.fsync(state)
                result = download(
                    connection,
                    base,
                    session,
                    fd,
                    deadline,
                )
                name = f"{result['snapshotId']}.jsonl"
                # Atomic no-overwrite publication. A crash between link/unlink
                # retains both names; strict verification refuses that ambiguous
                # custody state until an operator reconciles the retained links.
                os.link(partial, name, src_dir_fd=state, dst_dir_fd=state, follow_symlinks=False)
                os.fsync(state)
                os.unlink(partial, dir_fd=state)
                os.fsync(state)
                return result | {"file": name, "source": base, "durablyRetained": True}
            finally:
                os.close(fd)
    finally:
        connection.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--session-file", type=Path, required=True)
    parser.add_argument("--base", required=True)
    args = parser.parse_args()

    def expired(_signum: int, _frame: FrameType | None) -> None:
        message = "snapshot deadline; retain partial artifact"
        raise TimeoutError(message)

    signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, min(LIFETIME, PROGRESS))
    try:
        print(
            json.dumps(
                receive(args.state, args.base, credentials(args.session_file)),
                ensure_ascii=False,
                sort_keys=True,
            )
        )
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)


if __name__ == "__main__":
    try:
        main()
    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
        IndexError,
        RecursionError,
        http.client.HTTPException,
    ) as error:
        print(
            "snapshot receive refused; retained partial files require inspection", file=sys.stderr
        )
        raise SystemExit(1) from error
