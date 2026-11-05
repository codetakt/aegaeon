#!/usr/bin/env python3
"""Bounded human-authorized audit fetch and durable acknowledgment.

No network retries or redirects. Use the same saved batch for uncertain replies.
The state directory and session JSON must be private to the invoking Unix user.
"""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import http.client
import itertools
import json
import os
import signal
import ssl
import stat
import uuid
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterator
    from types import FrameType
    from typing import NoReturn
from urllib.parse import urlsplit

MAX_BODY = 65536
MAX_BATCHES = 10000
TIMEOUT = 30
MAX_URL = 2048
URL_PARTS = 9
MAX_EVENTS = 100
SPACE = 32
DELETE = 127
HTTP_OK = 200


def refuse(message: str) -> NoReturn:
    raise ValueError(message)


def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result = {}
    for key, value in pairs:
        if key in result:
            refuse("duplicate JSON field")
        result[key] = value
    return result


DECODER = json.JSONDecoder(object_pairs_hook=unique)


def encode(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def identifier(value: str) -> str:
    parsed = uuid.UUID(value)
    if str(parsed) != value or parsed.int == 0:
        refuse("noncanonical UUID")
    return value


def source(base: str) -> tuple[str, str]:
    if not isinstance(base, str) or len(base) > MAX_URL or any(ord(c) <= SPACE for c in base):
        refuse("invalid source URL")
    url = urlsplit(base)
    parts = url.path.split("/")
    if (
        url.scheme != "https"
        or not url.hostname
        or url.username
        or url.password
        or url.query
        or url.fragment
        or len(parts) != URL_PARTS
        or parts[:4] != ["", "api", "v1", "teams"]
        or parts[5] != "environments"
        or parts[7] != "organization-domains"
    ):
        refuse("exact HTTPS Team/Environment/domain base required")
    for index in (4, 6, 8):
        identifier(parts[index])
    # Explicit port validation; no credentials, fragments, query or redirects.
    _ = url.port
    return parts[6], parts[8]


def skip_space(text: str, offset: int) -> int:
    while text[offset].isspace():
        offset += 1
    return offset


def fields(text: str) -> dict[str, str]:
    """Extract exact member-value slices without reserializing audit numbers."""
    i = skip_space(text, 0)
    if text[i] != "{":
        refuse("object required")
    i += 1
    result = {}
    while True:
        i = skip_space(text, i)
        if text[i] == "}":
            return result
        key, i = DECODER.raw_decode(text, i)
        i = skip_space(text, i)
        if not isinstance(key, str) or text[i] != ":" or key in result:
            refuse("invalid member")
        i += 1
        i = skip_space(text, i)
        start = i
        _, i = DECODER.raw_decode(text, i)
        result[key] = text[start:i]
        i = skip_space(text, i)
        if text[i] == "}":
            return result
        if text[i] != ",":
            refuse("invalid separator")
        i += 1


def validate_batch(payload: bytes, etag: str, base: str) -> list[tuple[str, str, bytes]]:
    environment, domain = source(base)
    if len(payload) > MAX_BODY:
        refuse("batch byte limit")
    text = payload.decode("utf-8")
    batch = DECODER.decode(text)
    if (
        set(batch) != {"version", "environmentId", "domainId", "deliveries"}
        or type(batch["version"]) is not int
        or batch["version"] != 1
        or batch["environmentId"] != environment
        or batch["domainId"] != domain
        or not isinstance(batch["deliveries"], list)
        or len(batch["deliveries"]) > MAX_EVENTS
    ):
        refuse("batch scope/version/limit")
    # Each digest covers the exact UTF-8 JSON event bytes in the response. This
    # preserves strings, member ordering and number lexemes across runtimes.
    array = fields(text)["deliveries"]
    i = 1
    events = []
    previous = ""
    for item in batch["deliveries"]:
        while array[i].isspace() or array[i] == ",":
            i += 1
        start = i
        _, i = DECODER.raw_decode(array, i)
        raw = fields(array[start:i])["event"].encode("utf-8")
        event = item["event"]
        if (
            set(item) != {"event", "sha256"}
            or sha(raw) != item["sha256"]
            or event["environmentId"] != environment
            or event["domainId"] != domain
        ):
            refuse("event scope or digest")
        event_id = identifier(event["id"])
        if event_id <= previous:
            refuse("events must be distinct and ordered")
        previous = event_id
        events.append((event_id, item["sha256"], raw))
    # This server profile fixes this hash input: sorted object keys, compact JSON,
    # ASCII UUID/digest strings and integer version. No arbitrary JSON numbers.
    pairs = [{"id": eid, "sha256": digest} for eid, digest, _ in events]
    binding = {
        "events": pairs,
        "scope": {"domain_id": domain, "environment_id": environment},
        "version": 1,
    }
    if etag != '"audit-batch.' + sha(encode(binding)) + '"':
        refuse("batch precondition digest")
    return events


def private(fd: int, *, directory: bool = False) -> None:
    info = os.fstat(fd)
    if (
        info.st_uid != os.getuid()
        or info.st_mode & 0o077
        or not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
        or (not directory and info.st_nlink != 1)
    ):
        refuse("private owned regular file/directory required")


@contextlib.contextmanager
def directory(path: str | Path, parent: int | None = None) -> Iterator[int]:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
    try:
        private(fd, directory=True)
        yield fd
    finally:
        os.close(fd)


def read(
    name: str | Path, parent: int | None = None, maximum: int = MAX_BODY, *, durable: bool = False
) -> bytes:
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
    try:
        private(fd)
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read(maximum + 1)
        if len(data) > maximum:
            refuse("file exceeds finite limit")
        if durable:
            os.fsync(fd)
        return data
    finally:
        os.close(fd)


def save(name: str, data: bytes, parent: int) -> None:
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
    try:
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(fd)
    finally:
        os.close(fd)


def credentials(path: Path) -> dict[str, str]:
    session = DECODER.decode(read(path, maximum=4096).decode())
    if set(session) != {"cookie", "csrfToken", "origin"}:
        refuse("session fields")
    for value in session.values():
        if (
            not isinstance(value, str)
            or not value
            or any(ord(c) < SPACE or ord(c) == DELETE for c in value)
        ):
            refuse("session header")
    origin = urlsplit(session["origin"])
    if (
        origin.scheme != "https"
        or not origin.hostname
        or origin.username
        or origin.password
        or origin.path
        or origin.query
        or origin.fragment
    ):
        refuse("HTTPS management origin required")
    return session


def save_receipt(body: bytes, saved: int) -> None:
    # Only the incomplete temporary receipt is replaceable on retry. The stable
    # receipt, batch, event bytes and request key are never overwritten.
    fd = os.open(".receipt.pending", os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600, dir_fd=saved)
    try:
        private(fd)
        os.ftruncate(fd, 0)
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(body)
            stream.flush()
            os.fsync(fd)
    finally:
        os.close(fd)
    os.rename(".receipt.pending", "receipt.json", src_dir_fd=saved, dst_dir_fd=saved)
    os.fsync(saved)


def exchange(
    base: str,
    session: dict[str, str],
    method: str,
    suffix: str,
    request: tuple[bytes, str, str] | None = None,
) -> tuple[bytes, str]:
    source(base)
    url = urlsplit(base)
    connection = http.client.HTTPSConnection(
        url.hostname, url.port, timeout=TIMEOUT, context=ssl.create_default_context()
    )
    headers = {"Cookie": session["cookie"], "Accept": "application/json"}
    payload = None
    if request is not None:
        payload, etag, key = request
        headers.update(
            {
                "Content-Type": "application/json",
                "Origin": session["origin"],
                "X-CSRF-Token": session["csrfToken"],
                "Idempotency-Key": key,
                "If-Match": etag,
            }
        )
    try:
        connection.request(method, url.path + "/audit-events/" + suffix, payload, headers)
        response = connection.getresponse()
        body = response.read(MAX_BODY + 1)
        tags = response.headers.get_all("ETag", [])
        if (
            response.status != HTTP_OK
            or len(body) > MAX_BODY
            or len(tags) != 1
            or response.headers.get_content_type() != "application/json"
        ):
            refuse("server refused or returned an invalid bounded response")
        return body, tags[0]
    finally:
        connection.close()


def retain(root: Path, base: str, payload: bytes, etag: str) -> str | None:
    events = validate_batch(payload, etag, base)
    if not events:
        return None
    with directory(root) as state:
        fcntl.flock(state, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with os.scandir(state) as entries:
            count = sum(1 for _ in itertools.islice(entries, MAX_BATCHES + 1))
        if count >= MAX_BATCHES + 1:
            refuse("local batch capacity; retained history is never deleted automatically")
        try:
            os.mkdir("events", 0o700, dir_fd=state)
            os.fsync(state)
        except FileExistsError:
            pass
        batch = str(uuid.uuid4())
        os.mkdir(batch, 0o700, dir_fd=state)
        os.fsync(state)
        with directory(batch, state) as output, directory("events", state) as index:
            for eid, digest, raw in events:
                try:
                    old = read(eid, index, durable=True)
                except FileNotFoundError:
                    save(eid, raw, index)
                else:
                    if sha(old) != digest:
                        refuse("same event ID has different retained content")
            os.fsync(index)
            save("batch.json", payload, output)
            manifest = {
                "version": 1,
                "base": base,
                "etag": etag,
                "key": str(uuid.uuid4()),
                "payloadSha256": sha(payload),
                "events": len(events),
                "request": {
                    "events": [{"id": eid, "sha256": digest} for eid, digest, _ in events],
                    "reason": "durable receiver custody",
                },
            }
            save("manifest.json", encode(manifest), output)
            os.fsync(output)
        os.fsync(state)
    return batch


def acknowledge(root: Path, batch: str, session: dict[str, str]) -> None:
    identifier(batch)
    with directory(root) as state:
        fcntl.flock(state, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with directory(batch, state) as saved, directory("events", state) as index:
            manifest = DECODER.decode(read("manifest.json", saved, durable=True).decode())
            payload = read("batch.json", saved, durable=True)
            events = validate_batch(payload, manifest["etag"], manifest["base"])
            pairs = [{"id": eid, "sha256": digest} for eid, digest, _ in events]
            if (
                manifest["version"] != 1
                or sha(payload) != manifest["payloadSha256"]
                or not events
                or manifest["events"] != len(events)
                or manifest["request"] != {"events": pairs, "reason": "durable receiver custody"}
            ):
                refuse("saved batch correspondence")
            identifier(manifest["key"])
            for eid, digest, _ in events:
                if sha(read(eid, index, durable=True)) != digest:
                    refuse("retained event correspondence")
            # Restore durable directory entries even after interrupted fetch.
            os.fsync(index)
            os.fsync(saved)
            os.fsync(state)
            body, tag = exchange(
                manifest["base"],
                session,
                "POST",
                "acknowledgments",
                (encode(manifest["request"]), manifest["etag"], manifest["key"]),
            )
            receipt = DECODER.decode(body.decode())
            if (
                tag != manifest["etag"]
                or receipt["version"] != 1
                or receipt["events"] != pairs
                or receipt["batchSha256"] != tag[13:-1]
                or receipt["reason"] != manifest["request"]["reason"]
            ):
                refuse("receipt correspondence; retain batch and retry original key")
            identifier(receipt["actorId"])
            if not isinstance(receipt["requestId"], str) or not receipt["requestId"]:
                refuse("receipt request identity")
            try:
                previous = read("receipt.json", saved)
            except FileNotFoundError:
                save_receipt(body, saved)
            else:
                if DECODER.decode(previous.decode()) != receipt:
                    refuse("receipt replay differs")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("fetch", "ack"))
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--session-file", type=Path, required=True)
    parser.add_argument("--base")
    parser.add_argument("--batch")
    args = parser.parse_args()

    def deadline(_signum: int, _frame: FrameType | None) -> None:
        message = "finite consumer deadline; retain original batch/key"
        raise TimeoutError(message)

    signal.signal(signal.SIGALRM, deadline)
    signal.setitimer(signal.ITIMER_REAL, TIMEOUT)
    try:
        session = credentials(args.session_file)
        if args.operation == "fetch":
            if not args.base or args.batch:
                parser.error("fetch requires --base and no --batch")
            payload, tag = exchange(args.base, session, "GET", "pending")
            batch = retain(args.state, args.base, payload, tag)
            print(batch or "No pending events")
        else:
            if not args.batch or args.base:
                parser.error("ack requires --batch and no --base")
            acknowledge(args.state, args.batch, session)
            print("Acknowledgment retained")
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)


if __name__ == "__main__":
    main()
