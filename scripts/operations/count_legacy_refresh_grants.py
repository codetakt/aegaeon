#!/usr/bin/env python3
"""Read-only counts for a drained token-store namespace; never print token bytes."""

from __future__ import annotations

import argparse
import collections
import json
import os
import subprocess
import urllib.parse
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterator

NANOS_PER_SECOND = 1_000_000_000
MAX_SCAN_CURSOR = (1 << 64) - 1
MAX_SCAN_CURSOR_DIGITS = len(str(MAX_SCAN_CURSOR))
MAX_TIME_SECONDS = (1 << 63) - 1
MICROS_PER_SECOND = 1_000_000
SCOPE = "read-only drained namespace inventory; not an active-token or assurance decision"


def connection() -> tuple[list[str], dict[str, str]]:
    url = urllib.parse.urlsplit(os.environ["AEGAEON_TOKEN_STORE_REDIS_URL"])
    if url.scheme not in ("redis", "rediss") or not url.hostname:
        message = "AEGAEON_TOKEN_STORE_REDIS_URL must be redis:// or rediss://"
        raise ValueError(message)
    command = [
        "redis-cli",
        "--json",
        "--no-auth-warning",
        "-e",
        "-h",
        url.hostname,
        "-p",
        str(url.port or 6379),
        "-n",
        str(int(url.path.removeprefix("/") or "0")),
    ]
    if url.username:
        command += ["--user", urllib.parse.unquote(url.username)]
    if url.scheme == "rediss":
        command += ["--tls"]
    env = os.environ.copy()
    if url.password is not None:
        env["REDISCLI_AUTH"] = urllib.parse.unquote(url.password)
    return command, env


class RedisReader:
    def __init__(self) -> None:
        self.command, self.env = connection()

    def read(self, *words: str) -> object:
        # Fixed redis-cli executable and argument vector; no shell or token logging.
        result = subprocess.run(  # noqa: S603
            self.command + list(words), env=self.env, capture_output=True, check=False
        )
        message = "Redis read failed; no complete inventory was produced"
        # redis-cli may exit successfully after AUTH or SELECT fails, returning
        # valid JSON from a different connection context. Warnings also make
        # the inventory incomplete; never expose raw diagnostics or counts.
        if result.returncode or result.stderr:
            raise RuntimeError(message)
        try:
            return json.loads(result.stdout)
        except ValueError:
            raise RuntimeError(message) from None

    def keys(self, pattern: str) -> Iterator[str]:
        cursor, seen = "0", set()
        while True:
            reply = self.read("SCAN", cursor, "MATCH", pattern, "COUNT", "256")
            cursor, page = scan_reply(reply)
            for key in page:
                if key not in seen:
                    seen.add(key)
                    yield key
            if int(cursor) == 0:
                break

    def record(self, key: str) -> dict[str, object] | None:
        raw = self.read("GET", key)
        if not isinstance(raw, str):
            return None
        try:
            value = json.loads(raw)
        except ValueError:
            return None
        return value if isinstance(value, dict) else None

    def time(self) -> tuple[int, int]:
        reply = self.read("TIME")
        return time_reply(reply)


def time_reply(reply: object) -> tuple[int, int]:
    message = "Malformed TIME response; inventory incomplete"
    if not isinstance(reply, list) or len(reply) != 2:  # noqa: PLR2004
        raise RuntimeError(message)
    limits = (MAX_TIME_SECONDS, MICROS_PER_SECOND - 1)
    for part, maximum in zip(reply, limits, strict=True):
        if (
            not isinstance(part, str)
            or not part.isascii()
            or not part.isdecimal()
            or (part != "0" and part.startswith("0"))
            or len(part) > len(str(maximum))
            or int(part) > maximum
        ):
            raise RuntimeError(message)
    seconds, micros = map(int, reply)
    return seconds, seconds * NANOS_PER_SECOND + micros * 1000


def scan_reply(reply: object) -> tuple[str, list[str]]:
    message = "Malformed SCAN response; inventory incomplete"
    if not isinstance(reply, list) or len(reply) != 2:  # noqa: PLR2004
        raise RuntimeError(message)
    cursor, page = reply
    if (
        not isinstance(cursor, str)
        or not cursor.isascii()
        or not cursor.isdecimal()
        or len(cursor) > MAX_SCAN_CURSOR_DIGITS
        or int(cursor) > MAX_SCAN_CURSOR
        or not isinstance(page, list)
        or any(not isinstance(key, str) for key in page)
    ):
        raise RuntimeError(message)
    return cursor, page


def timestamp(value: object) -> int | None:
    if not isinstance(value, dict):
        return None
    seconds, nanos = value.get("secs_since_epoch"), value.get("nanos_since_epoch")
    if type(seconds) is not int or type(nanos) is not int:
        return None
    return (
        seconds * NANOS_PER_SECOND + nanos
        if seconds >= 0 and 0 <= nanos < NANOS_PER_SECOND
        else None
    )


def count_dependent_access(
    reader: RedisReader, key: str, prefix: str, now: int, counts: collections.Counter[str]
) -> None:
    counts["live_legacy_dependent_bearer_records"] += 1
    access_key = key.replace(f"{prefix}:bearer:", f"{prefix}:access:", 1)
    access = reader.record(access_key)
    if access is None:
        return
    counts["live_legacy_dependent_bearer_with_access_record"] += 1
    created, ttl = timestamp(access.get("created_at")), access.get("expires_in")
    if created is None or type(ttl) is not int or ttl < 0:
        counts["dependent_access_malformed_expiry"] += 1
    elif created + ttl * NANOS_PER_SECOND > now:
        counts["live_legacy_dependent_access_records"] += 1


def count_records(
    reader: RedisReader, prefix: str, kind: str, now: int, counts: collections.Counter[str]
) -> None:
    for key in reader.keys(f"{prefix}:{kind}:*"):
        counts[f"{kind}_records"] += 1
        value = reader.record(key)
        expiry = None if value is None else timestamp(value.get("expires_at"))
        if value is None or expiry is None:
            counts[f"{kind}_missing_or_malformed"] += 1
            continue
        if value.get("refresh_grant") is not None:
            continue
        counts[f"{kind}_without_reference"] += 1
        if expiry <= now:
            continue
        counts[f"{kind}_live_without_reference"] += 1
        if kind == "bearer" and value.get("refresh_parent") is not None:
            count_dependent_access(reader, key, prefix, now, counts)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--prefix", required=True, help="Exact configured token-store v3 Redis prefix"
    )
    args = parser.parse_args()
    if any(char in args.prefix for char in "*?[]\\\r\n") or not args.prefix:
        parser.error("prefix must be exact and contain no Redis glob characters")
    reader = RedisReader()
    seconds, now = reader.time()
    counts: collections.Counter[str] = collections.Counter()
    for kind in ("refresh", "bearer"):
        count_records(reader, args.prefix, kind, now, counts)
    print(
        json.dumps(
            {
                "scope": SCOPE,
                "redis_time_seconds": seconds,
                "counts": dict(sorted(counts.items())),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
