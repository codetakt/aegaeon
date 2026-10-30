#!/usr/bin/env python3
"""Verify the complete, exact-byte Organizations snapshot format, without adoption."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
import sys
from pathlib import Path
from typing import BinaryIO

from organization_audit_consumer import DECODER, fields, identifier, private, refuse

SECTIONS = (
    "domain",
    "targets",
    "roles",
    "client_bindings",
    "operators",
    "organizations",
    "memberships",
    "invitations",
    "challenges",
    "identity_requests",
    "administrative_grants",
    "audit",
    "receipts",
    "outbox",
    "owners",
    "subject_history",
    "identities",
    "namespace",
    "environment_dependency",
    "client_dependencies",
)
MAX_ROWS = 1_000_000
MAX_BYTES = 64 * 1024 * 1024 * 1024
MAX_LINE = 320 * 1024
MAX_DATA = 256 * 1024
MAX_KEY = 4096


def frame(value: bytes) -> bytes:
    return struct.pack(">Q", len(value)) + value


class Chain:
    """Independent implementation of the versioned supplier hash-chain framing."""

    def __init__(self, section: str) -> None:
        collection = f"aegaeon-organizations-snapshot-v1:{section}".encode()
        self.state = hashlib.sha256(
            frame(b"aegaeon-subject-inventory-v1") + frame(collection)
        ).digest()
        self.count = 0
        self.previous: bytes | None = None

    def push(self, key: str, data: bytes) -> None:
        encoded = key.encode("utf-8")
        if (
            len(encoded) > MAX_KEY
            or len(data) > MAX_DATA
            or self.count >= MAX_ROWS
            or (self.previous is not None and encoded <= self.previous)
        ):
            refuse("snapshot row bound or ordering")
        self.count += 1
        self.state = hashlib.sha256(
            b"\x01"
            + self.state
            + struct.pack(">Q", self.count)
            + frame(encoded)
            + hashlib.sha256(frame(data)).digest()
        ).digest()
        self.previous = encoded

    def finish(self, section: str) -> dict[str, object]:
        digest = hashlib.sha256(b"\x02" + self.state + struct.pack(">Q", self.count)).hexdigest()
        return {"section": section, "count": self.count, "sha256": digest}


def validate_header(value: dict) -> dict:
    if (
        set(value)
        != {"record", "version", "snapshotId", "scope", "capturedAt", "credentialTransfer"}
        or value["record"] != "header"
        or type(value["version"]) is not int
        or value["version"] != 1
        or value["credentialTransfer"] is not False
        or not isinstance(value["scope"], dict)
        or set(value["scope"]) != {"environment_id", "domain_id"}
        or not isinstance(value["capturedAt"], str)
    ):
        refuse("snapshot header shape/version")
    for key in (value["snapshotId"], *value["scope"].values()):
        identifier(key)
    return value


def validate_manifest(value: dict, header: dict, chains: list[Chain], previous: int) -> dict:
    expected = {
        "record": "manifest",
        "version": 1,
        "snapshotId": header["snapshotId"],
        "scope": header["scope"],
        "contentBytes": previous,
        "sections": [
            chain.finish(section) for section, chain in zip(SECTIONS, chains, strict=True)
        ],
    }
    # Python bool/int equality must not admit non-integer count/version fields.
    if (
        type(value.get("version")) is not int
        or type(value.get("contentBytes")) is not int
        or not isinstance(value.get("sections"), list)
        or any(
            not isinstance(v, dict) or type(v.get("count")) is not int for v in value["sections"]
        )
        or value != expected
    ):
        refuse("snapshot terminal manifest")
    return expected


def push_row(value: dict, text: str, header: dict, chains: list[Chain], position: int) -> int:
    if (
        set(value) != {"record", "section", "key", "data"}
        or value["record"] != "row"
        or value["section"] not in SECTIONS
        or not isinstance(value["key"], str)
        or not isinstance(value["data"], dict)
    ):
        refuse("snapshot row shape")
    next_position = SECTIONS.index(value["section"])
    if next_position < position:
        refuse("snapshot section order")
    for scope_key, scope_id in header["scope"].items():
        if scope_key in value["data"] and value["data"][scope_key] != scope_id:
            refuse("snapshot row scope")
    chains[next_position].push(value["key"], fields(text)["data"].encode("utf-8"))
    return next_position


def verify(stream: BinaryIO) -> dict[str, object]:
    """Checks integrity and transfer framing; never grants import/restore authority."""
    total = 0
    whole = hashlib.sha256()
    header = None
    chains = [Chain(section) for section in SECTIONS]
    position = 0
    for _ in range(len(SECTIONS) * MAX_ROWS + 2):
        raw = stream.readline(MAX_LINE + 1)
        if not raw or len(raw) > MAX_LINE or not raw.endswith(b"\n"):
            refuse("snapshot truncated or line limit")
        previous = total
        total += len(raw)
        if total > MAX_BYTES:
            refuse("snapshot byte limit")
        whole.update(raw)
        text = raw.decode("utf-8")
        value = DECODER.decode(text)
        if not isinstance(value, dict):
            refuse("snapshot record must be an object")
        if header is None:
            header = validate_header(value)
        elif value.get("record") == "manifest":
            manifest = validate_manifest(value, header, chains, previous)
            if stream.read(1):
                refuse("snapshot trailing bytes")
            return {
                "integrityChecked": True,
                "snapshotId": header["snapshotId"],
                "scope": header["scope"],
                "bytes": total,
                "sha256": whole.hexdigest(),
                "sections": manifest["sections"],
                "importAuthorized": False,
            }
        else:
            position = push_row(value, text, header, chains, position)
    return refuse("snapshot row limit")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("snapshot", type=Path)
    args = parser.parse_args()
    fd = os.open(args.snapshot, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        private(fd)
        with os.fdopen(fd, "rb", closefd=False) as stream:
            print(json.dumps(verify(stream), ensure_ascii=False, sort_keys=True))
    finally:
        os.close(fd)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, IndexError, RecursionError) as error:
        print("snapshot verification refused", file=sys.stderr)
        raise SystemExit(1) from error
