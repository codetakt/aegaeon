"""Retain fresh replacement secrets before any credential or journal mutation."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import secrets
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import organization_cutover_credentials as credentials
import organization_cutover_journal as journal
import organization_cutover_token as token
import organization_recovery as recovery
import organization_recovery_runtime as runtime
from organization_recovery_store import require

if TYPE_CHECKING:
    from pathlib import Path

MAX_PLAN = 4 * 1024 * 1024
STORE_COUNT = 2


@dataclass(frozen=True, repr=False)
class Plan:
    value: dict = field(repr=False)
    sha256: str

    def sql(self, index: int) -> list[credentials.Replacement]:
        return [
            credentials.Replacement(
                item["old"], item["new"], item["attributes"], item["verifier"].encode()
            )
            for item in self.value["sql"][index]["replacements"]
        ]

    def redis(self) -> token.Credential:
        value = self.value["token"]
        return token.credential(value["name"], value["password"].encode(), set(value["commands"]))


def canonical(value: dict) -> bytes:
    data = (
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode() + b"\n"
    )
    require(len(data) <= MAX_PLAN, "cutover secret plan exceeds budget")
    return data


def directory(path: Path) -> int:
    recovery.protected_path(path)
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(descriptor)
        require(
            info.st_uid == 0 and not info.st_mode & 0o077, "private root plan directory required"
        )
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BaseException:
        os.close(descriptor)
        raise
    else:
        return descriptor


def require_absent(descriptor: int) -> None:
    try:
        entry = os.stat("plan.json", dir_fd=descriptor, follow_symlinks=False)
    except FileNotFoundError:
        entry = None
    require(entry is None, "cutover secret plan already exists; load exact original")


def _retain(
    config: dict, stores: list, names: list[dict[str, str]], redis: dict, path: Path
) -> Plan:
    """Called under the live independent fence; also locks the private directory."""
    require(os.geteuid() == 0, "root secret custody required")
    require(len(stores) == len(names) == STORE_COUNT, "control and destination mappings required")
    require(
        stores[0].identity["cluster"] != stores[1].identity["cluster"],
        "independent stores required",
    )
    require(set(redis) == {"name", "commands"}, "explicit replacement token profile required")
    descriptor = directory(path)
    try:
        # Refuse before generating a second secret. A missing/partial plan after
        # registration is an operator recovery condition, never permission to reset.
        require_absent(descriptor)
        value = {"version": 1, "configuration_sha256": runtime.digest(config), "sql": []}
        for store, mapping in zip(stores, names, strict=True):
            require(
                type(mapping) is dict and 0 < len(mapping) <= credentials.MAX_ROLES,
                "secret mapping budget exceeded",
            )
            passwords = {old: secrets.token_urlsafe(48).encode() for old in mapping}
            replacements = credentials.plan(store, mapping, passwords)
            value["sql"].append(
                {
                    "identity": store.identity,
                    "replacements": [
                        {
                            "old": item.old,
                            "new": item.new,
                            "attributes": item.attributes,
                            "verifier": item.verifier.decode(),
                            "password": passwords[item.old].decode(),
                        }
                        for item in replacements
                    ],
                }
            )
        password = secrets.token_urlsafe(48)
        selected = token.credential(redis["name"], password.encode(), set(redis["commands"]))
        value["token"] = {
            "name": selected.name,
            "commands": sorted(selected.commands),
            "password": password,
        }
        data = canonical(value)
        sha256 = recovery.retain(descriptor, "plan.json", value)
        require(hashlib.sha256(data).hexdigest() == sha256, "secret plan encoding differs")
        parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
        return Plan(value, sha256)
    finally:
        os.close(descriptor)


def create(config: dict, stores: list, path: Path) -> Plan:
    """Persist before journal COMMIT; missing registered plans can never be regenerated."""
    require(os.geteuid() == 0, "root secret custody required")
    require(
        set(config)
        in ({"inspection", "names", "redis"}, {"inspection", "names", "redis", "preparation"}),
        "exact cutover preparation config required",
    )
    inspection = config["inspection"]
    expected, operation = inspection["fence"], inspection["operation_id"]
    journal.identity(expected, operation, "0" * 64)
    require(
        len(stores) == STORE_COUNT
        and [store.identity for store in stores]
        == [inspection["stores"][index]["identity"] for index in [0, 2]],
        "cutover secret store selection differs",
    )
    with journal.locked(stores[0], expected):
        require(
            not journal.pending_or_registered(stores[0], expected["deployment_id"], operation),
            "cutover already registered; recover exact retained plan",
        )
        result = _retain(config, stores, config["names"], config["redis"], path)
        journal.register(stores[0], expected, operation, result.sha256)
        return result


def load(config: dict, path: Path, expected_sha256: str) -> Plan:
    require(os.geteuid() == 0, "root secret custody required")
    descriptor = directory(path)
    try:
        data = recovery.private_file(path / "plan.json", MAX_PLAN)
        require(
            hashlib.sha256(data).hexdigest() == expected_sha256,
            "cutover secret plan digest differs",
        )
        value = json.loads(data)
        require(
            set(value) == {"version", "configuration_sha256", "sql", "token"}
            and value["version"] == 1
            and value["configuration_sha256"] == runtime.digest(config)
            and canonical(value) == data,
            "cutover secret plan configuration differs",
        )
        require(
            type(value["sql"]) is list and len(value["sql"]) == STORE_COUNT,
            "secret store inventory differs",
        )
        # Generated plan bytes are bound by the independent journal digest. Do
        # not regenerate SCRAM verifiers: their salts belong to this exact plan.
        result = Plan(value, expected_sha256)
        for index in range(STORE_COUNT):
            require(result.sql(index), "empty secret mapping")
        result.redis()
        return result
    finally:
        os.close(descriptor)
