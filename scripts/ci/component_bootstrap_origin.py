"""Standard-library raw-source gate, before any package-source import.

This private seam assumes an independently admitted original-service reader and
protected runtime/CA/credential/inventory inputs. Constructing these records or
providing fixture replies does not establish those premises or production access.
The richer package installer must still perform its existing release checks.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from dataclasses import dataclass
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Never, Protocol, cast
from urllib.parse import quote

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

REPOSITORY = "codetakt/aegaeon"
API_ROOT = "https://api.github.com/repos/" + REPOSITORY + "/"
CREDENTIAL_SCOPE = API_ROOT
POLICY_PATH = "ci/pr-policy.json"
DESCRIPTOR_PATH = "ci/component-release.json"
MAX_REPLY = 8 * 1024 * 1024
MAX_TOTAL = 256 * 1024 * 1024
MAX_RETAINED_REPLIES = 512 * 1024 * 1024
MAX_ROWS = 100_000
JsonObject = dict[str, Any]


class OriginRejectedError(ValueError):
    """An original source predicate or retained-input relation failed."""


def require(condition: object, message: str) -> None:
    if not condition:
        raise OriginRejectedError(message)


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def object_id(value: object) -> bool:
    return type(value) is str and re.fullmatch(r"[0-9a-f]{40}(?:[0-9a-f]{24})?", value) is not None


def path_parts(value: str) -> tuple[str, ...]:
    require(type(value) is str, "original source path is not text")
    parts = tuple(value.split("/"))
    require(
        0 < len(value.encode()) <= 4096
        and len(parts) <= 128
        and all(part not in {"", ".", ".."} and len(part.encode()) <= 255 for part in parts)
        and "\\" not in value
        and all(ord(char) >= 32 and ord(char) != 127 for char in value),
        "noncanonical original source path",
    )
    return parts


def _unique(pairs: list[tuple[str, Any]]) -> JsonObject:
    value: JsonObject = {}
    for key, item in pairs:
        require(key not in value, "duplicate original JSON key")
        value[key] = item
    return value


def _reject_constant(_value: str) -> Never:
    raise OriginRejectedError("nonfinite original JSON constant")


def strict_object(raw: bytes) -> JsonObject:
    require(type(raw) is bytes and len(raw) <= MAX_REPLY, "original JSON byte bound differs")
    try:
        value = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_unique, parse_constant=_reject_constant
        )
    except (UnicodeError, ValueError) as error:
        raise OriginRejectedError("malformed original JSON") from error
    require(type(value) is dict, "original JSON object required")
    return cast("JsonObject", value)


def git_blob(raw: bytes, oid: str) -> str:
    """Git object identity; SHA256 separately binds security-sensitive content."""
    require(object_id(oid), "original Git blob identity differs")
    algorithm = "sha1" if len(oid) == 40 else "sha256"
    return hashlib.new(
        algorithm, b"blob " + str(len(raw)).encode() + b"\0" + raw, usedforsecurity=False
    ).hexdigest()


@dataclass(frozen=True)
class BootstrapPremises:
    """Protected inputs, not an admission receipt or candidate-owned inventory.

    recheck is a protected independent primitive, never supplied by package S.
    It must authenticate actual_base, the complete adopted inventory, the exact
    runtime import closure, CA bytes/closure and credential origin/scope. The
    production implementation of that primitive remains an external obligation.
    """

    actual_base: str
    source_inventory: tuple[str, ...]
    interpreter: str
    runtime_import_paths: tuple[str, ...]
    runtime_packages: tuple[str, ...]
    module_map: tuple[tuple[str, str], ...]
    entrypoint: str
    ca_file: str
    ca_sha256: str
    credential_scope: str
    recheck: Callable[[BootstrapPremises], None]

    def verify(self) -> None:
        require(object_id(self.actual_base), "actual protected base identity differs")
        require(
            type(self.source_inventory) is tuple
            and 0 < len(self.source_inventory) <= MAX_ROWS
            and self.source_inventory == tuple(sorted(set(self.source_inventory)))
            and DESCRIPTOR_PATH not in self.source_inventory,
            "independent exact unique protected inventory required",
        )
        for path in self.source_inventory:
            path_parts(path)
        require(
            type(self.module_map) is tuple
            and bool(self.module_map)
            and len({name for name, _ in self.module_map}) == len(self.module_map)
            and self.entrypoint in dict(self.module_map)
            and all(
                all(part.isidentifier() for part in name.split("."))
                and path in self.source_inventory
                and path.endswith(".py")
                for name, path in self.module_map
            ),
            "independent fixed module-map/entrypoint differs",
        )
        require(
            self.interpreter.startswith("/nix/store/")
            and self.ca_file.startswith("/nix/store/")
            and re.fullmatch(r"[0-9a-f]{64}", self.ca_sha256) is not None
            and type(self.runtime_import_paths) is tuple
            and bool(self.runtime_import_paths)
            and all(path.startswith("/nix/store/") for path in self.runtime_import_paths)
            and type(self.runtime_packages) is tuple
            and len(set(self.runtime_packages)) == len(self.runtime_packages)
            and all(name.isidentifier() for name in self.runtime_packages)
            and self.credential_scope == CREDENTIAL_SCOPE,
            "independent immutable runtime/CA/credential scope unavailable",
        )
        self.recheck(self)


@dataclass(frozen=True)
class OriginalReply:
    """Original transport fields; construction is not HTTPS origin authority."""

    request_url: str
    final_url: str
    method: str
    status: int
    content_type: str
    body: bytes


class OriginalRead(Protocol):
    """Independent fixed GET service, not a fixture or URL-based origin proof.

    Implementations must use the admitted runtime and explicit CA, prohibit
    redirects/proxies/ambient credentials, restrict the credential to API_ROOT,
    authenticate HTTPS and retain complete original replies within the bound.
    No concrete production transport is installed by this private source unit.
    """

    def read(self, url: str, maximum_bytes: int, premises: BootstrapPremises) -> OriginalReply: ...


@dataclass(frozen=True)
class VerifiedSources:
    """Complete bytes checked against independently supplied original premises."""

    premises: BootstrapPremises
    policy: bytes
    descriptor: bytes
    sources: Mapping[str, bytes]
    modes: Mapping[str, str]
    original_replies: tuple[tuple[str, bytes], ...]


class _OriginalGate:
    def __init__(self, reader: OriginalRead, premises: BootstrapPremises) -> None:
        self.reader = reader
        self.premises = premises
        self.replies: list[tuple[str, bytes]] = []
        self.reply_total = 0
        self.trees: dict[str, dict[str, JsonObject]] = {}

    def read(self, route: str) -> JsonObject:
        self.premises.verify()
        url = API_ROOT + route
        reply = self.reader.read(url, MAX_REPLY, self.premises)
        self.premises.verify()
        require(
            type(reply) is OriginalReply
            and reply.request_url == url == reply.final_url
            and reply.method == "GET"
            and type(reply.status) is int
            and reply.status == 200
            and reply.content_type.split(";", 1)[0].strip().lower() == "application/json",
            "fixed original GET/TLS route or response fields differ",
        )
        raw = reply.body
        require(
            type(raw) is bytes and self.reply_total + len(raw) <= MAX_RETAINED_REPLIES,
            "aggregate complete original reply byte budget exceeded",
        )
        value = strict_object(raw)
        self.reply_total += len(raw)
        self.replies.append((url, raw))
        return value

    def tree(self, commit: str) -> dict[str, JsonObject]:
        require(object_id(commit), "immutable source commit identity differs")
        if commit in self.trees:
            return self.trees[commit]
        reply = self.read("commits/" + commit)
        require(
            reply.get("sha") == commit and type(reply.get("commit")) is dict,
            "whole original signed commit reply differs",
        )
        body = reply["commit"]
        verification = body.get("verification")
        require(
            type(verification) is dict
            and verification.get("verified") is True
            and verification.get("reason") == "valid"
            and type(verification.get("signature")) is str
            and bool(verification["signature"])
            and type(verification.get("payload")) is str
            and bool(verification["payload"]),
            "original immutable commit signature invalid",
        )
        require(type(body.get("tree")) is dict, "original commit tree absent")
        tree = body["tree"].get("sha")
        require(object_id(tree), "original commit tree identity differs")
        require(
            verification["payload"].splitlines()[0] == "tree " + tree,
            "signed payload tree differs from original commit tree",
        )
        inventory = self.read("git/trees/" + tree + "?recursive=1")
        entries = inventory.get("tree")
        require(
            inventory.get("sha") == tree
            and inventory.get("truncated") is False
            and type(entries) is list
            and 0 < len(entries) <= MAX_ROWS,
            "complete nontruncated original tree unavailable",
        )
        result: dict[str, JsonObject] = {}
        entries = cast("list[JsonObject]", entries)
        for entry in entries:
            require(
                type(entry) is dict and type(entry.get("path")) is str,
                "original tree entry malformed",
            )
            path = entry["path"]
            path_parts(path)
            require(
                path not in result and object_id(entry.get("sha")),
                "duplicate path or invalid blob in original whole tree",
            )
            require(
                (entry.get("type"), entry.get("mode"))
                in {
                    ("blob", "100644"),
                    ("blob", "100755"),
                    ("blob", "120000"),
                    ("tree", "040000"),
                    ("commit", "160000"),
                },
                "original Git tree type/mode differs",
            )
            result[path] = entry
        self.trees[commit] = result
        return result

    def source(self, commit: str, path: str, mode: str) -> bytes:
        path_parts(path)
        entry = self.tree(commit).get(path)
        require(
            type(entry) is dict
            and entry.get("type") == "blob"
            and entry.get("mode") == mode
            and mode in {"100644", "100755"},
            "original regular source path/mode differs",
        )
        entry = cast("JsonObject", entry)
        reply = self.read("contents/" + quote(path, safe="/") + "?ref=" + commit)
        require(
            reply.get("type") == "file"
            and reply.get("path") == path
            and reply.get("sha") == entry["sha"]
            and reply.get("encoding") == "base64"
            and type(reply.get("content")) is str,
            "original contents/blob association differs",
        )
        try:
            raw = base64.b64decode(reply["content"].replace("\n", ""), validate=True)
        except (ValueError, binascii.Error) as error:
            raise OriginRejectedError("original complete source encoding differs") from error
        require(
            type(reply.get("size")) is int
            and reply["size"] == len(raw)
            and len(raw) <= MAX_REPLY
            and git_blob(raw, entry["sha"]) == entry["sha"],
            "actual Git blob/complete original bytes differ",
        )
        return raw


def verify_original_sources(  # noqa: PLR0915 - ordered original admissions before any import
    reader: OriginalRead, premises: BootstrapPremises, policy: bytes
) -> VerifiedSources:
    """Authenticate all original code/data before returning any loader input."""
    premises.verify()
    gate = _OriginalGate(reader, premises)
    require(
        gate.source(premises.actual_base, POLICY_PATH, "100644") == policy,
        "actual-base original policy differs",
    )
    value = strict_object(policy)
    require(
        type(value.get("plan_envelope_version")) is int
        and value["plan_envelope_version"] == 2
        and type(value.get("supplemental_lanes")) is dict
        and value["supplemental_lanes"].get("components") in {"pending", "required"},
        "adopted protected component policy unavailable",
    )
    binding = value.get("component_release")
    require(
        type(binding) is dict
        and set(binding) == {"version", "descriptor_path", "descriptor_sha256"}
        and type(binding.get("version")) is int
        and binding["version"] == 1
        and binding.get("descriptor_path") == DESCRIPTOR_PATH
        and type(binding.get("descriptor_sha256")) is str
        and re.fullmatch(r"[0-9a-f]{64}", binding["descriptor_sha256"]) is not None,
        "closed literal descriptor policy binding differs",
    )
    binding = cast("JsonObject", binding)
    descriptor = gate.source(premises.actual_base, DESCRIPTOR_PATH, "100644")
    require(sha256(descriptor) == binding["descriptor_sha256"], "literal descriptor digest differs")
    rows = strict_object(descriptor).get("source_registry")
    require(
        type(rows) is list and len(rows) == len(premises.source_inventory),
        "exact independently adopted registry size differs",
    )
    rows = cast("list[JsonObject]", rows)
    sources: dict[str, bytes] = {}
    modes: dict[str, str] = {}
    identities: set[str] = set()
    total = len(policy) + len(descriptor)
    for row in rows:
        require(
            type(row) is dict and type(row.get("relative_path")) is str,
            "original source registry row malformed",
        )
        path = row["relative_path"]
        path_parts(path)
        require(
            path in premises.source_inventory
            and path not in sources
            and type(row.get("registry_id")) is str
            and bool(row["registry_id"])
            and row["registry_id"] not in identities,
            "exact unique protected registry membership differs",
        )
        require(
            row.get("repository_or_supplier") == REPOSITORY
            and object_id(row.get("commit_or_version"))
            and row.get("git_mode") in {"100644", "100755"}
            and not (path == POLICY_PATH and row["commit_or_version"] == premises.actual_base),
            "original repository/commit/mode or policy backedge differs",
        )
        raw = gate.source(row["commit_or_version"], path, row["git_mode"])
        digest = sha256(raw)
        require(
            type(row.get("bytes")) is int
            and row["bytes"] == len(raw)
            and row.get("sha256") == digest == row.get("tree_or_content_digest"),
            "whole original registry bytes/size/SHA256 differs",
        )
        sources[path], modes[path] = raw, row["git_mode"]
        identities.add(row["registry_id"])
        total += len(raw)
        require(total <= MAX_TOTAL, "complete original source byte budget exceeded")
    require(
        tuple(sorted(sources)) == premises.source_inventory,
        "complete independent source inventory differs",
    )
    premises.verify()
    return VerifiedSources(
        premises,
        policy,
        descriptor,
        MappingProxyType(sources),
        MappingProxyType(modes),
        tuple(gate.replies),
    )
