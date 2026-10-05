"""Fixed guest delivery common responsibility."""

from __future__ import annotations

import base64
import json
import re
from pathlib import Path, PurePosixPath
from typing import Any, NoReturn
from urllib.parse import urlsplit

REDIS_NAMES = (
    "AEGAEON_PAR_REDIS_URL",
    "AEGAEON_AUTH_CODE_REDIS_URL",
    "AEGAEON_TOKEN_STORE_REDIS_URL",
    "AEGAEON_DPOP_REDIS_URL",
    "AEGAEON_JWKS_REDIS_URL",
    "AEGAEON_REQUEST_OBJECT_JTI_REDIS_URL",
    "AEGAEON_AUTH_SESSION_REDIS_URL",
    "AEGAEON_DEVICE_CODE_REDIS_URL",
    "AEGAEON_DEVICE_CSRF_REDIS_URL",
    "AEGAEON_DEVICE_RATE_LIMIT_REDIS_URL",
    "AEGAEON_LOCAL_AUTH_CSRF_REDIS_URL",
    "AEGAEON_LOCAL_LOGIN_RATE_LIMIT_REDIS_URL",
    "AEGAEON_STEPUP_REDIS_URL",
    "AEGAEON_MANAGEMENT_SESSION_REDIS_URL",
    "AEGAEON_MANAGEMENT_LOGIN_RATE_LIMIT_REDIS_URL",
    "AEGAEON_UPSTREAM_AUTH_REDIS_URL",
    "AEGAEON_UPSTREAM_LOGOUT_RELAY_REDIS_URL",
    "AEGAEON_DPOP_NONCE_REDIS_URL",
    "AEGAEON_CLIENT_ASSERTION_REPLAY_REDIS_URL",
    "AEGAEON_OIDC_LOGOUT_SESSION_REDIS_URL",
)

SERVER_NAMES = (*REDIS_NAMES, "AEGAEON_DATABASE_URL", "AEGAEON_KEY_ENCRYPTION_KEY")

CLIENT_NAMES = (
    "schema_version",
    "client_secret",
    "profile_manifest_base64",
    "session_cookie",
    "session_provenance_base64",
)

ATOMIC_NAMES = (
    "AEGAEON_PAR_REDIS_URL",
    "AEGAEON_AUTH_CODE_REDIS_URL",
    "AEGAEON_TOKEN_STORE_REDIS_URL",
    "AEGAEON_REQUEST_OBJECT_JTI_REDIS_URL",
    "AEGAEON_OIDC_LOGOUT_SESSION_REDIS_URL",
)


SCOPE_EXCLAMATION = 0x21
SCOPE_FIRST_START = 0x23
SCOPE_FIRST_END = 0x5B
SCOPE_SECOND_START = 0x5D
SCOPE_SECOND_END = 0x7E
MAX_DURATION_SECONDS = 86400


def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in items:
        if key in result:
            fail("duplicate field")
        result[key] = value
    return result


def json_object(raw: str | bytes | bytearray) -> dict[str, Any]:
    value = json.loads(raw, object_pairs_hook=pairs, parse_constant=reject_constant)
    if not isinstance(value, dict):
        fail("object required")
    return value


def single_line(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip()) and all(c.isprintable() for c in value)


def https_origin(value: str) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or (parsed.password is not None)
        or (parsed.path not in ("", "/"))
        or parsed.query
        or parsed.fragment
    ):
        fail("HTTPS origin required")
    return value.rstrip("/")


def canonical_base64(value: object) -> bytes:
    if not isinstance(value, str):
        fail("base64 bytes required")
    raw = base64.b64decode(value, validate=True)
    if not raw or base64.b64encode(raw).decode() != value:
        fail("noncanonical base64")
    return raw


def scope_tokens(value: object) -> set[str]:
    if not isinstance(value, str) or not value:
        fail("scope required")
    tokens = value.split(" ")
    if len(tokens) != len(set(tokens)) or any(
        not token
        or any(
            not (
                ord(c) == SCOPE_EXCLAMATION
                or SCOPE_FIRST_START <= ord(c) <= SCOPE_FIRST_END
                or SCOPE_SECOND_START <= ord(c) <= SCOPE_SECOND_END
            )
            for c in token
        )
        for token in tokens
    ):
        fail("OAuth scope syntax")
    return set(tokens)


def digest(value: object, length: int = 64) -> str:
    if not isinstance(value, str) or not re.fullmatch("[0-9a-f]{" + str(length) + "}", value):
        fail("lowercase digest required")
    return value


def absolute_path(value: object) -> Path:
    if (
        not isinstance(value, str)
        or not single_line(value)
        or (not value.startswith("/"))
        or (str(PurePosixPath(value)) != value)
        or (".." in PurePosixPath(value).parts)
    ):
        fail("canonical absolute path required")
    return Path(value)


def executable_path(value: object) -> Path:
    if (
        not isinstance(value, str)
        or re.fullmatch(r"/[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*", value) is None
        or any(part in {".", ".."} for part in value.split("/"))
    ):
        fail("canonical executable path required")
    return Path(value)


def duration_seconds(value: str, *, warmup: bool = False) -> int:
    match = re.fullmatch("(0|[1-9][0-9]*)([smh]?)", value)
    if not match:
        fail("bounded CLI duration required")
    number, unit = match.groups()
    seconds = int(number) * {"": 1, "s": 1, "m": 60, "h": 3600}[unit]
    if seconds > MAX_DURATION_SECONDS or (not warmup and seconds == 0):
        fail("duration outside CLI bounds")
    return seconds


def fail(message: str) -> NoReturn:
    raise ValueError(message)


def reject_constant(_value: str) -> NoReturn:
    fail("nonfinite JSON number")
