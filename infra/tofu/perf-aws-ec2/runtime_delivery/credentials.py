"""Fixed guest delivery credentials responsibility."""

from __future__ import annotations

import base64
import hashlib
import re
import subprocess
from typing import Any
from urllib.parse import parse_qs

from runtime_delivery.common import (
    ATOMIC_NAMES,
    CLIENT_NAMES,
    REDIS_NAMES,
    SERVER_NAMES,
    canonical_base64,
    checked_url,
    fail,
    https_origin,
    json_object,
    scope_tokens,
    single_line,
)
from runtime_delivery.filesystem import aws_executable

CLIENT_BUNDLE_VERSION = 2
KEK_BYTES = 32


def profile_fields(profile: dict[str, Any]) -> None:
    required = {
        "issuer",
        "environment_id",
        "configuration_version_id",
        "oauth_profile_id",
        "activation",
        "client_id",
        "redirect_uri",
        "client_auth",
        "scope",
        "subject",
        "sender_policy",
        "par_policy",
    }
    optional = {"oidc_scope", "resource", "id_token_alg"}
    if not required <= set(profile) or set(profile) - required - optional:
        fail("profile schema")
    if not all(single_line(profile[name]) for name in required):
        fail("profile identity")
    if any(profile.get(name) is not None and (not single_line(profile[name])) for name in optional):
        fail("profile optional field")


def profile_policy(profile: dict[str, Any], issuer: str) -> None:
    if (
        profile["issuer"] != issuer
        or https_origin(issuer) != issuer
        or (profile["activation"] != "ACTIVE")
        or (profile["client_auth"] not in {"client_secret_basic", "client_secret_post"})
        or (profile["sender_policy"] not in {"none", "dpop"})
        or (profile["par_policy"] not in {"optional", "required"})
    ):
        fail("profile policy/issuer")
    for field in ("redirect_uri", "resource"):
        if field == "resource" and profile.get(field) is None:
            continue
        url = checked_url(profile[field])
        if (
            url.scheme != "https"
            or not url.hostname
            or url.username is not None
            or url.password is not None
            or url.fragment
            or (
                field == "redirect_uri"
                and set(parse_qs(url.query, keep_blank_values=True))
                & {"state", "iss", "code", "error", "error_description", "error_uri"}
            )
        ):
            fail("profile redirect" if field == "redirect_uri" else "profile resource")
    scope = scope_tokens(profile["scope"])
    oidc = scope_tokens(profile["oidc_scope"]) if profile.get("oidc_scope") is not None else set()
    if ("openid" in scope or "openid" in oidc) and profile.get("id_token_alg") != "RS256":
        fail("RS256 profile required")


def session_provenance(
    provenance: dict[str, Any],
    profile: dict[str, Any],
    issuer: str,
    profile_raw: bytes,
    session_raw: bytes,
) -> str:
    expected = {"issuer", "subject", "method", "producer", "profile_sha256", "session_sha256"}
    if set(provenance) != expected or not all(single_line(v) for v in provenance.values()):
        fail("session provenance schema")
    profile_sha = hashlib.sha256(profile_raw).hexdigest()
    if (
        provenance["issuer"] != issuer
        or provenance["subject"] != profile["subject"]
        or provenance["method"] != "public-login"
        or (provenance["profile_sha256"] != profile_sha)
        or (provenance["session_sha256"] != hashlib.sha256(session_raw).hexdigest())
    ):
        fail("session provenance binding")
    return profile_sha


def validate_client_bundle(values: dict[str, Any], issuer: str) -> dict[str, Any]:
    if (
        set(values) != set(CLIENT_NAMES)
        or type(values["schema_version"]) is not int
        or values["schema_version"] != CLIENT_BUNDLE_VERSION
    ):
        fail("client bundle2 required")
    if not single_line(values["client_secret"]):
        fail("client secret required")
    profile_raw = canonical_base64(values["profile_manifest_base64"])
    provenance_raw = canonical_base64(values["session_provenance_base64"])
    profile = json_object(profile_raw)
    profile_fields(profile)
    profile_policy(profile, issuer)
    session = values["session_cookie"]
    if not isinstance(session, str) or not re.fullmatch(
        "aegaeon_auth_session=[A-Za-z0-9_-]+", session
    ):
        fail("canonical session line required")
    session_raw = session.encode()
    provenance = json_object(provenance_raw)
    profile_sha = session_provenance(provenance, profile, issuer, profile_raw, session_raw)
    return {
        "secret": values["client_secret"],
        "profile": profile_raw,
        "session": session_raw,
        "provenance": provenance_raw,
        "profile_sha256": profile_sha,
        "provenance_sha256": hashlib.sha256(provenance_raw).hexdigest(),
    }


def server_bundle(values: dict[str, Any]) -> None:
    kek = values["AEGAEON_KEY_ENCRYPTION_KEY"]
    decoded = base64.urlsafe_b64decode(kek + "=" * (-len(kek) % 4))
    if len(decoded) != KEK_BYTES or base64.urlsafe_b64encode(decoded).decode().rstrip("=") != kek:
        fail("noncanonical KEK")
    db = checked_url(values["AEGAEON_DATABASE_URL"])
    if (
        db.scheme not in ("postgres", "postgresql")
        or not db.hostname
        or db.fragment
        or (parse_qs(db.query).get("sslmode") not in (["require"], ["verify-ca"], ["verify-full"]))
    ):
        fail("TLS database required")
    identities = {}
    for name in REDIS_NAMES:
        url = checked_url(values[name])
        if (
            url.scheme != "rediss"
            or not url.hostname
            or url.query
            or url.fragment
            or (not re.fullmatch("/?[0-9]*", url.path))
        ):
            fail("TLS Redis required")
        identities[name] = (
            url.scheme,
            url.hostname.lower(),
            url.port if url.port is not None else 6379,
            int(url.path.lstrip("/") or "0"),
        )
    if len({identities[name] for name in ATOMIC_NAMES}) != 1:
        fail("atomic Redis topology")


def validate_bundle(profile: str, raw: str | bytes | bytearray, issuer: str) -> dict[str, Any]:
    if profile not in ("server", "client", "metrics"):
        fail("unsupported profile")
    values = json_object(raw)
    if profile == "client":
        return validate_client_bundle(values, issuer)
    expected = set(SERVER_NAMES if profile == "server" else ("api_key",))
    if set(values) != expected or not all(single_line(v) for v in values.values()):
        fail("unsupported bundle schema")
    if profile == "server":
        server_bundle(values)
    elif not re.fullmatch("aeg_[A-Za-z0-9_-]+", values["api_key"]):
        fail("management API key")
    return values


def retrieve(
    profile: str, identifier: str, version: str, region: str, issuer: str
) -> dict[str, Any]:
    if not re.fullmatch("[A-Za-z0-9-]{32,64}", version):
        fail("version required")
    result = subprocess.run(  # noqa: S603 -- fixed root-owned guest executable, direct argv, no shell
        [
            str(aws_executable()),
            "--region",
            region,
            "secretsmanager",
            "get-secret-value",
            "--secret-id",
            identifier,
            "--version-id",
            version,
            "--output",
            "json",
        ],
        check=True,
        capture_output=True,
        timeout=60,
    )
    response = json_object(result.stdout)
    if response.get("ARN") != identifier or response.get("VersionId") != version:
        fail("secret identity mismatch")
    return validate_bundle(profile, response["SecretString"], issuer)
