"""Seed only the fresh private database created by review.py."""

import base64
import hashlib
import json
import secrets
import uuid

import psycopg
from argon2 import PasswordHasher
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from psycopg.types.json import Jsonb


def b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def signing_key(environment, kek):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    der = key.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public = key.public_key().public_numbers()
    kid = "review-" + secrets.token_hex(8)
    jwk = {"kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid}
    for field, value in (("n", public.n), ("e", public.e)):
        jwk[field] = b64(value.to_bytes((value.bit_length() + 7) // 8, "big"))
    aad = b"aegaeon/runtime-key-handle/v1"
    for field in (
        environment.bytes,
        b"OIDC_ID_TOKEN_SIGNING",
        b"databaseEncrypted",
        b"RS256",
        kid.encode(),
    ):
        aad += len(field).to_bytes(8, "big") + field
    nonce = secrets.token_bytes(12)
    encrypted = nonce + AESGCM(kek).encrypt(nonce, b64(der).encode(), aad)
    return jwk, "aeg-runtime-key-handle-v1." + b64(encrypted)


def seed(database_url, issuer_host, password, kek):
    team, tenant, environment, version, user = (uuid.uuid4() for _ in range(5))
    jwk, handle = signing_key(environment, kek)
    with psycopg.connect(database_url) as connection, connection.cursor() as cursor:
        # The source migration installs pgcrypto in the aegaeon schema.
        cursor.execute("ALTER ROLE review SET search_path = aegaeon, public")
        cursor.execute("SELECT count(*) FROM aegaeon.environments")
        if cursor.fetchone()[0] != 0:
            msg = "review seeding requires an empty database"
            raise ValueError(msg)
        cursor.execute(
            "INSERT INTO aegaeon.control_plane_policies (id,management_issuer_base_domain) "
            "VALUES ('default','example.com')"
        )
        cursor.execute(
            "INSERT INTO aegaeon.teams (id,name,slug) VALUES (%s,'Preview review','review')",
            (team,),
        )
        cursor.execute(
            "INSERT INTO aegaeon.tenants (id,team_id,slug,name,region) VALUES "
            "(%s,%s,'review','Preview review','local')",
            (tenant, team),
        )
        cursor.execute(
            "INSERT INTO aegaeon.environments (id,tenant_id,name,slug,issuer_host) VALUES "
            "(%s,%s,'Preview review','review',%s)",
            (environment, tenant, issuer_host),
        )
        cursor.execute(
            "INSERT INTO aegaeon.configuration_versions "
            "(id,environment_id,version_number,configuration_hash,status,configuration_document) "
            "VALUES (%s,%s,1,'initializing','DRAFT','{}')",
            (version, environment),
        )
        cursor.execute(
            """
            INSERT INTO aegaeon.environment_policies
            (environment_id,configuration_version_id,pkce_required,dcr_enabled,
             require_state_parameter,oidc_enabled,oidc_require_nonce,sender_constrained,
             dpop_require_nonce,require_client_auth_token,dcr_require_pkce_for_public,
             allowed_grant_types,allowed_signing_algorithms,
             access_token_time_to_live_seconds,id_token_time_to_live_seconds,
             refresh_token_time_to_live_seconds,authorization_code_time_to_live_seconds)
            VALUES (%s,%s,true,true,true,true,true,'NONE',false,false,true,
                    ARRAY['authorization_code'],ARRAY['RS256'],300,300,3600,120)
            RETURNING to_jsonb(environment_policies)
        """,
            (environment, version),
        )
        row = cursor.fetchone()[0]
        for name in ("environment_id", "configuration_version_id", "created_at", "updated_at"):
            row.pop(name)
        row["sender_constraint"] = row.pop("sender_constrained").lower()
        policy = {}
        for key, value in row.items():
            first, *rest = key.split("_")
            policy[first + "".join(part.title() for part in rest)] = value
        document = {
            "schemaVersion": 1,
            "issuerHost": issuer_host,
            "issuerUrl": "https://" + issuer_host,
            "policy": policy,
            "scopeAllowlist": ["email", "openid", "profile"],
            "keyStore": {"type": "databaseEncrypted", "configuration": {}, "redacted": True},
        }
        canonical = json.dumps(document, sort_keys=True, separators=(",", ":"))
        cursor.execute(
            "UPDATE aegaeon.configuration_versions SET "
            "configuration_document=%s,configuration_hash=%s,status='ACTIVE',activated_at=now() "
            "WHERE id=%s",
            (Jsonb(document), hashlib.sha256(canonical.encode()).hexdigest(), version),
        )
        cursor.execute(
            "UPDATE aegaeon.environments SET active_configuration_version_id=%s WHERE id=%s",
            (version, environment),
        )
        cursor.execute(
            "INSERT INTO aegaeon.oauth_profiles "
            "(environment_id,configuration_version_id,name,profile_type,is_default,"
            "require_iss_parameter,sender_constrained,allowed_grant_types,"
            "token_endpoint_auth_methods_allowed) "
            "VALUES (%s,%s,'Review Code+PKCE','DOWNSTREAM',true,true,'NONE',"
            "ARRAY['authorization_code'],ARRAY['none'])",
            (environment, version),
        )
        cursor.execute(
            "INSERT INTO aegaeon.runtime_keys "
            "(environment_id,configuration_version_id,usage,kid,algorithm,provider,"
            "status,public_jwk,key_handle,activated_at) "
            "VALUES "
            "(%s,%s,'OIDC_ID_TOKEN_SIGNING',%s,'RS256','databaseEncrypted','ACTIVE',%s,%s,now())",
            (environment, version, jwk["kid"], Jsonb(jwk), handle),
        )
        cursor.execute(
            "INSERT INTO aegaeon.end_users (id,environment_id,subject,email,status) VALUES "
            "(%s,%s,'preview-review-user','reviewer@example.com','ACTIVE')",
            (user, environment),
        )
        cursor.execute(
            "INSERT INTO aegaeon.end_user_password_credentials (end_user_id,password_hash) "
            "VALUES (%s,%s)",
            (user, PasswordHasher(time_cost=2, memory_cost=19456, parallelism=1).hash(password)),
        )
        cursor.execute(
            "INSERT INTO aegaeon.end_user_profiles (end_user_id,email_verified,display_name) "
            "VALUES (%s,true,'Preview Reviewer')",
            (user,),
        )
    return {
        "environment_id": str(environment),
        "configuration_version_id": str(version),
        "configuration": document,
    }
