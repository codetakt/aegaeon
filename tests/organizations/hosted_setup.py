"""Configure a dedicated invitation client, bounded exchange and real encrypted delivery."""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
from urllib.parse import urlsplit, urlunsplit
from uuid import uuid4

from current_database import connect
from delivery_journey import require
from issuer_configuration import GRANTS
from protocol_setup import ADMIN, READ
from psycopg import sql

SCOPE = "organization.invitation.accept"
RETURN_URL = "https://client.example.test/organizations"


def encoded(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def register_domain(api):
    domain, _ = api.call(
        "POST",
        api.base + "/organization-domains/default",
        {"reason": "test hosted invitations"},
        key="hosted-domain",
    )
    path = api.base + "/organization-domains/" + domain["id"]
    grant = domain["operator"]["id"]
    api.call(
        "PATCH",
        path + "/operators/" + grant,
        {
            "active": True,
            "capabilities": ["configure", "provision", "reconcile"],
            "reason": "manage invitations",
        },
        tag=f'"{grant}.1"',
        key="hosted-grants",
    )
    return domain["id"]


def register(f, api):
    environment, _ = api.call("GET", api.base)
    registered, _ = api.call(
        "POST",
        api.base + "/clients",
        {
            "hostedInvitationDomainId": f.domain,
            "baseConfigurationVersionId": environment["activeConfigurationVersionId"],
            "name": "Hosted invitations",
            "clientType": "CONFIDENTIAL",
            "redirectUris": [f.receipt["issuer"] + "/organization-invitations/hosted/callback"],
            "allowedGrantTypes": GRANTS,
            "allowedScopes": ["openid", "read", "offline_access", SCOPE],
            "tokenEndpointAuthenticationMethod": "client_secret_basic",
            "dpopBoundAccessTokens": True,
        },
        expected=201,
    )
    require(
        registered["client"]["clientIdentifier"] == "aegaeon-hosted-invitation-" + f.domain,
        "registered domain-scoped client",
    )
    return registered


def exchange_policy(f, api):
    env, _ = api.call("GET", api.base)
    issuer = f.receipt["issuer"]
    rules, targets = [], []
    for suffix, registration, permission in [
        ("organization-invitations", f.registered, SCOPE),
        ("organizations", f.app, "documents"),
    ]:
        audience = issuer + "/" + suffix
        targets.append({"audience": audience, "resourceAliases": []})
        rules.append(
            {
                "clientId": registration["client"]["clientIdentifier"],
                "sourceAudience": issuer + "/userinfo",
                "targetAudience": audience,
                "scopes": [{"targetScope": permission, "sourceScopes": ["read"]}],
                "defaultScopes": [permission],
            }
        )
    api.call(
        "PATCH",
        api.base + "/policies",
        {
            "baseConfigurationVersionId": env["activeConfigurationVersionId"],
            "tokenExchange": {"version": 1, "targets": targets, "rules": rules},
            "reason": "independent hosted and application grants",
            "allowSecurityDowngrade": True,
        },
    )


def configure_store(f):
    role, database, password = "hosted_fixture", "hosted_flows", secrets.token_urlsafe(32)
    with connect(f.admin) as connection:
        connection.execute(
            sql.SQL("CREATE ROLE {} LOGIN PASSWORD {}").format(
                sql.Identifier(role), sql.Literal(password)
            )
        )
        connection.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(database)))
    admin = urlsplit(f.admin)._replace(path="/" + database).geturl()
    script = f.root / "db/hosted-invitations/setup.sql"
    require(
        f.run(["psql", "-Xq", "-d", admin, "-v", "serving_role=" + role, "-f", script]).returncode
        == 0,
        "dedicated BFF schema",
    )
    primary = urlsplit(f.primary)
    url = urlunsplit(
        primary._replace(
            netloc=f"{role}:{password}@localhost:{primary.port}",
            path="/" + database,
            query="sslmode=verify-full&sslrootcert=" + str(f.directory / "trusted.crt"),
        )
    )
    config = f.directory / "hosted.json"
    config.write_text(
        json.dumps(
            {
                "database_url": url,
                "key": encoded(secrets.token_bytes(32)),
                "clients": {f.domain: f.credentials["secret"]},
            }
        )
    )
    f.env.update(
        AEGAEON_HOSTED_INVITATION_CONFIG_FILE=str(config),
        AEGAEON_HOSTED_INVITATION_CA_FILE=str(f.directory / "trusted.crt"),
    )
    return admin


def keys(f):
    def openssl(args):
        result = f.run(["openssl", *args], timeout=10)
        require(result.returncode == 0, "notification fixture key conversion")

    directory = f.directory
    pem = directory / "delivery-wrap.pem"
    pub, pkcs8 = directory / "spki.der", directory / "private.der"
    openssl(["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", pem])
    openssl(["pkey", "-in", pem, "-pubout", "-outform", "DER", "-out", pub])
    openssl(["pkcs8", "-topk8", "-nocrypt", "-in", pem, "-outform", "DER", "-out", pkcs8])
    now = int(time.time())
    cfg = json.loads(f.config.read_text())
    cfg["delivery_trust"] = [
        {"origin": "https://delivery.example.test", "root_cert": str(directory / "trusted.crt")}
    ]
    f.config.write_text(json.dumps(cfg))
    common = {
        "version": "hosted-test-key",
        "deployment_id": cfg["deployment_id"],
        "not_before": now - 60,
        "seal_until": now + 86400,
        "open_until": now + 172800,
        "spki_sha256": encoded(hashlib.sha256(pub.read_bytes()).digest()),
    }
    (directory / "worker.json").write_text(
        json.dumps(
            {
                "version": 1,
                "credential": f.adapter_credential,
                "keys": [
                    common
                    | {
                        "scope": {
                            "kind": "domain",
                            "environment_id": f.receipt["environment"],
                            "domain_id": f.domain,
                        },
                        "pkcs8": encoded(pkcs8.read_bytes()),
                    }
                ],
            }
        )
    )
    return {
        "version": common["version"],
        "deploymentId": common["deployment_id"],
        "publicSpki": encoded(pub.read_bytes()),
        "spkiSha256": common["spki_sha256"],
        "notBefore": common["not_before"],
        "sealUntil": common["seal_until"],
        "openUntil": common["open_until"],
    }


def set_return_destination(f, api, destination):
    path = api.base + "/organization-domains/" + f.domain + "/invitation-delivery"
    delivery, tag = api.call("GET", path)
    channel = delivery["channel"] | {"returnUrl": destination}
    api.call(
        "PUT",
        path,
        {"channel": channel, "reason": "exercise changed hosted destination"},
        tag=tag,
        key=str(uuid4()),
    )


def routing(f, api):
    path = api.base + "/organization-domains/" + f.domain

    def update(method, path_, action, doc):
        _, tag = api.call("GET", path_)
        return api.call(method, path_ + action, doc, tag=tag, key=str(uuid4()))

    audience = f.receipt["issuer"] + "/organization-invitations"
    update(
        "POST",
        path,
        "/targets",
        {"audience": audience, "management": True, "reason": "recipient API"},
    )
    update(
        "POST",
        path,
        "/clients",
        {
            "clientRegistrationId": f.registered["client"]["id"],
            "active": True,
            "targets": [{"audience": audience, "privileges": [SCOPE]}],
            "reason": "exact recipient client",
        },
    )
    business = f.receipt["issuer"] + "/organizations"
    update(
        "POST",
        path,
        "/targets",
        {"audience": business, "management": True, "reason": "selected member access"},
    )
    update(
        "POST",
        path,
        "/clients",
        {
            "clientRegistrationId": f.app["client"]["id"],
            "active": True,
            "targets": [{"audience": business, "privileges": ADMIN}],
            "reason": "delegated invitation client",
        },
    )
    update(
        "PUT",
        path + "/role-policy",
        "",
        {
            "roles": [
                {
                    "key": "admin",
                    "privileges": ADMIN,
                    "managesMembers": True,
                    "assignableRoles": ["admin", "member"],
                },
                {
                    "key": "member",
                    "privileges": [READ],
                    "managesMembers": False,
                    "assignableRoles": [],
                },
            ],
            "reason": "organization roles",
        },
    )
    update(
        "PATCH",
        path + "/role-policy/display",
        "",
        {"labels": {"admin": "Administrator", "member": "Member"}, "reason": "label roles"},
    )
    update(
        "PUT",
        path + "/identity-policy",
        "",
        {
            "policy": {"registration": True, "passwordRecovery": True, "subjectFormat": "uuid"},
            "reason": "allow enrollment",
        },
    )
    update("POST", path, "/enable", {"reason": "enable domain"})
    delivery, tag = api.call("GET", path + "/invitation-delivery")
    revision = delivery["revision"] + 1
    settings = {
        "channel": {
            "defaultRevision": revision,
            "legacyRevision": None,
            "returnUrl": RETURN_URL,
            "routes": [
                {
                    "revision": revision,
                    "enabled": True,
                    "hostedClientRegistrationId": f.registered["client"]["id"],
                    "channel": {
                        "endpoint": "https://delivery.example.test/envelopes",
                        "credentialSha256": hashlib.sha256(
                            f.adapter_credential.encode()
                        ).hexdigest(),
                        "encryption": f.public,
                    },
                }
            ],
        },
        "reason": "pin hosted invitation profile",
    }
    # The disabled route can be staged before enabling issuance. Confirm that
    # the operator can explicitly select it in a subsequent guarded update.
    settings["channel"]["defaultRevision"] = None
    settings["channel"]["routes"][0]["enabled"] = False
    _, tag = api.call(
        "PUT", path + "/invitation-delivery", settings, tag=tag, key="stage-hosted-route"
    )
    settings["channel"]["defaultRevision"] = revision
    settings["channel"]["routes"][0]["enabled"] = True
    api.call("PUT", path + "/invitation-delivery", settings, tag=tag, key="enable-hosted-route")
    org, _ = api.call(
        "POST",
        path + "/organizations",
        {"externalId": "hosted-first-admin", "reason": "invite first admin"},
        key="hosted-organization",
    )
    org_path = path + "/organizations/" + org["id"]
    update(
        "PUT",
        org_path + "/display",
        "",
        {"displayName": "Example school", "reason": "show recipient organization"},
    )
    _, tag = api.call("GET", org_path)
    invitation, _ = api.call(
        "POST",
        org_path + "/invitations",
        {
            "recipient": "invitee@example.test",
            "roles": ["admin"],
            "lifetimeSeconds": 3600,
            "reason": "first administrator",
        },
        tag=tag,
        key="first-admin",
    )
    return org["id"], invitation["id"]
