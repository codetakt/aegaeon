"""Independent discovery/ID Token checks after authenticated key and policy setup."""

from __future__ import annotations

import json
import time
from urllib.parse import urlsplit

from delivery_journey import require


def provision_key(api, root, usage):
    environment, _ = api.call("GET", api.base)
    # This public test key is deliberately distinct from a deployment credential.
    pem = root / "crates/server/tests/fixtures/rsa2048-private.pk8.pem"
    result, _ = api.call(
        "POST",
        api.base + "/runtimeKeys",
        {
            "baseConfigurationVersionId": environment["activeConfigurationVersionId"],
            "usage": usage,
            "algorithm": "RS256",
            "provider": "databaseEncrypted",
            "kid": "custom-issuer-" + usage.lower(),
            "privateKeyPem": pem.read_text(),
            "activate": True,
            "comment": "explicit custom issuer OIDC acceptance key",
        },
        expected=201,
    )
    require(result["runtimeKey"]["status"] == "ACTIVE", "OIDC key activated through management")


def verify(client, tokens, nonce):
    issuer = client.browser.issuer
    client.browser.request(
        "GET",
        "/.well-known/openid-configuration",
        headers={"host": "foreign.example.test"},
        expected=421,
    )
    metadata = json.loads(client.browser.request("GET", "/.well-known/openid-configuration"))
    require(metadata["issuer"] == issuer, "discovery is the exact configured issuer")
    require(metadata["jwks_uri"].startswith(issuer + "/"), "JWKS uses the registered origin")
    keys = json.loads(client.browser.request("GET", urlsplit(metadata["jwks_uri"]).path))["keys"]
    result = client.crypto({"action": "verify", "token": tokens["id_token"], "keys": keys})
    claims = result["claims"]
    require(result["header"]["alg"] == "RS256", "ID Token uses the provisioned signing algorithm")
    require(claims["iss"] == issuer, "signed ID Token issuer matches discovery")
    require(
        claims["aud"] in (client.credentials["client"], [client.credentials["client"]]),
        "ID Token audience",
    )
    require(claims["nonce"] == nonce, "ID Token nonce belongs to this authorization")
    require(
        claims["exp"] > int(time.time()) and claims["iat"] <= int(time.time()) + 5,
        "ID Token time window",
    )
    access = client.verified(tokens["access_token"], issuer + "/userinfo")
    require(claims["sub"] == access["sub"], "OIDC and OAuth retain the same subject")
    previous_subject = getattr(client.delivery, "observed_subject", claims["sub"])
    require(claims["sub"] == previous_subject, "restart preserves the issued OIDC subject")
    client.delivery.observed_subject = claims["sub"]
    # The supported ingress strips client-supplied forwarding authority.
    forwarded = json.loads(
        client.browser.request(
            "GET",
            "/.well-known/openid-configuration",
            headers={
                "Forwarded": "proto=https;host=foreign.example.test",
                "X-Forwarded-Host": "foreign.example.test",
            },
        )
    )
    require(forwarded["issuer"] == issuer, "forwarded input cannot change the public issuer")
    client.delivery.protocol_observations.append(
        {
            "oidc_issuer": issuer,
            "signed_id_token": True,
            "discovery_exact": True,
            "subject_preserved": True,
            "forwarded_authority_ignored": True,
            "ingress_unknown_host_rejected": True,
        }
    )
