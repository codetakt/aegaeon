"""Provision the custom-issuer fixture using authenticated management APIs."""

from __future__ import annotations

from uuid import uuid4

from delivery_journey import require

GRANTS = ["authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:token-exchange"]


def login(api):
    api.call(
        "POST",
        "/api/v1/authentication/sessions",
        {"email": "owner@example.test", "password": "Independent-Fixture-Password-7!"},
        expected=204,
    )


def policy(api):
    environment, _ = api.call("GET", api.base)
    current = environment["activeConfigurationVersionId"]
    version, _ = api.call("GET", api.base + "/configurationVersions/" + current)
    document = version["configurationDocument"]
    document["scopeAllowlist"] = ["openid", "read", "offline_access"]
    document["policy"].update(
        oidcEnabled=True,
        jwtAccessTokensEnabled=True,
        allowedGrantTypes=GRANTS,
        retainRefreshChain=True,
        enforceRefreshSenderBinding=True,
        accessTokenTimeToLiveSeconds=300,
        authorizationDetailsTypesSupported=[
            "https://github.com/codetakt/aegaeon/spec/organization-grant/v1",
            "https://github.com/codetakt/aegaeon/spec/organization-access/v1",
        ],
    )
    created, _ = api.call(
        "POST",
        api.base + "/configurationVersions",
        {
            "baseConfigurationVersionId": current,
            "configurationDocument": document,
            "comment": "explicit custom issuer protocol acceptance policy",
        },
        expected=201,
    )
    api.call(
        "POST",
        api.base + "/configurationVersions/" + created["id"] + "/activate",
        {"allowSecurityDowngrade": True, "reason": "explicit OIDC and renewable authorization"},
    )


def profile(api):
    api.call(
        "POST",
        api.base + "/oauthProfiles",
        {
            "name": "Issuer acceptance",
            "profileType": "DOWNSTREAM",
            "isDefault": True,
            "requirePkce": True,
            "requireStateParameter": True,
            "requireIssParameter": True,
            "senderConstrained": "DPOP",
            "enforceRefreshSenderBinding": True,
            "allowedGrantTypes": GRANTS,
            "tokenEndpointAuthMethodsAllowed": ["client_secret_basic"],
        },
        expected=201,
    )


def register(api):
    environment, _ = api.call("GET", api.base)
    registered, _ = api.call(
        "POST",
        api.base + "/clients",
        {
            "baseConfigurationVersionId": environment["activeConfigurationVersionId"],
            "name": "custom issuer client",
            "clientType": "CONFIDENTIAL",
            "redirectUris": ["https://client.example.test/cb"],
            "allowedGrantTypes": GRANTS,
            "allowedScopes": ["openid", "read", "offline_access"],
            "tokenEndpointAuthenticationMethod": "client_secret_basic",
            "dpopBoundAccessTokens": True,
        },
        expected=201,
    )
    return registered


def client_secret(api, registered):
    secret, _ = api.call(
        "POST",
        api.base + "/clients/" + registered["client"]["id"] + "/clientSecrets",
        {
            "baseConfigurationVersionId": registered["environment"]["activeConfigurationVersionId"],
            "expiresInDays": 1,
            "comment": "owned issuer acceptance client",
        },
        expected=201,
    )
    return {
        "client": registered["client"]["clientIdentifier"],
        "secret": secret["clientSecretValue"],
    }


def user(api):
    created, _ = api.call(
        "POST",
        api.base + "/users",
        {"subject": str(uuid4()), "email": "person@example.test"},
        key=str(uuid4()),
        expected=201,
    )
    token, _ = api.call(
        "POST",
        api.base + "/users/" + created["id"] + "/activationTokens",
        {"expiresInSeconds": 600},
    )
    return created, token


def organization(api, registered):
    domain, _ = api.call(
        "POST",
        api.base + "/organization-domains/default",
        {"reason": "issuer compatibility"},
        key="issuer-domain",
    )
    path = api.base + "/organization-domains/" + domain["id"]
    grant = domain["operator"]["id"]
    api.call(
        "POST",
        path + "/organizations",
        {"externalId": "denied", "reason": "least privilege"},
        key="issuer-denied",
        expected=403,
    )
    api.call(
        "PATCH",
        path + "/operators/" + grant,
        {
            "active": True,
            "capabilities": ["configure", "provision", "reconcile"],
            "reason": "explicit grant",
        },
        tag=f'"{grant}.1"',
        key="issuer-grant",
    )
    _, tag = api.call("GET", path)
    _, tag = api.call(
        "POST",
        path + "/targets",
        {"audience": "management-api", "management": True, "reason": "explicit target"},
        tag=tag,
        key="issuer-target",
    )
    api.call(
        "POST",
        path + "/clients",
        {
            "clientRegistrationId": registered["client"]["id"],
            "active": True,
            "targets": [
                {"audience": "management-api", "privileges": ["organization.members.manage"]}
            ],
            "reason": "explicit client",
        },
        tag=tag,
        key="issuer-binding",
    )
    _, tag = api.call("GET", path)
    api.call(
        "POST", path + "/enable", {"reason": "explicit activation"}, tag=tag, key="issuer-enable"
    )
    created, _ = api.call(
        "POST",
        path + "/organizations",
        {"externalId": "custom-issuer", "reason": "issuer compatibility"},
        key="issuer-create",
    )
    observed, _ = api.call("GET", path + "/organizations/" + created["id"])
    require(observed["id"] == created["id"], "organization persists under the custom issuer")
    return path + "/organizations/" + created["id"]
