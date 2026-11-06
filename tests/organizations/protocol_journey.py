"""Delivered recipient proof to selected organization JWT and current own RS access."""

from __future__ import annotations

from delivery_journey import require
from protocol_client import Client, ExpectedCodeRefusalError, ExpectedDpopRefusalError
from protocol_setup import READ


def accept_invitation(client, delivery, api, adapter, *, invitation_message=None):
    issuer = client.browser.issuer
    invitation_message = invitation_message or adapter.messages[0]
    invitation = invitation_message["invitationId"]
    capability = invitation_message["capability"]
    root = f"/organization-invitations/{api.domain}/{invitation}"
    parent = client.authorize()
    recipient = client.exchange(parent, issuer + "/organization-invitations")
    recipient_token = recipient["access_token"]
    client.verified(recipient_token, issuer + "/organization-invitations")
    # An ordinary code grant is not recipient authority, even from the same user.
    client.resource(
        "POST",
        root + "/challenges",
        parent["access_token"],
        body={"invitationCapability": capability},
        expected=401,
    )
    challenge = client.resource(
        "POST", root + "/challenges", recipient_token, body={"invitationCapability": capability}
    )
    before = len(adapter.messages)
    delivery.invoke(
        api,
        invitation,
        "recipient-proof",
        challenge=challenge["challengeId"],
        outcome="acknowledged",
    )
    require(len(adapter.messages) == before + 1, "recipient proof delivered exactly once")
    message = adapter.messages[-1]
    require(message["recipient"] == invitation_message["recipient"], "recipient proof address")
    body = {
        "invitationCapability": capability,
        "challengeId": challenge["challengeId"],
        "challengeCapability": message["capability"],
    }
    accepted = client.resource("POST", root + "/accept", recipient_token, body=body)
    replay = client.proof("POST", root + "/accept", recipient_token)
    require(
        client.resource("POST", root + "/accept", recipient_token, body=body, proof=replay)
        == accepted,
        "accept replay is current and idempotent with fresh proof",
    )
    client.resource(
        "POST", root + "/accept", recipient_token, body=body, proof=replay, expected=401
    )
    return accepted


def managed_journeys(client, api, adapter, organization, access):
    from audit_journey import exercise as audit_exercise  # noqa: PLC0415
    from delegated_journey import exercise as delegated_exercise  # noqa: PLC0415

    delegated = delegated_exercise(client, api, adapter, organization, access)
    client.delivery.secrets.extend(message["capability"] for message in adapter.messages)
    return {
        "delegatedManagement": delegated,
        "auditCustody": audit_exercise(client.delivery, api, client.browser),
    }


def exercise(delivery, api, adapter, browser):
    client = Client(delivery, browser, delivery.protocol_credentials)
    issuer = browser.issuer
    try:
        accepted = accept_invitation(client, delivery, api, adapter)
    except ExpectedDpopRefusalError:
        return {
            "passed": True,
            "missingRedisTimeRefused": True,
            "actualConsentCodeRefreshExchange": False,
        }
    organization = {"identifier": "School/学校-CaseSensitive-normal", "privileges": [READ]}
    try:
        parent = client.authorize(organization=organization)
    except ExpectedCodeRefusalError:
        return {"passed": True, "missingRedisStrlenRefused": True, "selectedCodeIssued": False}
    selected = client.exchange(parent, issuer + "/organizations", organization=organization)
    access = selected["access_token"]
    claims = client.verified(access, issuer + "/organizations")
    require(
        claims["authorization_details"][0]["identifier"] == organization["identifier"],
        "signed access token preserved exact UTF-8 external identifier",
    )
    client.inspect(access, active=True, identifier=organization["identifier"])
    context = client.resource("GET", "/organizations/context", access)
    require(
        context["organization"]["id"] == accepted["organizationId"]
        and context["organization"]["externalId"] == organization["identifier"],
        "own resource resolved exact internal/external organization identity",
    )
    wrong = client.proof("GET", "/organizations/context", "wrong-token")
    client.resource("GET", "/organizations/context", access, proof=wrong, expected=401)
    refreshed = client.token(
        {"grant_type": "refresh_token", "refresh_token": parent["refresh_token"]}
    )
    renewed = client.exchange(refreshed, issuer + "/organizations", organization=organization)
    client.resource("GET", "/organizations/context", renewed["access_token"])
    managed = managed_journeys(client, api, adapter, organization, access)
    # Current domain revocation invalidates both previously issued selected tokens.
    _, tag = api.call("GET", api.path)
    api.call(
        "POST",
        api.path + "/disable",
        {"reason": "currentness regression"},
        tag=tag,
        key="protocol-disable",
    )
    client.resource("GET", "/organizations/context", access, expected=401)
    client.resource("GET", "/organizations/context", renewed["access_token"], expected=401)
    client.inspect(access, active=False)
    delegate, credential, path, headers, body, _ = delivery.delegated_replay
    delegate.resource("PUT", path, credential, body=body, headers=headers, expected=401)
    return {
        "passed": True,
        "actualConsentCodeRefreshExchange": True,
        "recipientAddressProofAndAcceptance": True,
        "codeAndDpopReplayRefused": True,
        "signedJwtVerifiedIndependently": True,
        "utf8IdentifierPreserved": True,
        "ownResourceCurrentRevocation": True,
        "authenticatedJsonAndSignedIntrospection": True,
        **managed,
        "receiptReplayRechecksCurrentAuthority": True,
    }
