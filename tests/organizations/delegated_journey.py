"""Real enrollment, delegated membership and cross-organization HTTP boundaries."""

from __future__ import annotations

import secrets
import time
from urllib.parse import urlencode
from uuid import uuid4

from browser_transport import Browser
from delivery_journey import require
from protocol_client import Client
from protocol_setup import ADMIN


def selected(client, organization):
    parent = client.authorize(organization=organization)
    return client.exchange(
        parent, client.browser.issuer + "/organizations", organization=organization
    )["access_token"]


def enroll_member(delivery, api, adapter, browser, invitation):
    """A second browser obtains its own credential and session via delivered proof."""
    newcomer = Browser(delivery, browser.port)
    newcomer.events = browser.events
    path = f"/organization-invitations/{api.domain}/{invitation['invitationId']}/identity"
    requested = newcomer.form(
        path,
        {
            "action": "request",
            "purpose": "registration",
            "invitation_capability": invitation["capability"],
            "request_key": str(uuid4()),
        },
    )
    before = len(adapter.messages)
    delivery.invoke(
        api,
        invitation["invitationId"],
        "delegated-registration",
        identity_request=requested["requestId"],
        outcome="acknowledged",
    )
    require(len(adapter.messages) == before + 1, "one new member registration envelope")
    message = adapter.messages[-1]
    require(message["recipient"] == invitation["recipient"], "new member address proof")
    password = "Member-" + secrets.token_urlsafe(32) + "-9!"
    delivery.secrets.append(password)
    completed = newcomer.form(
        path,
        {
            "action": "complete",
            "request_id": requested["requestId"],
            "proof": message["capability"],
            "password": password,
            "password_confirmation": password,
        },
    )
    require("aegaeon_auth_session" not in newcomer.cookies, "no implicit member session")
    cutoff = delivery.checkpoint("member-registered")
    require(type(cutoff) is int and cutoff >= 0, "new member identity cutoff")
    deadline = time.monotonic() + 2
    while time.time_ns() // 1_000_000_000 <= cutoff:
        require(time.monotonic() < deadline, "new identity clock boundary exceeded two seconds")
        time.sleep(0.01)
    page = newcomer.form(
        "/auth/login",
        {
            "identifier": completed["subject"],
            "password": password,
        },
        json_response=False,
    )
    require("Your local sign-in succeeded" in page, "new member actual password login")
    client = Client(delivery, newcomer, delivery.protocol_credentials)
    client.authentication_cutoff = cutoff
    return client, completed["subject"]


def invite_member(client, api, adapter, access, organization):
    delivery = client.delivery
    context = client.resource("GET", "/organizations/context", access)
    path = f"/organizations/{organization}/invitations"
    body = {
        "recipient": "Member@example.test",
        "roles": ["member"],
        "lifetimeSeconds": 120,
        "reason": "explicit delegated invitation",
    }
    headers = {
        "if-match": context["organization"]["versionTag"],
        "idempotency-key": "delegated-member",
    }
    created = client.resource("POST", path, access, body=body, headers=headers)
    require(
        client.resource("POST", path, access, body=body, headers=headers) == created,
        "delegated invitation replay",
    )
    require(
        "capability" not in created and "recipient" not in created,
        "delegated invitation excludes address and capability",
    )
    before = len(adapter.messages)
    delivery.invoke(api, created["id"], "delegated-invitation", outcome="acknowledged")
    require(len(adapter.messages) == before + 1, "one delegated invitation envelope")
    return adapter.messages[-1]


def mutations(  # noqa: PLR0913 — independent principals and exact selected credentials
    client, member, access, member_access, *, organization, subject, administrator
):
    path = f"/organizations/{organization}/members/{subject}"
    first = client.resource("GET", path, access)
    original_tag = client.browser.last_response[1]["etag"]
    headers = {"if-match": original_tag, "idempotency-key": "suspend-member"}
    body = {"state": "suspended", "roles": ["member"], "reason": "suspend delegated member"}
    client.resource("PUT", path, access, body=body, expected=428)
    client.resource(
        "PUT",
        path,
        access,
        body={**body, "roles": ["auditor"]},
        headers={**headers, "idempotency-key": "unassignable-role"},
        expected=403,
    )
    suspended = client.resource("PUT", path, access, body=body, headers=headers)
    tag = client.browser.last_response[1]["etag"]
    require(
        suspended["revision"] == first["revision"] + 1 and suspended["state"] == "suspended",
        "delegated suspension advances revision once",
    )
    require(
        client.resource("PUT", path, access, body=body, headers=headers) == suspended,
        "complete semantic replay returns retained result",
    )
    client.resource(
        "PUT", path, access, body={**body, "reason": "different"}, headers=headers, expected=409
    )
    member.resource("GET", "/organizations/context", member_access, expected=401)
    client.resource(
        "PUT",
        path,
        access,
        body={**body, "state": "active"},
        headers={**headers, "idempotency-key": "stale-member"},
        expected=412,
    )
    restored = client.resource(
        "PUT",
        path,
        access,
        body={**body, "state": "active"},
        headers={"if-match": tag, "idempotency-key": "restore-member"},
    )
    require(
        restored["state"] == "active" and restored["revision"] > suspended["revision"],
        "explicit member restoration advances generation",
    )
    member.resource("GET", "/organizations/context", member_access, expected=401)
    self_path = f"/organizations/{organization}/members/{administrator}"
    client.resource("GET", self_path, access)
    client.resource(
        "PUT",
        self_path,
        access,
        body={"state": "removed", "roles": [], "reason": "last admin removal"},
        headers={
            "if-match": client.browser.last_response[1]["etag"],
            "idempotency-key": "last-admin",
        },
        expected=403,
    )
    return headers, body, suspended


def exercise(client, api, adapter, organization, readonly):  # noqa: PLR0915 — sequential protocol journey
    from protocol_journey import accept_invitation  # noqa: PLC0415

    delivery = client.delivery
    context = client.resource("GET", "/organizations/context", readonly)
    object_id = context["organization"]["id"]
    members_path = f"/organizations/{object_id}/members"
    client.resource("GET", members_path, readonly, expected=403)
    access = selected(client, {**organization, "privileges": ADMIN})
    administrator = client.resource("GET", members_path, access)["members"][0]["userId"]
    invitation = invite_member(client, api, adapter, access, object_id)
    member, subject = enroll_member(delivery, api, adapter, client.browser, invitation)
    accepted = accept_invitation(member, delivery, api, adapter, invitation_message=invitation)
    require(
        accepted["organizationId"] == object_id and accepted["userId"] == subject,
        "delegated acceptance uses the independently registered subject",
    )
    member_access = selected(member, organization)
    member.verified(member_access, client.browser.issuer + "/organizations")
    member.resource("GET", "/organizations/context", member_access)
    member.resource("GET", members_path, member_access, expected=403)

    first = client.resource("GET", members_path + "?limit=1", access)
    cursor = first["nextCursor"]
    require(cursor, "real bounded member pagination")
    second = client.resource(
        "GET", members_path + "?" + urlencode({"limit": 1, "after": cursor}), access
    )
    require(
        second["nextCursor"] is None
        and {first["members"][0]["userId"], second["members"][0]["userId"]}
        == {administrator, subject},
        "pagination returns both distinct members",
    )

    other_invitation, _ = api.invitation("other")
    delivery.invoke(api, other_invitation, "other-organization", outcome="acknowledged")
    other = accept_invitation(
        client, delivery, api, adapter, invitation_message=adapter.messages[-1]
    )
    other_selection = {"identifier": "School/学校-CaseSensitive-other", "privileges": ADMIN}
    other_access = selected(client, other_selection)
    other_path = f"/organizations/{other['organizationId']}/members"
    require(
        client.resource("GET", other_path, other_access)["members"][0]["userId"] == administrator,
        "same subject legitimately joins an independent organization",
    )
    client.resource("GET", other_path, access, expected=403)
    client.resource("GET", members_path, other_access, expected=403)
    client.resource(
        "GET", other_path + "?" + urlencode({"after": cursor}), other_access, expected=400
    )
    client.resource("GET", f"/organizations/{uuid4()}/members", access, expected=403)
    headers, body, suspended = mutations(
        client,
        member,
        access,
        member_access,
        organization=object_id,
        subject=subject,
        administrator=administrator,
    )
    renewed = selected(member, organization)
    member.resource("GET", "/organizations/context", renewed)
    # Preserve replay inputs so the caller can check current authority after disable.
    delivery.delegated_replay = (
        client,
        access,
        members_path + "/" + subject,
        headers,
        body,
        suspended,
    )
    return {
        "passed": True,
        "independentRegistrationAndDelegatedAcceptance": True,
        "twoOrganizationsNoConfusion": True,
        "paginationScopeBound": True,
        "originalPrivilegeAndAssignableRoleCeilings": True,
        "etagAndSemanticReplay": True,
        "suspensionAndFreshReauthorization": True,
        "lastAdministratorRetained": True,
    }
