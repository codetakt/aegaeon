"""Delivered invitation to actual HTTPS credential enrollment; no injected user/session."""

from __future__ import annotations

import secrets
import time
from uuid import UUID, uuid4

from browser_transport import frontend
from delivery_journey import require


def journey(delivery, api, adapter, capability):  # noqa: PLR0915 — sequential credential lifecycle
    _, tag = api.call("GET", api.path + "/identity-policy")
    api.call(
        "PUT",
        api.path + "/identity-policy",
        {
            "policy": {"registration": True, "passwordRecovery": True, "subjectFormat": "uuid"},
            "reason": "explicit invitation-linked registration and recovery",
        },
        tag=tag,
        key="identity-policy",
    )
    invitation = adapter.messages[0]["invitationId"]
    delivery.checkpoint("identity-policy")
    path = f"/organization-invitations/{api.domain}/{invitation}/identity"
    with frontend(delivery, api.port) as browser:
        delivery.browser_events = browser.events
        requested = browser.form(
            path,
            {
                "action": "request",
                "purpose": "registration",
                "invitation_capability": capability,
                "request_key": str(uuid4()),
            },
        )
        request = requested["requestId"]
        delivery.checkpoint("registration-requested")
        delivery.invoke(
            api, invitation, "identity-proof", identity_request=request, outcome="acknowledged"
        )
        require(len(adapter.messages) == 2, "one registration proof envelope")
        message = adapter.messages[1]
        delivery.checkpoint("registration-proof-delivered")
        require(message["recipient"] == "Invitee@example.test", "address proof recipient binding")
        proof = message["capability"]
        password = "Fixture-" + secrets.token_urlsafe(32) + "-7!"
        delivery.secrets.extend([proof, password])
        enrolled_history = "AEGAEON_TEST_ORGANIZATION_ENROLLMENT_FIXTURE" in delivery.env
        completed = browser.form(
            path,
            {
                "action": "complete",
                "request_id": request,
                "proof": proof,
                "password": password,
                "password_confirmation": password,
            },
            expected=200 if enrolled_history else 503,
        )
        if not enrolled_history:
            delivery.checkpoint("unsealed-history-refused")
            return {
                "passed": True,
                "http_count": len(browser.events),
                "http": browser.events,
                "unsealedHistoryRefused": True,
                "registrationThroughHttps": False,
            }
        require(
            str(UUID(completed["subject"])) == completed["subject"], "plain immutable subject UUID"
        )
        delivery.checkpoint("registration-completed")
        require(
            not any(name == "aegaeon_auth_session" for name in browser.cookies),
            "credential enrollment did not create a login session",
        )
        replay = browser.form(
            path,
            {
                "action": "complete",
                "request_id": request,
                "proof": proof,
                "password": password,
                "password_confirmation": password,
            },
        )
        require(replay == completed, "registration replay preserved subject")
        replacement = "Fixture-" + secrets.token_urlsafe(32) + "-8!"
        delivery.secrets.append(replacement)
        browser.form(
            path,
            {
                "action": "complete",
                "request_id": request,
                "proof": proof,
                "password": replacement,
                "password_confirmation": replacement,
            },
            expected=409,
        )
        signed_in = browser.form(
            "/auth/login",
            {"identifier": completed["subject"], "password": password},
            json_response=False,
        )
        require("Your local sign-in succeeded" in signed_in, "actual credential login")
        require("aegaeon_auth_session" in browser.cookies, "actual login session cookie")
        browser.cookies.clear()
        recovery = browser.form(
            path,
            {
                "action": "request",
                "purpose": "password_recovery",
                "invitation_capability": capability,
                "request_key": str(uuid4()),
                "login_identifier": completed["subject"],
            },
        )
        delivery.invoke(
            api,
            invitation,
            "recovery-proof",
            identity_request=recovery["requestId"],
            outcome="acknowledged",
        )
        require(len(adapter.messages) == 3, "one recovery proof envelope")
        recovered = browser.form(
            path,
            {
                "action": "complete",
                "request_id": recovery["requestId"],
                "proof": adapter.messages[2]["capability"],
                "password": replacement,
                "password_confirmation": replacement,
            },
        )
        require(recovered["subject"] == completed["subject"], "recovery preserved subject")
        require("aegaeon_auth_session" not in browser.cookies, "recovery requires fresh login")
        browser.form(
            "/auth/login",
            {"identifier": completed["subject"], "password": password},
            expected=401,
            json_response=False,
        )
        # The adopted identity contract deliberately refuses authentication in
        # the same whole second as password replacement. Observe that boundary
        # read-only, then perform one fresh login, without fabricating auth_time
        # or retrying a failed Organizations request until it happens to pass.
        cutoff = delivery.checkpoint("password-recovered")
        require(type(cutoff) is int and cutoff >= 0, "current identity cutoff")
        delivery.reauthentication_cutoff = cutoff
        deadline = time.monotonic() + 2
        while time.time_ns() // 1_000_000_000 <= cutoff:
            require(time.monotonic() < deadline, "identity clock boundary exceeded two seconds")
            time.sleep(0.01)
        signed_in = browser.form(
            "/auth/login",
            {"identifier": completed["subject"], "password": replacement},
            json_response=False,
        )
        require("Your local sign-in succeeded" in signed_in, "replacement credential login")
        protocol = None
        delivery.checkpoint("recovered-and-logged-in")
        if hasattr(delivery, "protocol_credentials"):
            from protocol_journey import exercise  # noqa: PLC0415

            protocol = exercise(delivery, api, adapter, browser)
        require(
            all(
                secret not in output
                for output in delivery.outputs
                for secret in [
                    capability,
                    proof,
                    password,
                    replacement,
                    adapter.messages[2]["capability"],
                ]
            ),
            "CLI secret disclosure",
        )
        return {
            "passed": True,
            "http_count": len(browser.events),
            "http": browser.events,
            "registrationThroughHttps": True,
            "addressProofDelivered": True,
            "sessionNotImplicitlyCreated": True,
            "subjectIsUuid": True,
            "idempotentCompletionAndChangedPasswordRefusal": True,
            "actualPasswordLoginAndRecovery": True,
            "retiredPasswordRefused": True,
            "membershipAcceptanceAndProtocol": protocol or "pending",
            "supplierQualified": False,
        }
