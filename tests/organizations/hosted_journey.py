"""Exercise the hosted UI from a real reference adapter spool on an isolated network."""

from __future__ import annotations

import contextlib
import email.policy
import html
import http.server
import importlib.util
import json
import secrets
import signal
import ssl
import threading
from collections import Counter
from email.parser import BytesParser

from browser_transport import frontend
from current_database import connect
from current_issuer import Fixture
from delegated_journey import selected
from delivery_journey import require
from hosted_setup import (
    RETURN_URL,
    SCOPE,
    configure_store,
    exchange_policy,
    keys,
    register,
    register_domain,
    routing,
    set_return_destination,
)
from hosted_sso import Application
from issuer_configuration import (
    client_secret,
    policy,
    profile,
    register as register_application,
    user,
)
from issuer_oidc import provision_key
from protocol_client import Client
from protocol_setup import ADMIN, READ


def certificate(f, name, *alternative_names):
    directory = f.directory
    prefix = directory / name
    extension = prefix.with_suffix(".ext")
    extension.write_text(
        "basicConstraints=critical,CA:FALSE\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:"
        + ",DNS:".join([name, *alternative_names])
        + "\n"
    )
    crt, key, csr = [directory / (name + suffix) for suffix in [".crt", ".key", ".csr"]]
    for args in [
        [
            "req",
            "-new",
            "-newkey",
            "rsa:2048",
            "-noenc",
            "-subj",
            "/CN=" + name,
            "-keyout",
            key,
            "-out",
            csr,
        ],
        [
            "x509",
            "-req",
            "-in",
            csr,
            "-CA",
            directory / "trusted.crt",
            "-CAkey",
            directory / "trusted.key",
            "-CAcreateserial",
            "-days",
            "1",
            "-extfile",
            extension,
            "-out",
            crt,
        ],
    ]:
        require(f.run(["openssl", *args], timeout=15).returncode == 0, "fixture certificate")
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.minimum_version = ssl.TLSVersion.TLSv1_3
    tls.load_cert_chain(crt, key)
    return tls


class Mailbox(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        if self.headers.get("host") == "client.example.test":
            self.application_page()
            return
        if self.path not in {"/", "/member"} or self.headers.get("host") != "mailbox.example.org":
            self.send_error(404)
            return
        # This mailbox belongs to one synthetic test recipient. Decode the
        # actual MIME body from the v2 spool rather than reconstructing a link.
        items = []
        with contextlib.closing(self.server.spool.connect()) as db:
            for (mail,) in db.execute("SELECT mail FROM accepted ORDER BY rowid"):
                msg = BytesParser(policy=email.policy.default).parsebytes(mail)
                expected = (
                    "person@example.test" if self.path == "/member" else "invitee@example.test"
                )
                if str(msg["To"]) != expected:
                    continue
                links = [
                    line
                    for line in msg.get_content().splitlines()
                    if line.startswith(self.server.landing + "#aegaeon=")
                ]
                require(len(links) == 1, "single hosted mail link")
                items.append(
                    '<li><a href="'
                    + html.escape(links[0], quote=True)
                    + '">'
                    + html.escape(str(msg["Subject"]))
                    + "</a></li>"
                )
        page = (
            "<!doctype html><title>Test mailbox</title><ul>" + "".join(items) + "</ul>"
        ).encode()
        self.page(page)

    def application_page(self):
        if self.path.startswith(("/sso/", "/cb?")) and self.server.application is not None:
            self.server.application.serve(self)
            return
        if self.path != "/organizations" or any(
            self.headers.get(name) for name in ["Referer", "Authorization", "Cookie"]
        ):
            self.send_error(400)
            return
        self.server.application_returns += 1
        self.server.after_application_return()
        self.page(b"<!doctype html><title>Application</title><h1>Organization application</h1>")

    def page(self, page):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(page)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(page)


@contextlib.contextmanager
def threaded(server):
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(5)
        require(not thread.is_alive(), "fixture HTTPS server stopped")


@contextlib.contextmanager
def delivery_and_mailbox(f):
    source = f.root / "examples/notification-adapter/adapter.py"
    spec = importlib.util.spec_from_file_location("hosted_reference_adapter", source)
    adapter = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(adapter)
    landing = f.receipt["issuer"] + "/organization-invitations/hosted"
    spool = adapter.Spool(
        f.directory / "mailbox.sqlite",
        issuer=f.receipt["issuer"],
        recipient_ui=landing,
        sender="postmaster@example.test",
    )
    with threaded(
        adapter.Server(
            ("8.8.8.8", 443), certificate(f, "delivery.example.test"), spool, f.adapter_credential
        )
    ):
        mailbox = http.server.ThreadingHTTPServer(("127.0.0.2", 443), Mailbox)
        mailbox.spool, mailbox.landing = spool, landing
        mailbox.application_returns = 0
        mailbox.application = None
        mailbox.socket = certificate(f, "mailbox.example.org", "client.example.test").wrap_socket(
            mailbox.socket, server_side=True
        )
        with threaded(mailbox):
            yield spool, mailbox
            require(mailbox.application_returns == 1, "one exact secret-free application return")


def verify_callback_head(transport, store):
    callback = "/organization-invitations/hosted/callback"
    query = (
        "SELECT (SELECT count(*) FROM hosted_invitation.flow), "
        "(SELECT count(*) FROM hosted_invitation.cleanup)"
    )
    with connect(store) as db:
        require(db.execute(query).fetchone() == (0, 0), "empty fresh BFF store")
        body = transport.request("HEAD", callback, expected=405)
        _, headers = transport.last_response
        require(
            body == ""
            and headers.get("allow") == "GET"
            and headers.get("cache-control") == "no-store"
            and "location" not in headers
            and "set-cookie" not in headers,
            "bare HEAD advertises GET without redirecting or opening a session",
        )
        require(db.execute(query).fetchone() == (0, 0), "HEAD created no BFF flow or cleanup work")
        require(
            transport.frontend.hosted_trace == [("HEAD", callback, 405)], "HEAD made no issuer call"
        )


def verify_application_access(f, transport, org, *, admin_password, member_password, accept_member):  # noqa: PLR0913
    issuer = f.receipt["issuer"]
    transport.form(
        "/auth/login",
        {"identifier": "invitee@example.test", "password": admin_password},
        json_response=False,
    )
    app = Client(f, transport, f.app_secret)
    token = selected(app, {"identifier": "hosted-first-admin", "privileges": ADMIN})
    context = app.resource("GET", "/organizations/context", token)
    app.resource(
        "POST",
        f"/organizations/{org}/invitations",
        token,
        body={
            "recipient": "person@example.test",
            "roles": ["member"],
            "lifetimeSeconds": 600,
            "reason": "invite existing member",
        },
        headers={
            "if-match": context["organization"]["versionTag"],
            "idempotency-key": "hosted-member",
        },
    )
    transport.form(
        "/auth/login",
        {"identifier": "person@example.test", "password": member_password},
        json_response=False,
    )
    member_app = Client(f, transport, f.app_secret)
    member_root = member_app.authorize()
    selection = {"identifier": "hosted-first-admin", "privileges": [READ]}
    before = member_app.exchange(
        member_root, issuer + "/organizations", organization=selection, expected=400
    )
    sso = Application(
        member_app,
        app.verified(token, issuer + "/organizations")["sub"],
        member_app.verified(member_root["access_token"], issuer + "/userinfo")["sub"],
    )
    accept_member(sso)
    require(
        sso.observed == list(sso.subjects) and sso.prior_session_checked,
        "independent application SSO observed account replacement; original app session survived",
    )
    # The pre-membership credential is still live and unselected.
    # The independent client must obtain a new grant with a selection.
    member_app.verified(member_root["access_token"], issuer + "/userinfo")
    after = member_app.exchange(
        member_root, issuer + "/organizations", organization=selection, expected=400
    )
    require(before["error"] == after["error"], "unchanged independent grant")
    renewed = member_app.token(
        {"grant_type": "refresh_token", "refresh_token": member_root["refresh_token"]}
    )
    require(
        member_app.verified(renewed["access_token"], issuer + "/userinfo")["sub"] == sso.subjects[1]
        and renewed.get("authorization_details") is None,
        "original independent refresh grant remains usable without new membership authority",
    )
    new_access = selected(member_app, selection)
    context = member_app.resource("GET", "/organizations/context", new_access)
    require(context["organization"]["id"] == org, "fresh member application context")


def exercise(directory, package, connection, helpers, chromium):  # noqa: PLR0915 — ordered, real browser and worker lifecycle.
    f = Fixture(directory, package, connection, helpers, retain_operator_session=True)
    issuer = f.receipt["issuer"]
    for usage in ["OIDC_ID_TOKEN_SIGNING", "JWT_ACCESS_TOKEN_SIGNING"]:
        f.serve(usage.lower(), lambda api, u=usage: provision_key(api, f.root, u), restarts=True)
    f.serve(
        "hosted-policy",
        lambda api: policy(api, extra_scopes=[SCOPE, "documents"], access_token_ttl=30),
        restarts=True,
    )
    f.serve("hosted-profile", profile)
    f.domain = f.serve("hosted-domain", register_domain)
    f.registered = f.serve("hosted-client", lambda api: register(f, api))
    f.credentials = f.serve("hosted-client-secret", lambda api: client_secret(api, f.registered))
    f.app = f.serve(
        "application-client", lambda api: register_application(api, extra_scopes=["documents"])
    )
    f.app_secret = f.serve("application-secret", lambda api: client_secret(api, f.app))
    f.serve("hosted-exchange", lambda api: exchange_policy(f, api), restarts=True)
    f.adapter_credential = secrets.token_urlsafe(32)
    f.public = keys(f)
    hosted_store = configure_store(f)
    try:
        org, invitation = f.serve("hosted-routing", lambda api: routing(f, api))
    finally:
        (directory / "hosted-management.json").write_text(json.dumps(f.journal))

    def browser(api):
        # The second recipient already has credentials from a separate,
        # independently administered account.
        _, activate = user(api)
        admin_password = "Test-" + secrets.token_urlsafe(24) + "-1!"
        member_password = "Member-" + secrets.token_urlsafe(24) + "-2!"
        with (
            frontend(f, api.port, port=443) as transport,
            delivery_and_mailbox(f) as (spool, mailbox),
        ):
            transport.form(
                "/auth/activate",
                {
                    "token": activate["token"],
                    "password": member_password,
                    "password_confirmation": member_password,
                },
                json_response=False,
            )

            transport.frontend.hosted_trace = []
            verify_callback_head(transport, hosted_store)
            # After the first explicit return has reached the independent app,
            # the domain operator changes the destination on the actual issuer.
            mailbox.after_application_return = lambda: set_return_destination(
                f, api, "https://client.example.test/changed"
            )

            def run_browser(password, delegated, sso=None):
                mailbox.application = sso
                result = f.run(
                    ["node", f.root / "tests/organizations/hosted_mailbox.mjs"],
                    environment=f.env | {"AEGAEON_CHROMIUM": str(chromium)},
                    timeout=180,
                    data=json.dumps(
                        {
                            "directory": str(directory),
                            "issuer": issuer,
                            "organization": org,
                            "password": password,
                            "delegated": delegated,
                            "returnUrl": RETURN_URL,
                            "previousPassword": admin_password + "2" if delegated else None,
                            "parentLifetimeSeconds": 30,
                        }
                    ),
                    private_log=directory
                    / ("browser-member.log" if delegated else "browser-admin.log"),
                )
                (directory / "hosted-endpoints.json").write_text(
                    json.dumps(transport.frontend.hosted_trace)
                )
                require(result.returncode == 0, "Chromium mailbox walkthrough")

            def journey(worker):
                require(worker.poll() is None, "running worker")
                transport.frontend.drop_hosted_responses = {"challenges", "accept"}
                run_browser(admin_password, False)
                require(
                    not transport.frontend.drop_hosted_responses,
                    "post-commit nonces and idempotency replay recovered after two lost responses",
                )
                # The separate delegated flow opens with no registered destination.
                set_return_destination(f, api, None)
                verify_application_access(
                    f,
                    transport,
                    org,
                    admin_password=admin_password + "2",
                    member_password=member_password,
                    accept_member=lambda sso: run_browser(member_password, True, sso),
                )
                worker.send_signal(signal.SIGTERM)

            worker = f.run(
                [
                    f.package / "bin/aegaeon-notification-worker",
                    "--key-file",
                    directory / "worker.json",
                ],
                environment=f.env,
                timeout=230,
                before_wait=journey,
                private_log=directory / "worker.log",
            )
            require(worker.returncode == 0, "worker drain")
            with contextlib.closing(spool.connect()) as db:
                messages = Counter(
                    str(BytesParser(policy=email.policy.default).parsebytes(row[0])["Subject"])
                    for row in db.execute("SELECT mail FROM accepted")
                )
                require(
                    messages
                    == {
                        "Organization invitation": 2,
                        "Complete account registration": 1,
                        "Recover your account": 1,
                        "Confirm your invitation": 6,
                    },
                    "one message per explicit request, including the five shared admin challenges",
                )
        with connect(f.admin) as db:
            records = db.execute(
                "SELECT (SELECT state FROM aegaeon.application_organizations WHERE id=%s), "
                "(SELECT count(*) FROM aegaeon.organization_memberships WHERE organization_id=%s), "
                "(SELECT state FROM aegaeon.organization_invitations WHERE id=%s)",
                (org, org, invitation),
            ).fetchone()
            require(records == ("active", 2, "accepted"), "activated organization with two members")
        return {
            "first_admin": True,
            "delegated_member": True,
            "mail_templates": len(messages),
            "adapter_messages": dict(messages),
            "memberships": records[1],
        }

    try:
        return f.serve("hosted-mailbox", browser) | {"passed": True}
    finally:
        (directory / "hosted-management.json").write_text(json.dumps(f.journal))
