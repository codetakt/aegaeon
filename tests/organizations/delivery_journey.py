"""Authenticated HTTP provisioning followed by actual packaged one-shot delivery."""

from __future__ import annotations

import base64
import hashlib
import http.client
import json
import signal
import socket
import subprocess
import time
from contextlib import contextmanager

from delivery_adapter import Adapter


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


class Management:
    def __init__(self, port, receipt):
        self.port = port
        self.cookie = ""
        self.base = f"/api/v1/teams/{receipt['team']}/environments/{receipt['environment']}"
        self.counts = [0, 0]
        self.journal = []

    def call(self, method, path, body=None, **options):
        tag, key, expected = (
            options.get(k, default)
            for k, default in [("tag", None), ("key", None), ("expected", 200)]
        )
        headers = {"x-forwarded-proto": "https", "origin": "https://admin.example.test"}
        headers["cookie"] = self.cookie + "; csrf_token=fixture-csrf"
        headers["x-csrf-token"] = "fixture-csrf"
        if tag:
            headers["if-match"] = tag
        if key:
            headers["idempotency-key"] = key
        if body is not None:
            headers["content-type"] = "application/json"
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=20)
        try:
            conn.request(method, path, json.dumps(body) if body is not None else None, headers)
            response = conn.getresponse()
            content = response.read(65_537)
            self.journal.append({"method": method, "path": path, "status": response.status})
            if response.status >= 400 and content:
                # Only public management error text; never record successful
                # response bodies, cookies or transport envelopes.
                value = json.loads(content)
                self.journal[-1]["error"] = {k: value.get(k) for k in ("code", "message")}
            self.counts[0] += 1
            if path.startswith(self.base) and self.cookie:
                self.counts[1] += 1
            require(
                response.status == expected,
                f"{method} {path}: {response.status}, expected {expected}",
            )
            require(len(content) <= 65_536, "management response exceeded bound")
            if path == "/api/v1/authentication/sessions":
                self.cookie = next(
                    v.split(";", 1)[0]
                    for k, v in response.getheaders()
                    if k.lower() == "set-cookie" and v.startswith("aegaeon_admin_session=")
                )
            return json.loads(content) if content else None, response.getheader("etag")
        finally:
            conn.close()

    def setup(self, receipt, credential):
        self.call(
            "POST",
            "/api/v1/authentication/sessions",
            {
                "email": "owner@example.test",
                "password": "Independent-Fixture-Password-7!",
            },
            expected=204,
        )
        self.call(
            "POST",
            self.base + "/oauthProfiles",
            {
                "name": "Organization delivery profile",
                "profileType": "DOWNSTREAM",
                "isDefault": True,
                "requirePkce": True,
                "requireStateParameter": True,
                "requireIssParameter": True,
                "senderConstrained": "DPOP",
                "enforceRefreshSenderBinding": True,
                "allowedGrantTypes": [
                    "authorization_code",
                    "refresh_token",
                    "urn:ietf:params:oauth:grant-type:token-exchange",
                ],
                "tokenEndpointAuthMethodsAllowed": ["client_secret_basic"],
            },
            expected=201,
        )
        registered, _ = self.call(
            "POST",
            self.base + "/clients",
            {
                "baseConfigurationVersionId": receipt["configuration"],
                "name": "delivery client",
                "clientType": "CONFIDENTIAL",
                "redirectUris": ["https://client.example.test/cb"],
                "allowedGrantTypes": [
                    "authorization_code",
                    "urn:ietf:params:oauth:grant-type:token-exchange",
                ],
                "allowedScopes": ["openid"],
                "tokenEndpointAuthenticationMethod": "client_secret_basic",
                "dpopBoundAccessTokens": True,
            },
            expected=201,
        )
        domain, tag = self.call(
            "POST",
            self.base + "/organization-domains/default",
            {"reason": "bootstrap domain"},
            key="bootstrap",
        )
        self.client = registered["client"]
        self.domain = domain["id"]
        self.path = self.base + "/organization-domains/" + self.domain
        grant = domain["operator"]["id"]
        self.operator = grant
        # The initial configure capability cannot provision organizations.
        self.call(
            "POST",
            self.path + "/organizations",
            {"externalId": "denied", "reason": "denied"},
            key="denied",
            expected=403,
        )
        self.call(
            "PATCH",
            self.path + f"/operators/{grant}",
            {
                "active": True,
                "capabilities": ["configure", "provision"],
                "reason": "explicit grant",
            },
            tag=f'"{grant}.1"',
            key="grant",
        )
        _, tag = self.call("GET", self.path)
        _, tag = self.call(
            "POST",
            self.path + "/targets",
            {
                "audience": "management-api",
                "management": True,
                "reason": "management target",
            },
            tag=tag,
            key="target",
        )
        self.binding = self.call(
            "POST",
            self.path + "/clients",
            {
                "clientRegistrationId": registered["client"]["id"],
                "active": True,
                "targets": [
                    {"audience": "management-api", "privileges": ["organization.members.manage"]}
                ],
                "reason": "bind registered client",
            },
            tag=tag,
            key="binding",
        )
        _, tag = self.call("GET", self.path + "/role-policy")
        self.call(
            "PUT",
            self.path + "/role-policy",
            {
                "roles": [
                    {
                        "key": "admin",
                        "privileges": ["organization.members.manage"],
                        "managesMembers": True,
                        "assignableRoles": ["admin"],
                    }
                ],
                "reason": "administrator vocabulary",
            },
            tag=tag,
            key="roles",
        )
        _, tag = self.call("GET", self.path)
        self.call("POST", self.path + "/enable", {"reason": "enable domain"}, tag=tag, key="enable")
        self.channel("delivery.example.test", credential)

    def channel(self, host, credential):
        _, tag = self.call("GET", self.path + "/invitation-delivery")
        self.call(
            "PUT",
            self.path + "/invitation-delivery",
            {
                "channel": {
                    "endpoint": f"https://{host}/envelopes",
                    "credentialSha256": hashlib.sha256(credential.encode()).hexdigest(),
                },
                "reason": "delivery adapter",
            },
            tag=tag,
            key="channel-" + host,
        )

    def invitation(self, label):
        organization, tag = self.call(
            "POST",
            self.path + "/organizations",
            {
                "externalId": "School/学校-CaseSensitive-" + label,
                "reason": "provision organization",
            },
            key="organization-" + label,
        )
        require(
            organization["externalId"] == "School/学校-CaseSensitive-" + label,
            "external ID changed",
        )
        path = self.path + "/organizations/" + organization["id"] + "/invitations"
        body = {
            "recipient": "Invitee@example.test",
            "roles": ["admin"],
            "lifetimeSeconds": 3600,
            "reason": "first administrator",
        }
        invite, invite_tag = self.call("POST", path, body, tag=tag, key="invite-" + label)
        # Identical replay must return the same invitation, not enqueue another envelope.
        repeated, _ = self.call("POST", path, body, tag=tag, key="invite-" + label)
        require(repeated == invite, "invitation replay changed object")
        require("capability" not in invite, "management exposed delivery capability")
        return invite["id"], invite_tag


class Delivery:
    def __init__(self, directory, package, environment, run):
        self.directory, self.package, self.run = directory, package, run
        self.receipt = json.loads((directory / "bootstrap.json").read_text())
        self.config = directory / "runtime.json"
        self.env = environment | {
            "AEGAEON_ORGANIZATION_RUNTIME_CONFIG": str(self.config),
            "AEGAEON_RUNTIME_ISSUER_HOST": self.receipt["issuer_host"],
        }
        self.credential = base64.urlsafe_b64encode(bytes([37]) * 32).decode().rstrip("=")
        self.counts = 0
        self.outputs = []
        self.secrets = [self.credential]
        self.events = []
        self.observe = None

    def checkpoint(self, label):
        if self.observe:
            return self.observe(label)
        return None

    def invoke(self, api, invitation, label, **options):
        config = options.get("trust_config", self.config)
        password = options.get("password", self.credential)
        outcome = options.get("outcome")
        result = self.run(
            [self.package / "bin/aegaeon-organization-delivery"],
            environment=self.env | {"AEGAEON_ORGANIZATION_RUNTIME_CONFIG": str(config)},
            data=json.dumps(
                {"domainId": api.domain, "invitationId": invitation, "credential": password}
                | (
                    {"identityRequestId": options["identity_request"]}
                    if options.get("identity_request")
                    else {}
                )
                | ({"challengeId": options["challenge"]} if options.get("challenge") else {})
            ),
            timeout=100,
        )
        self.outputs.extend([result.stdout, result.stderr])
        value = json.loads(result.stdout) if result.returncode == 0 else {}
        self.events.append(
            {"label": label, "returncode": result.returncode, "outcome": value.get("outcome")}
        )
        self.counts += 2
        require(self.credential not in result.stdout + result.stderr, "CLI credential disclosure")
        require(
            (result.returncode == 0) == (outcome is not None), f"{label}: unexpected CLI status"
        )
        if outcome is not None:
            require(value["outcome"] == outcome, f"{label}: unexpected delivery outcome")
            require(value["invitationId"] == invitation, f"{label}: invitation mismatch")

    def normal(self, api, adapter):
        invitation, _ = api.invitation("normal")
        wrong = base64.urlsafe_b64encode(bytes([38]) * 32).decode().rstrip("=")
        self.invoke(api, invitation, "wrong-credential", password=wrong)
        require(not adapter.messages, "invalid credential sent an envelope")
        self.invoke(api, invitation, "normal", outcome="acknowledged")
        self.invoke(api, invitation, "repeat", outcome="idle")
        require(len(adapter.messages) == 1, "normal delivery/replay count")
        message = adapter.messages[0]
        require(
            all(
                message[k] == v
                for k, v in {
                    "template": "organization_invitation",
                    "recipient": "Invitee@example.test",
                    "environmentId": self.receipt["environment"],
                    "domainId": api.domain,
                    "invitationId": invitation,
                    "issuer": self.receipt["issuer"],
                    "received_authorization": "Bearer " + self.credential,
                }.items()
            ),
            "delivery envelope binding",
        )
        require(bool(message["capability"]), "missing capability")
        return message["capability"]

    def transport_boundaries(self, api, adapter):
        document = json.loads(self.config.read_text())
        alternate = self.directory / "other-origin.json"
        cases = [
            ("unmatched-trust", "other.example.test", None, True),
            ("wrong-name", "wrong.example.test", "wrong.example.test", True),
            ("private-dns", "private.example.test", "private.example.test", False),
        ]
        for label, origin, host, contacted in cases:
            document["delivery_trust"][0]["origin"] = "https://" + origin
            alternate.write_text(json.dumps(document))
            alternate.chmod(0o600)
            if host:
                api.channel(host, self.credential)
            invitation, _ = api.invitation(label)
            before = adapter.connections
            self.invoke(api, invitation, label, trust_config=alternate, outcome="uncertain")
            require(
                (adapter.connections > before) == contacted and len(adapter.messages) == 1,
                f"{label}: DNS/TLS boundary",
            )


def ready(process, port):
    deadline = time.monotonic() + 30
    while True:
        require(process.poll() is None, "packaged server exited before readiness")
        require(time.monotonic() < deadline, "packaged server readiness timeout")
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
        try:
            conn.request("GET", "/health")
            response = conn.getresponse()
            response.read()
            require(response.status == 200, "unexpected readiness response")
        except OSError:
            pass
        else:
            return 1
        finally:
            conn.close()
        time.sleep(0.02)


@contextmanager
def serving(delivery, port, *, reload_configuration=False):
    sequence = len(list(delivery.directory.glob("delivery-server-*.log")))
    with (delivery.directory / f"delivery-server-{sequence}.log").open("x") as log:
        process = subprocess.Popen(  # noqa: S603 — immutable package and explicit argv
            [
                str(delivery.package / "bin/aegaeon-organizations-server"),
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
            ],
            env=delivery.env,
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=log,
        )
    try:
        health_requests = ready(process, port)
        yield health_requests
        if reload_configuration:
            require(
                process.wait(timeout=55) == 1, "configuration change requests supervised restart"
            )
            require(
                "runtime authority requested server restart"
                in (delivery.directory / f"delivery-server-{sequence}.log").read_text(),
                "restart is the observed configuration transition",
            )
        else:
            process.send_signal(signal.SIGTERM)
            require(process.wait(timeout=55) == 0, "packaged server shutdown")
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=10)


def journey(  # noqa: PLR0913, PLR0915 — bounded process lifecycle
    directory, package, environment, run, report, *, enrollment=False, protocol=False, observe=None
):
    delivery = Delivery(directory, package, environment, run)
    delivery.observe = observe
    delivery.checkpoint("before-server")
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    api = Management(port, delivery.receipt)
    adapter = Adapter(directory)
    try:
        with serving(delivery, port, reload_configuration=protocol) as health_requests:
            delivery.checkpoint("ready")
            api.setup(delivery.receipt, delivery.credential)
            delivery.checkpoint("management-setup")
            if protocol:
                from protocol_setup import allow_scopes  # noqa: PLC0415

                allow_scopes(api)
            else:
                capability = delivery.normal(api, adapter)
                delivery.checkpoint("invitation-delivered")
            enrolled = None
            if enrollment and not protocol:
                from enrollment_journey import journey as enroll  # noqa: PLC0415

                enrolled = enroll(delivery, api, adapter, capability)
            elif not protocol:
                delivery.transport_boundaries(api, adapter)
            if not protocol:
                require(
                    all(capability not in output for output in delivery.outputs),
                    "CLI capability disclosure",
                )
        if protocol:
            from enrollment_journey import journey as enroll  # noqa: PLC0415
            from protocol_setup import configure  # noqa: PLC0415

            with serving(delivery, port, reload_configuration=True) as reconfigured_health:
                health_requests += reconfigured_health
                delivery.protocol_credentials = configure(api, delivery.receipt["issuer"])
                delivery.secrets.append(delivery.protocol_credentials["secret"])
            with serving(delivery, port) as restarted_health:
                health_requests += restarted_health
                capability = delivery.normal(api, adapter)
                enrolled = enroll(delivery, api, adapter, capability)
        delivery.checkpoint("after-server")
        delivery.secrets.extend(message["capability"] for message in adapter.messages)
        logs = [path.read_text() for path in directory.glob("delivery-server-*.log")]
        require(
            all(
                secret not in output
                for secret in delivery.secrets
                for output in [*delivery.outputs, *logs]
            ),
            "packaged server or CLI disclosed a credential or capability",
        )
        report["journey"] = {
            "passed": True,
            "http": api.journal,
            "envelopes": len(adapter.messages),
            "transport_connections": adapter.connections,
            "readiness_http_requests": health_requests,
            "expected_generations": [
                (12 if protocol else 4) + n + delivery.counts for n in api.counts
            ],
        }
        if enrolled:
            report["journey"]["enrollment"] = enrolled
            report["journey"]["expected_generations"] = [
                value + enrolled["http_count"]
                for value in report["journey"]["expected_generations"]
            ]
    finally:
        report["journey_http"] = api.journal
        report["journey_browser"] = getattr(delivery, "browser_events", [])
        report["protocol_observations"] = getattr(delivery, "protocol_observations", [])
        report["audit_consumer_outcomes"] = getattr(delivery, "audit_outcomes", [])
        report["journey_cli"] = delivery.events
        report["adapter"] = {
            "connections": adapter.connections,
            "envelopes": len(adapter.messages),
            "tls_errors": adapter.tls_errors,
        }
        adapter.close()
