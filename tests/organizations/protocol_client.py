"""Independent OAuth client: actual consent/code/refresh/exchange, PKCE and DPoP."""

from __future__ import annotations

import base64
import hashlib
import html
import json
import secrets
import shutil
import time
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit
from uuid import uuid4

from delivery_journey import require
from protocol_setup import EXCHANGE

GRANT = "https://github.com/codetakt/aegaeon/spec/organization-grant/v1"
ACCESS = "https://github.com/codetakt/aegaeon/spec/organization-access/v1"


class ExpectedDpopRefusalError(Exception):
    """The deliberately incomplete Redis ACL refuses actual nonce issuance."""


class ExpectedCodeRefusalError(Exception):
    """An incomplete ACL cannot preflight the retained authorization-code counter."""


def encoded(data):
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def packed(value):
    return encoded(json.dumps(value, separators=(",", ":"), sort_keys=True).encode())


def hidden(page, name):
    marker = f'name="{name}" value="'
    require(marker in page, f"missing form field {name}")
    return html.unescape(page.split(marker, 1)[1].split('"', 1)[0])


class Client:
    def __init__(self, delivery, browser, credentials):
        self.delivery, self.browser, self.credentials = delivery, browser, credentials
        self.key = self.crypto({"action": "generate"})
        public = self.key["public"]
        self.jkt = encoded(
            hashlib.sha256(
                json.dumps(
                    {k: public[k] for k in ["crv", "kty", "x"]},
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()
            ).digest()
        )
        self.nonces = {}
        self.jwks = None
        self.authentication_cutoff = delivery.reauthentication_cutoff
        if not hasattr(self.delivery, "protocol_observations"):
            self.delivery.protocol_observations = []

    def crypto(self, value):
        result = self.delivery.run(
            [
                shutil.which("node") or "/missing/node",
                Path(__file__).with_name("protocol_crypto.mjs"),
            ],
            data=json.dumps(value),
            timeout=10,
        )
        require(result.returncode == 0, "independent cryptographic client failed")
        return json.loads(result.stdout)

    def proof(self, method, path, token=None, *, group="resource", overrides=None):
        claims = {
            "jti": str(uuid4()),
            "iat": int(time.time()),
            "htm": method,
            "htu": self.browser.issuer + urlsplit(path).path,
        }
        if token:
            claims["ath"] = encoded(hashlib.sha256(token.encode()).digest())
        if group in self.nonces:
            claims["nonce"] = self.nonces[group]
        claims.update(overrides or {})
        data = (
            packed({"typ": "dpop+jwt", "alg": "EdDSA", "jwk": self.key["public"]})
            + "."
            + packed(claims)
        )
        signature = self.crypto({"action": "sign", "key": self.key["private"], "data": data})
        return data + "." + signature["signature"]

    def basic(self):
        return (
            "Basic "
            + base64.b64encode(
                (self.credentials["client"] + ":" + self.credentials["secret"]).encode()
            ).decode()
        )

    def token(self, fields, *, expected=200):
        for attempt in range(2):
            value = json.loads(
                self.browser.request(
                    "POST",
                    "/token",
                    fields,
                    expected=(200, 400, 401, 503),
                    headers={
                        "authorization": self.basic(),
                        "dpop": self.proof("POST", "/token", group="token"),
                    },
                )
            )
            status, headers = self.browser.last_response
            if "AEGAEON_TEST_DENY_DPOP_TIME" in self.delivery.env:
                require(
                    status == 503
                    and value.get("error") == "temporarily_unavailable"
                    and value.get("error_description") == "DPoP protection backend unavailable",
                    "old Redis ACL must refuse DPoP issuance without a fallback",
                )
                raise ExpectedDpopRefusalError
            if value.get("error") != "use_dpop_nonce":
                require(
                    status == expected,
                    f"token response {status}, expected {expected}: {value.get('error')}",
                )
                return value
            require(
                attempt == 0 and headers.get("dpop-nonce"),
                "bounded authorization server nonce challenge",
            )
            self.nonces["token"] = headers["dpop-nonce"]
        message = "nonce challenge limit"
        raise AssertionError(message)

    def authorize(self, *, organization=None):
        verifier = secrets.token_urlsafe(48)
        state = secrets.token_urlsafe(24)
        fields = {
            "client_id": self.credentials["client"],
            "response_type": "code",
            "redirect_uri": "https://client.example.test/cb",
            "scope": "read offline_access",
            "prompt": "consent",
            "state": state,
            "iss": self.browser.issuer,
            "resource": self.browser.issuer + "/userinfo",
            "code_challenge_method": "S256",
            "code_challenge": encoded(hashlib.sha256(verifier.encode()).digest()),
            "dpop_jkt": self.jkt,
        }
        if organization:
            fields["authorization_details"] = json.dumps(
                [
                    {
                        "type": GRANT,
                        "locations": [self.browser.issuer + "/organizations"],
                        "organizations": [organization],
                    }
                ]
            )
        page = self.browser.request("GET", "/authorize?" + urlencode(fields))
        transaction = hidden(page, "transaction")
        approved = self.browser.request(
            "POST", "/auth/consent", {"transaction": transaction, "decision": "approve"}
        )
        marker = 'id="aegaeon-continuation" href="'
        require(marker in approved, "authorization continuation missing")
        target = urlsplit(html.unescape(approved.split(marker, 1)[1].split('"', 1)[0]))
        require(
            target.scheme == "https"
            and target.netloc == "client.example.test"
            and target.path == "/cb",
            "exact client redirect",
        )
        query = parse_qs(target.query)
        require(
            query.get("state") == [state] and query.get("iss") == [self.browser.issuer],
            "authorization response binding",
        )
        if organization and "AEGAEON_TEST_DENY_CODE_STRLEN" in self.delivery.env:
            require(
                query.get("error") == ["server_error"]
                and query.get("error_description") == ["authorization-code storage is unavailable"]
                and "code" not in query,
                "old Redis ACL must refuse code issuance without a fallback",
            )
            raise ExpectedCodeRefusalError
        require(
            len(query.get("code", [])) == 1,
            f"one authorization code: {query.get('error', [])}",
        )
        fields = {
            "grant_type": "authorization_code",
            "code": query["code"][0],
            "redirect_uri": "https://client.example.test/cb",
            "code_verifier": verifier,
        }
        parent = self.token(fields)
        require(
            parent["token_type"] == "DPoP" and parent.get("refresh_token"),  # noqa: S105 — protocol value
            "sender bound renewable grant",
        )
        self.token(fields, expected=400)
        return parent

    def exchange(self, parent, audience, *, organization=None):
        fields = {
            "grant_type": EXCHANGE,
            "subject_token": parent["access_token"],
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "audience": audience,
        }
        if organization:
            fields["authorization_details"] = json.dumps([{"type": ACCESS, **organization}])
        return self.token(fields)

    def resource(self, method, path, token, *, body=None, expected=200, proof=None, headers=None):  # noqa: PLR0913
        for attempt in range(2):
            signed = proof if proof is not None else self.proof(method, path, token)
            value = json.loads(
                self.browser.request(
                    method,
                    path,
                    expected=(expected, 401),
                    json_body=body,
                    headers={
                        "authorization": "DPoP " + token,
                        "dpop": signed,
                        "idempotency-key": "recipient-acceptance",
                    }
                    | (headers or {}),
                )
            )
            status, response_headers = self.browser.last_response
            if value.get("error") != "use_dpop_nonce" or proof is not None:
                require(
                    status == expected,
                    f"resource response {status}, expected {expected}: {value.get('error')}",
                )
                return value
            require(
                attempt == 0 and response_headers.get("dpop-nonce"),
                "bounded resource server nonce challenge",
            )
            self.nonces["resource"] = response_headers["dpop-nonce"]
        message = "resource nonce challenge limit"
        raise AssertionError(message)

    def verified(self, token, audience):
        if self.jwks is None:
            self.jwks = json.loads(self.browser.request("GET", "/jwks"))["keys"]
        result = self.crypto({"action": "verify", "token": token, "keys": self.jwks})
        claims = result["claims"]
        self.delivery.protocol_observations.append(
            {
                "audience": audience,
                "auth_time": claims.get("auth_time"),
                "iat": claims["iat"],
                "exp": claims["exp"],
                "scope": claims.get("scope"),
            }
        )
        require(
            self.authentication_cutoff < claims["auth_time"] <= int(time.time()),
            "actual authentication is strictly after the retained identity cutoff",
        )
        require(
            claims["iss"] == self.browser.issuer and claims["aud"] == audience,
            "signed token issuer/audience",
        )
        require(
            0 < claims["exp"] - claims["iat"] <= 300 and claims["exp"] > int(time.time()),
            "short token lifetime",
        )
        require(claims["cnf"]["jkt"] == self.jkt, "signed token sender binding")
        return claims

    def inspect(self, token, *, active, identifier=None):
        for signed in [False, True]:
            headers = {"authorization": self.basic()}
            if signed:
                headers["accept"] = "application/token-introspection+jwt"
            raw = self.browser.request("POST", "/introspect", {"token": token}, headers=headers)
            if signed:
                result = self.crypto({"action": "verify", "token": raw, "keys": self.jwks})
                claims = result["claims"]
                require(
                    claims["iss"] == self.browser.issuer
                    and claims["aud"] == self.credentials["client"],
                    "signed introspection issuer and recipient",
                )
                require(claims["exp"] > int(time.time()), "current signed introspection")
                value = claims["token_introspection"]
            else:
                value = json.loads(raw)
            require(value["active"] == active, "current introspection activity")
            if active:
                require(
                    value["authorization_details"][0]["identifier"] == identifier,
                    "introspection preserved exact external organization ID",
                )
            else:
                require(
                    value == {"active": False},
                    "inactive introspection does not disclose organization",
                )
