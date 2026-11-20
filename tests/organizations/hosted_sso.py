"""Independent OIDC relying party used by the invitation browser walkthrough."""

from __future__ import annotations

import hashlib
import json
import secrets
import time
from http.cookies import SimpleCookie
from urllib.parse import parse_qs, urlencode, urlsplit

from delivery_journey import require
from protocol_client import encoded

CALLBACK = "https://client.example.test/cb"
COOKIE = "fixture_application_session"


class Application:
    def __init__(self, client, administrator, member, before_accept):
        require(administrator != member, "two independent issuer subjects")
        self.client = client
        self.subjects = (administrator, member)
        self.observed = []
        self.pending = None
        self.session = None
        self.prior_session_checked = False
        self.before_accept = before_accept

    def redirect(self, handler, location, cookie):
        handler.send_response(303)
        handler.send_header("Location", location)
        handler.send_header("Set-Cookie", cookie)
        handler.send_header("Cache-Control", "no-store")
        handler.send_header("Referrer-Policy", "no-referrer")
        handler.send_header("Content-Length", "0")
        handler.end_headers()

    def start(self, handler):
        require(len(self.observed) < 2 and self.pending is None, "one pending SSO request")
        state, verifier, nonce = (secrets.token_urlsafe(32) for _ in range(3))
        self.pending = state, verifier, nonce
        issuer = self.client.browser.issuer
        fields = {
            "iss": issuer,
            "response_type": "code",
            "client_id": self.client.credentials["client"],
            "redirect_uri": CALLBACK,
            "resource": issuer + "/userinfo",
            "scope": "openid read",
            "prompt": "none",
            "state": state,
            "nonce": nonce,
            "dpop_jkt": self.client.jkt,
            "code_challenge_method": "S256",
            "code_challenge": encoded(hashlib.sha256(verifier.encode()).digest()),
        }
        self.redirect(
            handler,
            issuer + "/authorize?" + urlencode(fields),
            f"fixture_sso={state}; Path=/cb; Secure; HttpOnly; SameSite=Lax",
        )

    def callback(self, handler, path, cookies):
        require(self.pending is not None, "application SSO request was initiated")
        state, verifier, nonce = self.pending
        self.pending = None
        query = parse_qs(path.query)
        issuer = self.client.browser.issuer
        require(
            query.get("state") == [state]
            and query.get("iss") == [issuer]
            and cookies.get("fixture_sso")
            and cookies["fixture_sso"].value == state
            and len(query.get("code", [])) == 1,
            "application SSO response binding",
        )
        tokens = self.client.token(
            {
                "grant_type": "authorization_code",
                "code": query["code"][0],
                "redirect_uri": CALLBACK,
                "code_verifier": verifier,
            }
        )
        access = self.client.verified(tokens["access_token"], issuer + "/userinfo")
        metadata = json.loads(
            self.client.browser.request("GET", "/.well-known/openid-configuration")
        )
        require(metadata["issuer"] == issuer, "application OIDC metadata issuer")
        keys = json.loads(self.client.browser.request("GET", urlsplit(metadata["jwks_uri"]).path))[
            "keys"
        ]
        signed = self.client.crypto({"action": "verify", "token": tokens["id_token"], "keys": keys})
        claims = signed["claims"]
        subject = self.subjects[len(self.observed)]
        require(
            signed["header"]["alg"] == "RS256"
            and claims["iss"] == issuer
            and claims["aud"]
            in (self.client.credentials["client"], [self.client.credentials["client"]])
            and claims["nonce"] == nonce
            and claims["exp"] > int(time.time())
            and claims["sub"] == access["sub"] == subject,
            "application SSO signed subject",
        )
        self.observed.append(subject)
        if self.session is None:
            self.session = (secrets.token_urlsafe(32), subject)
            cookie = f"{COOKIE}={self.session[0]}; Path=/sso; Secure; HttpOnly; SameSite=Lax"
        else:
            cookie = "fixture_sso=; Max-Age=0; Path=/cb; Secure; HttpOnly; SameSite=Lax"
        self.redirect(handler, "/sso/observed", cookie)

    def session_page(self, handler, path, cookies):
        require(
            self.session is not None
            and cookies.get(COOKIE)
            and cookies[COOKIE].value == self.session[0]
            and self.session[1] == self.subjects[0],
            "original relying-party session and subject",
        )
        if path.path == "/sso/before-accept":
            self.before_accept()
            message = "Existing application grant checked"
        elif path.path == "/sso/session":
            self.prior_session_checked = True
            message = "Original application session"
        else:
            message = "Application observed " + (
                "administrator" if len(self.observed) == 1 else "member"
            )
        handler.page(f"<!doctype html><h1>{message}</h1>".encode())

    def serve(self, handler):
        path = urlsplit(handler.path)
        cookies = SimpleCookie(handler.headers.get("Cookie", ""))
        if path.path == "/sso/start":
            self.start(handler)
        elif path.path == "/cb":
            self.callback(handler, path, cookies)
        elif path.path in {"/sso/session", "/sso/observed", "/sso/before-accept"}:
            self.session_page(handler, path, cookies)
        else:
            handler.send_error(404)
