"""A small review RP; independent of the separate Aegaeon SDK."""

import hashlib
import html
import json
import secrets
import time
from html.parser import HTMLParser
from urllib.parse import parse_qs, urlencode, urljoin, urlsplit

import jwt
import requests
from flask import Flask, redirect, request
from seed import b64


class RelyingParty:
    def __init__(self, issuer, callback, ca):
        self.issuer = issuer
        self.callback = callback
        self.http = requests.Session()
        self.http.trust_env = False
        self.http.verify = str(ca)
        self.metadata = self.get_json(issuer + "/.well-known/openid-configuration")
        if self.metadata.get("issuer") != issuer:
            msg = "discovery issuer mismatch"
            raise ValueError(msg)
        for name in (
            "authorization_endpoint",
            "token_endpoint",
            "jwks_uri",
            "registration_endpoint",
            "userinfo_endpoint",
        ):
            self.same_origin(self.metadata[name])
        registration = self.http.post(
            self.metadata["registration_endpoint"],
            json={
                "redirect_uris": [callback],
                "grant_types": ["authorization_code"],
                "response_types": ["code"],
                "token_endpoint_auth_method": "none",
                "pkce_required": True,
                "scope": "openid profile email",
            },
            timeout=15,
            allow_redirects=False,
        )
        if registration.status_code != 201:
            try:
                error = registration.json()
            except ValueError:
                # JSON decoding can also reject oversized integers.
                error = {}
            detail = (
                error.get("error_description", "registration rejected")
                if isinstance(error, dict)
                else "registration rejected"
            )
            msg = f"DCR returned HTTP {registration.status_code}: {detail}"
            raise ValueError(msg)
        self.client_id = registration.json()["client_id"]

    def same_origin(self, url):
        target = urlsplit(url)
        issuer = urlsplit(self.issuer)
        if (
            (target.scheme, target.netloc) != (issuer.scheme, issuer.netloc)
            or target.username
            or target.fragment
        ):
            msg = "RP endpoint or redirect leaves the selected issuer"
            raise ValueError(msg)

    def get_json(self, url):
        self.same_origin(url)
        response = self.http.get(url, timeout=15, allow_redirects=False)
        response.raise_for_status()
        return response.json()

    def begin(self):
        transaction = {
            "state": secrets.token_urlsafe(32),
            "nonce": secrets.token_urlsafe(32),
            "verifier": secrets.token_urlsafe(48),
            "created": time.monotonic(),
        }
        params = {
            "response_type": "code",
            "iss": self.issuer,
            "client_id": self.client_id,
            "redirect_uri": self.callback,
            "scope": "openid profile email",
            "state": transaction["state"],
            "nonce": transaction["nonce"],
            "code_challenge": b64(hashlib.sha256(transaction["verifier"].encode()).digest()),
            "code_challenge_method": "S256",
        }
        return transaction, self.metadata["authorization_endpoint"] + "?" + urlencode(params)

    def exchange(self, code, verifier):
        return self.http.post(
            self.metadata["token_endpoint"],
            data={
                "grant_type": "authorization_code",
                "code": code,
                "client_id": self.client_id,
                "redirect_uri": self.callback,
                "code_verifier": verifier,
            },
            timeout=15,
            allow_redirects=False,
        )

    def finish(self, transaction, callback_url):
        code = callback_code(transaction, callback_url, self.callback, self.issuer)
        response = self.exchange(code, transaction["verifier"])
        response.raise_for_status()
        tokens = response.json()
        jwks = self.get_json(self.metadata["jwks_uri"])
        claims = validate_id_token(
            tokens["id_token"], jwks, self.issuer, self.client_id, transaction["nonce"]
        )
        userinfo = self.http.get(
            self.metadata["userinfo_endpoint"],
            headers={"Authorization": "Bearer " + tokens["access_token"]},
            timeout=15,
            allow_redirects=False,
        )
        userinfo.raise_for_status()
        if userinfo.json().get("sub") != claims["sub"]:
            msg = "userinfo subject mismatch"
            raise ValueError(msg)
        return claims, code


def callback_code(transaction, callback_url, callback, issuer):
    parsed = urlsplit(callback_url)
    expected = urlsplit(callback)
    if (parsed.scheme, parsed.netloc, parsed.path) != (
        expected.scheme,
        expected.netloc,
        expected.path,
    ) or parsed.fragment:
        msg = "callback URI mismatch"
        raise ValueError(msg)
    params = parse_qs(parsed.query, keep_blank_values=True)
    if any(len(value) != 1 for value in params.values()):
        msg = "duplicate callback parameter"
        raise ValueError(msg)
    state = params.get("state", [""])[0]
    if not state or not secrets.compare_digest(state, transaction["state"]):
        msg = "callback state mismatch"
        raise ValueError(msg)
    if time.monotonic() - transaction["created"] > 300:
        msg = "authorization transaction expired"
        raise ValueError(msg)
    if params.get("iss", [issuer])[0] != issuer:
        msg = "authorization response issuer mismatch"
        raise ValueError(msg)
    code = params.get("code", [""])[0]
    if "error" in params or not code:
        error = params.get("error", ["missing_code"])[0]
        detail = params.get("error_description", [""])[0]
        msg = f"authorization did not return a code: {error} {detail}"
        raise ValueError(msg)
    return code


def validate_id_token(token, jwks, issuer, audience, nonce):
    header = jwt.get_unverified_header(token)
    if header.get("alg") != "RS256" or not header.get("kid"):
        msg = "unsupported signing algorithm or missing key identity"
        raise ValueError(msg)
    keys = [key for key in jwks["keys"] if key.get("kid") == header["kid"]]
    if len(keys) != 1 or keys[0].get("kty") != "RSA" or keys[0].get("use", "sig") != "sig":
        msg = "ambiguous or inappropriate signing key"
        raise ValueError(msg)
    claims = jwt.decode(
        token,
        jwt.PyJWK(keys[0]).key,
        algorithms=["RS256"],
        issuer=issuer,
        audience=audience,
        options={"require": ["iss", "sub", "aud", "exp", "iat", "nonce"]},
    )
    if not isinstance(claims["sub"], str) or not claims["sub"] or claims["nonce"] != nonce:
        msg = "ID token subject or nonce mismatch"
        raise ValueError(msg)
    if claims.get("azp", audience) != audience or (
        isinstance(claims["aud"], list) and len(claims["aud"]) > 1 and "azp" not in claims
    ):
        msg = "ID token authorized party mismatch"
        raise ValueError(msg)
    return claims


class LoginFields(HTMLParser):
    def __init__(self):
        super().__init__()
        self.fields = {}

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if tag == "input" and attributes.get("type") == "hidden" and "name" in attributes:
            self.fields[attributes["name"]] = attributes.get("value", "")


def smoke(rp, password):
    browser = requests.Session()
    browser.trust_env = False
    browser.verify = rp.http.verify
    transaction, url = rp.begin()
    for _ in range(10):
        rp.same_origin(url)
        response = browser.get(url, timeout=15, allow_redirects=False)
        if response.status_code == 200:
            form = LoginFields()
            form.feed(response.text)
            if "csrf_token" not in form.fields:
                msg = "expected the local login form"
                raise ValueError(msg)
            response = browser.post(
                urlsplit(url)._replace(query="").geturl(),
                data={**form.fields, "identifier": "reviewer@example.com", "password": password},
                timeout=15,
                allow_redirects=False,
            )
        if response.status_code not in (302, 303):
            msg = f"login did not redirect (HTTP {response.status_code})"
            raise ValueError(msg)
        url = urljoin(url, response.headers["Location"])
        if urlsplit(url)._replace(query="", fragment="").geturl() == rp.callback:
            claims, code = rp.finish(transaction, url)
            replay = rp.exchange(code, transaction["verifier"])
            if replay.status_code != 400 or replay.json().get("error") != "invalid_grant":
                msg = "redeemed authorization code was not rejected"
                raise ValueError(msg)
            return {
                "status": "passed",
                "flow": "authorization_code+S256",
                "id_token_signature": "RS256 verified",
                "issuer_audience_nonce_expiry": "checked",
                "userinfo_subject": "matched",
                "code_replay": "rejected",
                "subject": claims["sub"],
            }
    msg = "login redirect limit exceeded"
    raise ValueError(msg)


def expire_sessions(sessions):
    now = time.monotonic()
    for key in list(sessions):
        if now - sessions[key]["created"] > 300:
            del sessions[key]


def create_app(rp):
    app = Flask(__name__)
    sessions = {}

    @app.after_request
    def response_headers(response):
        response.headers["Cache-Control"] = "no-store"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    @app.get("/")
    def index():
        expire_sessions(sessions)
        entry = sessions.get(request.cookies.get("aegaeon_review_rp"), {})
        if entry.get("claims"):
            return (
                "<h1>Aegaeon preview review</h1><p>Verified ID token claims</p><pre>"
                + html.escape(json.dumps(entry["claims"], indent=2))
                + '</pre><a href="/login">Start another login</a>'
            )
        return (
            "<h1>Aegaeon preview review</h1><p>Local server review.</p>"
            '<a href="/login">Login with Aegaeon</a>'
        )

    @app.get("/login")
    def login():
        expire_sessions(sessions)
        if len(sessions) >= 100:
            return "Review session limit reached; retry in five minutes.", 429
        sessions.pop(request.cookies.get("aegaeon_review_rp"), None)
        transaction, location = rp.begin()
        session_id = secrets.token_urlsafe(32)
        sessions[session_id] = transaction
        response = redirect(location)
        response.set_cookie(
            "aegaeon_review_rp", session_id, secure=True, httponly=True, samesite="Lax", max_age=300
        )
        return response

    @app.get("/callback")
    def callback():
        session_id = request.cookies.get("aegaeon_review_rp")
        transaction = sessions.pop(session_id, None)
        if not transaction or "claims" in transaction:
            return "Authorization transaction missing or already used.", 400
        try:
            claims, _ = rp.finish(
                transaction, rp.callback + "?" + request.query_string.decode("ascii")
            )
        except (ValueError, KeyError, jwt.PyJWTError, requests.RequestException):
            return "Login validation failed. Start a new login.", 400
        sessions[session_id] = {"created": time.monotonic(), "claims": claims}
        return redirect("/")

    return app
