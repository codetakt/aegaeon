#!/usr/bin/env python3
"""Minimal OIDC Relying Party for Aegaeon.

Demonstrates the Authorization Code flow with PKCE (S256):
  1. OIDC Discovery
  2. Dynamic Client Registration (RFC 7591)
  3. Authorization request with PKCE + state
  4. Code exchange at the token endpoint
  5. ID token decoding and display
"""

import base64
import hashlib
import html
import json
import math
import os
import secrets
import sys

import jwt
import requests
from flask import Flask, redirect, request, session

# Configuration
ISSUER = os.environ.get("AEGAEON_ISSUER", "http://localhost:8080")
RP_PORT = int(os.environ.get("RP_PORT", "5000"))
RP_REDIRECT_URI = os.environ.get("RP_REDIRECT_URI", f"http://localhost:{RP_PORT}/callback")

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", secrets.token_hex(32))

# PKCE helpers


def _pkce_verifier() -> str:
    return secrets.token_urlsafe(64)


def _pkce_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


# Discovery + DCR (run once at startup)

_discovery: dict = {}
_client: dict = {}


def _bootstrap():
    """Fetch OIDC discovery and register a client via DCR."""
    global _discovery, _client

    disco_url = f"{ISSUER}/.well-known/openid-configuration"
    print(f"[rp] Fetching discovery from {disco_url}")
    resp = requests.get(disco_url, timeout=10)
    resp.raise_for_status()
    _discovery = resp.json()
    print(f"[rp] Discovery OK — issuer={_discovery.get('issuer')}")

    reg_endpoint = _discovery.get("registration_endpoint")
    if not reg_endpoint:
        sys.exit("[rp] ERROR: server does not advertise a registration_endpoint")

    reg_body = {
        "redirect_uris": [RP_REDIRECT_URI],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "client_secret_post",
    }
    print(f"[rp] Registering client at {reg_endpoint}")
    resp = requests.post(reg_endpoint, json=reg_body, timeout=10)
    resp.raise_for_status()
    _client = resp.json()
    print(f"[rp] Registered client_id={_client['client_id']}")


# Routes


@app.route("/")
def index():
    """Landing page with a login button."""
    id_token_claims = session.get("id_token_claims")
    if id_token_claims:
        claims_html = html.escape(json.dumps(id_token_claims, indent=2))
        return (
            "<h1>Aegaeon Minimal RP</h1>"
            "<h2>ID Token Claims</h2>"
            f"<pre>{claims_html}</pre>"
            '<p><a href="/logout">Logout</a></p>'
        )
    return '<h1>Aegaeon Minimal RP</h1><p><a href="/login">Login with Aegaeon</a></p>'


@app.route("/login")
def login():
    """Build the authorization URL and redirect the user."""
    verifier = _pkce_verifier()
    challenge = _pkce_challenge(verifier)
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)

    session["pkce_verifier"] = verifier
    session["oauth_state"] = state
    session["nonce"] = nonce

    params = {
        "response_type": "code",
        "client_id": _client["client_id"],
        "redirect_uri": RP_REDIRECT_URI,
        "scope": "openid profile email",
        "state": state,
        "nonce": nonce,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    authz_url = _discovery["authorization_endpoint"]
    qs = "&".join(f"{k}={requests.utils.quote(str(v))}" for k, v in params.items())
    return redirect(f"{authz_url}?{qs}")


def _exchange_code(code, verifier):
    """Return decoded claims without exposing token endpoint bodies on failure."""
    issuer, client_id = _discovery.get("issuer"), _client.get("client_id")
    if not isinstance(issuer, str) or not issuer or not isinstance(client_id, str) or not client_id:
        raise ValueError
    resp = requests.post(
        _discovery["token_endpoint"],
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": RP_REDIRECT_URI,
            "client_id": client_id,
            "client_secret": _client.get("client_secret", ""),
            "code_verifier": verifier,
        },
        timeout=10,
    )
    if resp.status_code != 200:
        raise ValueError
    tokens = resp.json()
    if not isinstance(tokens, dict):
        raise ValueError  # noqa: TRY004 - invalid protocol response
    id_token_raw = tokens.get("id_token")
    if not isinstance(id_token_raw, str) or not id_token_raw.strip():
        raise ValueError

    # WARNING: This demo skips ID token signature verification for simplicity.
    # Production RPs MUST fetch the provider's JWKS and verify the signature.
    # See: https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
    if jwt.get_unverified_header(id_token_raw).get("alg") not in ("RS256", "ES256"):
        raise ValueError
    claims = jwt.decode(
        id_token_raw,
        issuer=issuer,
        audience=client_id,
        options={
            "verify_signature": False,
            "verify_iss": True,
            "verify_aud": True,
            "verify_sub": True,
            "verify_exp": True,
            "verify_iat": True,
            "verify_nbf": True,
            "require": ["iss", "sub", "aud", "exp", "iat", "nonce"],
        },
        algorithms=["RS256", "ES256"],
    )
    if not isinstance(claims["sub"], str) or not claims["sub"]:
        raise ValueError
    if any(
        name in claims
        and (type(claims[name]) not in (int, float) or not math.isfinite(claims[name]))
        for name in ("exp", "iat", "nbf")
    ):
        raise ValueError
    if ("azp" in claims and claims["azp"] != client_id) or (
        isinstance(claims["aud"], list) and len(claims["aud"]) > 1 and "azp" not in claims
    ):
        raise ValueError
    return claims


@app.route("/callback")
def callback():
    """Consume one pending OpenID login, including on unsuccessful callbacks."""
    expected_state = session.pop("oauth_state", None)
    verifier = session.pop("pkce_verifier", None)
    expected_nonce = session.pop("nonce", None)
    session.pop("id_token_claims", None)

    if request.args.get("error") is not None:
        # Provider error descriptions may contain credentials or tokens.
        return "<h1>Error</h1><p>Authorization request failed</p>", 400
    code = request.args.get("code")
    if not code:
        return "<h1>Error</h1><p>Missing authorization code</p>", 400
    if (
        not isinstance(expected_state, str)
        or not expected_state
        or request.args.get("state") != expected_state
    ):
        return "<h1>Error</h1><p>State mismatch (possible CSRF)</p>", 400
    if not isinstance(verifier, str) or not verifier:
        return "<h1>Error</h1><p>Missing PKCE verifier in session</p>", 400
    if not isinstance(expected_nonce, str) or not expected_nonce:
        return "<h1>Error</h1><p>Missing nonce in session</p>", 400

    try:
        claims = _exchange_code(code, verifier)
    except (requests.RequestException, ValueError, TypeError, OverflowError, jwt.PyJWTError):
        # Do not echo response bodies, token strings or transport exception details.
        return "<h1>Token Error</h1><p>Invalid token response</p>", 400
    if not isinstance(claims, dict) or claims.get("nonce") != expected_nonce:
        return "<h1>Error</h1><p>Nonce mismatch (possible replay)</p>", 400
    session["id_token_claims"] = claims

    # Note: access_token is intentionally not stored in the session cookie.
    # Production RPs should use server-side storage for tokens.
    return redirect("/")


@app.route("/logout")
def logout():
    """Clear the RP session."""
    session.clear()
    return redirect("/")


if __name__ == "__main__":
    _bootstrap()
    print(f"[rp] Listening on http://localhost:{RP_PORT}")
    app.run(host="0.0.0.0", port=RP_PORT, debug=False)
