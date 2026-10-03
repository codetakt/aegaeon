"""Installed dependency contracts; the sample intentionally does not verify signatures."""

# unittest assertions must remain effective when Python runs with -O.
# ruff: noqa: PT009, PT027
from __future__ import annotations

import base64
import importlib.util
import json
import os
import sys
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

os.environ["AEGAEON_ISSUER"] = "https://issuer.example"
os.environ["RP_REDIRECT_URI"] = "https://rp.example/callback"
os.environ["FLASK_SECRET"] = "local-test-cookie-key-not-for-deployment"  # noqa: S105
APP_PATH = Path(sys.argv.pop(1))
RESULT_PATH = Path(sys.argv.pop(1))
spec = importlib.util.spec_from_file_location("minimal_rp_dependency_smoke", APP_PATH)
rp = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = rp
spec.loader.exec_module(rp)
rp.app.config.update(TESTING=True)
DISCOVERY = {
    "issuer": "https://issuer.example",
    "authorization_endpoint": "https://issuer.example/authorize",
    "token_endpoint": "https://issuer.example/token",
    "registration_endpoint": "https://issuer.example/register",
}
CLIENT = {"client_id": "sample-client", "client_secret": "sample-secret"}


class Response:
    def __init__(self, payload=None, status_code=200, text=""):
        self.payload, self.status_code, self.text = payload, status_code, text

    def json(self):
        if isinstance(self.payload, Exception):
            raise self.payload
        return self.payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise rp.requests.HTTPError(str(self.status_code))


def unsigned_token(claims):
    def segment(value):
        return base64.urlsafe_b64encode(json.dumps(value).encode()).rstrip(b"=").decode()

    return segment({"alg": "RS256", "typ": "JWT"}) + "." + segment(claims) + ".AA"


class ApplicationSmoke(unittest.TestCase):
    def setUp(self):
        rp._discovery, rp._client = DISCOVERY.copy(), CLIENT.copy()
        self.client = rp.app.test_client()

    def begin(self):
        result = self.client.get("/login")
        self.assertEqual(result.status_code, 302)
        query = parse_qs(urlsplit(result.location).query)
        with self.client.session_transaction() as session:
            saved = dict(session)
        return query, saved

    def callback(self, saved, claims=None, response=None):
        claims = claims if claims is not None else {"sub": "subject-1", "nonce": saved["nonce"]}
        response = response or Response(
            {"id_token": unsigned_token(claims), "access_token": "not-stored"}
        )
        with patch.object(rp.requests, "post", return_value=response) as post:
            result = self.client.get(
                "/callback", query_string={"code": "code-1", "state": saved["oauth_state"]}
            )
        return result, post

    def assert_rejected(self, result, saved):
        self.assertEqual(result.status_code, 400)
        for secret in (b"sample-secret", b"not-stored", b"secret-token-marker"):
            self.assertNotIn(secret, result.data)
        with self.client.session_transaction() as session:
            for key in ("oauth_state", "pkce_verifier", "nonce", "id_token_claims", "access_token"):
                self.assertNotIn(key, session)
        with patch.object(rp.requests, "post") as post:
            replay = self.client.get(
                "/callback", query_string={"code": "code-1", "state": saved["oauth_state"]}
            )
        self.assertEqual(replay.status_code, 400)
        post.assert_not_called()
        with self.client.session_transaction() as session:
            self.assertNotIn("id_token_claims", session)

    def failure_begin(self):
        _, saved = self.begin()
        with self.client.session_transaction() as session:
            session["id_token_claims"] = {"sub": "previous-session"}
        return saved

    def test_bootstrap_discovery_registration(self):
        with (
            patch.object(rp.requests, "get", return_value=Response(DISCOVERY)) as get,
            patch.object(rp.requests, "post", return_value=Response(CLIENT)) as post,
        ):
            rp._bootstrap()
        get.assert_called_once_with(
            "https://issuer.example/.well-known/openid-configuration", timeout=10
        )
        post.assert_called_once_with(
            DISCOVERY["registration_endpoint"],
            json={
                "redirect_uris": [rp.RP_REDIRECT_URI],
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
                "token_endpoint_auth_method": "client_secret_post",
            },
            timeout=10,
        )
        self.assertEqual(rp._client, CLIENT)

    def test_pkce_rfc7636_and_verifier(self):
        self.assertEqual(
            rp._pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        )
        verifier = rp._pkce_verifier()
        self.assertRegex(verifier, r"^[A-Za-z0-9_-]{43,128}$")

    def test_landing_and_login_session(self):
        self.assertIn(b"Login with Aegaeon", self.client.get("/").data)
        query, saved = self.begin()
        self.assertEqual(query["response_type"], ["code"])
        self.assertEqual(query["scope"], ["openid profile email"])
        self.assertEqual(query["client_id"], [CLIENT["client_id"]])
        self.assertEqual(query["redirect_uri"], [rp.RP_REDIRECT_URI])
        self.assertEqual(query["state"], [saved["oauth_state"]])
        self.assertEqual(query["nonce"], [saved["nonce"]])
        self.assertEqual(query["code_challenge_method"], ["S256"])
        self.assertEqual(query["code_challenge"], [rp._pkce_challenge(saved["pkce_verifier"])])

    def test_callback_decodes_without_signature_verification(self):
        _, saved = self.begin()
        result, post = self.callback(saved)
        self.assertEqual(result.status_code, 302)
        self.assertEqual(result.location, "/")
        post.assert_called_once_with(
            DISCOVERY["token_endpoint"],
            data={
                "grant_type": "authorization_code",
                "code": "code-1",
                "redirect_uri": rp.RP_REDIRECT_URI,
                "client_id": CLIENT["client_id"],
                "client_secret": CLIENT["client_secret"],
                "code_verifier": saved["pkce_verifier"],
            },
            timeout=10,
        )
        with self.client.session_transaction() as session:
            self.assertEqual(session["id_token_claims"]["sub"], "subject-1")
            for name in ("access_token", "oauth_state", "pkce_verifier", "nonce"):
                self.assertNotIn(name, session)
        with patch.object(rp.requests, "post") as replay_post:
            replay = self.client.get(
                "/callback", query_string={"code": "code-1", "state": saved["oauth_state"]}
            )
        self.assertEqual(replay.status_code, 400)
        replay_post.assert_not_called()

    def test_missing_code_and_wrong_state(self):
        for query in ({}, {"code": "code-1", "state": "wrong"}):
            with self.subTest(query=query):
                saved = self.failure_begin()
                with patch.object(rp.requests, "post") as post:
                    result = self.client.get("/callback", query_string=query)
                self.assert_rejected(result, saved)
                post.assert_not_called()

    def test_missing_pkce_verifier(self):
        saved = self.failure_begin()
        with self.client.session_transaction() as session:
            del session["pkce_verifier"]
        with patch.object(rp.requests, "post") as post:
            result = self.client.get(
                "/callback", query_string={"code": "code-1", "state": saved["oauth_state"]}
            )
        self.assertIn(b"Missing PKCE verifier", result.data)
        self.assert_rejected(result, saved)
        post.assert_not_called()

    def test_missing_or_invalid_expected_state(self):
        for expected in (None, "", False, 1, []):
            with self.subTest(expected=expected):
                saved = self.failure_begin()
                with self.client.session_transaction() as session:
                    if expected is None:
                        del session["oauth_state"]
                    else:
                        session["oauth_state"] = expected
                with patch.object(rp.requests, "post") as post:
                    # Absent returned state must not equal an absent session state.
                    result = self.client.get("/callback", query_string={"code": "code-1"})
                self.assertIn(b"State mismatch", result.data)
                self.assert_rejected(result, saved)
                post.assert_not_called()

    def test_missing_or_invalid_expected_nonce(self):
        for expected in (None, "", False, 1, []):
            with self.subTest(expected=expected):
                saved = self.failure_begin()
                with self.client.session_transaction() as session:
                    if expected is None:
                        del session["nonce"]
                    else:
                        session["nonce"] = expected
                result, post = self.callback(saved, claims={"sub": "no-nonce"})
                self.assertIn(b"Missing nonce", result.data)
                self.assert_rejected(result, saved)
                post.assert_not_called()

    def test_nonce_mismatch_and_missing_claim(self):
        for claim in (
            {"sub": "subject-1", "nonce": "wrong"},
            {"sub": "subject-1"},
            {"nonce": None},
        ):
            with self.subTest(claim=claim):
                saved = self.failure_begin()
                result, _ = self.callback(saved, claims=claim)
                self.assertIn(b"Nonce mismatch", result.data)
                self.assert_rejected(result, saved)

    def test_protocol_error_does_not_echo_provider_details(self):
        saved = self.failure_begin()
        with patch.object(rp.requests, "post") as post:
            result = self.client.get(
                "/callback",
                query_string={
                    "error": "<script>secret-token-marker</script>",
                    "error_description": "<img src=x onerror=x>",
                },
            )
        self.assertNotIn(b"<script>", result.data)
        self.assertNotIn(b"<img", result.data)
        self.assert_rejected(result, saved)
        post.assert_not_called()

    def test_token_error_does_not_echo_provider_details(self):
        saved = self.failure_begin()
        result, _ = self.callback(
            saved,
            response=Response(
                status_code=400, text="<script>secret-token-marker</script>" + "a" * 600
            ),
        )
        self.assertNotIn(b"<script>", result.data)
        self.assertNotIn(b"a" * 501, result.data)
        self.assert_rejected(result, saved)

    def test_malformed_token_payload_rejected(self):
        for payload in (
            None,
            [],
            "secret-token-marker",
            True,
            42,
            rp.requests.exceptions.JSONDecodeError("secret-token-marker", "invalid-json", 0),
        ):
            with self.subTest(payload=type(payload).__name__):
                saved = self.failure_begin()
                result, _ = self.callback(saved, response=Response(payload))
                self.assert_rejected(result, saved)

    def test_token_transport_failure_rejected(self):
        for failure in (rp.requests.Timeout, rp.requests.ConnectionError, rp.requests.HTTPError):
            with self.subTest(failure=failure):
                saved = self.failure_begin()
                with patch.object(rp.requests, "post", side_effect=failure("secret-token-marker")):
                    result = self.client.get(
                        "/callback", query_string={"code": "code-1", "state": saved["oauth_state"]}
                    )
                self.assert_rejected(result, saved)

    def test_claims_escaping_and_logout(self):
        _, saved = self.begin()
        result, _ = self.callback(
            saved, claims={"sub": "<script>x</script>", "nonce": saved["nonce"]}
        )
        self.assertEqual(result.status_code, 302)
        page = self.client.get("/")
        self.assertIn(b"&lt;script&gt;", page.data)
        self.assertNotIn(b"<script>", page.data)
        self.assertEqual(self.client.get("/logout").status_code, 302)
        with self.client.session_transaction() as session:
            self.assertEqual(dict(session), {})

    def test_missing_empty_or_malformed_id_token_rejected(self):
        payloads = [{"access_token": "not-stored"}]
        payloads.extend(
            {"id_token": token}
            for token in (
                None,
                "",
                " ",
                False,
                1,
                [],
                {},
                "secret-token-marker",
                unsigned_token([]),
            )
        )
        for payload in payloads:
            with self.subTest(payload=payload):
                saved = self.failure_begin()
                result, _ = self.callback(saved, response=Response(payload))
                self.assert_rejected(result, saved)


class HttpProviderContract(unittest.TestCase):
    """Exercise installed requests against a disposable loopback stub provider."""

    def test_discovery_registration_and_token_exchange_over_http(self):
        calls = []
        claims = {}

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, _format, *_args):
                pass

            def send_payload(self, payload):
                raw = json.dumps(payload).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_GET(self):
                calls.append(("GET", self.path, None))
                self.send_payload(discovery)

            def do_POST(self):
                raw = self.rfile.read(int(self.headers["Content-Length"]))
                payload = json.loads(raw) if self.path == "/register" else parse_qs(raw.decode())
                calls.append(("POST", self.path, payload))
                self.send_payload(
                    CLIENT
                    if self.path == "/register"
                    else {
                        "id_token": unsigned_token(claims),
                        "access_token": "never-store-this",
                    }
                )

        with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
            issuer = f"http://127.0.0.1:{server.server_port}"
            discovery = {
                "issuer": issuer,
                "authorization_endpoint": issuer + "/authorize",
                "token_endpoint": issuer + "/token",
                "registration_endpoint": issuer + "/register",
            }
            worker = Thread(target=server.serve_forever, daemon=True)
            worker.start()
            try:
                with patch.object(rp, "ISSUER", issuer):
                    rp._bootstrap()
                client = rp.app.test_client()
                login = client.get("/login")
                self.assertEqual(login.status_code, 302)
                with client.session_transaction() as session:
                    saved = dict(session)
                claims.update(sub="http-subject", nonce=saved["nonce"])
                result = client.get(
                    "/callback", query_string={"code": "http-code", "state": saved["oauth_state"]}
                )
                self.assertEqual(result.status_code, 302)
                self.assertEqual(calls[0][:2], ("GET", "/.well-known/openid-configuration"))
                self.assertEqual(calls[1][2]["token_endpoint_auth_method"], "client_secret_post")
                self.assertEqual(calls[2][2]["code_verifier"], [saved["pkce_verifier"]])
                self.assertEqual(calls[2][2]["client_secret"], [CLIENT["client_secret"]])
                with client.session_transaction() as session:
                    self.assertEqual(session["id_token_claims"]["sub"], "http-subject")
                    self.assertNotIn("access_token", session)
            finally:
                server.shutdown()
                worker.join(timeout=5)


class PyJwtCryptographyLibraryCheck(unittest.TestCase):
    """Library integration only; the sample itself does not verify signatures."""

    def test_rs256_es256_sign_verify_and_tamper(self):

        for alg, private in [
            ("RS256", rsa.generate_private_key(public_exponent=65537, key_size=2048)),
            ("ES256", ec.generate_private_key(ec.SECP256R1())),
        ]:
            with self.subTest(algorithm=alg):
                public_pem = private.public_key().public_bytes(
                    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
                )
                public = serialization.load_pem_public_key(public_pem)
                claims = {
                    "sub": "library-check",
                    "iss": "https://issuer.example",
                    "aud": "library-client",
                }
                token = jwt.encode(claims, private, algorithm=alg)
                self.assertEqual(
                    jwt.decode(
                        token,
                        public,
                        algorithms=[alg],
                        issuer="https://issuer.example",
                        audience="library-client",
                    ),
                    claims,
                )
                parts = token.split(".")
                signature = bytearray(
                    base64.urlsafe_b64decode(parts[2] + "=" * (-len(parts[2]) % 4))
                )
                signature[0] ^= 1
                parts[2] = base64.urlsafe_b64encode(signature).rstrip(b"=").decode()
                with self.assertRaises(jwt.InvalidSignatureError):
                    jwt.decode(
                        ".".join(parts),
                        public,
                        algorithms=[alg],
                        issuer="https://issuer.example",
                        audience="library-client",
                    )


class InventoryResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.test_ids = []

    def startTest(self, test):  # noqa: N802 - unittest interface
        self.test_ids.append(test.id().split(".", 1)[1])
        super().startTest(test)


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
    result = unittest.TextTestRunner(verbosity=2, resultclass=InventoryResult).run(suite)
    passed = result.wasSuccessful() and result.testsRun > 0 and not result.skipped
    RESULT_PATH.write_text(
        json.dumps(
            {
                "status": "passed" if passed else "failed",
                "tests_run": result.testsRun,
                "test_ids": result.test_ids,
                "failures": len(result.failures),
                "errors": len(result.errors),
                "skipped": len(result.skipped),
                "scope": "sample routes/session/decoding; separate JWT library integration",
                "sample_signature_verification": False,
            },
            indent=2,
        )
        + "\n"
    )
    raise SystemExit(0 if passed else 1)
