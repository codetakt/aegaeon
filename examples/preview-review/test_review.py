"""Reject false artifact identities and invalid OIDC authentication results."""

import copy
import io
import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import jwt
import requests
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.verification import PolicyBuilder, Store, VerificationError
from review import SOURCE_NAR_HASH, SOURCE_REVISION, certificates, main, validate_manifest
from rp import RelyingParty, create_app, validate_id_token
from seed import b64


class TransportTests(unittest.TestCase):
    def test_local_leaf_chains_to_root_and_cannot_issue_certificates(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            certificates(state)
            ca = x509.load_pem_x509_certificate((state / "review-ca.pem").read_bytes())
            leaf = x509.load_pem_x509_certificate((state / "localhost.pem").read_bytes())
            policy = PolicyBuilder().store(Store([ca]))
            self.assertEqual(
                policy.build_server_verifier(x509.DNSName("localhost")).verify(leaf, []),
                [leaf, ca],
            )
            with self.assertRaises(VerificationError):
                policy.build_server_verifier(x509.DNSName("other.example")).verify(leaf, [])
            self.assertFalse(
                leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
            )
            self.assertFalse(
                leaf.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign
            )
            self.assertEqual(
                {path.name for path in state.iterdir()},
                {"review-ca.pem", "localhost.pem", "localhost-key.pem"},
            )

    def test_registration_failure_preserves_status_for_unusable_error_bodies(self):
        metadata = {"issuer": "https://localhost:4000"}
        for name in (
            "authorization_endpoint",
            "token_endpoint",
            "jwks_uri",
            "registration_endpoint",
            "userinfo_endpoint",
        ):
            metadata[name] = metadata["issuer"] + "/" + name
        for body in (
            b"",
            b"<html>unavailable</html>",
            b"[]",
            b'{"error":' + b"9" * 5000 + b"}",
        ):
            with self.subTest(body=body):
                response = requests.Response()
                response.status_code = 503
                response.raw = io.BytesIO(body)
                with (
                    patch("rp.requests.Session") as session,
                    patch.object(RelyingParty, "get_json", return_value=metadata),
                ):
                    session.return_value.post.return_value = response
                    with self.assertRaisesRegex(ValueError, "DCR returned HTTP 503"):
                        RelyingParty(
                            metadata["issuer"], "https://localhost:5000/callback", "ca.pem"
                        )


class ArtifactTests(unittest.TestCase):
    def setUp(self):
        store_path = "/nix/store/" + "0" * 32 + "-review-server"
        self.manifest = {
            "version": 1,
            "distribution": "internal-preview",
            "repository": "codetakt/aegaeon",
            "attribute": "packages.x86_64-linux.server",
            "executable": "bin/aegaeon-server",
            "revision": "a" * 40,
            "binary_sha256": "b" * 64,
            "store_path": store_path,
            "closure": {store_path: SOURCE_NAR_HASH},
            "server_source": {
                "owner": "codetakt",
                "repo": "aegaeon",
                "rev": SOURCE_REVISION,
                "narHash": SOURCE_NAR_HASH,
            },
            "flakeref_exact": "codetakt-inc/aegaeon/=0.1.10+rev-" + "a" * 40,
        }

    def test_exact_publication_and_separate_source_identity(self):
        validate_manifest(self.manifest, SOURCE_REVISION)

    def test_local_manifest_may_omit_exact_reference(self):
        record = {key: value for key, value in self.manifest.items() if key != "flakeref_exact"}
        validate_manifest(record, SOURCE_REVISION)

    def test_missing_manifest_fields_have_explicit_diagnostics(self):
        for field in self.manifest.keys() - {"flakeref_exact"}:
            with self.subTest(field=field):
                record = copy.deepcopy(self.manifest)
                del record[field]
                with self.assertRaisesRegex(ValueError, rf"manifest\.{field} is required"):
                    validate_manifest(record, SOURCE_REVISION)
        for field in self.manifest["server_source"]:
            with self.subTest(source_field=field):
                record = copy.deepcopy(self.manifest)
                del record["server_source"][field]
                with self.assertRaisesRegex(
                    ValueError, rf"manifest\.server_source\.{field} is required"
                ):
                    validate_manifest(record, SOURCE_REVISION)

    def test_wrong_manifest_types_have_explicit_diagnostics(self):
        for value in (None, [], True):
            with (
                self.subTest(record=value),
                self.assertRaisesRegex(ValueError, "manifest must be a JSON object"),
            ):
                validate_manifest(value, SOURCE_REVISION)
        for field in self.manifest:
            with self.subTest(field=field):
                record = {**self.manifest, field: None}
                with self.assertRaisesRegex(ValueError, rf"manifest\.{field} must have type"):
                    validate_manifest(record, SOURCE_REVISION)
        for field in self.manifest["server_source"]:
            with self.subTest(source_field=field):
                record = copy.deepcopy(self.manifest)
                record["server_source"][field] = None
                with self.assertRaisesRegex(
                    ValueError, rf"manifest\.server_source\.{field} must have type"
                ):
                    validate_manifest(record, SOURCE_REVISION)

    def test_store_path_and_closure_must_describe_nix_outputs(self):
        for path in (
            "/opt/review-server",
            "./result-server",
            "/nix/store/not-a-store-output",
            self.manifest["store_path"] + "/bin/aegaeon-server",
            self.manifest["store_path"] + "\n",
        ):
            with (
                self.subTest(store_path=path),
                self.assertRaisesRegex(ValueError, "manifest.store_path"),
            ):
                validate_manifest({**self.manifest, "store_path": path}, SOURCE_REVISION)
            with self.subTest(closure_path=path):
                closure = {**self.manifest["closure"], path: SOURCE_NAR_HASH}
                with self.assertRaisesRegex(ValueError, "manifest.closure keys"):
                    validate_manifest({**self.manifest, "closure": closure}, SOURCE_REVISION)
        for closure in ({}, {"/nix/store/" + "1" * 32 + "-other-output": SOURCE_NAR_HASH}):
            with (
                self.subTest(closure=closure),
                self.assertRaisesRegex(ValueError, "closure must include the server"),
            ):
                validate_manifest({**self.manifest, "closure": closure}, SOURCE_REVISION)

    def test_closure_hashes_must_be_canonical_sha256_sri(self):
        for value in (
            None,
            42,
            "",
            "sha256-invalid",
            "sha256-YQ==",
            SOURCE_NAR_HASH.replace("sha256-", "sha512-"),
            SOURCE_NAR_HASH[:-2] + "Z=",
        ):
            with self.subTest(nar_hash=value):
                closure = {self.manifest["store_path"]: value}
                with self.assertRaisesRegex(ValueError, "canonical SHA-256 SRI"):
                    validate_manifest({**self.manifest, "closure": closure}, SOURCE_REVISION)

    def test_malformed_manifest_cli_records_failure_before_fetch_or_startup(self):
        for field in ("store_path", "closure", "server_source"):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                manifest = root / "manifest.json"
                record = {key: value for key, value in self.manifest.items() if key != field}
                manifest.write_text(json.dumps(record))
                state = root / "state"
                with (
                    patch(
                        "sys.argv",
                        ["review.py", "--manifest", str(manifest), "--state-dir", str(state)],
                    ),
                    patch.dict(
                        "os.environ",
                        {
                            "AEGAEON_REVIEW_SOURCE_REVISION": SOURCE_REVISION,
                            "AEGAEON_REVIEW_MIGRATIONS": str(root / "migrations"),
                        },
                    ),
                    patch("review.os.umask"),
                    patch("review.signal.signal"),
                    patch("review.subprocess.run") as fetch,
                    patch("review.prepare_local") as startup,
                    patch("sys.stderr", new_callable=io.StringIO) as stderr,
                ):
                    with self.assertRaises(SystemExit) as raised:
                        main()
                    self.assertEqual(raised.exception.code, 1)
                    self.assertIn(f"Review failed: manifest.{field} is required", stderr.getvalue())
                    self.assertNotIn("Traceback", stderr.getvalue())
                    fetch.assert_not_called()
                    startup.assert_not_called()
                evidence = json.loads((state / "evidence.json").read_text())
                self.assertEqual(evidence["status"], "failed")
                self.assertEqual(evidence["failure_type"], "ValueError")
                self.assertEqual({path.name for path in state.iterdir()}, {"evidence.json"})

    def test_mutated_manifest_identity_is_rejected(self):
        for field, value in (
            ("version", 2),
            ("version", True),
            ("repository", "unknown/aegaeon"),
            ("repository", "codetakt-inc/aegaeon"),
            ("attribute", "packages.x86_64-linux.default"),
            ("executable", "bin/other"),
            ("flakeref_exact", "codetakt-inc/aegaeon/0.1"),
            ("flakeref_exact", "codetakt/aegaeon/=0.1.10+rev-" + "a" * 40),
            ("revision", "c" * 40),
            ("binary_sha256", "not-a-digest"),
        ):
            with self.subTest(field=field):
                record = {**self.manifest, field: value}
                with self.assertRaises(ValueError):
                    validate_manifest(record, SOURCE_REVISION)

    def test_migrations_cannot_silently_follow_a_different_server(self):
        record = copy.deepcopy(self.manifest)
        record["server_source"]["rev"] = "d" * 40
        with self.assertRaises(ValueError):
            validate_manifest(record, SOURCE_REVISION)
        with self.assertRaises(ValueError):
            validate_manifest(self.manifest, "d" * 40)
        record["server_source"]["rev"] = SOURCE_REVISION
        record["server_source"]["narHash"] = "wrong hash"
        with self.assertRaises(ValueError):
            validate_manifest(record, SOURCE_REVISION)
        record = copy.deepcopy(self.manifest)
        record["server_source"]["owner"] = "codetakt-inc"
        with self.assertRaises(ValueError):
            validate_manifest(record, SOURCE_REVISION)


class TokenTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public = cls.key.public_key().public_numbers()
        cls.jwk = {"kty": "RSA", "kid": "test-key", "use": "sig", "alg": "RS256"}
        for name, value in (("n", public.n), ("e", public.e)):
            cls.jwk[name] = b64(value.to_bytes((value.bit_length() + 7) // 8, "big"))

    def setUp(self):
        self.claims = {
            "iss": "https://localhost:4000",
            "sub": "user",
            "aud": "client",
            "nonce": "nonce",
            "iat": int(time.time()),
            "exp": int(time.time()) + 300,
        }

    def token(self, claims=None, key=None):
        return jwt.encode(
            self.claims if claims is None else claims,
            key or self.key,
            algorithm="RS256",
            headers={"kid": "test-key"},
        )

    def admit(self, token, keys=None):
        return validate_id_token(
            token, {"keys": keys or [self.jwk]}, "https://localhost:4000", "client", "nonce"
        )

    def test_valid_signed_token(self):
        self.assertEqual(self.admit(self.token())["sub"], "user")

    def test_forged_signature(self):
        with self.assertRaises(jwt.InvalidSignatureError):
            self.admit(self.token(key=self.other_key))

    def test_claim_boundaries(self):
        for field, value in (
            ("iss", "https://other.example"),
            ("aud", "another-client"),
            ("nonce", "another-nonce"),
            ("exp", int(time.time()) - 10),
            ("iat", int(time.time()) + 600),
            ("sub", ""),
            ("azp", "another-client"),
        ):
            with self.subTest(field=field), self.assertRaises((jwt.PyJWTError, ValueError)):
                self.admit(self.token({**self.claims, field: value}))

    def test_required_claims(self):
        for field in ("iss", "sub", "aud", "exp", "iat", "nonce"):
            with self.subTest(field=field), self.assertRaises(jwt.MissingRequiredClaimError):
                self.admit(
                    self.token({key: value for key, value in self.claims.items() if key != field})
                )

    def test_unsigned_token_is_rejected(self):
        token = jwt.encode(self.claims, key=None, algorithm="none", headers={"kid": "test-key"})
        with self.assertRaises(ValueError):
            self.admit(token)

    def test_duplicate_or_inappropriate_key(self):
        for keys in (
            [self.jwk, self.jwk],
            [{**self.jwk, "kid": "different"}],
            [{**self.jwk, "use": "enc"}],
        ):
            with self.subTest(keys=keys), self.assertRaises(ValueError):
                self.admit(self.token(), keys)

    def test_multiple_audiences_require_authorized_party(self):
        with self.assertRaises(ValueError):
            self.admit(self.token({**self.claims, "aud": ["client", "another-client"]}))


class TransactionTests(unittest.TestCase):
    def setUp(self):
        self.rp = object.__new__(RelyingParty)
        self.rp.issuer = "https://localhost:4000"
        self.rp.callback = "https://localhost:5000/callback"
        self.rp.exchange = Mock()
        self.transaction = {
            "state": "expected",
            "created": time.monotonic(),
            "nonce": "nonce",
            "verifier": "verifier",
        }

    def test_invalid_callback_never_exchanges_code(self):
        for query in (
            "code=x",
            "state=wrong&code=x",
            "state=expected&code=x&code=y",
            "state=expected&error=access_denied",
            "state=expected&code=x&iss=https://other.example",
        ):
            with self.subTest(query=query), self.assertRaises(ValueError):
                self.rp.finish(self.transaction, self.rp.callback + "?" + query)
        self.rp.exchange.assert_not_called()

    def test_expired_transaction_never_exchanges_code(self):
        self.transaction["created"] -= 301
        with self.assertRaises(ValueError):
            self.rp.finish(self.transaction, self.rp.callback + "?state=expected&code=x")
        self.rp.exchange.assert_not_called()

    def test_endpoints_cannot_escape_issuer(self):
        for url in (
            "http://localhost:4000/token",
            "https://other.example/token",
            "https://localhost:4000@other.example/token",
        ):
            with self.subTest(url=url), self.assertRaises(ValueError):
                self.rp.same_origin(url)

    def test_browser_transaction_is_consumed_even_on_failed_validation(self):
        self.rp.begin = Mock(return_value=(self.transaction, self.rp.issuer + "/authorize"))
        self.rp.finish = Mock(side_effect=ValueError("invalid token"))
        browser = create_app(self.rp).test_client()
        browser.get("/login", base_url="https://localhost:5000")
        self.assertEqual(
            browser.get(
                "/callback?state=expected&code=x", base_url="https://localhost:5000"
            ).status_code,
            400,
        )
        self.assertEqual(
            browser.get(
                "/callback?state=expected&code=x", base_url="https://localhost:5000"
            ).status_code,
            400,
        )
        self.rp.finish.assert_called_once()


if __name__ == "__main__":
    unittest.main()
