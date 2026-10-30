"""Actual TLS/CLI transport tests with an isolated receiver protocol fixture."""

from __future__ import annotations

import contextlib
import http.server
import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

from test_organization_audit_consumer import ACTOR, BASE, SCRIPT, consumer, fixture


class TransportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.state = self.root / "state"
        self.state.mkdir(mode=0o700)
        self.cert = self.root / "certificate.pem"
        key = self.root / "key.pem"
        openssl = shutil.which("openssl")
        if openssl is None:
            self.fail("pinned openssl is required for actual TLS fixtures")
        subprocess.run(  # noqa: S603 — resolved tool, fixed certificate flags, private owned paths
            [
                openssl,
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                str(key),
                "-out",
                str(self.cert),
                "-days",
                "1",
                "-subj",
                "/CN=localhost",
                "-addext",
                "subjectAltName=DNS:localhost",
            ],
            check=True,
            capture_output=True,
            timeout=20,
        )
        self.payload, self.tag, _, self.pair = fixture()
        self.requests = []
        self.first_ack = True
        self.mode = "normal"
        self.receipt = None
        owner = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_args: object) -> None:
                pass

            def send_body(self, body: bytes, status: int = 200) -> None:
                self.send_response(status)
                self.send_header("Content-Type", getattr(owner, "content_type", "application/json"))
                self.send_header("ETag", owner.tag)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                with contextlib.suppress(BrokenPipeError, ssl.SSLError):
                    self.wfile.write(body)

            def do_GET(self) -> None:
                owner.requests.append(("GET", self.path, dict(self.headers)))
                if owner.mode == "stall":
                    time.sleep(2)
                if owner.mode == "redirect":
                    self.send_response(302)
                    self.send_header("Location", "https://other.example/")
                    self.end_headers()
                    return
                self.send_body(b"x" * 65537 if owner.mode == "oversize" else owner.payload)

            def do_POST(self) -> None:
                request = self.rfile.read(int(self.headers["Content-Length"]))
                owner.requests.append(("POST", self.path, dict(self.headers), request))
                if owner.receipt is None:
                    body = json.loads(request)
                    owner.receipt = consumer.encode(
                        {
                            "version": 1,
                            "batchSha256": owner.tag[13:-1],
                            "events": body["events"],
                            "actorId": ACTOR,
                            "requestId": "original",
                            "reason": body["reason"],
                        }
                    )
                if owner.first_ack:
                    owner.first_ack = False
                    self.connection.shutdown(socket.SHUT_RDWR)
                    self.connection.close()
                else:
                    self.send_body(owner.receipt)

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(self.cert, key)
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.close_server)
        self.base = BASE.replace("issuer.example", f"localhost:{self.server.server_port}")
        self.session = self.root / "session.json"
        self.session.write_bytes(
            consumer.encode(
                {
                    "cookie": "aegaeon_admin_session=fixture; csrf_token=fixture",
                    "csrfToken": "fixture",
                    "origin": "https://admin.example",
                }
            )
        )
        self.session.chmod(0o600)

    def close_server(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)

    def cli(
        self, operation: str, *arguments: str, trusted: bool = True, short: bool = False
    ) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment.pop("SSL_CERT_FILE", None)
        environment.pop("SSL_CERT_DIR", None)
        if trusted:
            environment["SSL_CERT_FILE"] = str(self.cert)
        command = [sys.executable, str(SCRIPT)]
        if short:
            code = (
                f"import sys;sys.path.insert(0,{str(SCRIPT.parent)!r});"
                "import organization_audit_consumer as c;c.TIMEOUT=1;c.main()"
            )
            command = [sys.executable, "-c", code]
        return subprocess.run(  # noqa: S603 — current interpreter and fixed repository test command
            [
                *command,
                operation,
                "--state",
                str(self.state),
                "--session-file",
                str(self.session),
                *arguments,
            ],
            env=environment,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )

    def test_tls_fetch_lost_ack_and_same_key_recovery(self) -> None:
        fetched = self.cli("fetch", "--base", self.base)
        self.assertEqual(fetched.returncode, 0, fetched.stderr)
        batch = fetched.stdout.strip()
        self.assertTrue((self.state / batch / "manifest.json").is_file())
        self.assertNotEqual(self.cli("ack", "--batch", batch).returncode, 0)
        self.assertFalse((self.state / batch / "receipt.json").exists())
        recovered = self.cli("ack", "--batch", batch)
        self.assertEqual(recovered.returncode, 0, recovered.stderr)
        self.assertEqual(self.requests[1][3], self.requests[2][3])
        self.assertEqual(
            self.requests[1][2]["Idempotency-Key"], self.requests[2][2]["Idempotency-Key"]
        )
        self.assertEqual(self.requests[2][2]["If-Match"], self.tag)
        self.assertEqual(self.requests[2][2]["X-CSRF-Token"], "fixture")
        self.assertEqual(self.requests[2][2]["Origin"], "https://admin.example")
        self.assertEqual((self.state / batch / "receipt.json").read_bytes(), self.receipt)

    def test_untrusted_tls_refused_before_http(self) -> None:
        failed = self.cli("fetch", "--base", self.base, trusted=False)
        self.assertNotEqual(failed.returncode, 0)
        self.assertIn("CERTIFICATE_VERIFY_FAILED", failed.stderr)
        self.assertEqual(self.requests, [])
        self.assertEqual(list(self.state.iterdir()), [])

    def test_redirect_and_oversize_do_not_create_custody(self) -> None:
        for mode in ("redirect", "oversize"):
            self.mode = mode
            failed = self.cli("fetch", "--base", self.base)
            self.assertNotEqual(failed.returncode, 0, mode)
            self.assertEqual(list(self.state.iterdir()), [])
        self.assertEqual(len(self.requests), 2)

    def test_absolute_deadline_interrupts_blocked_read(self) -> None:
        self.mode = "stall"
        started = time.monotonic()
        failed = self.cli("fetch", "--base", self.base, short=True)
        self.assertNotEqual(failed.returncode, 0)
        self.assertLess(time.monotonic() - started, 3)
        self.assertIn("finite consumer deadline", failed.stderr)
        self.assertEqual(list(self.state.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
