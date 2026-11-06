"""Owned bounded TLS adapter; no production resolver or trust overrides."""

from __future__ import annotations

import http.server
import json
import ssl
import threading


class Adapter(http.server.HTTPServer):
    def __init__(self, directory):
        self.messages = []
        self.connections = 0
        self.tls_errors = []
        self.tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.tls.load_cert_chain(directory / "delivery.crt", directory / "delivery.key")
        super().__init__(("0.0.0.0", 443), Handler)  # noqa: S104 — isolated namespace, no external route
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)
        self.thread.start()

    def get_request(self):
        raw, peer = super().get_request()
        self.connections += 1
        raw.settimeout(3)
        try:
            return self.tls.wrap_socket(raw, server_side=True), peer
        except ssl.SSLError as error:
            self.tls_errors.append(error.reason)
            raw.close()
            raise
        except Exception:
            raw.close()
            raise

    def close(self):
        self.shutdown()
        self.server_close()
        self.thread.join(timeout=5)
        if self.thread.is_alive():
            msg = "delivery adapter did not stop"
            raise RuntimeError(msg)


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_POST(self):
        size = int(self.headers.get("content-length", "0"))
        if self.path != "/envelopes" or not 0 < size <= 8192:
            self.send_error(400)
            return
        value = json.loads(self.rfile.read(size))
        # Retain capabilities only in fixture memory for leak checks, never logs.
        value["received_authorization"] = self.headers.get("authorization")
        self.server.messages.append(value)
        self.send_response(204)
        self.end_headers()
