"""Owned HTTPS frontend and same-origin form client; no TLS verification bypass."""

from __future__ import annotations

import http.client
import http.server
import json
import socket
import ssl
import threading
from contextlib import contextmanager
from http.cookies import SimpleCookie
from urllib.parse import urlencode, urlsplit

from delivery_journey import require


def certificate(delivery):
    directory = delivery.directory
    host = urlsplit(delivery.receipt["issuer"]).hostname
    (directory / "browser.ext").write_text(
        "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
        f"extendedKeyUsage=serverAuth\nsubjectAltName=DNS:{host},DNS:admin.example.test\n"
    )
    commands = [
        [
            "openssl",
            "req",
            "-new",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-subj",
            "/CN=" + host,
            "-keyout",
            directory / "browser.key",
            "-out",
            directory / "browser.csr",
        ],
        [
            "openssl",
            "x509",
            "-req",
            "-in",
            directory / "browser.csr",
            "-CA",
            directory / "trusted.crt",
            "-CAkey",
            directory / "trusted.key",
            "-CAcreateserial",
            "-days",
            "1",
            "-extfile",
            directory / "browser.ext",
            "-out",
            directory / "browser.crt",
        ],
    ]
    for command in commands:
        require(delivery.run(command, timeout=20).returncode == 0, "fixture TLS certificate")
    (directory / "browser.key").chmod(0o600)


class Frontend(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, delivery, backend):
        self.backend = backend
        self.host = urlsplit(delivery.receipt["issuer"]).netloc
        self.failures = []
        self.audit_requests = []
        self.drop_audit_ack = False
        super().__init__(("127.0.0.1", 0), Handler)
        self.tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.tls.minimum_version = ssl.TLSVersion.TLSv1_2
        self.tls.load_cert_chain(
            delivery.directory / "browser.crt", delivery.directory / "browser.key"
        )
        self.socket = self.tls.wrap_socket(self.socket, server_side=True)


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        self.forward()

    def do_POST(self):
        self.forward()

    def do_PUT(self):
        self.forward()

    def forward(self):
        try:
            self.transfer()
        except Exception as error:  # noqa: BLE001 — fixture fails without retaining secret input
            self.server.failures.append(type(error).__name__)
            self.send_error(502)

    def transfer(self):
        self.connection.settimeout(20)
        size = int(self.headers.get("content-length", "0"))
        require(
            0 <= size <= 65536 and "transfer-encoding" not in self.headers, "bounded frontend input"
        )
        body = self.rfile.read(size)
        require(len(body) == size, "complete frontend body")
        headers = {
            name: value
            for name, value in self.headers.items()
            if name.lower() not in {"host", "forwarded", "connection"}
            and not name.lower().startswith("x-forwarded-")
        }
        headers["host"] = self.server.host
        headers["forwarded"] = f'for=127.0.0.1;proto=https;host="{self.server.host}"'
        link = http.client.HTTPConnection("127.0.0.1", self.server.backend, timeout=20)
        try:
            link.request(self.command, self.path, body, headers)
            response = link.getresponse()
            data = response.read(65537)
            require(len(data) <= 65536, "bounded frontend response")
            if "/audit-events/" in self.path:
                self.server.audit_requests.append(
                    {"method": self.command, "path": self.path, "status": response.status}
                )
                if self.path.endswith("/acknowledgments") and self.server.drop_audit_ack:
                    require(response.status == 200, "lost ACK follows actual successful commit")
                    self.server.drop_audit_ack = False
                    self.connection.shutdown(socket.SHUT_RDWR)
                    self.connection.close()
                    return
            self.send_response(response.status)
            for name, value in response.getheaders():
                if name.lower() not in {"transfer-encoding", "content-length", "connection"}:
                    self.send_header(name, value)
            self.send_header("content-length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        finally:
            link.close()


class Connection(http.client.HTTPSConnection):
    def connect(self):
        # Only the owned fixture's physical address is routed locally. Certificate
        # trust, SNI, hostname and protocol origin stay the actual issuer's values.
        raw = socket.create_connection(("127.0.0.1", self.port), timeout=self.timeout)
        self.sock = self._context.wrap_socket(raw, server_hostname=self.host)


class Browser:
    def __init__(self, delivery, port):
        self.issuer = delivery.receipt["issuer"]
        self.host = urlsplit(self.issuer).hostname
        self.port = port
        self.tls = ssl.create_default_context(cafile=delivery.directory / "trusted.crt")
        self.cookies = SimpleCookie()
        self.events = []

    def request(self, method, path, fields=None, **options):
        expected = options.get("expected", 200)
        headers = {"host": self.host, "origin": self.issuer}
        cookies = [
            f"{name}={value.value}"
            for name, value in self.cookies.items()
            if path.startswith(value["path"] or "/") and value["max-age"] != "0"
        ]
        headers["cookie"] = "; ".join(cookies)
        body = urlencode(fields) if fields is not None else None
        if body is not None:
            headers["content-type"] = "application/x-www-form-urlencoded"
        if options.get("json_body") is not None:
            require(fields is None, "one request body encoding")
            body = json.dumps(options["json_body"])
            headers["content-type"] = "application/json"
        headers.update(options.get("headers", {}))
        link = Connection(self.host, self.port, context=self.tls, timeout=20)
        try:
            link.request(method, path, body, headers)
            response = link.getresponse()
            content = response.read(65537)
            require(len(content) <= 65536, "bounded browser response")
            self.events.append(
                {"method": method, "path": urlsplit(path).path, "status": response.status}
            )
            if response.status >= 400 and response.getheader("content-type", "").startswith(
                "application/json"
            ):
                error = json.loads(content)
                self.events[-1]["error"] = {k: error.get(k) for k in ["error", "error_description"]}
            for name, value in response.getheaders():
                if name.lower() == "set-cookie":
                    self.cookies.load(value)
            self.last_response = response.status, {k.lower(): v for k, v in response.getheaders()}
            require(
                response.status in ((expected,) if isinstance(expected, int) else expected),
                f"{method} {path}: {response.status}, expected {expected}",
            )
            return content.decode()
        finally:
            link.close()

    def form(self, path, fields, *, expected=200, json_response=True):
        html = self.request("GET", path)
        marker = 'name="csrf_token" value="'
        require(marker in html, "fresh CSRF form")
        token = html.split(marker, 1)[1].split('"', 1)[0]
        result = self.request("POST", path, {"csrf_token": token, **fields}, expected=expected)
        return json.loads(result) if json_response else result


@contextmanager
def frontend(delivery, backend):
    certificate(delivery)
    server = Frontend(delivery, backend)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        browser = Browser(delivery, server.server_port)
        browser.frontend = server
        yield browser
        require(not server.failures, "fixture frontend failed")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        require(not thread.is_alive(), "fixture frontend did not stop")
