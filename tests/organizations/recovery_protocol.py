"""Actual TLS fault peers for the offline recovery RESP boundary."""

from __future__ import annotations

import socket
import ssl
import threading

import pytest


def refusals(certificate, key, connection_type):  # noqa: PLR0915 — ordered TLS fault inventory
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certificate, key)
    ca = certificate.read_text()
    cases = {
        "bulk budget": b"$1048577\r\n",
        "array budget": b"*4097\r\n",
        "nesting budget": b"*1\r\n" * 10 + b"+OK\r\n",
        "line budget": b"+" + b"x" * 4097 + b"\r\n",
        "truncated bulk": b"$10\r\nshort",
        "bulk terminator": b"$1\r\nx??",
        "unexpected RESP version": b"#t\r\n",
        "redacted error": b"-ERR private-token-must-not-escape\r\n",
    }
    passed = []
    for name, response in cases.items():
        failures = []
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            listener.settimeout(5)
            port = listener.getsockname()[1]

            def serve(listener=listener, response=response, failures=failures):
                try:
                    with (
                        listener.accept()[0] as raw,
                        context.wrap_socket(raw, server_side=True) as stream,
                    ):
                        stream.settimeout(5)
                        assert b"AUTH" in stream.recv(4096)
                        stream.sendall(b"+OK\r\n")
                        assert b"PING" in stream.recv(4096)
                        stream.sendall(response)
                except BaseException as error:  # noqa: BLE001 — retain thread failure
                    failures.append(type(error).__name__)

            worker = threading.Thread(target=serve, daemon=True)
            worker.start()
            client = None
            try:
                client = connection_type("localhost", port, ca, "admin", "fixture-password")
                with pytest.raises(Exception, match="Redis") as raised:
                    client.call("PING")
                assert "private-token" not in str(raised.value)
                assert client.failed
                with pytest.raises(Exception, match="cannot be reused"):
                    client.call("PING")
            finally:
                if client:
                    client.close()
                worker.join(timeout=6)
            assert not worker.is_alive()
            assert not failures
        passed.append(name)
    return passed
