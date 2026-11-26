"""Actual durable acceptance, restart, conflict and secret-lifetime boundaries."""

from __future__ import annotations

# ruff: noqa: PT027 - collected by the required unittest discovery gate.
import base64
import contextlib
import http.client
import json
import socket
import sqlite3
import ssl
import sys
import tempfile
import threading
import time
import unittest
import uuid
from concurrent.futures import ThreadPoolExecutor
from email import policy
from email.parser import BytesParser
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import override

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "examples/notification-adapter"))
import adapter

ROOT = Path(__file__).resolve().parents[2]
CERTIFICATE = ROOT / "tests/ci/fixtures/notification-adapter-cert.crt"


def message(**changes):
    invitation = str(uuid.uuid4())
    value = {
        "version": 2,
        "messageId": str(uuid.uuid4()),
        "template": "organization_invitation",
        "recipient": "Invitee+Test@example.test",
        "issuer": "https://issuer.example.test",
        "environmentId": str(uuid.uuid4()),
        "domainId": str(uuid.uuid4()),
        "invitationId": invitation,
        "objectId": invitation,
        "deliveryRevision": 1,
        "capability": base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip("="),
        "expiresAt": 200,
    }
    value.update(changes)
    return value, json.dumps(value, separators=(",", ":")).encode()


def contact_message(template, now, environment):
    v = {
        "version": 3,
        "template": template,
        "templateVersion": 1,
        "messageId": str(uuid.uuid4()),
        "environmentId": environment,
        "issuer": "https://issuer.example.test",
        "operationId": str(uuid.uuid4()),
        "address": "Contact+Case@example.test",
        "expiresAt": now + (600 if template == "contact_verification" else 86400),
    }
    if template == "contact_verification":
        v["proof"] = base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip("=")
    else:
        v["changedAt"] = now
    return v


def open_spool(path, environment=None):
    return adapter.Spool(
        path,
        issuer="https://issuer.example.test",
        recipient_ui="https://recipient.example.test/continue" if environment is None else None,
        environment_id=environment,
        sender="sender@example.test",
    )


def rows(spool):
    with contextlib.closing(spool.connect()) as connection:
        return connection.execute("SELECT id, digest, mail FROM accepted ORDER BY id").fetchall()


def stored_mail(raw, originated_at):
    assert b"\n" not in raw.replace(b"\r\n", b"")
    mail = BytesParser(policy=policy.default).parsebytes(raw)
    assert len(mail.get_all("Date")) == 1
    assert parsedate_to_datetime(mail["Date"]).timestamp() == originated_at
    return mail


@contextlib.contextmanager
def https_server(spool, handler=adapter.Handler):
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.minimum_version = ssl.TLSVersion.TLSv1_3
    # Public test certificate, using the repository's existing public fixture key.
    tls.load_cert_chain(CERTIFICATE, ROOT / "crates/server/tests/fixtures/rsa2048-private.pk8.pem")
    credential = base64.urlsafe_b64encode(bytes([7]) * 32).decode().rstrip("=")
    server = adapter.Server(("127.0.0.1", 0), tls, spool, credential)
    server.RequestHandlerClass = handler
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05})
    thread.start()
    try:
        yield server.server_address[1], credential
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()


def client_tls_context():
    context = ssl.create_default_context(cafile=str(CERTIFICATE))
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    return context


def post(port, credential, raw, key, *, timeout=2):
    context = client_tls_context()
    connection = http.client.HTTPSConnection("localhost", port, context=context, timeout=timeout)
    try:
        connection.request(
            "POST",
            "/envelopes",
            body=raw,
            headers={
                "Content-Type": "application/json",
                "Authorization": "Bearer " + credential,
                "Idempotency-Key": key,
            },
        )
        response = connection.getresponse()
        assert response.read() == b""
        return response.status
    finally:
        connection.close()


class NotificationAdapterTests(unittest.TestCase):
    def test_contact_real_https_replay_restart_and_plain_mail(self):
        now = int(time.time())
        environment = str(uuid.uuid4())
        spool = open_spool(self.spool.path.with_name("contact.sqlite"), environment)
        for template in ["contact_verification", "contact_changed"]:
            v = contact_message(template, now, environment)
            raw = json.dumps(v, separators=(",", ":")).encode()
            with https_server(spool) as (port, credential):
                assert post(port, credential, raw, v["messageId"]) == 204
                assert post(port, credential, raw, v["messageId"]) == 204
            stored = [r for r in rows(spool) if r[0] == v["messageId"]]
            assert len(stored) == 1
            mail = BytesParser(policy=policy.default).parsebytes(stored[0][2])
            assert str(mail["To"]) == v["address"]
            assert "#aegaeon" not in mail.get_content()
            if template == "contact_verification":
                assert v["proof"] in mail.get_content()
            else:
                assert "proof" not in mail.get_content()
            restarted = open_spool(spool.path, environment)
            assert restarted.accept(raw, v["messageId"], now + 1) == 204
            assert next(r for r in rows(restarted) if r[0] == v["messageId"])[2] == stored[0][2]

    def test_contact_strict_purpose_identity_and_lifetime(self):
        environment = str(uuid.uuid4())
        spool = open_spool(self.spool.path.with_name("contact.sqlite"), environment)
        for template in ["contact_verification", "contact_changed"]:
            base = contact_message(template, 100, environment)
            changes = [
                {"version": 3.0},
                {"templateVersion": True},
                {"issuer": "https://foreign.example.test"},
                {"environmentId": str(uuid.UUID(int=0))},
                {"expiresAt": 100},
                {"expiresAt": 100001},
                {"address": "bad\n@example.test"},
                {"template": "organization_invitation"},
            ]
            changes += (
                [{"proof": "A" * 43}]
                if template == "contact_changed"
                else [{"proof": "x" * 42}, {"changedAt": 100}]
            )
            for change in changes:
                value = base | change
                with self.assertRaises(adapter.RefusedError):
                    spool.accept(json.dumps(value).encode(), base["messageId"], 100)

    def test_environment_route_isolation_including_duplicate_receipts(self):
        environment = str(uuid.uuid4())
        path = self.spool.path.with_name("contact.sqlite")
        value = contact_message("contact_verification", 100, environment)
        raw = json.dumps(value).encode()
        key = value["messageId"]
        spool = open_spool(path, environment)
        assert spool.accept(raw, key, 100) == 204
        assert spool.accept(raw, key, value["expiresAt"] + 1) == 204
        for receiver in [self.spool, open_spool(path), open_spool(path, str(uuid.uuid4()))]:
            with self.assertRaises(adapter.RefusedError):
                receiver.accept(raw, key, 100)
        invitation, payload = message()
        with self.assertRaises(adapter.RefusedError):
            spool.accept(payload, invitation["messageId"], 100)
        assert len(rows(spool)) == 1

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="notification-adapter-")
        self.addCleanup(temporary.cleanup)
        directory = Path(temporary.name)
        directory.chmod(0o700)
        self.spool = open_spool(directory / "spool.sqlite")

    def test_acceptance_survives_restart_and_lost_reply_without_second_mail(self):
        spool = self.spool
        value, raw = message()
        assert spool.accept(raw, value["messageId"], 100) == 204
        original_mail = rows(spool)[0][2]
        restarted = open_spool(spool.path)
        assert restarted.accept(raw, value["messageId"], 101) == 204
        assert restarted.accept(raw, value["messageId"], 201) == 204
        stored = rows(restarted)
        assert len(stored) == 1
        assert stored[0][2] == original_mail
        mail = stored_mail(stored[0][2], 100)
        assert mail["To"] == value["recipient"]
        assert mail["Message-ID"] == "<" + value["messageId"] + "@notification.invalid>"
        link = next(line for line in mail.get_content().splitlines() if "#aegaeon=" in line)
        assert link.startswith("https://recipient.example.test/continue#aegaeon=")
        fragment = link.split("#aegaeon=", 1)[1]
        restored = json.loads(base64.urlsafe_b64decode(fragment + "=" * (-len(fragment) % 4)))
        assert restored["capability"] == value["capability"]
        assert restored["expiresAt"] == value["expiresAt"]
        with self.assertRaises(adapter.RefusedError) as error:
            restarted.accept(raw + b" ", value["messageId"], 101)
        assert error.exception.status == 409
        restarted.purge(100 + adapter.MAX_LIFETIME - 1)
        assert len(rows(restarted)) == 1
        restarted.purge(100 + adapter.MAX_LIFETIME)
        assert not rows(restarted)
        with self.assertRaises(adapter.RefusedError) as error:
            restarted.accept(raw, value["messageId"], 100 + adapter.MAX_LIFETIME)
        assert error.exception.status == 410

    def test_concurrent_duplicate_acceptance_creates_one_mail(self):
        spool = self.spool
        value, raw = message()
        with ThreadPoolExecutor(max_workers=4) as executor:
            attempts = [
                executor.submit(spool.accept, raw, value["messageId"], 100) for _ in range(8)
            ]
            assert [attempt.result(timeout=5) for attempt in attempts] == [204] * 8
        assert len(rows(spool)) == 1

    def test_failed_transaction_does_not_reserve_id_or_acknowledge_mail(self):
        spool = self.spool
        value, raw = message()
        with contextlib.closing(spool.connect()) as connection, connection:
            connection.execute(
                "CREATE TRIGGER refuse_mail BEFORE INSERT ON accepted "
                "BEGIN SELECT RAISE(ABORT, 'injected storage refusal'); END"
            )
        with self.assertRaises(sqlite3.IntegrityError):
            spool.accept(raw, value["messageId"], 100)
        assert not rows(spool)
        with contextlib.closing(spool.connect()) as connection, connection:
            connection.execute("DROP TRIGGER refuse_mail")
        assert open_spool(spool.path).accept(raw, value["messageId"], 100) == 204
        assert len(rows(spool)) == 1

    def test_invalid_authority_or_rendering_input_never_creates_mail(self):
        spool = self.spool
        for changes in [
            {"version": True},
            {"template": []},
            {"issuer": "https://another.example.test"},
            {"environmentId": str(uuid.UUID(int=0))},
            {"deliveryRevision": 0},
            {"deliveryRevision": 6},
            {"recipient": "Victim <victim@example.test>"},
            {"recipient": "victim@example.test\r\nBcc: other@example.test"},
            {"capability": "A" * 42},
            {"objectId": str(uuid.uuid4())},
            {"expiresAt": 100},
            {"expiresAt": 100 + adapter.MAX_LIFETIME + 1},
            {"extra": "unaccepted"},
        ]:
            with self.subTest(changes=changes):
                value, raw = message(**changes)
                with self.assertRaises(adapter.RefusedError):
                    spool.accept(raw, value["messageId"], 100)
                assert not rows(spool)

    def test_duplicate_fields_wrong_key_and_oversize_refused(self):
        spool = self.spool
        value, raw = message()
        duplicate = raw[:-1] + b',"version":2}'
        for body, key in [
            (duplicate, value["messageId"]),
            (raw, str(uuid.uuid4())),
            (b" " * (adapter.MAX_BODY + 1), value["messageId"]),
        ]:
            with self.assertRaises(adapter.RefusedError):
                spool.accept(body, key, 100)
        assert not rows(spool)

    def test_shared_or_linked_secret_storage_refused(self):
        spool = self.spool
        spool.path.chmod(0o640)
        with self.assertRaises(adapter.RefusedError):
            open_spool(spool.path)
        spool.path.chmod(0o600)
        linked = spool.path.with_name("linked.sqlite")
        linked.symlink_to(spool.path)
        with self.assertRaises(adapter.RefusedError):
            open_spool(linked)
        spool.path.parent.chmod(0o750)
        with self.assertRaises(adapter.RefusedError):
            open_spool(spool.path)

    def test_child_purposes_retain_parent_and_use_the_selected_template(self):
        spool = self.spool
        for template in list(adapter.SUBJECTS)[1:]:
            with self.subTest(template=template):
                value, raw = message(template=template, objectId=str(uuid.uuid4()))
                assert spool.accept(raw, value["messageId"], 100) == 204
                stored = next(row for row in rows(spool) if row[0] == value["messageId"])
                mail = BytesParser(policy=policy.default).parsebytes(stored[2])
                assert mail["Subject"] == adapter.SUBJECTS[template]

    def test_adapter_refuses_deduplication_window_shorter_than_message_lifetime(self):
        spool = self.spool
        with self.assertRaises(adapter.RefusedError):
            adapter.Spool(
                spool.path,
                issuer=spool.issuer,
                recipient_ui=spool.recipient_ui,
                sender=spool.sender,
                retention=adapter.MAX_LIFETIME - 1,
            )

    def test_actual_https_acceptance_deduplicates_across_server_restart(self):
        spool = self.spool
        value, raw = message(expiresAt=int(time.time()) + 100)
        with https_server(spool) as (port, credential):
            assert post(port, "wrong", raw, value["messageId"]) == 401
            assert not rows(spool)
            assert post(port, credential, raw, value["messageId"]) == 204
        restarted = open_spool(spool.path)
        with https_server(restarted) as (port, credential):
            assert post(port, credential, raw, value["messageId"]) == 204
            assert post(port, credential, raw + b" ", value["messageId"]) == 409
        assert len(rows(restarted)) == 1

    def test_slow_tls_request_line_headers_and_body_release_server_by_absolute_deadline(self):
        for phase in ["request-line", "headers", "body"]:
            with self.subTest(phase=phase), https_server(self.spool) as (port, credential):
                context = client_tls_context()
                raw_socket = socket.create_connection(("127.0.0.1", port), timeout=2)
                with context.wrap_socket(raw_socket, server_hostname="localhost") as peer:
                    prefix = {
                        "request-line": b"POST /envelopes",
                        "headers": b"POST /envelopes HTTP/1.1\r\nX-Slow: ",
                        "body": (
                            "POST /envelopes HTTP/1.1\r\nContent-Type: application/json\r\n"
                            f"Authorization: Bearer {credential}\r\n"
                            f"Idempotency-Key: {uuid.uuid4()}\r\n"
                            f"Content-Length: {adapter.MAX_BODY}\r\n\r\n{{"
                        ).encode(),
                    }[phase]
                    started = time.monotonic()
                    peer.sendall(prefix)
                    stopped = threading.Event()
                    sent = []

                    def trickle(connection, start, stop, timestamps):
                        # Finite cleanup even against the old vulnerable server.
                        # Every write is far inside its former inactivity timeout.
                        end = start + adapter.REQUEST_SECONDS + 4
                        while time.monotonic() < end and not stop.wait(0.1):
                            try:
                                connection.sendall(b"x")
                                timestamps.append(time.monotonic())
                            except OSError:
                                return

                    thread = threading.Thread(target=trickle, args=(peer, started, stopped, sent))
                    thread.start()
                    try:
                        value, raw = message(expiresAt=int(time.time()) + 100)
                        assert post(port, credential, raw, value["messageId"], timeout=6) == 204
                        assert time.monotonic() - started < adapter.REQUEST_SECONDS + 2
                        assert len(sent) >= 4
                    finally:
                        stopped.set()
                        peer.close()
                        thread.join(timeout=3)
                        assert not thread.is_alive()
        # No partial attack request reached durable acceptance.
        assert len(rows(self.spool)) == 3

    def test_lost_https_reply_after_durable_acceptance_does_not_duplicate_after_restart(self):
        class LostReply(adapter.Handler):
            @override
            def do_POST(self):
                # Exercise the real acceptance commit, then lose the response on
                # the wire. This is separate from merely calling accept twice.
                assert self.accept_request() == 204
                self.close_connection = True
                self.connection.shutdown(socket.SHUT_RDWR)

        value, raw = message(expiresAt=int(time.time()) + 100)
        with (
            https_server(self.spool, LostReply) as (port, credential),
            self.assertRaises(http.client.RemoteDisconnected),
        ):
            post(port, credential, raw, value["messageId"])
        accepted = rows(self.spool)
        assert len(accepted) == 1
        restarted = open_spool(self.spool.path)
        with https_server(restarted) as (port, credential):
            assert post(port, credential, raw, value["messageId"]) == 204
        assert rows(restarted) == accepted
