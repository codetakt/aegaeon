"""Bounded HTTPS acceptance example with a durable deduplicated mail spool.

The spool contains secrets. Run under a dedicated account in an encrypted,
private directory. A separate operator-controlled mail submission service reads
the stored RFC 5322 messages; HTTP acceptance does not establish inbox delivery.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import hmac
import http.server
import io
import json
import os
import sqlite3
import ssl
import stat
import sys
import time
import urllib.parse
import uuid
from dataclasses import dataclass, field
from email.headerregistry import Address
from email.message import EmailMessage
from email.policy import SMTP
from email.utils import formatdate
from pathlib import Path

MAX_BODY = 8192
MAX_LIFETIME = 86400
REQUEST_SECONDS = 3
FIELDS = frozenset(
    {
        "version",
        "messageId",
        "template",
        "recipient",
        "issuer",
        "environmentId",
        "domainId",
        "invitationId",
        "objectId",
        "deliveryRevision",
        "capability",
        "expiresAt",
    }
)
SUBJECTS = {
    "organization_invitation": "Organization invitation",
    "organization_recipient_challenge": "Confirm your invitation",
    "organization_identity_registration": "Complete account registration",
    "organization_identity_recovery": "Recover your account",
}
CONTACT_SUBJECTS = {
    "contact_verification": "Verify your contact address",
    "contact_changed": "Your account contact address changed",
}
CONTACT_FIELDS = {
    "version",
    "template",
    "templateVersion",
    "messageId",
    "environmentId",
    "issuer",
    "operationId",
    "address",
    "expiresAt",
}


class RefusedError(Exception):
    def __init__(self, status=400):
        self.status = status


def canonical_uuid(value):
    if not isinstance(value, str):
        raise RefusedError
    try:
        parsed = uuid.UUID(value)
    except ValueError as error:
        raise RefusedError from error
    if parsed.int == 0 or str(parsed) != value:
        raise RefusedError
    return value


def secret32(value):
    if not isinstance(value, str) or len(value) != 43:
        raise RefusedError
    try:
        raw = base64.b64decode(value + "=", altchars=b"-_", validate=True)
    except ValueError as error:
        raise RefusedError from error
    if len(raw) != 32 or base64.urlsafe_b64encode(raw).decode().rstrip("=") != value:
        raise RefusedError
    return value


def https_url(value):
    if not isinstance(value, str) or len(value) > 2048 or any(ord(c) <= 32 for c in value):
        raise RefusedError
    try:
        parts = urllib.parse.urlsplit(value)
        if (
            parts.scheme != "https"
            or not parts.hostname
            or parts.username is not None
            or parts.password is not None
            or parts.port not in (None, 443)
            or parts.query
            or parts.fragment
        ):
            raise RefusedError
    except ValueError as error:
        raise RefusedError from error
    return value


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise RefusedError
        value[key] = item
    return value


def read_envelope(raw, issuer, environment_id):
    try:
        value = json.loads(raw, object_pairs_hook=unique_object)
    except (ValueError, RecursionError, UnicodeError) as error:
        raise RefusedError from error
    if not isinstance(value, dict) or type(value.get("version")) is not int:
        raise RefusedError
    if value.get("issuer") != issuer:
        raise RefusedError
    if environment_id is None:
        if value["version"] != 2:
            raise RefusedError
    elif value["version"] != 3 or value.get("environmentId") != environment_id:
        raise RefusedError
    return value


def decode_invitation(value, key, now):
    if set(value) != FIELDS:
        raise RefusedError
    if not isinstance(value["template"], str) or value["template"] not in SUBJECTS:
        raise RefusedError
    for name in ["messageId", "environmentId", "domainId", "invitationId", "objectId"]:
        canonical_uuid(value[name])
    if value["messageId"] != key:
        raise RefusedError
    invitation = value["template"] == "organization_invitation"
    if (value["invitationId"] == value["objectId"]) != invitation:
        raise RefusedError
    if (
        type(value["deliveryRevision"]) is not int
        or not 1 <= value["deliveryRevision"] <= 5
        or type(value["expiresAt"]) is not int
    ):
        raise RefusedError
    if not now < value["expiresAt"] <= now + MAX_LIFETIME:
        raise RefusedError(410)
    valid_address(value["recipient"])
    secret32(value["capability"])
    return value


def decode_contact(value, key, now):
    template = value.get("template")
    if not isinstance(template, str) or template not in CONTACT_SUBJECTS:
        raise RefusedError
    extra = {"proof"} if template == "contact_verification" else {"changedAt"}
    if (
        set(value) != CONTACT_FIELDS | extra
        or type(value["templateVersion"]) is not int
        or value["templateVersion"] != 1
        or value["messageId"] != key
    ):
        raise RefusedError
    for name in ["messageId", "environmentId", "operationId"]:
        canonical_uuid(value[name])
    valid_address(value["address"])
    lifetime = 900 if template == "contact_verification" else MAX_LIFETIME
    if type(value["expiresAt"]) is not int or not now < value["expiresAt"] <= now + lifetime:
        raise RefusedError(410)
    if template == "contact_verification":
        secret32(value["proof"])
    elif type(value["changedAt"]) is not int or not 0 <= value["changedAt"] <= now:
        raise RefusedError
    return value


def valid_address(value):
    if (
        not isinstance(value, str)
        or not 3 <= len(value.encode()) <= 254
        or any(ord(c) < 32 or ord(c) == 127 for c in value)
    ):
        raise RefusedError
    try:
        canonical = Address(addr_spec=value).addr_spec
    except ValueError as error:
        raise RefusedError from error
    if canonical != value:
        raise RefusedError
    return value


def render(value, recipient_ui, sender, now):
    if value["version"] == 3:
        return render_contact(value, sender, now)
    # Fixed UI configuration; no request supplies a URL, HTML or a template path.
    fragment = {
        key: value[key]
        for key in [
            "issuer",
            "environmentId",
            "domainId",
            "invitationId",
            "objectId",
            "template",
            "deliveryRevision",
            "capability",
            "expiresAt",
        ]
    }
    encoded = (
        base64.urlsafe_b64encode(json.dumps(fragment, separators=(",", ":")).encode())
        .decode()
        .rstrip("=")
    )
    mail = EmailMessage(policy=SMTP)
    mail["From"] = sender
    mail["To"] = value["recipient"]
    mail["Subject"] = SUBJECTS[value["template"]]
    mail["Message-ID"] = "<" + value["messageId"] + "@notification.invalid>"
    mail["Date"] = formatdate(now, usegmt=True)
    mail.set_content(
        "Open this link to continue. Opening the link does not accept an invitation.\n\n"
        + recipient_ui
        + "#aegaeon="
        + encoded
        + "\n\nThis action expires at Unix time "
        + str(value["expiresAt"])
        + ".\n"
    )
    return mail.as_bytes()


def render_contact(value, sender, now):
    mail = EmailMessage(policy=SMTP)
    mail["From"] = sender
    mail["To"] = value["address"]
    mail["Subject"] = CONTACT_SUBJECTS[value["template"]]
    mail["Message-ID"] = "<" + value["messageId"] + "@notification.invalid>"
    mail["Date"] = formatdate(now, usegmt=True)
    if value["template"] == "contact_verification":
        body = (
            "Use this code only in the account contact change you requested.\n\n"
            + value["proof"]
            + "\n\nOperation: "
            + value["operationId"]
            + "\nExpires at Unix time "
            + str(value["expiresAt"])
            + ".\n"
            + "This code does not log you in or reset your password.\n"
        )
    else:
        body = (
            "Your account contact address changed at Unix time "
            + str(value["changedAt"])
            + ".\n"
            + "If you did not request this change, contact your account operator.\n"
        )
    mail.set_content(body)
    return mail.as_bytes()


@dataclass(kw_only=True, eq=False, repr=False)
class Spool:
    path: Path = field(kw_only=False)
    issuer: str
    sender: str
    recipient_ui: str | None = None
    environment_id: str | None = None
    retention: int = MAX_LIFETIME

    def __post_init__(self):
        self.path = Path(self.path)
        if (
            not self.path.is_absolute()
            or self.retention < MAX_LIFETIME
            or sqlite3.sqlite_version_info < (3, 51, 3)
        ):
            raise RefusedError
        parent = self.path.parent.lstat()
        if (
            not stat.S_ISDIR(parent.st_mode)
            or parent.st_uid != os.geteuid()
            or parent.st_mode & 0o077
        ):
            raise RefusedError
        if self.path.exists() or self.path.is_symlink():
            current = self.path.lstat()
            if (
                not stat.S_ISREG(current.st_mode)
                or current.st_uid != os.geteuid()
                or current.st_mode & 0o077
                or current.st_nlink != 1
            ):
                raise RefusedError
        https_url(self.issuer)
        if (self.recipient_ui is None) == (self.environment_id is None):
            raise RefusedError
        if self.environment_id is not None:
            canonical_uuid(self.environment_id)
        else:
            https_url(self.recipient_ui)
        valid_address(self.sender)
        # The account's private directory prevents path replacement by outsiders.
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        with contextlib.closing(self.connect()) as connection:
            if connection.execute("PRAGMA journal_mode=WAL").fetchone() != ("wal",):
                raise RefusedError
            connection.execute("""CREATE TABLE IF NOT EXISTS accepted(
                id TEXT PRIMARY KEY, digest BLOB NOT NULL, expires INTEGER NOT NULL,
                retained_until INTEGER NOT NULL, mail BLOB NOT NULL)""")
            connection.commit()

    def connect(self):
        connection = sqlite3.connect(self.path, timeout=2)
        connection.execute("PRAGMA synchronous=FULL")
        if connection.execute("PRAGMA synchronous").fetchone() != (2,):
            connection.close()
            raise RefusedError
        return connection

    def accept(self, raw, key, now):
        if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_BODY:
            raise RefusedError
        canonical_uuid(key)
        digest = hashlib.sha256(raw).digest()
        with contextlib.closing(self.connect()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            prior = connection.execute("SELECT digest FROM accepted WHERE id=?", (key,)).fetchone()
            if prior is not None and not hmac.compare_digest(prior[0], digest):
                raise RefusedError(409)
            value = read_envelope(raw, self.issuer, self.environment_id)
            if prior is not None:
                return 204
            if self.environment_id is None:
                decode_invitation(value, key, now)
            else:
                decode_contact(value, key, now)
            if connection.execute("SELECT count(*) FROM accepted").fetchone()[0] >= 10000:
                raise RefusedError(503)
            mail = render(value, self.recipient_ui, self.sender, now)
            connection.execute(
                "INSERT INTO accepted VALUES(?,?,?,?,?)",
                (
                    key,
                    digest,
                    value["expiresAt"],
                    max(value["expiresAt"], now + self.retention),
                    mail,
                ),
            )
        return 204

    def purge(self, now):
        # Bounded logical cleanup; encrypted storage/backups have their own erasure policy.
        with contextlib.closing(self.connect()) as connection, connection:
            connection.execute(
                "DELETE FROM accepted WHERE id IN "
                "(SELECT id FROM accepted WHERE retained_until<=? "
                "ORDER BY retained_until LIMIT 32)",
                (now,),
            )


def private_credential(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_mode & 0o077
            or info.st_nlink != 1
            or not 43 <= info.st_size <= 44
        ):
            raise RefusedError
        return secret32(os.read(fd, 45).decode("ascii").removesuffix("\n"))
    finally:
        os.close(fd)


class Server(http.server.HTTPServer):
    request_queue_size = 16

    def __init__(self, address, tls, spool, credential):
        self.tls, self.spool, self.credential = tls, spool, credential
        super().__init__(address, Handler)

    def get_request(self):
        raw, peer = super().get_request()
        # This server handles one connection at a time. The same absolute
        # deadline covers TLS, request line, headers and the complete body.
        self.request_deadline = time.monotonic() + REQUEST_SECONDS
        raw.settimeout(REQUEST_SECONDS)
        try:
            return self.tls.wrap_socket(raw, server_side=True), peer
        except Exception:
            raw.close()
            raise

    def handle_error(self, _request, _client_address):
        # Never emit traceback text, headers or request bodies.
        pass


class DeadlineReader(io.RawIOBase):
    def __init__(self, connection, deadline):
        self.connection, self.deadline = connection, deadline

    def readable(self):
        return True

    def readinto(self, buffer):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError
        self.connection.settimeout(remaining)
        return self.connection.recv_into(buffer)


class Handler(http.server.BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.rfile.close()
        self.rfile = io.BufferedReader(
            DeadlineReader(self.connection, self.server.request_deadline)
        )

    def log_message(self, *_args):
        pass

    def accept_request(self):
        if self.path != "/envelopes" or self.headers.get_all("transfer-encoding"):
            raise RefusedError
        for name in ["content-length", "authorization", "content-type", "idempotency-key"]:
            if len(self.headers.get_all(name, [])) != 1:
                raise RefusedError
        if self.headers["content-type"] != "application/json":
            raise RefusedError
        expected = ("Bearer " + self.server.credential).encode("ascii")
        if not hmac.compare_digest(self.headers["authorization"].encode("ascii"), expected):
            raise RefusedError(401)
        size = int(self.headers["content-length"])
        if not 0 < size <= MAX_BODY:
            raise RefusedError
        raw = self.rfile.read(size)
        if len(raw) != size:
            raise RefusedError
        now = int(time.time())
        self.server.spool.purge(now)
        return self.server.spool.accept(raw, self.headers["idempotency-key"], now)

    def do_POST(self):
        status = 400
        try:
            status = self.accept_request()
        except RefusedError as error:
            status = error.status
        except (ValueError, UnicodeError, OSError, sqlite3.Error):
            status = 503
        self.send_response(status)
        self.send_header("Content-Length", "0")
        self.send_header("Cache-Control", "no-store")
        if status == 503:
            self.send_header("Retry-After", "60")
        self.end_headers()
        self.close_connection = True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["database", "credential-file", "certificate", "private-key"]:
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ["issuer", "sender", "bind"]:
        parser.add_argument("--" + name, required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--recipient-ui")
    mode.add_argument("--environment-id")
    parser.add_argument("--port", type=int, default=443)
    args = parser.parse_args()
    os.umask(0o077)
    try:
        spool = Spool(
            args.database,
            issuer=args.issuer,
            recipient_ui=args.recipient_ui,
            environment_id=args.environment_id,
            sender=args.sender,
        )
        credential = private_credential(args.credential_file)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.minimum_version = ssl.TLSVersion.TLSv1_3
        tls.load_cert_chain(args.certificate, args.private_key)
        with Server((args.bind, args.port), tls, spool, credential) as server:
            server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        return 0
    except (RefusedError, OSError, ValueError, sqlite3.Error):
        print("notification adapter unavailable", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
