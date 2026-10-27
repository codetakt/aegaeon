"""Authenticated receipt admission for an owned controller, not a public service.

The caller supplies protected policy/event state. No PR code, network, cloud or
GitHub mutation runs here. Commissioning the issuer and delivery adapter remains
separate from testing this boundary with isolated test credentials.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import re
import sqlite3
import stat
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from inspect_dudect_evidence import (
    check_inventory,
    check_request,
    decode,
    digest,
    inspect,
    read_bounded,
    require,
)

DOMAIN = "aegaeon/external-dudect-receipt/1"
ROLES = ("producer", "verifier")
FINGERPRINT = re.compile(r"[0-9A-F]{40}|[0-9A-F]{64}")
SIGNATURE_LIMIT = 65536
VERIFICATION_SECONDS = 15


def encode(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def statement(role: str, document: bytes) -> bytes:
    require(role in ROLES, "unknown signing role")
    return encode({"domain": DOMAIN, "role": role, "document_sha256": digest(document)})


def validate_policy(policy: dict[str, Any]) -> None:
    require(policy["schema"] == "external-dudect-authentication/1", "unknown auth policy")
    for role in ROLES:
        require(
            isinstance(policy[role + "_fingerprint"], str)
            and FINGERPRINT.fullmatch(policy[role + "_fingerprint"]),
            "full primary fingerprint required",
        )
    require(
        policy["producer_fingerprint"] != policy["verifier_fingerprint"],
        "separate signing credentials required",
    )
    require(policy["producer_id"] != policy["verifier_id"], "separate operator identities required")


def verify_signature(role: str, document: bytes, signature: bytes, policy: dict[str, Any]) -> str:
    """Use only pinned public keys and binary; never consult the user's keyring."""
    validate_policy(policy)
    require(0 < len(signature) <= SIGNATURE_LIMIT, "signature size bound")
    binary = Path(policy["gpgv"])
    keyring = Path(policy["keyring"])
    require(binary.is_absolute() and keyring.is_absolute(), "absolute verifier paths required")
    require(digest(read_bounded(binary)) == policy["gpgv_sha256"], "verifier binary changed")
    keys = read_bounded(keyring)
    require(digest(keys) == policy["keyring_sha256"], "keyring changed")
    with tempfile.TemporaryDirectory(prefix="dudect-auth-") as temp:
        root = Path(temp)
        (root / "keys.gpg").write_bytes(keys)
        (root / "statement").write_bytes(statement(role, document))
        (root / "signature").write_bytes(signature)
        result = subprocess.run(
            [
                str(binary),
                "--homedir",
                temp,
                "--keyring",
                str(root / "keys.gpg"),
                "--status-fd",
                "1",
                str(root / "signature"),
                str(root / "statement"),
            ],
            env={"LC_ALL": "C", "GNUPGHOME": temp},
            capture_output=True,
            timeout=VERIFICATION_SECONDS,
            check=False,
        )
    require(result.returncode == 0, "signature verification failed")
    lines = [line.split() for line in result.stdout.decode("ascii").splitlines()]
    valid = [line[2:] for line in lines if line[:2] == ["[GNUPG:]", "VALIDSIG"]]
    forbidden = {"BADSIG", "ERRSIG", "EXPSIG", "EXPKEYSIG", "REVKEYSIG", "FAILURE"}
    require(not any(len(x) > 1 and x[1] in forbidden for x in lines), "invalid signature status")
    require(len(valid) == 1 and len(valid[0]) == 10, "one complete OpenPGP signature required")
    fields = valid[0]
    require(fields[7] in {"8", "9", "10"}, "SHA256 or stronger signature required")
    require(fields[8] == "00", "binary detached signature required")
    require(fields[9] == policy[role + "_fingerprint"], "unauthorized signing key")
    return fields[9]


def owned_database(path: Path) -> sqlite3.Connection:
    """Open a private local ledger. Its directory is an explicit trust boundary."""
    parent = path.parent.lstat()
    require(
        stat.S_ISDIR(parent.st_mode)
        and parent.st_uid == os.getuid()
        and stat.S_IMODE(parent.st_mode) == 0o700,
        "controller-owned 0700 ledger directory required",
    )
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        info = os.fstat(fd)
        require(
            stat.S_ISREG(info.st_mode)
            and info.st_uid == os.getuid()
            and info.st_nlink == 1
            and stat.S_IMODE(info.st_mode) == 0o600,
            "private regular ledger required",
        )
    finally:
        os.close(fd)
    db = sqlite3.connect(path, timeout=2, isolation_level=None)
    db.execute("PRAGMA synchronous=FULL")
    db.execute(
        "CREATE TABLE IF NOT EXISTS requests ("
        "id TEXT PRIMARY KEY, request BLOB NOT NULL, context BLOB NOT NULL, "
        "policy TEXT NOT NULL, state TEXT NOT NULL, result BLOB, "
        "delivered INTEGER NOT NULL DEFAULT 0, reason TEXT)"
    )
    return db


class Ledger:
    """Serialize issuance, cancellation, admission and resumable result delivery."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def issue(
        self, request: bytes, context: dict[str, Any], policy: dict[str, Any], now: int
    ) -> None:
        """Called only by a protected issuer after deriving the real event target."""
        validate_policy(policy)
        parsed = decode(request)

        check_request(parsed, context, now)
        check_inventory(parsed, context)
        require(now < parsed["acquisition_deadline"], "acquisition already expired")
        require(context["request_sha256"] == digest(request), "request digest mismatch")
        for name in ("producer_id", "verifier_id", "verifier_runtime_sha256"):
            require(context[name] == policy[name], "issuer policy mismatch")
        with contextlib.closing(owned_database(self.path)) as db, db:
            db.execute(
                "INSERT INTO requests(id,request,context,policy,state) VALUES(?,?,?,?, 'open')",
                (parsed["request_id"], request, encode(context), digest(encode(policy))),
            )

    def cancel(self, request_id: str, reason: str) -> None:
        require(bool(reason), "cancellation reason required")
        with contextlib.closing(owned_database(self.path)) as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT state FROM requests WHERE id=?", (request_id,)).fetchone()
            require(row is not None, "unknown request")
            db.execute(
                "UPDATE requests SET state='cancelled',reason=? WHERE id=?", (reason, request_id)
            )
            db.commit()

    def admit(  # noqa: PLR0913 - explicit authenticated inputs and protected target
        self,
        request_id: str,
        *,
        producer: bytes,
        replay: bytes,
        signatures: dict[str, bytes],
        policy: dict[str, Any],
        expected_subject: dict[str, Any],
    ) -> dict[str, Any]:
        """Authenticate off-lock, then recheck all mutable state before consuming."""
        auth = {
            "producer": verify_signature("producer", producer, signatures["producer"], policy),
            "verifier": verify_signature("verifier", replay, signatures["verifier"], policy),
        }
        with contextlib.closing(owned_database(self.path)) as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT request,context,policy,state FROM requests WHERE id=?", (request_id,)
            ).fetchone()
            require(row is not None, "unknown request")
            request, stored_context, policy_sha, state = row
            require(state == "open", "request already consumed or cancelled")
            require(policy_sha == digest(encode(policy)), "issued policy changed")
            context = decode(stored_context)
            require(context["subject"] == expected_subject, "current target differs from request")
            context["producer_sha256"] = digest(producer)
            context["replay_sha256"] = digest(replay)
            now = int(time.time())
            checked = inspect(
                context, {"request": request, "producer": producer, "replay": replay}, now
            )
            result = {
                "schema": "external-dudect-admission/1",
                "request_id": request_id,
                "subject": expected_subject,
                "request_sha256": digest(request),
                "producer_sha256": digest(producer),
                "replay_sha256": digest(replay),
                "policy_sha256": policy_sha,
                "authenticated_primary_keys": auth,
                "cases": checked["cases"],
                "admitted_at": now,
                "expires_at": decode(request)["expires_at"],
                "request_consumed": True,
                "dudect_admission": True,
                "github_check_published": False,
            }
            db.execute(
                "UPDATE requests SET state='admitted',result=? WHERE id=?",
                (encode(result), request_id),
            )
            db.commit()
        return result

    def pending(self, request_id: str, expected_subject: dict[str, Any]) -> dict[str, Any]:
        """Read an outbox item for exact-target publication; never create a trial."""
        with contextlib.closing(owned_database(self.path)) as db:
            row = db.execute(
                "SELECT state,result,delivered FROM requests WHERE id=?", (request_id,)
            ).fetchone()
        require(row is not None and row[0] == "admitted" and row[2] == 0, "no pending admission")
        result = decode(row[1])
        require(result["subject"] == expected_subject, "delivery target mismatch")
        require(int(time.time()) < result["expires_at"], "delivery expired")
        return result

    def delivered(self, request_id: str, result_sha256: str) -> None:
        """Acknowledge the exact idempotently published result, never another ID."""
        with contextlib.closing(owned_database(self.path)) as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT state,result FROM requests WHERE id=?", (request_id,)
            ).fetchone()
            require(row is not None and row[0] == "admitted", "admission cancelled or missing")
            require(digest(row[1]) == result_sha256, "published result digest mismatch")
            require(int(time.time()) < decode(row[1])["expires_at"], "publication expired")
            db.execute("UPDATE requests SET delivered=1 WHERE id=?", (request_id,))
            db.commit()


def command(args: argparse.Namespace) -> dict[str, Any]:
    """Explicit owned-controller entry; policy and subject are trusted inputs."""
    ledger = Ledger(args.ledger)
    if args.command == "issue":
        ledger.issue(
            read_bounded(args.request),
            decode(read_bounded(args.context)),
            decode(read_bounded(args.policy)),
            int(time.time()),
        )
        return {"state": "issued", "dudect_admission": False}
    if args.command == "cancel":
        ledger.cancel(args.request_id, args.reason)
        return {"state": "cancelled", "dudect_admission": False}
    if args.command == "delivered":
        ledger.delivered(args.request_id, args.result_sha256)
        return {"state": "delivery_recorded", "request_id": args.request_id}
    subject = decode(read_bounded(args.subject))
    if args.command == "pending":
        return ledger.pending(args.request_id, subject)
    return ledger.admit(
        args.request_id,
        producer=read_bounded(args.producer),
        replay=read_bounded(args.replay),
        signatures={
            "producer": read_bounded(args.producer_signature),
            "verifier": read_bounded(args.verifier_signature),
        },
        policy=decode(read_bounded(args.policy)),
        expected_subject=subject,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ledger", type=Path, required=True)
    commands = parser.add_subparsers(dest="command", required=True)
    for name, files, strings in (
        ("issue", ("request", "context", "policy"), ()),
        (
            "admit",
            ("producer", "replay", "producer-signature", "verifier-signature", "policy", "subject"),
            ("request-id",),
        ),
        ("cancel", (), ("request-id", "reason")),
        ("pending", ("subject",), ("request-id",)),
        ("delivered", (), ("request-id", "result-sha256")),
    ):
        sub = commands.add_parser(name)
        for field in files:
            sub.add_argument("--" + field, type=Path, required=True)
        for field in strings:
            sub.add_argument("--" + field, required=True)
    try:
        result = command(parser.parse_args())
    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
        sqlite3.Error,
        subprocess.SubprocessError,
    ) as error:
        print(json.dumps({"state": "rejected", "reason": str(error), "dudect_admission": False}))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
