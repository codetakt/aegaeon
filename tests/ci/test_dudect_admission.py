# ruff: noqa: S603 - isolated test-only GnuPG processes with explicit argv
"""Authenticate actual signatures and exercise the durable request state machine."""

from __future__ import annotations

import concurrent.futures
import copy
import json
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import pytest
from test_dudect_evidence_inspection import bound_blobs, fixture

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/ci"))
import dudect_admission as admission  # noqa: E402 - repository script import


class AdmissionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.home = tempfile.TemporaryDirectory(prefix="dudect-test-keys-")
        cls.root = Path(cls.home.name)
        cls.gpg = str(Path(shutil.which("gpg")).resolve())
        cls.gpgv = str(Path(shutil.which("gpgv")).resolve())
        cls.command = [cls.gpg, "--homedir", cls.home.name, "--batch", "--no-options"]
        cls.fingerprints = []
        for name in ("producer", "verifier"):
            subprocess.run(
                [
                    *cls.command,
                    "--pinentry-mode",
                    "loopback",
                    "--passphrase",
                    "",
                    "--quick-generate-key",
                    f"Dudect test {name} <{name}@example.invalid>",
                    "ed25519",
                    "sign",
                    "1d",
                ],
                check=True,
                capture_output=True,
                timeout=30,
            )
            listing = subprocess.check_output(
                [*cls.command, "--with-colons", "--list-keys", f"{name}@example.invalid"],
                timeout=10,
            ).decode()
            cls.fingerprints.append(
                next(x.split(":")[9] for x in listing.splitlines() if x.startswith("fpr:"))
            )
        cls.keyring = cls.root / "public.gpg"
        cls.keyring.write_bytes(subprocess.check_output([*cls.command, "--export"], timeout=10))

    @classmethod
    def tearDownClass(cls):
        subprocess.run(
            [
                str(Path(shutil.which("gpgconf")).resolve()),
                "--homedir",
                cls.home.name,
                "--kill",
                "gpg-agent",
            ],
            check=True,
            capture_output=True,
            timeout=10,
        )
        cls.home.cleanup()

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="dudect-ledger-")
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "ledger.sqlite"
        self.ledger = admission.Ledger(self.path)
        self.context, self.documents = fixture()
        self.blobs = bound_blobs(self.context, self.documents)
        self.policy = {
            "schema": "external-dudect-authentication/1",
            "producer_id": self.context["producer_id"],
            "verifier_id": self.context["verifier_id"],
            "verifier_runtime_sha256": self.context["verifier_runtime_sha256"],
            "producer_fingerprint": self.fingerprints[0],
            "verifier_fingerprint": self.fingerprints[1],
            "gpgv": self.gpgv,
            "gpgv_sha256": admission.digest(Path(self.gpgv).read_bytes()),
            "keyring": str(self.keyring),
            "keyring_sha256": admission.digest(self.keyring.read_bytes()),
        }
        self.signatures = {
            "producer": self.sign("producer", self.blobs["producer"], 0),
            "verifier": self.sign("verifier", self.blobs["replay"], 1),
        }
        self.ledger.issue(self.blobs["request"], self.context, self.policy, 15)

    def sign(self, role, data, signer):
        return subprocess.check_output(
            [
                *self.command,
                "--local-user",
                self.fingerprints[signer],
                "--pinentry-mode",
                "loopback",
                "--passphrase",
                "",
                "--detach-sign",
            ],
            input=admission.statement(role, data),
            timeout=10,
        )

    def admit(self):
        return self.ledger.admit(
            self.context["request_id"],
            producer=self.blobs["producer"],
            replay=self.blobs["replay"],
            signatures=self.signatures,
            policy=self.policy,
            expected_subject=self.context["subject"],
        )

    @patch.object(admission.time, "time", return_value=125)
    def test_real_signature_admission_and_restart_delivery(self, clock):
        result = self.admit()
        assert result["dudect_admission"] is True
        assert result["github_check_published"] is False
        assert result["cases"] == 42
        with pytest.raises(ValueError, match="consumed"):
            self.admit()
        restarted = admission.Ledger(self.path)
        assert restarted.pending(self.context["request_id"], self.context["subject"]) == result
        sha = admission.digest(admission.encode(result))
        restarted.delivered(self.context["request_id"], sha)
        restarted.delivered(self.context["request_id"], sha)
        with pytest.raises(ValueError, match="pending"):
            restarted.pending(self.context["request_id"], self.context["subject"])

    def test_byte_role_and_signer_substitution_rejected(self):
        for role, data, signature in (
            ("producer", self.blobs["producer"] + b" ", self.signatures["producer"]),
            ("verifier", self.blobs["producer"], self.signatures["producer"]),
            ("producer", self.blobs["producer"], self.sign("producer", self.blobs["producer"], 1)),
        ):
            with (
                self.subTest(role=role, data=data[:20]),
                pytest.raises(ValueError, match=r"signature|signing"),
            ):
                admission.verify_signature(role, data, signature, self.policy)

    @patch.object(admission.time, "time", return_value=125)
    def test_invalid_packet_does_not_consume_request(self, clock):
        self.documents["replay"]["results"][0]["qualification"] = "not_satisfied"
        bad = json.dumps(self.documents["replay"]).encode()
        with pytest.raises(ValueError, match="role not met"):
            self.ledger.admit(
                self.context["request_id"],
                producer=self.blobs["producer"],
                replay=bad,
                signatures={**self.signatures, "verifier": self.sign("verifier", bad, 1)},
                policy=self.policy,
                expected_subject=self.context["subject"],
            )
        assert self.admit()["dudect_admission"]

    @patch.object(admission.time, "time", return_value=125)
    def test_cancellation_before_and_after_validation(self, clock):
        self.ledger.cancel(self.context["request_id"], "event cancelled")
        with pytest.raises(ValueError, match="cancelled"):
            self.admit()
        with pytest.raises(sqlite3.IntegrityError):
            self.ledger.issue(self.blobs["request"], self.context, self.policy, 15)

    @patch.object(admission.time, "time", return_value=125)
    def test_cancelled_pending_result_cannot_publish(self, clock):
        result = self.admit()
        self.ledger.cancel(self.context["request_id"], "head changed")
        with pytest.raises(ValueError, match="pending"):
            self.ledger.pending(self.context["request_id"], self.context["subject"])
        with pytest.raises(ValueError, match="cancelled"):
            self.ledger.delivered(
                self.context["request_id"], admission.digest(admission.encode(result))
            )

    @patch.object(admission.time, "time", return_value=150)
    def test_exact_expiry_rejected(self, clock):
        with pytest.raises(ValueError, match="expired"):
            self.admit()

    @patch.object(admission.time, "time", return_value=125)
    def test_two_consumers_have_exactly_one_winner(self, clock):
        def consume():
            try:
                return self.admit()["dudect_admission"]
            except ValueError:
                return False

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            assert sorted(pool.map(lambda _: consume(), range(2))) == [False, True]

    @patch.object(admission.time, "time", return_value=125)
    def test_wrong_target_and_policy_rejected(self, clock):
        old = copy.deepcopy(self.context["subject"])
        self.context["subject"]["target_revision"] = "f" * 40
        with pytest.raises(ValueError, match="target"):
            self.admit()
        self.context["subject"] = old
        self.policy["verifier_runtime_sha256"] = "2" * 64
        with pytest.raises(ValueError, match="policy changed"):
            self.admit()

    def test_unsafe_ledger_and_keys_rejected(self):
        self.path.chmod(0o644)
        with pytest.raises(ValueError, match="private regular"):
            self.ledger.cancel(self.context["request_id"], "test")
        self.policy["producer_fingerprint"] = self.policy["verifier_fingerprint"]
        with pytest.raises(ValueError, match="separate signing"):
            admission.validate_policy(self.policy)

    def test_keyring_and_verifier_hashes_are_enforced(self):
        for key in ("keyring_sha256", "gpgv_sha256"):
            policy = {**self.policy, key: "0" * 64}
            with self.subTest(key=key), pytest.raises(ValueError, match="changed"):
                admission.verify_signature(
                    "producer", self.blobs["producer"], self.signatures["producer"], policy
                )

    @patch.object(admission.time, "time", return_value=125)
    def test_delivery_rechecks_digest_target_and_expiry(self, clock):
        self.admit()
        with pytest.raises(ValueError, match="digest"):
            self.ledger.delivered(self.context["request_id"], "0" * 64)
        with pytest.raises(ValueError, match="target"):
            self.ledger.pending(self.context["request_id"], {})
        with (
            patch.object(admission.time, "time", return_value=150),
            pytest.raises(ValueError, match="expired"),
        ):
            self.ledger.pending(self.context["request_id"], self.context["subject"])

    def test_ledger_symlink_and_directory_permission_refused(self):
        symlink = self.path.with_name("link")
        symlink.symlink_to(self.path)
        with pytest.raises(OSError, match="symbolic"):
            admission.owned_database(symlink)
        Path(self.directory.name).chmod(0o755)
        with pytest.raises(ValueError, match="0700"):
            admission.owned_database(self.path)

    @patch.object(admission.time, "time", return_value=125)
    def test_cancel_during_signature_verification_is_observed(self, clock):
        verify = admission.verify_signature

        def interleave(role, *args):
            signer = verify(role, *args)
            if role == "producer":
                self.ledger.cancel(self.context["request_id"], "cancel during authentication")
            return signer

        with (
            patch.object(admission, "verify_signature", side_effect=interleave),
            pytest.raises(ValueError, match="cancelled"),
        ):
            self.admit()

    @patch.object(admission.time, "time", return_value=125)
    def test_stopped_writer_does_not_create_unbounded_wait(self, clock):
        db = sqlite3.connect(self.path, isolation_level=None)
        try:
            db.execute("BEGIN IMMEDIATE")
            start = time.monotonic()
            with pytest.raises(sqlite3.OperationalError, match="locked"):
                self.admit()
            assert time.monotonic() - start < 5
        finally:
            db.close()
        assert self.admit()["dudect_admission"]

    @patch.object(admission.time, "time", return_value=125)
    def test_crash_before_commit_does_not_consume_request(self, clock):
        code = (
            "import os,sqlite3,sys; c=sqlite3.connect(sys.argv[1],isolation_level=None);"
            "c.execute('BEGIN IMMEDIATE');"
            "c.execute(\"UPDATE requests SET state='admitted'\");os._exit(19)"
        )
        child = subprocess.run(
            [sys.executable, "-c", code, str(self.path)], check=False, timeout=10
        )
        assert child.returncode == 19
        assert self.admit()["dudect_admission"]

    def test_actual_cli_issue_authenticate_deliver_and_reject_reuse(self):
        now = int(time.time())
        request = self.documents["request"]
        request.update(
            issued_at=now - 10,
            acquisition_deadline=now + 60,
            recovery_deadline=now + 90,
            expires_at=now + 120,
        )
        self.documents["producer"].update(
            started_at=now - 9, completed_at=now - 8, recovered_at=now - 7
        )
        self.documents["replay"]["replayed_at"] = now - 6
        blobs = bound_blobs(self.context, self.documents)
        root = Path(self.directory.name)
        for name, value in {
            **blobs,
            "context": admission.encode(self.context),
            "policy": admission.encode(self.policy),
            "subject": admission.encode(self.context["subject"]),
        }.items():
            (root / name).write_bytes(value)
        for role, name, key in (("producer", "producer", 0), ("verifier", "replay", 1)):
            (root / (role + "-signature")).write_bytes(self.sign(role, blobs[name], key))

        def cli(action, files, extra=()):
            argv = [
                sys.executable,
                str(ROOT / "scripts/ci/dudect_admission.py"),
                "--ledger",
                str(root / "cli.sqlite"),
                action,
            ]
            for name in files:
                argv.extend(("--" + name, str(root / name)))
            return subprocess.run(
                [*argv, *extra], capture_output=True, text=True, check=False, timeout=20
            )

        issued = cli("issue", ("request", "context", "policy"))
        assert issued.returncode == 0, issued.stdout + issued.stderr
        args = ("--request-id", self.context["request_id"])
        files = (
            "producer",
            "replay",
            "producer-signature",
            "verifier-signature",
            "policy",
            "subject",
        )
        admitted = cli("admit", files, args)
        assert admitted.returncode == 0, admitted.stdout + admitted.stderr
        result = json.loads(admitted.stdout)
        assert result["dudect_admission"] is True
        assert result["github_check_published"] is False
        assert cli("admit", files, args).returncode == 1
        pending = cli("pending", ("subject",), args)
        assert json.loads(pending.stdout) == result
        delivered = cli(
            "delivered", (), (*args, "--result-sha256", admission.digest(admission.encode(result)))
        )
        assert delivered.returncode == 0, delivered.stdout + delivered.stderr
        assert cli("pending", ("subject",), args).returncode == 1


if __name__ == "__main__":
    unittest.main()
