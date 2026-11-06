"""Actual TLS, subprocess and filesystem failures for snapshot custody."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

import test_organization_audit_transport as transport
from test_organization_snapshot import DOMAIN, ENVIRONMENT, SNAPSHOT, fixture

SCRIPT = Path(__file__).resolve().parents[1] / "organization_snapshot_receive.py"


class SnapshotReceiveTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = transport.TransportTests("runTest")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.payload = fixture()
        self.fixture.content_type = "application/x-ndjson"
        parts = self.fixture.base.split("/")
        parts[-3], parts[-1] = ENVIRONMENT, DOMAIN
        self.base = "/".join(parts)

    def command(self, code: str | None = None) -> list[str]:
        executable = [sys.executable, str(SCRIPT)] if code is None else [sys.executable, "-c", code]
        return [
            *executable,
            "--state",
            str(self.fixture.state),
            "--base",
            self.base,
            "--session-file",
            str(self.fixture.session),
        ]

    def cli(
        self, code: str | None = None, *, trusted: bool = True
    ) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env.pop("SSL_CERT_FILE", None)
        env.pop("SSL_CERT_DIR", None)
        if trusted:
            env["SSL_CERT_FILE"] = str(self.fixture.cert)
        return subprocess.run(  # noqa: S603 — fixed current interpreter and owned fixture paths
            self.command(code), env=env, capture_output=True, text=True, timeout=10, check=False
        )

    def code(self, mutation: str) -> str:
        return (
            f"import sys;sys.path.insert(0,{str(SCRIPT.parent)!r});"
            "import organization_snapshot_receive as r;" + mutation + ";r.main()"
        )

    def test_verified_tls_preserves_exact_file_and_never_overwrites(self) -> None:
        first = self.cli()
        self.assertEqual(first.returncode, 0, first.stderr)
        result = json.loads(first.stdout)
        self.assertTrue(result["durablyRetained"])
        self.assertFalse(result["importAuthorized"])
        final = self.fixture.state / f"{SNAPSHOT}.jsonl"
        self.assertEqual(final.read_bytes(), fixture())
        self.assertEqual(final.stat().st_mode & 0o777, 0o600)
        self.assertEqual(final.stat().st_nlink, 1)
        self.assertEqual(list(self.fixture.state.glob(".partial-*")), [])
        self.assertNotEqual(self.cli().returncode, 0)
        self.assertEqual(final.read_bytes(), fixture())
        self.assertEqual(len(list(self.fixture.state.glob(".partial-*"))), 1)
        self.assertEqual(
            self.fixture.requests[0][1],
            self.base.split(f"localhost:{self.fixture.server.server_port}")[1] + "/snapshot",
        )

    def test_corrupt_or_truncated_transfer_retains_partial_without_publication(self) -> None:
        for value in [
            fixture()[:-1],
            fixture().replace(b"School", b"school"),
            fixture() + b"trailing",
        ]:
            with self.subTest(value=len(value)):
                self.fixture.payload = value
                self.assertNotEqual(self.cli().returncode, 0)
                self.assertFalse((self.fixture.state / f"{SNAPSHOT}.jsonl").exists())
        self.assertEqual(len(list(self.fixture.state.glob(".partial-*"))), 3)

    def test_different_requested_scope_is_not_published(self) -> None:
        self.base = self.base.replace(DOMAIN, "44444444-4444-4444-8444-444444444444")
        self.assertNotEqual(self.cli().returncode, 0)
        self.assertFalse((self.fixture.state / f"{SNAPSHOT}.jsonl").exists())

    def test_redirect_untrusted_tls_and_stall_refuse(self) -> None:
        self.assertNotEqual(self.cli(trusted=False).returncode, 0)
        self.assertEqual(self.fixture.requests, [])
        self.fixture.mode = "redirect"
        self.assertNotEqual(self.cli().returncode, 0)
        self.assertEqual(len(self.fixture.requests), 1)
        self.fixture.mode = "stall"
        self.assertNotEqual(self.cli(self.code("r.PROGRESS=1")).returncode, 0)
        self.assertFalse((self.fixture.state / f"{SNAPSHOT}.jsonl").exists())

    def test_fsync_failure_cannot_report_or_publish_complete(self) -> None:
        code = self.code(
            "r.os.fsync=lambda fd: (_ for _ in ()).throw(OSError('fixture storage failure'))"
        )
        self.assertNotEqual(self.cli(code).returncode, 0)
        self.assertFalse((self.fixture.state / f"{SNAPSHOT}.jsonl").exists())
        self.assertEqual(len(list(self.fixture.state.glob(".partial-*"))), 1)
        self.assertEqual(self.cli().returncode, 0)

    def test_killed_after_file_sync_preserves_partial_and_fresh_receive_recovers(self) -> None:
        # The actual child terminates immediately before no-overwrite publication.
        code = self.code(
            "import signal; r.os.link=lambda *a,**k:r.os.kill(r.os.getpid(),signal.SIGKILL)"
        )
        killed = self.cli(code)
        self.assertEqual(killed.returncode, -9)
        self.assertFalse((self.fixture.state / f"{SNAPSHOT}.jsonl").exists())
        partials = list(self.fixture.state.glob(".partial-*"))
        self.assertEqual(len(partials), 1)
        self.assertEqual(partials[0].read_bytes(), fixture())
        self.assertEqual(self.cli().returncode, 0)
        self.assertEqual(partials[0].read_bytes(), fixture())

    def test_private_directory_and_session_symlink_are_required(self) -> None:
        self.fixture.state.chmod(0o755)
        self.assertNotEqual(self.cli().returncode, 0)
        self.fixture.state.chmod(0o700)
        original = self.fixture.session.with_suffix(".original")
        self.fixture.session.rename(original)
        self.fixture.session.symlink_to(original)
        self.assertNotEqual(self.cli().returncode, 0)
        self.assertEqual(self.fixture.requests, [])

    def test_retention_capacity_refuses_without_deleting_prior_artifacts(self) -> None:
        for number in range(64):
            (self.fixture.state / f"retained-{number}").touch(mode=0o600)
        self.assertNotEqual(self.cli().returncode, 0)
        self.assertEqual(len(list(self.fixture.state.iterdir())), 64)
        self.assertEqual(self.fixture.requests, [])


if __name__ == "__main__":
    unittest.main()
