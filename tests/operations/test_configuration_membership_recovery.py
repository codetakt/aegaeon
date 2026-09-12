"""Exercise the recovery SQL on a disposable database containing db/schema.sql.

Set AEGAEON_RECOVERY_TEST_DATABASE_URL to a database named aegaeon_recovery_test_*.
This suite truncates that explicitly selected disposable database between cases.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import unittest
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[2]
URL = os.environ.get("AEGAEON_RECOVERY_TEST_DATABASE_URL")


def uid(value: int) -> str:
    return f"00000000-0000-0000-0000-{value:012d}"


@unittest.skipUnless(URL, "requires an explicitly configured disposable PostgreSQL database")
class ConfigurationMembershipRecoveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if URL is None or not urlsplit(URL).path.startswith("/aegaeon_recovery_test_"):
            message = "recovery tests require an aegaeon_recovery_test_* database"
            raise ValueError(message)

    def psql(self, sql: str, *args: str) -> subprocess.CompletedProcess[str]:
        environment = dict(os.environ)
        return subprocess.run(  # noqa: S603 - fixed psql executable, quoted variable argv, no shell
            [
                shutil.which("psql") or "/missing-psql",
                "--dbname",
                URL or "",
                "-X",
                "-qAt",
                "-v",
                "ON_ERROR_STOP=1",
                *args,
            ],
            input=sql,
            text=True,
            capture_output=True,
            env=environment,
            check=False,
        )

    def sql(self, sql: str) -> str:
        result = self.psql(sql)
        assert result.returncode == 0, result.stderr
        return result.stdout.strip()

    def setUp(self) -> None:
        assert self.sql("SELECT current_database();").startswith("aegaeon_recovery_test_")
        fixture = Path(__file__).parent / "fixtures/configuration_membership_recovery.sql"
        self.sql(fixture.read_text())

    def snapshot(self) -> dict[str, object]:
        result = {}
        for table in [
            "environments",
            "configuration_versions",
            "clients",
            "oauth_profiles",
            "connections",
            "client_secrets",
            "runtime_keys",
            "audit_events",
        ]:
            result[table] = json.loads(
                self.sql(
                    "SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY id), '[]'::jsonb) "  # noqa: S608 - fixed table list
                    f"FROM aegaeon.{table} t;"
                )
            )
        return result

    def recover(self, **overrides: str) -> subprocess.CompletedProcess[str]:
        values = {
            "environment_id": uid(10),
            "from_version": uid(20),
            "to_version": uid(21),
            "client_ids": "{" + uid(40) + "}",
            "profile_ids": "{" + uid(30) + "}",
            "connection_ids": "{" + uid(50) + "}",
            "request_id": "RECOVERY-TEST",
            "reason": "Restore only the reviewed fixture members",
        }
        values.update(overrides)
        args = [part for key, value in values.items() for part in ["-v", f"{key}={value}"]]
        return self.psql(
            (ROOT / "scripts/operations/recover_configuration_membership.sql").read_text(), *args
        )

    def test_default_dry_run_changes_nothing(self) -> None:
        before = self.snapshot()
        result = self.recover()
        assert result.returncode == 0, result.stderr
        assert before == self.snapshot()

    def test_apply_preserves_credentials_expiry_and_unselected_environments(self) -> None:
        expected = self.snapshot()
        for table, number in [("clients", 40), ("oauth_profiles", 30), ("connections", 50)]:
            for row in expected[table]:
                if row["id"] == uid(number):
                    row["configuration_version_id"] = uid(21)
        result = self.recover(apply="true")
        assert result.returncode == 0, result.stderr
        actual = self.snapshot()
        audit = actual.pop("audit_events")
        expected.pop("audit_events")
        assert expected == actual
        assert len(audit) == 1
        assert audit[0]["event_type"] == "CONFIGURATION_MEMBERSHIP_RECOVERED"
        assert audit[0]["actor_type"] == "DATABASE_OPERATOR"
        assert audit[0]["actor_id"] == self.sql("SELECT session_user;")
        assert len(audit[0]["data"]["members"]) == 3

    def test_invalid_manifest_and_stale_pointer_roll_back(self) -> None:
        for overrides in [
            {"to_version": uid(20)},
            {"environment_id": uid(11)},
            {"client_ids": "{" + uid(42) + "}"},
            {"profile_ids": "{}"},
            {"client_ids": "{" + uid(40) + "," + uid(40) + "}"},
            {"client_ids": "{" + uid(99) + "}"},
            {"reason": ""},
            {"client_ids": "{}", "profile_ids": "{}", "connection_ids": "{}"},
        ]:
            with self.subTest(overrides=overrides):
                before = self.snapshot()
                assert self.recover(apply="true", **overrides).returncode != 0
                assert before == self.snapshot()

    def test_deleted_member_is_not_restored(self) -> None:
        self.sql(
            "UPDATE aegaeon.clients SET status='DELETED' "
            "WHERE id='00000000-0000-0000-0000-000000000040';"
        )
        before = self.snapshot()
        assert self.recover(apply="true").returncode != 0
        assert before == self.snapshot()

    def test_committed_replay_is_rejected_without_another_audit(self) -> None:
        result = self.recover(apply="true")
        assert result.returncode == 0, result.stderr
        before = self.snapshot()
        assert self.recover(apply="true").returncode != 0
        assert before == self.snapshot()

    def test_audit_failure_rolls_back_membership_changes(self) -> None:
        self.sql("""
CREATE FUNCTION aegaeon.reject_recovery_audit() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'audit failure control'; END $$;
CREATE TRIGGER reject_recovery BEFORE INSERT ON aegaeon.audit_events
FOR EACH ROW EXECUTE FUNCTION aegaeon.reject_recovery_audit();
""")
        try:
            before = self.snapshot()
            result = self.recover(apply="true")
            assert result.returncode != 0
            assert "audit failure control" in result.stderr
            assert before == self.snapshot()
        finally:
            self.sql(
                "DROP TRIGGER reject_recovery ON aegaeon.audit_events; "
                "DROP FUNCTION aegaeon.reject_recovery_audit();"
            )


if __name__ == "__main__":
    unittest.main()
