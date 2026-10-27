#!/usr/bin/env python3
"""Exercise the driver's Atlas transition using disposable PostgreSQL and a named volume.

Run with `nix develop .#ci --command python3 scripts/tests/test_atlas_revision_ledger.py`.
Requires Docker. Cargo is a successful fixture: this checks the actual driver's migration
boundary; the separate Rust database lanes establish application behavior.
"""

# This standalone command uses the standard-library unittest runner.
# ruff: noqa: PT009

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SNAPSHOT = (
    "SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY version), '[]') "
    "FROM {}.atlas_schema_revisions r"
)


def run(
    argv: list[str], *, env: dict[str, str] | None = None, check: bool = True
) -> subprocess.CompletedProcess[str]:
    # Commands and SQL are constructed exclusively by this local regression fixture.
    return subprocess.run(  # noqa: S603
        argv, cwd=ROOT, env=env, capture_output=True, text=True, timeout=180, check=check
    )


class AtlasRevisionLedgerTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="aegaeon-atlas-ledger-")
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        project = self.work.name
        compose_file = self.work / "compose.json"
        compose_file.write_text(
            json.dumps(
                {
                    "services": {
                        "postgres": {
                            "image": "postgres:18.1",
                            "ports": ["127.0.0.1::5432"],
                            "environment": {
                                "POSTGRES_DB": "aegaeon",
                                "POSTGRES_USER": "aegaeon",
                                "POSTGRES_PASSWORD": "aegaeon",
                            },
                            "volumes": ["data:/var/lib/postgresql"],
                        }
                    },
                    "volumes": {"data": {}},
                }
            )
        )
        compose = ["docker", "compose", "-p", project, "-f", str(compose_file)]
        self.addCleanup(run, [*compose, "down", "--volumes", "--remove-orphans"])
        run([*compose, "up", "-d"])
        for _ in range(30):
            ready = run(
                [*compose, "exec", "-T", "postgres", "pg_isready", "-U", "aegaeon"], check=False
            )
            if ready.returncode == 0:
                break
            time.sleep(1)
        else:
            self.fail("PostgreSQL fixture did not become ready")
        address = run([*compose, "port", "postgres", "5432"]).stdout.strip()
        self.url = f"postgres://aegaeon:aegaeon@{address}/aegaeon?sslmode=disable"
        self.env = self.driver_environment(compose_file, project)
        self.driver = ["bash", "scripts/tests/run_server_container_integration.sh", "postgres"]

    def driver_environment(self, compose_file: Path, project: str) -> dict[str, str]:
        fixture_bin = self.work / "bin"
        fixture_bin.mkdir()
        cargo = fixture_bin / "cargo"
        cargo.write_text("#!/bin/sh\nprintf 'test result: ok. 1 passed; 0 failed; 0 ignored;\\n'\n")
        cargo.chmod(0o755)
        env = dict(
            os.environ,
            PATH=str(fixture_bin) + os.pathsep + os.environ["PATH"],
            DEV_COMPOSE_FILE=str(compose_file),
            COMPOSE_PROJECT_NAME=project,
            AEGAEON_DATABASE_URL=self.url,
            AEGAEON_SERVER_CONTAINER_SKIP_UP="1",
            AEGAEON_SERVER_CONTAINER_DOWN="0",
        )
        for key in ("AEGAEON_DATABASE_TEST_PACKAGE", "JOSE_SERVER_TEST_PACKAGE"):
            env.pop(key, None)
        return env

    def sql(self, query: str, database_url: str | None = None) -> str:
        return run(
            [
                "psql",
                database_url or self.url,
                "-X",
                "-A",
                "-t",
                "--set=ON_ERROR_STOP=1",
                "-c",
                query,
            ]
        ).stdout.strip()

    def prepare_legacy_volume(self) -> tuple[int, list[dict[str, object]]]:
        migrations = sorted((ROOT / "db/migrations").glob("*.sql"))
        self.assertGreater(len(migrations), 1)
        old = self.work / "old"
        old.mkdir()
        for migration in migrations[:-1]:
            shutil.copy2(migration, old / migration.name)
        run(["atlas", "migrate", "hash", "--dir", "file://" + str(old)])
        # The previous driver uses the default schema on this same named volume.
        run(["atlas", "migrate", "apply", "--url", self.url, "--dir", "file://" + str(old)])
        before = json.loads(self.sql(SNAPSHOT.format("atlas_schema_revisions")))
        self.assertEqual(len(before), len(migrations) - 1)
        self.sql(
            "CREATE TABLE public.ledger_fixture_payload(id integer PRIMARY KEY, value text); "
            "INSERT INTO public.ledger_fixture_payload VALUES (1,'preserve-existing-volume')"
        )
        return len(migrations), before

    def check_fresh_and_ambiguous(self, after: list[dict[str, object]]) -> None:
        self.sql("CREATE DATABASE fresh")
        fresh_url = self.url.replace("/aegaeon?", "/fresh?")
        run(self.driver, env=dict(self.env, AEGAEON_DATABASE_URL=fresh_url))
        self.assertEqual(
            len(json.loads(self.sql(SNAPSHOT.format("public"), fresh_url))), len(after)
        )
        self.sql(
            "CREATE TABLE atlas_schema_revisions.atlas_schema_revisions "
            "AS TABLE public.atlas_schema_revisions"
        )
        duplicate_before = self.sql(SNAPSHOT.format("atlas_schema_revisions"))
        refused = run(self.driver, env=self.env, check=False)
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn("Both Atlas revision ledgers exist", refused.stderr)
        self.assertEqual(self.sql(SNAPSHOT.format("atlas_schema_revisions")), duplicate_before)
        self.assertEqual(json.loads(self.sql(SNAPSHOT.format("public"))), after)

    def test_legacy_history_and_reused_volume(self) -> None:
        count, before = self.prepare_legacy_volume()
        run(self.driver, env=self.env)
        after = json.loads(self.sql(SNAPSHOT.format("public")))
        self.assertEqual(after[:-1], before)
        self.assertEqual(len(after), count)
        self.assertEqual(
            self.sql("SELECT to_regclass('atlas_schema_revisions.atlas_schema_revisions') IS NULL"),
            "t",
        )
        self.assertEqual(
            self.sql("SELECT value FROM public.ledger_fixture_payload WHERE id=1"),
            "preserve-existing-volume",
        )
        run(self.driver, env=self.env)
        self.assertEqual(json.loads(self.sql(SNAPSHOT.format("public"))), after)
        self.check_fresh_and_ambiguous(after)
        print(
            json.dumps(
                {
                    "legacy_revisions_preserved": len(before),
                    "current_revisions": len(after),
                    "same_volume_second_run": "pass",
                    "fresh_database": "pass",
                    "ambiguous_ledgers": "refused_without_change",
                    "payload": "preserved",
                }
            )
        )


if __name__ == "__main__":
    unittest.main()
