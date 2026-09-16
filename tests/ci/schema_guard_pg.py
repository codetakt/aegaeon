# ruff: noqa: PT009, S603 - unittest assertions; pinned Nix fixture executables only
"""Exercise the packaged entrypoints and real PostgreSQL, in a private cluster.

The Nix check supplies two immutable fixture releases and owns the cluster.
These are launcher tests, not server protocol or physical-schema evidence.
"""

from __future__ import annotations

import json
import os
import select
import signal
import subprocess
import sys
import unittest
from pathlib import Path

import psycopg


class PackagedLaunchTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.old, cls.new = map(Path, sys.argv[1:3])
        cls.url = os.environ["AEGAEON_DATABASE_URL"]
        cls.versions = ("20260101000000", "20260201000000")

    def setUp(self):
        with psycopg.connect(self.url, autocommit=True) as db:
            db.execute("DROP SCHEMA IF EXISTS scoped CASCADE")
            db.execute("DROP TABLE IF EXISTS public.atlas_schema_revisions")
            db.execute("""CREATE TABLE public.atlas_schema_revisions
                       (version text PRIMARY KEY, description text, hash text,
                        applied bigint, total bigint, error text)""")
            db.execute(
                "INSERT INTO public.atlas_schema_revisions "
                "VALUES (%s, 'baseline', NULL, 1, 1, NULL)",
                (self.versions[0],),
            )

    def upgrade(self):
        with psycopg.connect(self.url, autocommit=True) as db:
            db.execute(
                "INSERT INTO public.atlas_schema_revisions "
                "VALUES (%s, 'upgrade', NULL, 1, 1, NULL)",
                (self.versions[1],),
            )

    def run_release(self, release, *, accepted, url=None, name="aegaeon-server"):
        result = subprocess.run(
            [str(release / "bin" / name), "23", "literal argument"],
            env={**os.environ, "AEGAEON_DATABASE_URL": url or self.url},
            text=True,
            capture_output=True,
            timeout=15,
            check=False,
        )
        self.assertEqual(result.returncode, 23 if accepted else 78, result.stderr)
        if accepted:
            self.assertEqual(result.stdout.strip(), "executed:literal argument")
            self.assertIn("inventory accepted", result.stderr)
        else:
            self.assertEqual(result.stdout, "")
            self.assertIn("refused startup", result.stderr)
        return result

    def test_old_old_then_old_new_refused_and_new_new_accepted(self):
        self.run_release(self.old, accepted=True)
        self.run_release(self.new, accepted=False)
        self.upgrade()
        self.run_release(self.old, accepted=False)
        self.run_release(self.new, accepted=True)

    def test_initializer_uses_the_same_protection(self):
        self.run_release(self.old, accepted=True, name="aegaeon-management-init")
        self.upgrade()
        self.run_release(self.old, accepted=False, name="aegaeon-management-init")
        self.run_release(self.new, accepted=True, name="aegaeon-management-init")

    def test_unknown_old_revision_is_refused(self):
        with psycopg.connect(self.url, autocommit=True) as db:
            db.execute(
                "INSERT INTO public.atlas_schema_revisions "
                "VALUES ('19000101000000', NULL, NULL, 1, 1, NULL)"
            )
        self.run_release(self.old, accepted=False)

    def test_inaccessible_metadata_is_refused_without_driver_diagnostics(self):
        result = self.run_release(
            self.old,
            accepted=False,
            url="postgresql://guard_diagnostic_sentinel@localhost/missing?host=/missing-socket",
        )
        self.assertIn("cannot read Atlas revision metadata", result.stderr)
        self.assertNotIn("guard_diagnostic_sentinel", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_invalid_database_urls_refused_at_policy_boundary(self):
        for name in ("aegaeon-server", "aegaeon-management-init"):
            for url, reason in (
                ("postgresql:///postgres?host=/missing-socket", "explicit host"),
                ("postgresql://db.example/postgres?sslmode=disable", "strong sslmode"),
                (self.url + "#guard_diagnostic_sentinel", "fragment"),
            ):
                with self.subTest(name=name, reason=reason):
                    result = self.run_release(self.old, accepted=False, url=url, name=name)
                    self.assertIn(reason, result.stderr)
                    self.assertNotIn("guard_diagnostic_sentinel", result.stderr)
                    self.assertNotIn("Traceback", result.stderr)

    def test_missing_table_and_bad_query_shape_are_refused(self):
        with psycopg.connect(self.url, autocommit=True) as db:
            db.execute("ALTER TABLE public.atlas_schema_revisions DROP COLUMN applied")
        self.run_release(self.old, accepted=False)
        with psycopg.connect(self.url, autocommit=True) as db:
            db.execute("DROP TABLE public.atlas_schema_revisions")
        self.run_release(self.old, accepted=False)

    def test_private_search_path_precedes_public(self):
        with psycopg.connect(self.url, autocommit=True) as db:
            db.execute("CREATE SCHEMA scoped")
            db.execute(
                "CREATE TABLE scoped.atlas_schema_revisions (LIKE public.atlas_schema_revisions)"
            )
            db.execute(
                "INSERT INTO scoped.atlas_schema_revisions "
                "SELECT * FROM public.atlas_schema_revisions"
            )
            db.execute(
                "INSERT INTO public.atlas_schema_revisions "
                "VALUES ('19000101000000', NULL, NULL, 1, 1, NULL)"
            )
        self.run_release(self.old, accepted=True, url=self.url + "&options=-csearch_path%3Dscoped")
        self.run_release(self.old, accepted=False)

    def test_launch_preserves_pid_and_signal(self):
        process = subprocess.Popen(
            [str(self.old / "bin/aegaeon-server"), "wait"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            self.assertTrue(select.select([process.stdout], [], [], 10)[0])
            self.assertEqual(process.stdout.readline().strip(), f"pid:{process.pid}")
            process.send_signal(signal.SIGTERM)
            self.assertEqual(process.wait(timeout=5), -signal.SIGTERM)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            process.stdout.close()
            process.stderr.close()

    def test_manifest_binds_installed_executable(self):
        for release in (self.old, self.new):
            manifest = json.loads((release / "share/aegaeon/aegaeon-server.json").read_text())
            self.assertTrue(manifest["binary"]["path"].startswith("/nix/store/"))
            self.assertEqual(len(manifest["binary"]["sha256"]), 64)


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]], verbosity=2)
