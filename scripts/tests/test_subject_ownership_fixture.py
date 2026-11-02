"""Keep disposable database setup bound to its generated identity and database."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qsl, urlsplit

import subject_ownership_fixture as fixture


class SubjectOwnershipFixtureConnections(unittest.TestCase):
    def test_atlas_socket_conversion_preserves_credentials_database_and_query(self) -> None:
        url = "postgresql://role:p%40ss@localhost/owned?host=%2Ftmp%2Fowned&port=65432&sslmode=disable"
        actual = fixture.atlas_connection(url)
        self.assertEqual(actual, url.replace("@localhost/", "@/"))
        tcp = "postgresql://role:p%40ss@localhost:5432/owned?sslmode=require"
        self.assertEqual(fixture.atlas_connection(tcp), tcp)

    def test_identity_query_overrides_refuse_before_any_ddl(self) -> None:
        for setting in ("user=administrator", "password=override", "dbname=original", "%75ser=x"):
            with self.subTest(setting=setting), tempfile.TemporaryDirectory() as directory:
                url = "postgresql://operator:synthetic@localhost/control?" + setting
                with (
                    patch.object(fixture, "execute") as execute,
                    patch.object(fixture.subprocess, "run") as run,
                ):
                    with self.assertRaisesRegex(ValueError, "must not override"):
                        fixture.prepare(Path(directory), url)
                    with self.assertRaisesRegex(ValueError, "must not override"):
                        fixture.prepare_child("initialization_owned", url)
                    with self.assertRaisesRegex(ValueError, "must not override"):
                        fixture.connection(url, "runtime", "synthetic", "owned")
                    execute.assert_not_called()
                    run.assert_not_called()
                    self.assertEqual(list(Path(directory).iterdir()), [])

    def test_required_test_preflight_and_runtime_preparation_are_distinct(self) -> None:
        for entry, required in ((fixture.prepare, True), (fixture.prepare_runtime, False)):
            with self.subTest(required=required), tempfile.TemporaryDirectory() as directory:
                with (
                    patch.object(fixture.subprocess, "run") as run,
                    patch.object(fixture, "configure_database") as configure,
                ):
                    run.return_value.returncode = 0
                    entry(Path(directory), "postgresql://admin:synthetic@localhost/control")
                self.assertEqual(configure.call_count, 1)
                self.assertIs(configure.call_args.kwargs["run_pre_migration_tests"], required)
                self.assertTrue((Path(directory) / "owned-resources.json").is_file())
                self.assertEqual((Path(directory) / "runtime-env.sh").stat().st_mode & 0o777, 0o600)

    def test_preparation_never_overwrites_recorded_ownership(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            record = Path(directory) / "owned-resources.json"
            record.write_text("preserve-owned-resources")
            with patch.object(fixture.subprocess, "run") as run:
                for entry in (fixture.prepare, fixture.prepare_runtime):
                    with self.assertRaisesRegex(ValueError, "new empty"):
                        entry(Path(directory), "postgresql://admin:synthetic@localhost/control")
                run.assert_not_called()
            self.assertEqual(record.read_text(), "preserve-owned-resources")

    def test_generated_credentials_and_transport_survive_url_derivation(self) -> None:
        admin = "postgresql://operator:synthetic@[::1]:55432/control?sslmode=require&application_name=fixture"
        user, password = "runtime user", "synthetic /?#@:%"
        derived = fixture.connection(admin, user, password, "owned_database")
        self.assertEqual(
            dict(parse_qsl(urlsplit(derived).query)),
            {"sslmode": "require", "application_name": "fixture"},
        )
        environment = fixture.postgres_environment(derived)
        self.assertEqual(environment["PGHOST"], "::1")
        self.assertEqual(environment["PGPORT"], "55432")
        self.assertEqual(environment["PGDATABASE"], "owned_database")
        self.assertEqual(environment["PGUSER"], user)
        self.assertEqual(environment["PGPASSWORD"], password)
        self.assertEqual(environment["PGSSLMODE"], "require")
        self.assertEqual(environment["PGAPPNAME"], "fixture")


if __name__ == "__main__":
    unittest.main()
