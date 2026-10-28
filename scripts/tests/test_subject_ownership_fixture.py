"""Keep disposable database setup bound to its generated identity and database."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qsl, urlsplit

import subject_ownership_fixture as fixture


class SubjectOwnershipFixtureConnections(unittest.TestCase):
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
