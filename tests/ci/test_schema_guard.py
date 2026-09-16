# ruff: noqa: PT009, PT027 - this suite uses unittest and must work with Python -O
"""Admission and executable-identity controls for the distribution launcher."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from types import ModuleType
from unittest.mock import Mock, patch, sentinel

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts/runtime"))
import schema_guard as guard

ROOT = Path(__file__).resolve().parents[2]


class SchemaGuardTest(unittest.TestCase):
    def setUp(self):
        self.inventory = (ROOT / "db/migrations/atlas.sum").read_text()
        self.revisions = guard.parse_inventory(self.inventory)
        self.rows = [
            {
                "version": r.version,
                "description": r.description,
                "hash": r.file_hash,
                "applied": 1,
                "total": 1,
                "error": None,
            }
            for r in self.revisions
        ]
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name)
        self.binary = self.path / "executable"
        shutil.copyfile(sys.executable, self.binary)
        self.binary.chmod(0o555)
        self.manifest = {
            "schema_version": 1,
            "atlas_sum": self.inventory,
            "binary": {
                "path": str(self.binary),
                "sha256": hashlib.sha256(self.binary.read_bytes()).hexdigest(),
            },
        }

    def write_manifest(self, manifest):
        path = self.path / "manifest.json"
        path.write_text(json.dumps(manifest))
        return path

    def test_numeric_and_legacy_ledgers(self):
        guard.validate_rows(self.revisions, self.rows)
        for row, revision in zip(self.rows, self.revisions, strict=True):
            row.update(version=revision.stem, description=None, hash=None)
        guard.validate_rows(self.revisions, self.rows)

    def test_supported_head_checksum_formats(self):
        for digest in (self.revisions[-1].file_hash, self.revisions[-1].inventory_hash):
            for prefix in ("", "h1:"):
                with self.subTest(digest=digest, prefix=prefix):
                    self.rows[-1]["hash"] = prefix + digest
                    guard.validate_rows(self.revisions, self.rows)

    def test_bad_past_metadata_is_not_hidden_by_valid_head(self):
        for mutation in (
            {"error": "private database error"},
            {"applied": 0},
            {"total": 0},
            {"applied": True},
            {"total": "1"},
            {"version": "19000101000000"},
            {"version": "99990101000000"},
        ):
            with self.subTest(mutation=mutation):
                rows = copy.deepcopy(self.rows)
                rows[0].update(mutation)
                with self.assertRaises(guard.RefusedError) as failure:
                    guard.validate_rows(self.revisions, rows)
                self.assertNotIn("private database error", str(failure.exception))

    def test_alias_duplicate_refused(self):
        duplicate = dict(self.rows[0], version=self.revisions[0].stem)
        with self.assertRaisesRegex(guard.RefusedError, "duplicate"):
            guard.validate_rows(self.revisions, [*self.rows, duplicate])

    def test_every_missing_revision_refused(self):
        for i in range(len(self.rows)):
            with self.subTest(missing=i), self.assertRaisesRegex(guard.RefusedError, "incomplete"):
                guard.validate_rows(self.revisions, self.rows[:i] + self.rows[i + 1 :])

    def test_head_mismatch_refused(self):
        for mutation in ({"description": "different"}, {"hash": "other"}, {"hash": 23}):
            with self.subTest(mutation=mutation):
                rows = copy.deepcopy(self.rows)
                rows[-1].update(mutation)
                with self.assertRaises(guard.RefusedError):
                    guard.validate_rows(self.revisions, rows)

    def test_bad_inventory_refused(self):
        lines = self.inventory.splitlines()
        for inventory in (
            None,
            "",
            lines[0],
            "h1:bad\n" + lines[1],
            "\n".join([*lines, lines[1]]),
            "\n".join([lines[0], *reversed(lines[1:])]),
            self.inventory.replace(".sql", ".txt"),
            self.inventory + "extra",
        ):
            with self.subTest(inventory=inventory), self.assertRaises(guard.RefusedError):
                guard.parse_inventory(inventory)

    def test_invalid_manifest_shape_refused(self):
        for manifest in (
            [],
            {},
            dict(self.manifest, schema_version=True),
            dict(self.manifest, extra=True),
            dict(self.manifest, schema_version=2),
        ):
            with self.subTest(manifest=manifest), self.assertRaises(guard.RefusedError):
                guard.read_manifest(self.write_manifest(manifest))

    def test_duplicate_manifest_members_refused(self):
        path = self.path / "manifest.json"
        for raw in (
            '{"schema_version":1,"schema_version":1}',
            '{"binary":{"path":"/a","path":"/b"}}',
        ):
            path.write_text(raw)
            with self.assertRaisesRegex(guard.RefusedError, "duplicate"):
                guard.read_manifest(path)

    def test_invalid_binary_identity_refused(self):
        for mutation in ({"path": "relative"}, {"sha256": "bad"}, {"sha256": 1}):
            manifest = copy.deepcopy(self.manifest)
            manifest["binary"].update(mutation)
            with self.subTest(mutation=mutation), self.assertRaises(guard.RefusedError):
                guard.read_manifest(self.write_manifest(manifest))

    def test_held_executable_is_checked_and_cannot_be_swapped_by_path(self):
        binary, _ = guard.read_manifest(self.write_manifest(self.manifest))
        descriptor = guard.open_executable(binary)
        try:
            before = os.fstat(descriptor).st_ino
            self.binary.rename(self.path / "original")
            self.binary.write_bytes(b"replacement")
            self.assertEqual(os.fstat(descriptor).st_ino, before)
            self.assertNotEqual(self.binary.stat().st_ino, before)
        finally:
            os.close(descriptor)

    def test_executable_digest_mismatch_refused(self):
        binary = dict(self.manifest["binary"], sha256="0" * 64)
        with self.assertRaisesRegex(guard.RefusedError, "checksum"):
            guard.open_executable(binary)

    def test_writable_and_nonexecutable_files_refused(self):
        for mode in (0o755, 0o444):
            self.binary.chmod(mode)
            with self.subTest(mode=mode), self.assertRaises(guard.RefusedError):
                guard.open_executable(self.manifest["binary"])

    def test_symlink_executable_refused(self):
        alias = self.path / "alias"
        alias.symlink_to(self.binary)
        with self.assertRaises(OSError):
            guard.open_executable(dict(self.manifest["binary"], path=str(alias)))


class DatabaseUrlTest(unittest.TestCase):
    def setUp(self):
        # A driver boundary spy: accepted URLs reach connect; rejected URLs must
        # not import or call a real driver, even in the lightweight CI shell.
        class DriverError(Exception):
            pass

        self.connect = Mock(side_effect=DriverError("private driver diagnostic"))
        driver = ModuleType("psycopg")
        driver.connect = self.connect
        driver.Error = DriverError
        driver.sql = sentinel.sql
        rows = ModuleType("psycopg.rows")
        rows.dict_row = sentinel.dict_row
        self.enterContext(patch.dict(sys.modules, {"psycopg": driver, "psycopg.rows": rows}))
        self.enterContext(patch.dict(os.environ, {}, clear=True))

    def refused_without_connection(self, url, reason, environment=None):
        with (
            patch.dict(os.environ, environment or {}, clear=True),
            self.assertRaisesRegex(guard.RefusedError, reason) as failure,
        ):
            guard.check_database(url, [])
        self.connect.assert_not_called()
        self.assertNotIn("credential-sentinel", str(failure.exception))
        if url:
            self.assertNotIn(url, str(failure.exception))

    def test_missing_database_url_refused_before_connect(self):
        for url in (None, "", " \t\n"):
            with self.subTest(url=url):
                self.refused_without_connection(url, "required")

    def test_invalid_url_refused_before_connect(self):
        for url, reason in (
            ("host=localhost dbname=postgres password=credential-sentinel", "must use"),
            ("mysql://user:credential-sentinel@localhost/db", "must use"),
            ("postgresql:///db?host=localhost", "explicit host"),
            ("postgresql://user:credential-sentinel@/db", "explicit host"),
            ("postgresql://localhost/db#credential-sentinel", "fragment"),
            ("postgresql://localhost/db#", "fragment"),
            ("postgresql://[::1/db", "invalid"),
            ("postgresql://localhost:bad/db", "invalid"),
            ("postgresql://localhost:65536/db", "invalid"),
            ("postgresql://local\thost/db", "invalid"),
            ("postgresql://localhost/db?password=credential-sentinel\0", "invalid"),
        ):
            with self.subTest(url=url):
                self.refused_without_connection(url, reason)

    def test_remote_transport_refused_before_connect(self):
        for host in ("db.example", "192.0.2.1", "[2001:db8::1]", "[::ffff:127.0.0.1]"):
            for query in (
                "",
                "?sslmode=",
                "?sslmode=disable",
                "?sslmode=allow",
                "?sslmode=prefer",
                "?sslmode=require&sslmode=disable",
                "?sslmode=require&SSLMODE=verify-full",
            ):
                with self.subTest(host=host, query=query):
                    self.refused_without_connection(
                        f"postgresql://user:credential-sentinel@{host}/db{query}", "strong sslmode"
                    )

    def test_local_url_cannot_hide_remote_destination(self):
        for query, environment in (
            ("?host=db.example", {}),
            ("?hostaddr=192.0.2.1", {}),
            ("?host=localhost,db.example", {}),
            ("?hostaddr=127.0.0.1,192.0.2.1", {}),
            ("?host=db.example&sslmode=prefer", {}),
            ("?host=", {"PGHOST": "db.example"}),
            ("", {"PGHOSTADDR": "192.0.2.1"}),
            ("?hostaddr=", {"PGHOSTADDR": "192.0.2.1"}),
            ("?%68ost=db.example", {}),
        ):
            with self.subTest(query=query, environment=environment):
                self.refused_without_connection(
                    "postgresql://localhost/db" + query, "strong sslmode", environment
                )

    def test_service_indirection_refused_before_connect(self):
        for url, environment in (
            ("postgresql://localhost/db?service=unrecorded", {}),
            ("postgresql://localhost/db?%73ervice=unrecorded", {}),
            ("postgresql://localhost/db", {"PGSERVICE": "unrecorded"}),
        ):
            with self.subTest(url=url, environment=environment):
                self.refused_without_connection(url, "service indirection", environment)

    def test_loopback_and_socket_urls_reach_connect(self):
        for host in ("localhost", "LOCALHOST", "127.0.0.1", "127.255.255.254", "[::1]"):
            url = f"postgresql://{host}/db"
            with self.subTest(url=url):
                self.assertEqual(guard.validate_database_url(url, {}), (url, None))
        url = "postgresql://localhost/db?host=/private/socket"
        with self.assertRaisesRegex(guard.RefusedError, "cannot read Atlas"):
            guard.check_database(url, [])
        self.connect.assert_called_once_with(url, connect_timeout=5, row_factory=sentinel.dict_row)

    def test_strong_mode_is_bound_to_driver_call(self):
        for mode in ("require", "verify-ca", "verify-full"):
            for suffix in ("", "&requiressl=0"):
                self.connect.reset_mock()
                url = f"postgres://db.example/db?sslmode={mode}{suffix}"
                with (
                    self.subTest(mode=mode, suffix=suffix),
                    self.assertRaisesRegex(guard.RefusedError, "cannot read Atlas") as failure,
                ):
                    guard.check_database(" " + url + " ", [])
                self.connect.assert_called_once_with(
                    url, connect_timeout=5, row_factory=sentinel.dict_row, sslmode=mode
                )
                self.assertNotIn("private driver diagnostic", str(failure.exception))

    def test_explicit_strong_mode_allows_destination_overrides(self):
        for url, environment in (
            ("postgresql://localhost/db?host=db.example&sslmode=verify-full", {}),
            ("postgresql://localhost/db?sslmode=require", {"PGHOSTADDR": "192.0.2.1"}),
            ("postgresql://db.example/db?sslmode=verify-ca", {"PGSSLMODE": "disable"}),
        ):
            with self.subTest(url=url, environment=environment):
                checked, mode = guard.validate_database_url(url, environment)
                self.assertEqual(checked, url)
                self.assertIn(mode, ("require", "verify-ca", "verify-full"))


if __name__ == "__main__":
    unittest.main()
