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


if __name__ == "__main__":
    unittest.main()
