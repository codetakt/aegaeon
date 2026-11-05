"""Transfer-integrity refusals, independent of native export authorization tests."""

from __future__ import annotations

import io
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import organization_snapshot as snapshot

ENVIRONMENT = "11111111-1111-4111-8111-111111111111"
DOMAIN = "22222222-2222-4222-8222-222222222222"
SNAPSHOT = "33333333-3333-4333-8333-333333333333"


def encode(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode() + b"\n"


def fixture() -> bytes:
    scope = {"environment_id": ENVIRONMENT, "domain_id": DOMAIN}
    header = encode(
        {
            "record": "header",
            "version": 2,
            "snapshotId": SNAPSHOT,
            "scope": scope,
            "capturedAt": "2026-10-30T00:00:00.000000Z",
            "credentialTransfer": False,
        }
    )
    data = b'{"external_id": "School/\xc3\x89", "revision": 9223372036854775807}'
    row = b'{"record":"row","section":"organizations","key":"opaque","data":' + data + b"}\n"
    chains = [snapshot.Chain(name) for name in snapshot.SECTIONS]
    chains[snapshot.SECTIONS.index("organizations")].push("opaque", data)
    footer = encode(
        {
            "record": "manifest",
            "version": 2,
            "snapshotId": SNAPSHOT,
            "scope": scope,
            "contentBytes": len(header + row),
            "sections": [
                chain.finish(name) for name, chain in zip(snapshot.SECTIONS, chains, strict=True)
            ],
        }
    )
    return header + row + footer


class SnapshotTest(unittest.TestCase):
    def test_exact_utf8_integer_and_whitespace_are_preserved(self) -> None:
        result = snapshot.verify(io.BytesIO(fixture()))
        self.assertTrue(result["integrityChecked"])
        self.assertFalse(result["importAuthorized"])
        self.assertEqual(result["bytes"], len(fixture()))

    def test_every_truncation_and_trailing_record_refused(self) -> None:
        value = fixture()
        for end in (0, 1, value.index(b"\n") + 1, len(value) - 1):
            with self.subTest(end=end), self.assertRaises(ValueError):
                snapshot.verify(io.BytesIO(value[:end]))
        with self.assertRaises(ValueError):
            snapshot.verify(io.BytesIO(value + b"{}\n"))

    def test_changed_scope_content_checksum_and_snapshot_refused(self) -> None:
        for old, new in (
            (b"School", b"Other!"),
            (SNAPSHOT.encode(), DOMAIN.encode()),
            (b'"count":1', b'"count":2'),
            (b'"version":2', b'"version":true'),
        ):
            with self.subTest(old=old), self.assertRaises(ValueError):
                snapshot.verify(io.BytesIO(fixture().replace(old, new, 1)))

    def test_duplicate_json_fields_and_duplicate_rows_refused(self) -> None:
        with self.assertRaises(ValueError):
            snapshot.verify(
                io.BytesIO(
                    fixture().replace(b'"record":"row"', b'"record":"row","record":"row"', 1)
                )
            )
        lines = fixture().splitlines(keepends=True)
        with self.assertRaises(ValueError):
            snapshot.verify(io.BytesIO(lines[0] + lines[1] + lines[1] + lines[2]))

    def test_data_reserialization_changes_digest_even_when_json_equal(self) -> None:
        original = fixture()
        mutated = original.replace(b'"external_id": "School/', b'"external_id":"School/', 1)
        lines = mutated.splitlines(keepends=True)
        footer = json.loads(lines[-1])
        footer["contentBytes"] = len(lines[0] + lines[1])
        with self.assertRaises(ValueError):
            snapshot.verify(io.BytesIO(lines[0] + lines[1] + encode(footer)))

    def test_bounded_line_and_row_key_refused(self) -> None:
        with self.assertRaises(ValueError):
            snapshot.verify(io.BytesIO(b" " * (snapshot.MAX_LINE + 1)))
        chain = snapshot.Chain("organizations")
        with self.assertRaises(ValueError):
            chain.push("x" * (snapshot.MAX_KEY + 1), b"{}")
        chain.push("z", b"{}")
        with self.assertRaises(ValueError):
            chain.push("a", b"{}")


if __name__ == "__main__":
    unittest.main()
