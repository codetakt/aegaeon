#!/usr/bin/env python3
"""Supplier validation and deterministic generated-source regression checks."""

from __future__ import annotations

import generate_language_tags as generator
import pytest


class TestRegistry:
    def test_bundled_provenance_and_deterministic_table_correspondence(self) -> None:
        first = generator.render()
        assert first == generator.render()
        assert first.encode() == generator.OUTPUT.read_bytes()

    def test_rejects_malformed_records_and_wrong_type_fields(self) -> None:
        source = (generator.DATA / "language-subtag-registry.txt").read_bytes()
        for old, new, expected in [
            (b"Type: language", b"Type: language\nType: language", "duplicate field: Type"),
            (b"Subtag: aa", b"Subtag: aa\nTag: aa", "wrong identifier field"),
            (b"Subtag: aa", b"Subtag: abcdefghi", "invalid language"),
            (b"Type: language", b"Type: unknown", "unsupported registry type"),
            (b"Subtag: aa", b"Subtag: aa\nScope: invented", "unsupported Scope"),
            (b"Type: script", b"Type: script\nScope: collection", "Scope on wrong record type"),
            (b"Suppress-Script: Latn", b"Suppress-Script: Abcd", "unregistered record reference"),
            (b"Description: Afar", b"Broken record", "invalid field syntax"),
            (b"Added: 2005-10-16", b"Added: 2026-99-99", "month must be in"),
            (b"Prefix: ar", b"Prefix: xxxx", "invalid extlang enclosing primary"),
            (b"Subtag: Qaaa..Qabx", b"Subtag: Qaaa..Qaby", "unsupported range"),
            (b"Subtag: Qaaa..Qabx", b"Subtag: Qabx..Qaaa", "invalid private range"),
        ]:
            assert old in source
            changed = source.replace(old, new, 1)
            with pytest.raises(ValueError, match=expected):
                generator.ordinary(changed)
        with pytest.raises(ValueError, match="orphan continuation"):
            generator.records(b" orphan\n" + source)
        with pytest.raises(ValueError, match="missing Description"):
            generator.ordinary(source.replace(b"Description: Afar\n", b"", 1))

    def test_continuations_deprecation_and_unknown_fields_are_preserved(self) -> None:
        source = (generator.DATA / "language-subtag-registry.txt").read_bytes()
        changed = source.replace(
            b"Description: Afar",
            b"Description: Afar\n  continued\n\tcontinued again\nFuture-Field: opaque",
            1,
        )
        assert generator.ordinary(source) == generator.ordinary(changed)
        _, tables, _, prefixes = generator.ordinary(source)
        assert "iw" in tables["language"]
        assert "bu" in tables["region"]
        assert prefixes["cmn"] == "zh"
        assert len(tables["grandfathered"]) == 26

    def test_extension_allocations_are_data_driven_and_fail_closed(self) -> None:
        source = (generator.DATA / "language-tag-extensions-registry.txt").read_bytes()
        assert generator.extensions(source)[1] == ["t", "u"]
        assert generator.extensions(source.replace(b"Identifier: t", b"Identifier: a"))[1] == [
            "a",
            "u",
        ]
        for replacement in [b"x", b"uu", b"u"]:
            with pytest.raises(
                ValueError, match=r"invalid extension singleton|duplicate extension allocation"
            ):
                generator.extensions(
                    source.replace(b"Identifier: t", b"Identifier: " + replacement)
                )
        with pytest.raises(ValueError, match="missing extension field: Authority"):
            generator.extensions(source.replace(b"Authority: Unicode Consortium\n", b"", 1))


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__]))
