#!/usr/bin/env python3
"""Bind the compiled optional-claim table to independent, retained IANA input."""

from __future__ import annotations

import generate_lti_time_zones as generator
import pytest


def test_compiled_table_matches_pinned_source_and_retains_aliases() -> None:
    rendered = generator.render()
    assert rendered.encode() == generator.OUTPUT.read_bytes()
    for name in ["Asia/Tokyo", "Etc/UTC", "UTC", "US/Eastern", "America/New_York"]:
        assert f'    "{name}",\n' in rendered
    assert '"Mars/Olympus"' not in rendered


def test_changed_supplier_bytes_are_rejected() -> None:
    raw = (generator.DATA / "tzdata2026f.tar.gz").read_bytes()
    changed = raw[:-1] + bytes([raw[-1] ^ 1])
    with pytest.raises(ValueError, match="archive digest mismatch"):
        generator.render(changed)
