"""Reconstruct pinned LTI bytes, accepting only two volatile Drupal wrapper fields."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
from typing import TypedDict


class Wrapper(TypedDict):
    sha256: str
    cache_token: str
    theme_token: str
    asset_count: int


METADATA = pathlib.Path(__file__).with_name("lti_source_wrappers.json")
MAX_BYTES = 1024 * 1024
ASSET = re.compile(
    rb"(https:(?:/|\\/){2}www[.]imsglobal[.]org(?:/|\\/)(?:modules|sites)"
    rb'(?:/|\\/)[A-Za-z0-9_./\\-]+\?)([a-z0-9]{6})(?=["\\])'
)
THEME = re.compile(
    rb'("ajaxPageState":\{"theme":"ims_spec","theme_token":")[A-Za-z0-9_-]{43}("[,}])'
)


def restore(
    raw: bytes, *, sha256: str, cache_token: str, theme_token: str, asset_count: int
) -> bytes:
    """The final original digest also protects every unmodified byte and field location."""
    if len(raw) > MAX_BYTES:
        raise ValueError("LTI source exceeds the fixed size limit")
    matches = list(ASSET.finditer(raw))
    if len(matches) != asset_count or len({match[2] for match in matches}) != 1:
        raise ValueError("LTI asset wrapper differs from the pinned shape")
    restored = ASSET.sub(lambda match: match[1] + cache_token.encode("ascii"), raw)
    restored, count = THEME.subn(
        lambda match: match[1] + theme_token.encode("ascii") + match[2], restored
    )
    if count != 1:
        raise ValueError("LTI theme wrapper differs from the pinned shape")
    if hashlib.sha256(restored).hexdigest() != sha256:
        raise ValueError("LTI source does not reproduce the original pinned bytes")
    return restored


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source_id")
    parser.add_argument("sha256")
    parser.add_argument("path", type=pathlib.Path)
    args = parser.parse_args()
    metadata = json.loads(METADATA.read_text())[args.source_id]
    if args.sha256 != metadata["sha256"]:
        raise ValueError("LTI wrapper metadata does not match the adopted source digest")
    with args.path.open("rb") as source:
        raw = source.read(MAX_BYTES + 1)
    args.path.write_bytes(restore(raw, **metadata))


if __name__ == "__main__":
    main()
