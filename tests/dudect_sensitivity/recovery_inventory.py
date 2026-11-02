# Preserve import/annotation behavior of the measured checkpoint.
# Inline validation reasons remain part of the evidence error protocol.
# ruff: noqa: EM101, I002, TRY003
"""Inventory explicitly selected evidence trees, including forensic caches.

Call only after the writer is stopped. File types and duplicate paths are checked;
this manifest is not a replacement for the campaign's expected-case inventory.
"""

import hashlib
from pathlib import Path


def inventory(root, names):  # noqa: C901, PLR0912 -- ordered evidence checks retain each rejection boundary
    root = Path(root)
    rows = []
    seen = set()
    for name in names:
        name = Path(name)  # noqa: PLW2901 -- retain measured normalization and stream lifecycle
        if name.is_absolute() or ".." in name.parts:
            raise ValueError("Evidence selection must stay within its root")
        selected = root / name
        prefix = root
        for part in name.parts:
            prefix = prefix / part
            if prefix.is_symlink():
                raise ValueError("Unexpected evidence symlink")
        if not selected.exists():
            continue  # Optional failure-phase receipts may not exist.
        if not selected.is_file() and not selected.is_dir():
            raise ValueError("Unexpected evidence file type")
        paths = [selected] if selected.is_file() else sorted(selected.rglob("*"))
        for path in paths:
            if path.is_symlink():
                raise ValueError("Unexpected evidence symlink")
            if path.is_dir():
                continue
            if not path.is_file():
                raise ValueError("Unexpected evidence file type")
            relative = str(path.relative_to(root))
            if relative in seen:
                raise ValueError("Duplicate evidence selection")
            seen.add(relative)
            with path.open("rb") as stream:
                digest = hashlib.file_digest(stream, "sha256").hexdigest()
            rows.append({"path": relative, "bytes": path.stat().st_size, "sha256": digest})
    return rows
