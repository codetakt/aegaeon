"""Bind the packaged numerical runtime without conflating it with native code."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


def filehash(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def runtime_identity(directory):
    path = directory / "runtime-dependencies.json"
    if not path.exists():
        return {"kind": "unpackaged-source-checkout"}
    data = json.loads(path.read_text())
    if data.get("schema") != "dudect-nix-runtime/1" or not data.get("files"):
        msg = "Invalid packaged runtime binding"
        raise ValueError(msg)
    expected = data["files"]
    for name, digest in expected.items():
        if not name.startswith("/nix/store/") or filehash(name) != digest:
            msg = "Packaged runtime dependency changed"
            raise ValueError(msg)
    # A loader override must not substitute a same-named numerical dependency.
    names = {Path(name).name for name in expected}
    for line in Path("/proc/self/maps").read_text().splitlines():
        fields = line.split(maxsplit=5)
        if len(fields) == 6 and fields[5].startswith("/"):
            loaded = Path(fields[5])
            if loaded.name in names and str(loaded.resolve()) not in expected:
                msg = f"Loaded runtime dependency differs from package: {loaded}"
                raise ValueError(msg)
    return data
