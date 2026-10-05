#!/usr/bin/env -S python3 -I -B
"""Start only the fixed, verified guest delivery package."""

from __future__ import annotations

import hashlib
import stat
import sys
from pathlib import Path

PACKAGE_ROOT = Path("/usr/local/lib/aegaeon/runtime_delivery")
OWNER_UID = 0
PACKAGE_SHA256: dict[str, str] = {
    "__init__.py": "a93ecaebc51890db496fda2b5557cb8c510029ef19ae223ca2c0795a78a550d5",
    "artifacts.py": "495c96705a96d58935f4004f93c9a3d8dfaca190e7bb665afd792f8c1a1ecdaa",
    "common.py": "d77c7242fced489bdf248108d1ea09a299089a9f42daf0d1f950b69c5a1022bd",
    "credentials.py": "66222125d9e1c3bbd6f29410f3a4ac0a289609aed91dcda32e2c0ccd264bacc1",
    "filesystem.py": "61c7c9b4f709711dcf8d07a4c4a5bbdfa66439fc49b1179bd5436d059941fb89",
    "metrics.py": "30efa2e1a66585e2dc85c1147b25244d96249062d3d6e5ccf58ef5c01d53fe1f",
    "orchestration.py": "3881babdd873e5abe62987cc71375f33f051e0144f9a68578960c9b1e2b91559",
    "reports.py": "49018fa4201ea453c4952863cab9b0dcafc6b2eff8e1d056c580a049bd387b7c",
}


def protected_entry(path: Path, *, directory: bool) -> None:
    metadata = path.lstat()
    kind = stat.S_ISDIR if directory else stat.S_ISREG
    if metadata.st_uid != OWNER_UID or metadata.st_mode & 0o022 or not kind(metadata.st_mode):
        message = "unsafe delivery implementation path"
        raise ValueError(message)


def protected_directory(path: Path) -> None:
    current = Path("/")
    protected_entry(current, directory=True)
    for component in path.parts[1:]:
        current = current / component
        protected_entry(current, directory=True)


def startup_isolation() -> None:
    if not sys.flags.isolated or not sys.dont_write_bytecode:
        message = "isolated delivery startup required"
        raise ValueError(message)


def package_sources() -> None:
    protected_directory(PACKAGE_ROOT)
    protected_directory(Path(__file__).parent)
    protected_entry(Path(__file__), directory=False)
    if {entry.name for entry in PACKAGE_ROOT.iterdir()} != set(PACKAGE_SHA256):
        message = "unexpected delivery implementation inventory"
        raise ValueError(message)
    for name, expected in PACKAGE_SHA256.items():
        path = PACKAGE_ROOT / name
        protected_entry(path, directory=False)
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            message = "changed delivery implementation source"
            raise ValueError(message)
    if any(
        name == "runtime_delivery" or name.startswith("runtime_delivery.") for name in sys.modules
    ):
        message = "preloaded delivery implementation"
        raise ValueError(message)


if __name__ == "__main__":
    exit_status = 1
    try:
        startup_isolation()
        package_sources()
        sys.path.insert(0, str(PACKAGE_ROOT.parent))
        from runtime_delivery.orchestration import main as guest_main

        exit_status = guest_main()
    except Exception:  # noqa: BLE001 -- import/dispatch errors must never expose secret material
        sys.stderr.write("performance supply delivery failed\n")
    raise SystemExit(exit_status)
