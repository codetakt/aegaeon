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
    "common.py": "8fa8adf78bf204df2a16a50cf99909e665e6218da15ff3efbc132bec7bc4b8d5",
    "credentials.py": "46e960c505598bb2d0ad68dfb2cf6719d449822199a7ca62d630e81c35c59de1",
    "filesystem.py": "2c5cc6c6f2d3c7e71f0e69810d5bd7796c09a10153554caf08d298beb4462901",
    "metrics.py": "30efa2e1a66585e2dc85c1147b25244d96249062d3d6e5ccf58ef5c01d53fe1f",
    "orchestration.py": "42d11b1b90d5fe428c564829b6a8e17aee96034ceb9fa6523d71a1e2bda3f0b7",
    "reports.py": "eb6b3a991ae59dbf622d7e9adacd029476ad0227f80b2ab6179c70cf2129a4dd",
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
