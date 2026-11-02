"""Build-time inventory; no timing measurements are performed."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

import flint

directory = Path(sys.argv[1])
# Nix's environment interpreter can be a hard link. The kernel reports the
# original executable in maps, even though sys.executable names the environment.
# Bind both identities rather than assuming symlink resolution is sufficient.
roots = [
    Path(sys.executable).resolve(),
    Path("/proc/self/exe").resolve(),
    *Path(flint.__file__).parent.rglob("*.so"),
]
files = set()
for root in roots:
    files.add(root.resolve())
    result = subprocess.run(  # noqa: S603 -- pinned Nix builder PATH, trusted ELF
        ["ldd", str(root)],  # noqa: S607 -- pinned Nix builder PATH
        capture_output=True,
        text=True,
        check=True,
    )
    if "not found" in result.stdout:
        msg = "Unresolved packaged runtime dependency"
        raise RuntimeError(msg)
    files.update(Path(p).resolve() for p in re.findall(r"(/\S+)\s+\(", result.stdout))


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


assert files
assert all(str(p).startswith("/nix/store/") for p in files)
value = {
    "schema": "dudect-nix-runtime/1",
    "python_flint_version": flint.__version__,
    "files": {str(p): sha(p) for p in sorted(files)},
    "package_recipe_sha256": sha(directory / "dudect-analysis.nix"),
    "inventory_implementation_sha256": sha(Path(__file__)),
}
(directory / "runtime-dependencies.json").write_text(json.dumps(value, sort_keys=True) + "\n")
