"""Archive a new hosted opportunity, including partial and failed observations."""

from __future__ import annotations

import argparse
import hashlib
import tarfile
from pathlib import Path
from typing import Any

from verify_dudect_analysis_matrix import require, sha256, write_json


def retain(source: Path, destination: Path) -> dict[str, Any]:
    require(source.is_dir() and not source.is_symlink(), "Missing evidence directory")
    require(not destination.resolve().is_relative_to(source.resolve()), "Archive inside evidence")
    destination.mkdir(parents=True, exist_ok=False)
    files: list[dict[str, Any]] = []
    for path in sorted(source.rglob("*")):
        require(not path.is_symlink(), "Evidence symlink is not an upload input")
        if path.is_file():
            files.append(
                {
                    "path": str(path.relative_to(source)),
                    "sha256": sha256(path),
                    "bytes": path.stat().st_size,
                }
            )
        else:
            require(path.is_dir(), "Non-regular evidence input")
    manifest = {
        "schema": "dudect-hosted-retention/1",
        "files": files,
        "ci_admission": False,
        "includes_failures_and_partial_runs": True,
    }
    write_json(destination / "manifest.json", manifest)
    with tarfile.open(destination / "evidence.tar.gz", "w:gz") as archive:
        for item in files:
            path = source / item["path"]
            require(sha256(path) == item["sha256"], "Evidence changed during archive")
            archive.add(path, arcname="evidence/" + item["path"], recursive=False)
    # Verify the actual archive stream before calling upload-artifact.
    with tarfile.open(destination / "evidence.tar.gz", "r:gz") as archive:
        for member, item in zip(archive.getmembers(), files, strict=True):
            stream = archive.extractfile(member)
            require(
                stream is not None and member.name == "evidence/" + item["path"],
                "Archive inventory differs",
            )
            if stream is None:
                raise ValueError("Missing archived file stream")
            digest = hashlib.sha256()
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
            require(digest.hexdigest() == item["sha256"], "Archived bytes differ")
    write_json(
        destination / "archive.json",
        {
            "sha256": sha256(destination / "evidence.tar.gz"),
            "manifest_sha256": sha256(destination / "manifest.json"),
            "files": len(files),
            "bytes": sum(item["bytes"] for item in files),
            "ci_admission": False,
        },
    )
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args()
    retain(args.source, args.destination)


if __name__ == "__main__":
    main()
