#!/usr/bin/env python3
"""Reject new broken repository-local Markdown file links relative to a Git baseline."""

from __future__ import annotations

import argparse
import posixpath
import re
import subprocess
from pathlib import PurePosixPath
from urllib.parse import unquote, urlsplit


def local_links(text: str) -> set[str]:
    # Code examples are not links. This check covers inline and reference-style
    # file destinations, not remote availability or renderer-specific anchors.
    text = re.sub(r"(?ms)^```[^\n]*\n.*?^```[^\n]*$|^~~~[^\n]*\n.*?^~~~[^\n]*$", "", text)
    text = re.sub(r"`[^`\n]*`", "", text)
    destinations = re.findall(r"\]\(\s*(<[^>]+>|[^\s)]+)", text)
    destinations += re.findall(r"(?m)^\s*\[[^\]]+\]:\s*(<[^>]+>|\S+)", text)
    result = set()
    for destination in destinations:
        url = urlsplit(destination.strip("<>"))
        if not url.scheme and not url.netloc and url.path:
            result.add(unquote(url.path))
    return result


def broken_links(files: dict[str, str], paths: set[str]) -> set[tuple[str, str]]:
    available = paths | {str(parent) for path in paths for parent in PurePosixPath(path).parents}
    errors = set()
    for source, text in files.items():
        for destination in local_links(text):
            target = posixpath.normpath(posixpath.join(posixpath.dirname(source), destination))
            if target not in available:
                errors.add((source, destination))
    return errors


def snapshot(revision: str) -> tuple[dict[str, str], set[str]]:
    raw = subprocess.check_output(["git", "ls-tree", "-r", "-z", revision])
    blobs = {}
    paths = set()
    for record in raw.split(b"\0"):
        if not record:
            continue
        metadata, raw_name = record.split(b"\t", 1)
        mode, kind, oid = metadata.split()
        path = raw_name.decode("utf-8")
        paths.add(path)
        if path.endswith(".md") and kind == b"blob" and mode in {b"100644", b"100755"}:
            blobs[path] = oid.decode("ascii")
    if not blobs:
        return {}, paths
    proc = subprocess.run(
        ["git", "cat-file", "--batch"],
        input=("\n".join(blobs.values()) + "\n").encode(),
        stdout=subprocess.PIPE,
        check=True,
    )
    files = {}
    offset = 0
    for name in blobs:
        end = proc.stdout.index(b"\n", offset)
        header = proc.stdout[offset:end].split()
        if len(header) != 3 or header[1] != b"blob":
            raise ValueError("cannot read Markdown blob")
        size = int(header[2])
        files[name] = proc.stdout[end + 1 : end + 1 + size].decode("utf-8", errors="replace")
        offset = end + 1 + size + 1
    return files, paths


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", required=True)
    parser.add_argument("--head", default="HEAD")
    args = parser.parse_args()
    errors = broken_links(*snapshot(args.head)) - broken_links(*snapshot(args.base))
    for source, target in sorted(errors):
        print(f"{source}: new broken local file link: {target}")
    if errors:
        return 1
    print("No new broken local Markdown file links.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
