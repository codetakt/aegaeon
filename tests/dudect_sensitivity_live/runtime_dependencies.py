# Preserve import/annotation behavior of the measured checkpoint.
# Inline validation reasons remain part of the evidence error protocol.
# ruff: noqa: EM101, I001, I002, TRY003
"""Identify dependencies using the ELF's own interpreter, never the host ldd.

This bounded helper supports the frozen Linux x86-64 diagnostic build only.
It does not execute the target's main function or collect timing samples.
"""

import hashlib
import os
from pathlib import Path
import re
import struct
import subprocess


def sha(path):
    with Path(path).open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def interpreter(binary):
    with Path(binary).open("rb") as source:
        header = source.read(64)
        if len(header) != 64 or header[:7] != b"\x7fELF\x02\x01\x01":
            raise ValueError("Expected little-endian ELF64")
        if struct.unpack_from("<H", header, 18)[0] != 62:
            raise ValueError("Expected x86-64 ELF")
        offset = struct.unpack_from("<Q", header, 32)[0]
        size, count = struct.unpack_from("<HH", header, 54)
        length = os.fstat(source.fileno()).st_size
        if size != 56 or not 0 < count <= 4096 or offset + size * count > length:
            raise ValueError("Invalid program header table")
        paths = []
        for index in range(count):
            source.seek(offset + size * index)
            program = source.read(size)
            if struct.unpack_from("<I", program)[0] != 3:
                continue
            start = struct.unpack_from("<Q", program, 8)[0]
            width = struct.unpack_from("<Q", program, 32)[0]
            if not 2 <= width <= 4096 or start + width > length:
                raise ValueError("Invalid interpreter range")
            source.seek(start)
            value = source.read(width)
            if value[-1:] != b"\0" or b"\0" in value[:-1]:
                raise ValueError("Invalid interpreter string")
            paths.append(value[:-1].decode("ascii"))
    if len(paths) != 1:
        raise ValueError("Exactly one interpreter required")
    store_root(paths[0])
    return paths[0]


def store_root(path):
    path = Path(path)
    if len(path.parts) < 5 or path.parts[:3] != ("/", "nix", "store") or ".." in path.parts:
        raise ValueError("Dependency outside the frozen Nix store")
    return str(Path(*path.parts[:4]))


def parse_listing(text, loader):
    paths = set()
    for line in text.splitlines():
        line = line.strip()  # noqa: PLW2901 -- retain measured normalization and stream lifecycle
        if re.fullmatch(r"linux-vdso\.so\.1 \(0x[0-9a-fA-F]+\)", line):
            continue
        match = re.fullmatch(r"(?:\S+ => )?(/\S+) \(0x[0-9a-fA-F]+\)", line)
        if not match:
            raise ValueError("Unresolved or unexpected loader output")
        path = match[1]
        store_root(path)
        paths.add(path)
    if loader not in paths:
        raise ValueError("Target interpreter absent from its dependency listing")
    return sorted(paths)


def inspect(binary):
    loader = interpreter(binary)
    binary_before, loader_before = sha(binary), sha(loader)
    result = subprocess.run(  # noqa: S603 -- explicit argv; artifact validation precedes execution
        [loader, "--list", str(Path(binary).resolve())],
        env={"LC_ALL": "C"},
        capture_output=True,
        timeout=30,
        check=True,
    )
    if result.stderr:
        raise ValueError("Unexpected loader diagnostics")
    paths = parse_listing(result.stdout.decode("ascii"), loader)
    libraries = {path: sha(path) for path in paths}
    if sha(binary) != binary_before or libraries[loader] != loader_before:
        raise ValueError("Artifact changed during dependency inspection")
    return {
        "method": "elf-pt-interp-list/1",
        "interpreter": loader,
        "binary_sha256": binary_before,
        "dynamic_libraries": libraries,
        "store_roots": sorted({store_root(p) for p in paths}),
        "environment": {"LC_ALL": "C"},
        "listing": result.stdout.decode("ascii"),
    }
