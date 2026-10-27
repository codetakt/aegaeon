# Preserve import/annotation behavior of the measured checkpoint.
# ruff: noqa: I001, I002
"""Bounded age-authenticated chunks; no complete plaintext archive copy.

The recipient/private identity is provisioned separately. A trusted receipt binds
the encrypted manifest; a truncated campaign never becomes a complete archive.
Each plaintext spool holds at most one chunk, and is unlinked on exit.
"""

import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time

RAW_LIMIT = 16 * 1024**3
CIPHER_LIMIT = 20 * 1024**3
CHUNK = 256 * 1024**2


def canonical(x):
    return json.dumps(x, sort_keys=True, separators=(",", ":")).encode()


def sha(path):
    with Path(path).open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def require(ok, message):
    if not ok:
        raise ValueError(message)


def invoke(argv, source, destination, deadline):
    require(time.monotonic() < deadline, "Recovery deadline")
    with Path(destination).open("xb") as out, tempfile.TemporaryFile() as errors:
        process = subprocess.Popen(  # noqa: S603 -- explicit argv; artifact validation precedes execution
            argv, stdin=source, stdout=out, stderr=errors, start_new_session=True
        )
        try:
            code = process.wait(timeout=max(0.001, deadline - time.monotonic()))
            if code != 0:
                errors.seek(0)
                detail = errors.read(4096)
                Path(str(destination) + ".stderr").write_bytes(detail)
                raise ValueError(
                    "Authenticated transport command failed: "
                    + detail[:512].decode("utf-8", "replace")
                )
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)
        out.flush()
        os.fsync(out.fileno())
    require(time.monotonic() < deadline, "Recovery deadline after command")


def encrypt(  # noqa: PLR0913, PLR0915, PLR0917 -- explicit fields from the frozen invocation contract; ordered evidence checks retain each rejection boundary
    blocks,
    destination,
    age,
    recipient,
    generation,
    deadline,
    *,
    raw_limit=RAW_LIMIT,
    cipher_limit=CIPHER_LIMIT,
    chunk_size=CHUNK,
):
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=False)
    require(
        0 < chunk_size <= CHUNK and 0 < raw_limit <= RAW_LIMIT and 0 < cipher_limit <= CIPHER_LIMIT,
        "Invalid capacity",
    )
    rows = []
    raw_total = cipher_total = 0
    complete = False
    spool = None
    count = 0
    h = None

    def begin():
        nonlocal spool, count, h
        spool = tempfile.TemporaryFile(dir=destination)  # noqa: SIM115 -- stream closes explicitly on rollover and in finally
        count = 0
        h = hashlib.sha256()
        spool.write(
            canonical(
                {"schema": "dudect-recovery-chunk/1", "generation": generation, "index": len(rows)}
            )
            + b"\n"
        )

    def finish():
        nonlocal spool, count, cipher_total
        spool.seek(0)
        name = f"{len(rows):06d}.age"
        path = destination / name
        invoke([str(age), "-r", recipient], spool, path, deadline)
        cipher_total += path.stat().st_size
        require(cipher_total <= cipher_limit, "Encrypted capacity exceeded")
        rows.append(
            {
                "name": name,
                "index": len(rows),
                "plain_bytes": count,
                "plain_sha256": h.hexdigest(),
                "cipher_bytes": path.stat().st_size,
                "cipher_sha256": sha(path),
            }
        )
        spool.close()
        spool = None

    try:
        begin()
        for block in blocks:
            require(isinstance(block, bytes), "Non-byte archive block")
            require(time.monotonic() < deadline, "Recovery producer deadline")
            raw_total += len(block)
            require(raw_total <= raw_limit, "Raw capacity exceeded")
            offset = 0
            while offset < len(block):
                n = min(len(block) - offset, chunk_size - count)
                part = block[offset : offset + n]
                spool.write(part)
                h.update(part)
                count += n
                offset += n
                if count == chunk_size:
                    finish()
                    begin()
        if count or not rows:
            finish()
        complete = True
    finally:
        if spool is not None:
            spool.close()
        manifest = {
            "schema": "dudect-recovery-manifest/1",
            "generation": generation,
            "complete": complete,
            "raw_bytes": raw_total,
            "cipher_bytes": cipher_total,
            "chunks": rows,
            "raw_limit": raw_limit,
            "cipher_limit": cipher_limit,
            "chunk_size": chunk_size,
        }
        # A partial manifest is authentic and explicit, never a complete claim.
        with tempfile.TemporaryFile(dir=destination) as source:
            source.write(canonical(manifest))
            source.seek(0)
            if time.monotonic() < deadline:
                invoke([str(age), "-r", recipient], source, destination / "manifest.age", deadline)
    manifest_bytes = (destination / "manifest.age").stat().st_size
    require(cipher_total + manifest_bytes <= cipher_limit, "Manifest exceeded encrypted capacity")
    return {
        "manifest_sha256": sha(destination / "manifest.age"),
        "generation": generation,
        "complete": complete,
        "raw_bytes": raw_total,
        "cipher_bytes": cipher_total,
        "manifest_bytes": manifest_bytes,
        "chunks": len(rows),
    }


def decrypt_chunks(directory, age, key, receipt, deadline):  # noqa: PLR0915 -- ordered evidence checks retain each rejection boundary
    """Yield authenticated chunks; a later failure does not invalidate earlier ones."""
    directory = Path(directory)
    require(
        (directory / "manifest.age").stat().st_size == receipt["manifest_bytes"] < 2 * 1024**2
        and sha(directory / "manifest.age") == receipt["manifest_sha256"],
        "Manifest receipt mismatch",
    )
    with tempfile.TemporaryDirectory(dir=directory) as temp:
        temp = Path(temp)  # noqa: PLW2901 -- retain measured normalization and stream lifecycle
        meta = temp / "manifest"
        with (directory / "manifest.age").open("rb") as source:
            invoke([str(age), "-d", "-i", str(key)], source, meta, deadline)
        require(meta.stat().st_size < 1024**2, "Unbounded manifest")
        manifest = json.loads(meta.read_bytes())
        require(
            manifest["schema"] == "dudect-recovery-manifest/1"
            and manifest["generation"] == receipt["generation"],
            "Wrong generation",
        )
        total = cipher = 0
        for index, row in enumerate(manifest["chunks"]):
            require(
                row["index"] == index and row["name"] == f"{index:06d}.age",
                "Reordered or unsafe chunk",
            )
            path = directory / row["name"]
            size = path.stat().st_size
            cipher += size
            require(
                size == row["cipher_bytes"]
                and size <= CHUNK + 1024**2
                and cipher + receipt["manifest_bytes"] <= CIPHER_LIMIT
                and sha(path) == row["cipher_sha256"],
                "Changed encrypted chunk",
            )
            plain = temp / "chunk"
            with path.open("rb") as source:
                invoke([str(age), "-d", "-i", str(key)], source, plain, deadline)
            with plain.open("rb") as source:
                header = source.readline(4096)
                require(
                    header.endswith(b"\n")
                    and json.loads(header)
                    == {
                        "schema": "dudect-recovery-chunk/1",
                        "generation": receipt["generation"],
                        "index": index,
                    },
                    "Chunk belongs to another archive",
                )
                offset = source.tell()
                h = hashlib.sha256()
                count = 0
                while data := source.read(1024**2):
                    h.update(data)
                    count += len(data)
                    require(count <= CHUNK, "Unbounded plaintext")
                require(
                    count == row["plain_bytes"] and h.hexdigest() == row["plain_sha256"],
                    "Plaintext identity mismatch",
                )
                total += count
                require(total <= RAW_LIMIT, "Raw recovery capacity exceeded")
                source.seek(offset)
                while data := source.read(1024**2):
                    yield data
            plain.unlink()
        require(manifest["complete"] is True and receipt["complete"] is True, "Partial archive")
        require(
            total == manifest["raw_bytes"] == receipt["raw_bytes"]
            and cipher == manifest["cipher_bytes"] == receipt["cipher_bytes"]
            and len(manifest["chunks"]) == receipt["chunks"],
            "Archive totals differ",
        )
