# ruff: noqa: EM101, TRY003 - refusals intentionally use fixed, credential-free messages
"""Launch a pinned release executable only against its matching Atlas ledger.

The release's immutable manifest is a trusted packaging input. This checks
metadata and executable identity; it does not authenticate DB administrators,
attest physical schema, or permit concurrent incompatible migrations.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence


class RefusedError(Exception):
    """A public, credential-free explanation for refusing startup."""


@dataclass(frozen=True, slots=True)
class Revision:
    version: str
    stem: str
    description: str
    file_hash: str
    inventory_hash: str


def checksum(value: object) -> str:
    if not isinstance(value, str) or not value.startswith("h1:"):
        raise RefusedError("invalid packaged migration checksum")
    try:
        decoded = base64.b64decode(value[3:], validate=True)
    except ValueError as error:
        raise RefusedError("invalid packaged migration checksum") from error
    if len(decoded) != hashlib.sha256().digest_size:
        raise RefusedError("invalid packaged migration checksum")
    return value[3:]


def parse_inventory(text: object) -> list[Revision]:
    if not isinstance(text, str):
        raise RefusedError("missing packaged migration inventory")
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if len(lines) <= 1:
        raise RefusedError("empty packaged migration inventory")
    root_hash = checksum(lines[0])
    revisions = []
    for line in lines[1:]:
        fields = line.split()
        if len(fields) != len(("filename", "hash")):
            raise RefusedError("invalid packaged migration entry")
        match = re.fullmatch(r"(\d{14})_([A-Za-z0-9_]+)\.sql", fields[0])
        if not match:
            raise RefusedError("invalid packaged migration name")
        version, description = match.groups()
        revisions.append(
            Revision(version, fields[0][:-4], description, checksum(fields[1]), root_hash)
        )
    versions = [revision.version for revision in revisions]
    if versions != sorted(set(versions)):
        raise RefusedError("duplicate or unordered packaged migrations")
    return revisions


def validate_rows(revisions: Sequence[Revision], rows: Sequence[Mapping[str, object]]) -> None:
    aliases = {
        alias: revision for revision in revisions for alias in (revision.version, revision.stem)
    }
    seen = set()
    head = None
    for row in rows:
        version = row.get("version")
        if not isinstance(version, str) or version not in aliases:
            raise RefusedError("database contains an unsupported migration")
        revision = aliases[version]
        if revision.version in seen:
            raise RefusedError("database contains duplicate migration aliases")
        seen.add(revision.version)
        if row.get("error") not in (None, ""):
            raise RefusedError("database contains a failed migration")
        applied, total = row.get("applied"), row.get("total")
        if type(applied) is not int or type(total) is not int or total <= 0 or applied != total:
            raise RefusedError("database contains a partial migration")
        if revision == revisions[-1]:
            head = row
    if seen != {revision.version for revision in revisions} or head is None:
        raise RefusedError("database migration inventory is incomplete")
    validate_head(revisions[-1], head)


def validate_head(expected: Revision, head: Mapping[str, object]) -> None:
    if head["version"] == expected.version and head.get("description") not in (
        None,
        expected.description,
    ):
        raise RefusedError("database migration head description differs")
    head_hash = head.get("hash")
    if head_hash is not None and (
        not isinstance(head_hash, str)
        or head_hash.removeprefix("h1:") not in (expected.file_hash, expected.inventory_hash)
    ):
        raise RefusedError("database migration head checksum differs")


def check_database(url: str | None, revisions: Sequence[Revision]) -> None:
    # Import only for a real connection: pure admission tests need no driver.
    import psycopg  # noqa: PLC0415 - pure admission checks do not need libpq
    from psycopg import sql  # noqa: PLC0415
    from psycopg.rows import dict_row  # noqa: PLC0415

    if not url:
        raise RefusedError("AEGAEON_DATABASE_URL is required")
    try:
        with (
            psycopg.connect(url, connect_timeout=5, row_factory=dict_row) as connection,
            connection.cursor() as cursor,
        ):
            cursor.execute("SET TRANSACTION READ ONLY")
            cursor.execute("SET LOCAL statement_timeout = '5s'")
            cursor.execute(
                """
SELECT table_schema, table_name
FROM information_schema.tables
WHERE table_name = 'atlas_schema_revisions' AND table_type = 'BASE TABLE'
  AND table_schema IN (current_schema(), 'public', 'aegaeon')
ORDER BY CASE WHEN table_schema = current_schema() THEN 0
          WHEN table_schema = 'public' THEN 1 ELSE 2 END
LIMIT 1
"""
            )
            table = cursor.fetchone()
            if table is None:
                raise RefusedError("Atlas revision metadata is missing or inaccessible")
            query = sql.SQL(
                "SELECT version, description, hash, applied, total, error "
                "FROM {} ORDER BY version LIMIT %s"
            ).format(sql.Identifier(table["table_schema"], table["table_name"]))
            # More rows than the fixed inventory can never be accepted.
            cursor.execute(query, (len(revisions) + 1,))
            validate_rows(revisions, cursor.fetchall())
    except psycopg.Error as error:
        # Driver diagnostics may contain DSNs, passwords or operator metadata.
        raise RefusedError("cannot read Atlas revision metadata") from error


def unique_members(pairs: Sequence[tuple[str, object]]) -> dict[str, object]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise RefusedError("duplicate release manifest member")
        result[key] = value
    return result


def read_manifest(path: str | Path) -> tuple[dict[str, str], list[Revision]]:
    manifest = json.loads(Path(path).read_text(), object_pairs_hook=unique_members)
    if not isinstance(manifest, dict) or set(manifest) != {"schema_version", "binary", "atlas_sum"}:
        raise RefusedError("invalid release manifest")
    binary = manifest["binary"]
    if (
        type(manifest["schema_version"]) is not int
        or manifest["schema_version"] != 1
        or not isinstance(binary, dict)
        or set(binary) != {"path", "sha256"}
    ):
        raise RefusedError("invalid release manifest")
    if not isinstance(binary["path"], str) or not Path(binary["path"]).is_absolute():
        raise RefusedError("release executable must have an absolute path")
    if not isinstance(binary["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", binary["sha256"]):
        raise RefusedError("invalid release executable checksum")
    return binary, parse_inventory(manifest["atlas_sum"])


def open_executable(binary: Mapping[str, str]) -> int:
    # Hold the same file description through hashing, DB check and exec. A
    # pathname replacement cannot swap in another executable after admission.
    descriptor = os.open(binary["path"], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        verify_executable(descriptor, binary["sha256"])
    except BaseException:
        os.close(descriptor)
        raise
    else:
        return descriptor


def verify_executable(descriptor: int, expected_digest: str) -> None:
    mode = os.fstat(descriptor).st_mode
    if not stat.S_ISREG(mode) or not mode & 0o111 or mode & 0o222:
        raise RefusedError("release executable is not a read-only executable file")
    with os.fdopen(os.dup(descriptor), "rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    if digest != expected_digest:
        raise RefusedError("release executable checksum differs")
    os.lseek(descriptor, 0, os.SEEK_SET)


def launch(manifest_path: str | Path, arguments: Sequence[str]) -> None:
    if os.execve not in os.supports_fd:
        raise RefusedError("descriptor-based launch is not supported on this platform")
    binary, revisions = read_manifest(manifest_path)
    descriptor = open_executable(binary)
    try:
        check_database(os.environ.get("AEGAEON_DATABASE_URL"), revisions)
        print(
            "aegaeon schema gate: executable and migration inventory accepted",
            file=sys.stderr,
            flush=True,
        )
        os.execve(descriptor, [binary["path"], *arguments], dict(os.environ))  # noqa: S606 - checked FD
    finally:
        os.close(descriptor)


def main() -> int:  # noqa: PLR0911 - distinct CLI refusal branches
    if len(sys.argv) <= 1:
        print("aegaeon schema gate refused startup: release manifest is required", file=sys.stderr)
        return 78
    try:
        launch(sys.argv[1], sys.argv[2:])
    except RefusedError as error:
        print(f"aegaeon schema gate refused startup: {error}", file=sys.stderr)
        return 78
    except (OSError, ValueError, KeyError, TypeError, ImportError):
        print(
            "aegaeon schema gate refused startup: invalid or inaccessible release inputs",
            file=sys.stderr,
        )
        return 78
    return 0


if __name__ == "__main__":
    sys.exit(main())
