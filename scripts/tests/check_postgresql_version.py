"""Verify the explicit CI/test supplier against the source-managed PostgreSQL version."""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MINIMUM_MAJOR = 10
MAJOR_MULTIPLIER = 10000
PROBE = """
import os
import psycopg
with psycopg.connect(os.environ['AEGAEON_PG_VERSION_DATABASE_URL'], connect_timeout=10) as db:
    print(db.execute('SHOW server_version_num').fetchone()[0])
"""


def version_number(version: str) -> int:
    if re.fullmatch(r"[1-9][0-9]+\.[0-9]+", version) is None:
        message = "PostgreSQL baseline must be a complete stable major.minor version"
        raise ValueError(message)
    major, minor = map(int, version.split("."))
    if major < MINIMUM_MAJOR or minor >= MAJOR_MULTIPLIER:
        message = "PostgreSQL baseline is outside the supported version-number format"
        raise ValueError(message)
    return major * MAJOR_MULTIPLIER + minor


def check(version: str, database_url: str) -> int:
    expected = version_number(version)
    if not database_url:
        message = "An explicit PostgreSQL test database URL is required"
        raise ValueError(message)
    # The child bounds connection/query time and receives credentials only in its
    # environment. Pass the URI directly to libpq; PGDATABASE alone does not
    # expand a URI and can silently select the ambient connection defaults.
    result = subprocess.run(  # noqa: S603 - fixed child code and read-only query
        [sys.executable, "-c", PROBE],
        env=dict(os.environ, AEGAEON_PG_VERSION_DATABASE_URL=database_url),
        capture_output=True,
        text=True,
        check=True,
        timeout=15,
    )
    observed = result.stdout.strip()
    if observed != str(expected):
        message = f"PostgreSQL version mismatch: expected {expected}, observed {observed!r}"
        raise ValueError(message)
    return expected


def main() -> None:
    version = (ROOT / "ci/postgresql-version").read_text().strip()
    url = os.environ.get("AEGAEON_TEST_ADMIN_DATABASE_URL") or os.environ.get(
        "AEGAEON_DATABASE_URL", ""
    )
    observed = check(version, url)
    print(f"PostgreSQL baseline {version}: observed server_version_num={observed}")


if __name__ == "__main__":
    main()
