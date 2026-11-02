"""Verify the explicit CI/test supplier against the source-managed PostgreSQL version."""

from __future__ import annotations

import os
import re
import runpy
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCHEMA_GUARD = runpy.run_path(str(ROOT / "scripts/runtime/schema_guard.py"))
MINIMUM_MAJOR = 10
MAJOR_MULTIPLIER = 10000
PROBE = """
import os
import sys
try:
    import psycopg
except ImportError:
    sys.exit(20)
try:
    mode = os.environ['AEGAEON_PG_VERSION_SSLMODE']
    options = {'sslmode': mode} if mode else {}
    with psycopg.connect(
        os.environ['AEGAEON_PG_VERSION_DATABASE_URL'], connect_timeout=10, **options
    ) as db:
        print(db.execute('SHOW server_version_num').fetchone()[0])
except psycopg.OperationalError:
    sys.exit(21)
except psycopg.Error:
    sys.exit(22)
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
    # Share the launcher's libpq/SQLx identity and transport contract, including
    # explicit hosts, query decoding, ambient defaults and TLS mode binding.
    try:
        database_url, strong_mode = SCHEMA_GUARD["validate_database_url"](database_url, os.environ)
    except SCHEMA_GUARD["RefusedError"] as error:
        message = f"PostgreSQL probe: {error}"
        raise ValueError(message) from None
    # The child bounds connection/query time and receives credentials only in its
    # environment. Pass the URI directly to libpq; PGDATABASE alone does not
    # expand a URI and can silently select the ambient connection defaults.
    try:
        result = subprocess.run(  # noqa: S603 - fixed child code and read-only query
            [sys.executable, "-c", PROBE],
            env=dict(
                os.environ,
                AEGAEON_PG_VERSION_DATABASE_URL=database_url,
                AEGAEON_PG_VERSION_SSLMODE=strong_mode or "",
            ),
            capture_output=True,
            text=True,
            check=True,
            timeout=15,
        )
    except subprocess.CalledProcessError as error:
        reason = {
            20: "psycopg dependency unavailable",
            21: "connection or authentication failed",
            22: "version query failed",
        }.get(error.returncode, "unexpected child failure")
        message = f"PostgreSQL probe: {reason} (exit {error.returncode})"
        raise RuntimeError(message) from None
    except subprocess.TimeoutExpired:
        message = "PostgreSQL probe: 15-second deadline exceeded"
        raise RuntimeError(message) from None
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
