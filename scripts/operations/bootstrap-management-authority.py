#!/usr/bin/env python3
"""Submit one explicit management grant using the deployment's dedicated PG login."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import tempfile
from pathlib import Path
from uuid import UUID

MAX_REQUEST_BYTES = 16384


def read_request(path: Path) -> dict:
    with path.open("rb") as source:
        encoded = source.read(MAX_REQUEST_BYTES + 1)
    if len(encoded) > MAX_REQUEST_BYTES:
        message = "bootstrap request exceeds 16 KiB"
        raise ValueError(message)
    request = json.loads(encoded)
    if not isinstance(request, dict) or request.get("adopt_installation") is not True:
        message = "an explicit installation adoption request is required"
        raise ValueError(message)
    for name in ("installation_id", "operation_id", "grant_id", "principal_id", "principal_kind"):
        if not isinstance(request.get(name), str) or not request[name]:
            message = f"explicit {name} is required"
            raise ValueError(message)
    return request


def statement(request: dict) -> str:
    # JSON is one SQL literal. Doubling quotes and fixed standard strings keep
    # request contents out of SQL syntax; no shell expands either input.
    literal = json.dumps(request, ensure_ascii=True, separators=(",", ":")).replace("'", "''")
    return (
        "BEGIN ISOLATION LEVEL REPEATABLE READ;\n"
        "SET LOCAL standard_conforming_strings=on;\n"
        "SET LOCAL statement_timeout='30s';\n"
        "SET LOCAL lock_timeout='5s';\n"
        f"SELECT management_authority.bootstrap_v1('{literal}'::jsonb);\n"
        "COMMIT;\n"
    )


def write_receipt(path: Path, receipt: dict) -> None:
    # Publish only a complete successful receipt with private permissions.
    with tempfile.NamedTemporaryFile(mode="w", dir=path.parent, delete=False) as temporary:
        temporary_path = Path(temporary.name)
        try:
            json.dump(receipt, temporary, indent=2)
            temporary.write("\n")
            temporary.flush()
            os.fsync(temporary.fileno())
            temporary_path.replace(path)
            directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            temporary_path.unlink(missing_ok=True)


def same_uuid(received: object, requested: str) -> bool:
    if not isinstance(received, str):
        return False
    try:
        return UUID(received) == UUID(requested)
    except ValueError:
        return False


def run(request_file: Path, receipt_file: Path) -> None:
    if request_file.resolve() == receipt_file.resolve():
        message = "request and receipt must use separate files"
        raise ValueError(message)
    request = read_request(request_file)
    # libpq's normal PGSERVICE/PGHOST/PGDATABASE/PGUSER/PGPASSFILE settings select
    # the deployment-held credential. It is never a management bearer token.
    result = subprocess.run(
        ["psql", "-X", "-qAt", "-v", "ON_ERROR_STOP=1"],  # noqa: S607 - pinned operator tool
        input=statement(request),
        text=True,
        capture_output=True,
        timeout=35,
        check=False,
    )
    if result.returncode != 0:
        message = (
            "bootstrap refused or completion unconfirmed; retain and retry the identical request"
        )
        raise ValueError(message)
    receipt = json.loads(result.stdout)
    if (
        not isinstance(receipt, dict)
        or not same_uuid(receipt.get("operationId"), request["operation_id"])
        or not same_uuid(receipt.get("grantId"), request["grant_id"])
        or receipt.get("revision") != 1
        or receipt.get("delegationEpoch") != 1
    ):
        message = "unexpected bootstrap receipt; retain the request for investigation"
        raise ValueError(message)
    write_receipt(receipt_file, receipt)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()
    try:
        run(args.request, args.receipt)
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        # Never print the request, credential-bearing connection settings or SQL
        # diagnostics. A timeout may follow commit: reuse the same operation ID.
        print(f"Management bootstrap did not produce a verified receipt ({type(error).__name__}).")
        print("Retain the exact request and inspect deployment diagnostics before retrying it.")
        return 1
    print("Management bootstrap receipt saved.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
