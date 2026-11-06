"""Actual SQL upgrade and distinct failed-start journal terminal state."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from uuid import uuid4

import psycopg
import pytest
from deployment_control import Fixture
from psycopg import sql
from psycopg.types.json import Jsonb


def main():  # noqa: PLR0915 — bounded actual migration and constraint matrix
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ("schema", "catalog", "output"):
        parser.add_argument("--" + key, type=Path, required=True)
    args = parser.parse_args()
    f = Fixture("serving_migration")
    deployment, operation, cutover = [uuid4() for _ in range(3)]
    original = f.maintenance("deployment_initialize", deployment, operation)
    f.admin(
        "INSERT INTO organization_witness.cutover_operations "
        "(deployment_id,operation_id,fence_operation_id,fence_revision,fence_sha256,plan_sha256) "
        "VALUES(%s,%s,%s,1,%s,%s)",
        (deployment, cutover, operation, "a" * 64, "b" * 64),
    )
    with pytest.raises(psycopg.errors.RaiseException, match="drained fenced"):
        f.admin(args.schema.read_text())
    assert (
        f.admin(
            "SELECT count(*) FROM information_schema.columns "
            "WHERE table_schema='organization_witness' "
            "AND table_name='cutover_operations' AND column_name='aborted'"
        ).fetchone()[0]
        == 0
    )
    # This fixture manufactures an old completed operation; it does not claim
    # that a serving coordinator or any external store completed its protocol.
    f.admin(
        "UPDATE organization_witness.cutover_operations SET step=16,completed=true,receipts=%s",
        (Jsonb(["c" * 64] * 16),),
    )
    prior = f.admin("SELECT to_jsonb(c) FROM organization_witness.cutover_operations c").fetchone()[
        0
    ]
    f.admin(args.schema.read_text())
    assert f.maintenance("deployment_state", deployment) == original
    assert f.admin("SELECT to_jsonb(c) FROM organization_witness.cutover_operations c").fetchone()[
        0
    ] == dict(prior, aborted=False, abort_receipt_sha256=None)
    assert f.admin((args.schema.parent / "catalog-v5.sql").read_text()).fetchone()[0] == json.loads(
        args.catalog.read_text()
    )
    pending = uuid4()
    insert = (
        "INSERT INTO organization_witness.cutover_operations "
        "(deployment_id,operation_id,fence_operation_id,fence_revision,"
        "fence_sha256,plan_sha256,step,receipts) "
        "VALUES(%s,%s,%s,1,%s,%s,14,%s)"
    )
    values = (deployment, pending, operation, "a" * 64, "b" * 64, Jsonb(["d" * 64] * 14))
    f.admin(insert, values)
    successor = (deployment, uuid4(), *values[2:])
    with pytest.raises(psycopg.errors.UniqueViolation):
        f.admin(insert, successor)
    for statement in [
        "aborted=true",
        "abort_receipt_sha256=repeat('e',64)",
        "aborted=true,abort_receipt_sha256='bad'",
        "aborted=true,completed=true,abort_receipt_sha256=repeat('e',64)",
    ]:
        with pytest.raises(psycopg.errors.CheckViolation):
            f.admin(
                sql.SQL(
                    "UPDATE organization_witness.cutover_operations SET {} WHERE operation_id=%s"
                ).format(sql.SQL(statement)),
                (pending,),
            )
    before = f.admin(
        "SELECT to_jsonb(c) FROM organization_witness.cutover_operations c WHERE operation_id=%s",
        (pending,),
    ).fetchone()[0]
    for group in (
        "aegaeon_organization_witness_runtime",
        "aegaeon_organization_witness_maintenance",
    ):
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            f.admin(
                sql.SQL(
                    "SET ROLE {}; UPDATE organization_witness.cutover_operations SET aborted=true"
                ).format(sql.Identifier(group))
            )
    f.admin(
        "UPDATE organization_witness.cutover_operations SET aborted=true,abort_receipt_sha256=%s "
        "WHERE operation_id=%s",
        ("e" * 64, pending),
    )
    after = f.admin(
        "SELECT to_jsonb(c) FROM organization_witness.cutover_operations c WHERE operation_id=%s",
        (pending,),
    ).fetchone()[0]
    assert after == dict(before, aborted=True, abort_receipt_sha256="e" * 64)
    f.admin(insert, successor)
    assert (
        f.admin("SELECT count(*) FROM organization_witness.cutover_operations").fetchone()[0] == 3
    )
    args.output.write_text(
        json.dumps(
            {
                "passed": True,
                "conditions": [
                    "unfinished operation refuses migration atomically",
                    "completed history survives upgrade",
                    "runtime and maintenance cannot mark abort",
                    "abort requires distinct receipt and excludes success",
                    "only confirmed abort releases unfinished slot; old receipts preserved",
                ],
                "scope": "SQL journal constraints; actual closure evidence remains separate",
                "newCompositeDischarges": 0,
            },
            indent=2,
        )
        + "\n"
    )


if __name__ == "__main__":
    main()
