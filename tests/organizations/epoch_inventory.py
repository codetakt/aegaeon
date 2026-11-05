"""Actual epoch-intent migration, privilege, inventory and lock boundaries."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from uuid import uuid4

import psycopg
import pytest
from deployment_control import Fixture
from psycopg.types.json import Jsonb


def main():  # noqa: PLR0915 — finite catalog/transaction inventory
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--schema", type=Path, required=True)
    parser.add_argument("--catalog", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    f = Fixture("epoch_migration")
    deployment, operation, cutover = [uuid4() for _ in range(3)]
    f.maintenance("deployment_initialize", deployment, operation)
    children = [uuid4(), uuid4()]
    for child in children:
        f.maintenance("initialize", child, deployment, uuid4())
    snapshot = f.admin("SELECT to_jsonb(d) FROM organization_witness.deployments d").fetchone()[0]
    sha = "a" * 64
    f.admin(
        "INSERT INTO organization_witness.cutover_operations "
        "(deployment_id,operation_id,fence_operation_id,fence_revision,fence_sha256,plan_sha256) "
        "VALUES(%s,%s,%s,1,%s,%s)",
        (deployment, cutover, operation, sha, sha),
    )
    with pytest.raises(psycopg.errors.RaiseException, match="without pending cutover"):
        f.admin(args.schema.read_text())
    assert (
        f.admin(
            "SELECT to_regprocedure('organization_witness.cutover_selection(uuid,uuid,text)')"
        ).fetchone()[0]
        is None
    )
    # Remove only this fixture's never-executed registration, not a real cutover.
    row = f.admin(
        "DELETE FROM organization_witness.cutover_operations RETURNING to_jsonb(cutover_operations)"
    ).fetchone()[0]
    f.admin(args.schema.read_text())
    assert (
        f.admin("SELECT to_jsonb(d) FROM organization_witness.deployments d").fetchone()[0]
        == snapshot
    )
    actual = f.admin((args.schema.parent / "catalog-v5.sql").read_text()).fetchone()[0]
    assert actual == json.loads(args.catalog.read_text())
    f.admin(
        "INSERT INTO organization_witness.cutover_operations "
        "SELECT * FROM jsonb_populate_record(NULL::organization_witness.cutover_operations,%s)",
        (Jsonb(row),),
    )
    for step in (0, 7, 9, 16):
        f.admin(
            "UPDATE organization_witness.cutover_operations SET step=%s,receipts=%s",
            (step, Jsonb([sha] * step)),
        )
        f.maintenance(
            "cutover_selection", deployment, cutover, sha, refusal="registered epoch intent differs"
        )
    f.admin(
        "UPDATE organization_witness.cutover_operations SET step=8,receipts=%s", (Jsonb([sha] * 8),)
    )
    f.call("cutover_selection", deployment, cutover, sha, refusal="permission denied")
    f.maintenance("cutover_selection", deployment, cutover, "b" * 64, refusal="intent differs")
    for role in ("organization_runtime", "organization_maintenance"):
        with f.connection(role) as connection, pytest.raises(psycopg.errors.InsufficientPrivilege):
            connection.execute("SELECT * FROM organization_witness.cutover_operations")
    observed = f.maintenance("cutover_selection", deployment, cutover, sha)
    assert {r["environment_id"] for r in observed["children"]} == {str(c) for c in children}
    assert observed["parent"]["revision"] == 1
    with f.connection("organization_maintenance") as connection, connection.transaction():
        connection.execute(
            "SELECT organization_witness.cutover_selection(%s,%s,%s)", (deployment, cutover, sha)
        )
        with f.connection("organization_maintenance_other") as other:
            other.execute("SET lock_timeout='100ms'")
            with pytest.raises(psycopg.errors.LockNotAvailable):
                other.execute(
                    "SELECT organization_witness.initialize(%s,%s,%s)",
                    (uuid4(), deployment, uuid4()),
                )
            with pytest.raises(psycopg.errors.LockNotAvailable):
                other.execute(
                    "SELECT organization_witness.deployment_fence(%s,%s,1)", (deployment, uuid4())
                )
    assert f.maintenance("cutover_selection", deployment, cutover, sha) == observed
    f.admin(
        "UPDATE organization_witness.slots SET pending=true,generation=1,epoch=%s,worker_id=%s,"
        "principal=session_user WHERE environment_id=%s AND slot=0",
        (uuid4(), uuid4(), children[0]),
    )
    f.maintenance(
        "cutover_selection", deployment, cutover, sha, refusal="complete drained child inventory"
    )
    f.admin("UPDATE organization_witness.slots SET pending=false")
    assert f.maintenance("cutover_selection", deployment, cutover, sha) == observed
    args.output.write_text(
        json.dumps(
            {
                "passed": True,
                "upgrade_preserves_authority": True,
                "unfinished_cutover_upgrade_refused": True,
                "wrong_intent_step_and_runtime_refused": True,
                "complete_children": 2,
                "concurrent_registration_fence_blocked": True,
                "pending_child_refused": True,
                "new_atomic_discharge": 0,
            },
            indent=2,
        )
        + "\n"
    )


if __name__ == "__main__":
    main()
