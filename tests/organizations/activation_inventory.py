"""Actual activation catalog/locks with manufactured physical checkpoint inputs."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from uuid import uuid4

import psycopg
import pytest
from deployment_control import Fixture
from psycopg.types.json import Jsonb


def main():  # noqa: PLR0915 — ordered actual catalog/role/transaction fixture
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ("schema", "catalog", "output"):
        parser.add_argument("--" + key, type=Path, required=True)
    args = parser.parse_args()
    f = Fixture("activation_migration")
    deployment, operation, cutover = [uuid4() for _ in range(3)]
    original = f.maintenance("deployment_initialize", deployment, operation)
    children = [(uuid4(), uuid4(), uuid4()), (uuid4(), uuid4(), uuid4())]
    for child, child_operation, _ in children:
        f.maintenance("initialize", child, deployment, child_operation)
    digests = ("a" * 64, "b" * 64, "c" * 64)
    f.admin(
        "INSERT INTO organization_witness.cutover_operations "
        "(deployment_id,operation_id,fence_operation_id,fence_revision,fence_sha256,plan_sha256) "
        "VALUES(%s,%s,%s,1,%s,%s)",
        (deployment, cutover, operation, digests[0], digests[0]),
    )
    with pytest.raises(psycopg.errors.RaiseException, match="without pending cutover"):
        f.admin(args.schema.read_text())
    assert (
        f.admin(
            "SELECT to_regprocedure('organization_witness."
            "cutover_activation_selection(uuid,uuid,text,text,text)')"
        ).fetchone()[0]
        is None
    )
    registration = f.admin(
        "DELETE FROM organization_witness.cutover_operations RETURNING to_jsonb(cutover_operations)"
    ).fetchone()[0]
    f.admin(args.schema.read_text())
    assert f.maintenance("deployment_state", deployment) == original
    assert f.admin((args.schema.parent / "catalog-v5.sql").read_text()).fetchone()[0] == json.loads(
        args.catalog.read_text()
    )
    f.admin(
        "INSERT INTO organization_witness.cutover_operations "
        "SELECT * FROM jsonb_populate_record(NULL::organization_witness.cutover_operations,%s)",
        (Jsonb(registration),),
    )
    epoch, primary, token = [uuid4() for _ in range(3)]
    pg = {
        "cluster_id": 123,
        "database_oid": 456,
        "database_name": "primary",
        "started_us": 789,
        "timeline": 1,
        "wal_position": 100,
    }
    redis = {"run_id": "a" * 40, "database": 0}
    f.maintenance(
        "deployment_prepare", deployment, operation, 1, epoch, primary, token, *[digests[0]] * 3
    )
    f.maintenance(
        "deployment_store_progress_pin", deployment, operation, 2, Jsonb(pg), Jsonb(redis)
    )
    for child, child_operation, child_epoch in children:
        f.maintenance(
            "prepare",
            child,
            deployment,
            child_operation,
            1,
            child_epoch,
            primary,
            token,
            *[digests[0]] * 3,
        )
        f.maintenance(
            "store_progress_pin", child, deployment, child_operation, 2, Jsonb(pg), Jsonb(redis)
        )
    request = (deployment, cutover, *digests)
    receipts = ["d" * 64] * 12
    receipts[7], receipts[9], receipts[11] = digests
    for step in [0, 8, 10, 11, 13, 16]:
        entries = (receipts + ["d" * 64] * 4)[:step]
        f.admin(
            "UPDATE organization_witness.cutover_operations SET step=%s,receipts=%s",
            (step, Jsonb(entries)),
        )
        f.maintenance(
            "cutover_activation_selection", *request, refusal="registered activation intent differs"
        )
    f.admin(
        "UPDATE organization_witness.cutover_operations SET step=12,receipts=%s", (Jsonb(receipts),)
    )
    f.call("cutover_activation_selection", *request, refusal="permission denied")
    f.call(
        "cutover_activation_selection",
        *request,
        role="organization_maintenance_other",
        refusal="selected checkpoint principal required",
    )
    for index in range(3):
        changed = list(request)
        changed[index + 2] = "e" * 64
        f.maintenance(
            "cutover_activation_selection", *changed, refusal="registered activation intent differs"
        )
    before = f.maintenance("cutover_activation_selection", *request)
    assert before["parent"]["phase"] == "prepared"
    assert len(before["children"]) == 2
    assert before["bindings"] == []
    with f.connection("organization_maintenance") as connection, connection.transaction():
        connection.execute(
            "SELECT organization_witness.cutover_activation_selection(%s,%s,%s,%s,%s)", request
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
                    "SELECT organization_witness.fence(%s,%s,%s,2)",
                    (children[-1][0], deployment, uuid4()),
                )
    f.admin(
        "UPDATE organization_witness.slots SET pending=true,generation=1,epoch=%s,"
        "worker_id=%s,principal=session_user "
        "WHERE environment_id=%s AND slot=0",
        (children[0][2], uuid4(), children[0][0]),
    )
    f.maintenance(
        "cutover_activation_selection",
        *request,
        refusal="complete drained activation inventory required",
    )
    f.admin("UPDATE organization_witness.slots SET pending=false")
    with pytest.raises(psycopg.errors.RaiseException, match="activation boundary"):
        activate(f, request, operation, epoch, children, fail_last=True)
    assert f.maintenance("cutover_activation_selection", *request) == before
    # A committed partial transition is not a valid resume state.
    f.maintenance("deployment_activate", deployment, operation, 2, digests[0])
    f.maintenance(
        "cutover_activation_selection",
        *request,
        refusal="complete drained activation inventory required",
    )
    # Reset only the manufactured fixture's parent transition, not production data.
    f.admin("UPDATE organization_witness.deployments SET phase='prepared',revision=2")
    f.admin(
        "UPDATE organization_witness.deployment_operations SET "
        "activate_from=NULL,activate_principal=NULL,activated_at=NULL"
    )
    after = activate(f, request, operation, epoch, children, fail_last=False)
    assert after["parent"]["phase"] == "active"
    assert all(child["phase"] == "active" for child in after["children"])
    assert len(after["bindings"]) == 2
    assert f.maintenance("cutover_activation_selection", *request) == after
    args.output.write_text(
        json.dumps(
            {
                "passed": True,
                "complete_children": 2,
                "cases": [
                    "migration rejects unfinished cutover and preserves drained authority",
                    "catalog equals actual PostgreSQL definitions",
                    "exact step and three registered hashes required",
                    "runtime and other maintenance principal refused",
                    "parent and complete child locks exclude concurrent mutation",
                    "pending and mixed authority refused",
                    "transaction prefix rollback and complete active replay",
                ],
                "manufacturedCheckpointInputs": True,
                "nativeCompositionQualified": False,
                "supplierQualified": False,
                "new_atomic_discharge": 0,
            },
            indent=2,
        )
        + "\n"
    )


def activate(f, request, operation, epoch, children, *, fail_last):  # noqa: PLR0913 — exact transaction fixture
    deployment = request[0]
    with f.connection("organization_maintenance") as connection, connection.transaction():
        connection.execute(
            "SELECT organization_witness.cutover_activation_selection(%s,%s,%s,%s,%s)", request
        )
        connection.execute(
            "SELECT organization_witness.deployment_activate(%s,%s,2,%s)",
            (deployment, operation, request[2]),
        )
        for index, (child, child_operation, child_epoch) in enumerate(children):
            connection.execute(
                "SELECT organization_witness.deployment_bind_child(%s,%s,%s,%s)",
                (deployment, epoch, child, child_epoch),
            )
            digest = "f" * 64 if fail_last and index == len(children) - 1 else request[2]
            connection.execute(
                "SELECT organization_witness.activate(%s,%s,%s,2,%s)",
                (child, deployment, child_operation, digest),
            )
        return connection.execute(
            "SELECT organization_witness.cutover_activation_selection(%s,%s,%s,%s,%s)", request
        ).fetchone()[0]


if __name__ == "__main__":
    main()
