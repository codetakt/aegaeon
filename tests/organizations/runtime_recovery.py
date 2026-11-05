"""Actual SQL recovery transitions; external worker/token premises are conditional."""

from __future__ import annotations

import json
from uuid import uuid4

import pytest
from psycopg import sql
from psycopg.types.json import Jsonb


def scenario(stores, maintenance, output, operator):  # noqa: PLR0915 — ordered SQL acceptance
    import organization_recovery_runtime as runtime  # noqa: PLC0415
    from organization_recovery import checked_catalog  # noqa: PLC0415
    from organization_recovery_store import clear  # noqa: PLC0415

    control, primary = stores
    deployment = maintenance["deployment_id"]
    epoch, primary_id, token_id, child, child_op, child_epoch = map(
        str, [uuid4() for _ in range(6)]
    )
    digest = "a" * 64
    passed = []

    def call(name, *args):
        query = sql.SQL("SELECT organization_witness.{}({})").format(
            sql.Identifier(name), sql.SQL(",").join(sql.Placeholder() for _ in args)
        )
        return control.connection.execute(query, args).fetchone()[0]

    checked_catalog(control)
    with (
        control.connection.transaction(),
        pytest.raises(Exception, match="maintenance ownership"),
    ):
        runtime.state(control, deployment)
    with control.connection.transaction():
        clear(control, maintenance, "b" * 64)
    control.connection.execute(
        "CREATE ROLE old_runtime LOGIN IN ROLE aegaeon_organization_witness_runtime"
    )
    control.old_logins.append("old_runtime")
    for name in ("old_runtime", "old_worker"):
        control.connection.execute(
            sql.SQL("SET SESSION AUTHORIZATION {}").format(sql.Identifier(name))
        )
        try:
            with pytest.raises(Exception, match="permission denied"):
                control.connection.execute("SELECT * FROM organization_witness.runtime_recoveries")
        finally:
            control.connection.execute("RESET SESSION AUTHORIZATION")
    passed.append("runtime/maintenance principals cannot read recovery receipts")
    operation = control.one(
        "SELECT operation_id::text FROM organization_witness.deployments WHERE deployment_id=%s",
        (deployment,),
    )
    call("initialize", child, deployment, child_op)
    call(
        "prepare",
        child,
        deployment,
        child_op,
        1,
        child_epoch,
        primary_id,
        token_id,
        digest,
        digest,
        digest,
    )
    pg = primary.one(
        "SELECT jsonb_build_object('cluster_id',system_identifier,'database_oid',"
        "(SELECT oid::bigint FROM pg_database WHERE datname=current_database()),"
        "'database_name',current_database(),'started_us',"
        "(extract(epoch from pg_postmaster_start_time())*1000000)::bigint,"
        "'timeline',(pg_control_checkpoint()).timeline_id,"
        "'wal_position',(pg_current_wal_lsn()-'0/0'::pg_lsn)::numeric) FROM pg_control_system()"
    )
    token = {"run_id": "a" * 40, "database": 0}
    call("store_progress_pin", child, deployment, child_op, 2, Jsonb(pg), Jsonb(token))
    call("fence", child, deployment, str(uuid4()), 2)
    call(
        "deployment_prepare",
        deployment,
        operation,
        1,
        epoch,
        primary_id,
        token_id,
        digest,
        digest,
        digest,
    )
    call("deployment_store_progress_pin", deployment, operation, 2, Jsonb(pg), Jsonb(token))
    with pytest.raises(Exception, match="deployment durable seal required"):
        call("deployment_activate", deployment, operation, 2, digest)
    # This SQL-only fixture manufactures observations; it does not qualify the
    # physical post-work seal protocol. Keep its v16 activation premise explicit.
    call("deployment_store_seal_pin", deployment, operation, 2, str(uuid4()))
    call("deployment_activate", deployment, operation, 2, digest)
    passed.append("v16 activation refuses an absent seal before fixture preparation")
    control.connection.execute("SET SESSION AUTHORIZATION old_runtime")
    try:
        slot = call("deployment_acquire", deployment, epoch, primary_id, token_id, str(uuid4()))
        slot_args = tuple(
            slot[k] for k in ("deployment_id", "slot", "generation", "epoch", "worker_id")
        )
        call("deployment_store_progress_begin", *slot_args)
    finally:
        control.connection.execute("RESET SESSION AUTHORIZATION")
    # Manufacture an interrupted child admission under this fixture administrator.
    # This tests recovery's SQL boundary, not native admission or external cleanup.
    control.connection.execute(
        "UPDATE organization_witness.slots SET pending=true,generation=1,epoch=%s,"
        "worker_id=%s,principal='old_runtime' WHERE environment_id=%s AND slot=0",
        (child_epoch, str(uuid4()), child),
    )
    with control.connection.transaction(), pytest.raises(Exception, match="deployment fence"):
        runtime.state(control, deployment)
    fence_op = str(uuid4())
    call("deployment_fence", deployment, fence_op, 3)
    with control.connection.transaction():
        before = runtime.state(control, deployment)
    expected = {
        "deployment_id": deployment,
        "recovery_id": str(uuid4()),
        "fence_operation_id": fence_op,
        "fence_revision": 4,
        "state_sha256": runtime.digest(before),
    }
    runtime.selection(before, expected, control, primary, token)
    with pytest.raises(Exception, match="selected store"):
        runtime.selection(before, expected, control, primary, token | {"database": 1})
    for key, value in (
        ("fence_revision", 3),
        ("state_sha256", "0" * 64),
        ("fence_operation_id", str(uuid4())),
    ):
        with pytest.raises(Exception, match="state differs"):
            runtime.selection(before, expected | {key: value}, control, primary, token)
    passed.append("fence, selected store and exact snapshot identity required")
    control.connection.execute(
        "UPDATE organization_witness.deployment_slots SET generation=generation+1 "
        "WHERE deployment_id=%s AND pending",
        (deployment,),
    )
    with control.connection.transaction(), pytest.raises(Exception, match="state changed"):
        runtime.release(control, expected, digest, before, "b" * 64)
    control.connection.execute(
        "UPDATE organization_witness.deployment_slots SET generation=generation-1 "
        "WHERE deployment_id=%s AND pending",
        (deployment,),
    )
    for store in stores:
        store.exclude()
        store.drain()

    class RollbackFixtureError(Exception):
        pass

    with pytest.raises(RollbackFixtureError), control.connection.transaction():  # noqa: PT012 — fail before commit
        runtime.release(control, expected, digest, before, "b" * 64)
        raise RollbackFixtureError
    with control.connection.transaction():
        assert runtime.state(control, deployment) == before
        assert runtime.completed(control, expected, digest) is None
        receipt = runtime.release(control, expected, digest, before, "b" * 64)
    assert receipt["prior_state"] == before
    with control.connection.transaction():
        assert runtime.completed(control, expected, digest) == receipt
        with pytest.raises(Exception, match="replay conflicts"):
            runtime.completed(control, expected, "c" * 64)
    with control.connection.transaction():
        after = runtime.state(control, deployment)
    assert after["parent_slots"] == []
    assert after["child_slots"] == []
    for key in (
        "parent",
        "children",
        "parent_progress",
        "child_progress",
        "parent_checkpoint",
        "child_checkpoints",
    ):
        assert after[key] == before[key]
    assert after["parent_progress"][0]["finished_wal"] is None
    passed.append("generation race/rollback retain pending; replay preserves unfinished progress")
    (output / "runtime-result.json").write_text(
        json.dumps(
            {
                "passed": passed,
                "operator": str(operator),
                "actual_sql": True,
                "external_service_and_token_premises": "conditional; not exercised here",
                "activation": False,
                "new_atomic_discharge": 0,
            },
            indent=2,
        )
        + "\n"
    )
    return passed
