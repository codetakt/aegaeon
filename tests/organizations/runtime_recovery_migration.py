"""Actual v9-to-v10 upgrade with retained, explicitly conditional pending work."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from uuid import uuid4

import psycopg
import pytest
from deployment_control import Fixture
from psycopg.types.json import Jsonb


def main():  # noqa: PLR0915 — ordered offline upgrade
    parser = argparse.ArgumentParser()
    parser.add_argument("--schema", type=Path, required=True)
    parser.add_argument("--catalog", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cutover-schema", type=Path, required=True)
    parser.add_argument("--cutover-catalog", type=Path, required=True)
    args = parser.parse_args()
    fixture = Fixture("runtime_migration")
    deployment, operation, epoch, primary, token, work = [uuid4() for _ in range(6)]
    sha = "a" * 64
    fixture.maintenance("deployment_initialize", deployment, operation)
    held = fixture.maintenance(
        "maintenance_acquire", deployment, operation, 1, work, "history-inspect", sha
    )
    migration = args.schema.read_text()
    with pytest.raises(psycopg.errors.RaiseException, match="fenced, non-maintenance"):
        fixture.admin(migration)
    assert fixture.maintenance("maintenance_state", deployment) == held
    fixture.maintenance("maintenance_complete", deployment, 1, work, sha, "b" * 64)
    fixture.maintenance(
        "deployment_prepare", deployment, operation, 1, epoch, primary, token, sha, sha, sha
    )
    pg = {
        "cluster_id": 123,
        "database_oid": 456,
        "database_name": "primary",
        "started_us": 789,
        "timeline": 1,
        "wal_position": 100,
    }
    redis = {"run_id": "a" * 40, "database": 0}
    fixture.maintenance(
        "deployment_store_progress_pin", deployment, operation, 2, Jsonb(pg), Jsonb(redis)
    )
    fixture.maintenance("deployment_activate", deployment, operation, 2, sha)
    slot = fixture.call("deployment_acquire", deployment, epoch, primary, token, uuid4())
    fixture.call("deployment_store_progress_begin", *fixture.parent_args(slot))
    with pytest.raises(psycopg.errors.RaiseException, match="fenced, non-maintenance"):
        fixture.admin(migration)
    fixture.maintenance("deployment_fence", deployment, uuid4(), 3)
    before = fixture.maintenance("deployment_pending_work", deployment)
    fixture.admin(migration)
    assert fixture.maintenance("deployment_pending_work", deployment) == before
    assert before["state"]["pending"] == 1
    assert (
        fixture.admin(
            "SELECT finished_wal FROM organization_witness.deployment_store_observations"
        ).fetchone()[0]
        is None
    )
    actual = fixture.admin((args.schema.parent / "catalog-v5.sql").read_text()).fetchone()[0]
    assert actual == json.loads(args.catalog.read_text())
    for role in ("organization_runtime", "organization_maintenance"):
        with (
            fixture.connection(role) as connection,
            pytest.raises(psycopg.errors.InsufficientPrivilege),
        ):
            connection.execute("SELECT * FROM organization_witness.runtime_recoveries")
    cutover = args.cutover_schema.read_text()
    with pytest.raises(psycopg.errors.RaiseException, match="drained fenced"):
        fixture.admin(cutover)
    assert fixture.maintenance("deployment_pending_work", deployment) == before
    # This fixture fabricated the only pending owner and has no worker. Clearing
    # it here is not an operator recovery procedure or a production ACK.
    fixture.admin("UPDATE organization_witness.deployment_slots SET pending=false")
    retained = fixture.maintenance("deployment_pending_work", deployment)
    fixture.admin(cutover)
    assert fixture.maintenance("deployment_pending_work", deployment) == retained
    assert fixture.admin((args.schema.parent / "catalog-v5.sql").read_text()).fetchone()[
        0
    ] == json.loads(args.cutover_catalog.read_text())
    for role in ("organization_runtime", "organization_maintenance"):
        with (
            fixture.connection(role) as connection,
            pytest.raises(psycopg.errors.InsufficientPrivilege),
        ):
            connection.execute("SELECT * FROM organization_witness.cutover_operations")
    args.output.write_text(
        json.dumps(
            {
                "blocked_pending_maintenance": True,
                "blocked_active_authority": True,
                "fenced_runtime_pending_preserved": True,
                "unfinished_progress_preserved": True,
                "current_catalog_matches": True,
                "service_roles_excluded": True,
                "v11_refuses_pending_runtime": True,
                "v11_drained_upgrade_retains_authority": True,
                "v11_catalog_and_service_role_exclusion": True,
                "external_worker_stop": "conditional premise; not observed here",
                "new_atomic_discharge": 0,
            },
            indent=2,
        )
        + "\n"
    )


if __name__ == "__main__":
    main()
