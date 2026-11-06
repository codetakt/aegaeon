"""Durable maintenance SQL transitions; completion inputs are manufactured Own-Pre.

This does not establish actual worker/connection shutdown or supplier custody.
"""

from __future__ import annotations

import argparse
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from uuid import uuid4

import psycopg
from deployment_control import Fixture
from psycopg.types.json import Jsonb


def scenario(fixture, *, negative=False):  # noqa: PLR0915 - ordered protocol acceptance
    deployment, operation, work, epoch, primary, token = [uuid4() for _ in range(6)]
    digest = "a" * 64
    fixture.maintenance("deployment_initialize", deployment, operation)
    empty = fixture.maintenance("maintenance_state", deployment)
    assert empty["generation"] == 0
    assert not empty["pending"]
    acquire = (deployment, operation, 1, work, "history-restore", digest)
    fixture.call("maintenance_acquire", *acquire, refusal="permission denied")
    fixture.call("maintenance_state", deployment, refusal="permission denied")
    for args, message in [
        ((*acquire[:2], 2, *acquire[3:]), "drained deployment fence required"),
        ((*acquire[:4], "arbitrary-shell", digest), "check constraint"),
        ((*acquire[:-1], "invalid-digest"), "check constraint"),
    ]:
        fixture.maintenance("maintenance_acquire", *args, refusal=message)
    assert fixture.maintenance("maintenance_state", deployment) == empty
    fixture.passed.append("runtime role, invalid plan and stale fence refused without state change")

    def attempt():
        try:
            return fixture.maintenance("maintenance_acquire", *acquire)
        except Exception as error:
            if "maintenance unavailable" not in str(error):
                raise
            return None

    with ThreadPoolExecutor(max_workers=2) as executor:
        candidates = list(executor.map(lambda _: attempt(), range(2)))
    assert sum(value is not None for value in candidates) == 1
    held = next(value for value in candidates if value is not None)
    assert held["generation"] == 1
    assert held["pending"]
    assert fixture.maintenance("maintenance_state", deployment) == held
    fixture.passed.append("concurrent acquisition has one winner; connection exit retains pending")
    prepare = (deployment, operation, 1, epoch, primary, token, digest, digest, digest)
    if negative:
        # The identical expected-refusal test must detect the removed guard.
        detected = None
        try:
            fixture.maintenance("deployment_prepare", *prepare, refusal="maintenance still pending")
        except AssertionError as error:
            detected = str(error)
        assert detected is not None
        assert "deployment_prepare accepted" in detected
        fixture.passed.append("removed pending-maintenance guard detected")
        return

    fixture.maintenance("deployment_prepare", *prepare, refusal="maintenance still pending")
    fixture.maintenance(
        "deployment_activate", deployment, operation, 2, digest, refusal="maintenance still pending"
    )
    fixture.maintenance("maintenance_acquire", *acquire, refusal="maintenance unavailable")
    fixture.passed.append(
        "pending maintenance excludes preparation, activation and duplicate acquisition"
    )
    completion = (deployment, held["generation"], work, digest, "b" * 64)
    fixture.call("maintenance_complete", *completion, refusal="permission denied")
    fixture.call(
        "maintenance_complete",
        *completion,
        role="organization_maintenance_other",
        refusal="completion differs",
    )
    for bad in [
        (deployment, 2, *completion[2:]),
        (deployment, 1, uuid4(), *completion[3:]),
        (*completion[:3], "c" * 64, completion[4]),
    ]:
        fixture.maintenance("maintenance_complete", *bad, refusal="completion differs")
    assert fixture.maintenance("maintenance_state", deployment) == held
    done = fixture.maintenance("maintenance_complete", *completion)
    assert not done["pending"]
    assert fixture.maintenance("maintenance_complete", *completion) == done
    fixture.maintenance(
        "maintenance_complete", *completion[:-1], "c" * 64, refusal="completion conflicts"
    )
    fixture.passed.append("principal/generation/plan binding; exact completion replay only")
    second = fixture.maintenance("maintenance_acquire", *acquire[:3], uuid4(), *acquire[4:])
    assert second["generation"] == 2
    fixture.maintenance("maintenance_complete", *completion, refusal="completion differs")
    next_fence = uuid4()
    fenced = fixture.maintenance("deployment_fence", deployment, next_fence, 1)
    fixture.maintenance(
        "deployment_prepare",
        deployment,
        next_fence,
        fenced["revision"],
        *prepare[3:],
        refusal="maintenance still pending",
    )
    fixture.maintenance("maintenance_complete", deployment, 2, second["work_id"], digest, "d" * 64)
    fixture.passed.append(
        "old capability cannot close new generation; re-fencing does not clear pending"
    )
    child, child_operation, child_epoch = [uuid4() for _ in range(3)]
    fixture.maintenance("initialize", child, deployment, child_operation)
    fixture.maintenance(
        "prepare",
        child,
        deployment,
        child_operation,
        1,
        child_epoch,
        primary,
        token,
        digest,
        digest,
        digest,
    )
    request = (deployment, next_fence, fenced["revision"], uuid4(), "history-inspect", digest)
    fixture.maintenance("maintenance_acquire", *request, refusal="drained child fences required")
    fixture.maintenance("fence", child, deployment, uuid4(), 2)
    fixture.passed.append("non-fenced child excludes deployment maintenance")
    fixture.maintenance(
        "deployment_prepare", deployment, next_fence, fenced["revision"], *prepare[3:]
    )
    fixture.maintenance(
        "maintenance_acquire", *request, refusal="drained deployment fence required"
    )
    prepared_revision = fenced["revision"] + 1
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
        "deployment_store_progress_pin",
        deployment,
        next_fence,
        prepared_revision,
        Jsonb(pg),
        Jsonb(redis),
    )
    active = fixture.maintenance(
        "deployment_activate", deployment, next_fence, prepared_revision, digest
    )
    fixture.maintenance(
        "maintenance_acquire", *request, refusal="drained deployment fence required"
    )
    parent = fixture.call("deployment_acquire", deployment, epoch, primary, token, uuid4())
    last_operation = uuid4()
    final_fence = fixture.maintenance(
        "deployment_fence", deployment, last_operation, active["revision"]
    )
    request = (
        deployment,
        last_operation,
        final_fence["revision"],
        uuid4(),
        "history-inspect",
        digest,
    )
    fixture.maintenance(
        "maintenance_acquire", *request, refusal="drained deployment fence required"
    )
    fixture.call("deployment_release", *fixture.parent_args(parent))
    final = fixture.maintenance("maintenance_acquire", *request)
    fixture.maintenance(
        "maintenance_complete", deployment, final["generation"], request[3], digest, "e" * 64
    )
    fixture.passed.append(
        "prepared/active and live runtime work refuse maintenance; drained fence admits it"
    )


def migration(fixture, path):
    deployment, operation, epoch, primary, token = [uuid4() for _ in range(5)]
    digest = "a" * 64
    fixture.maintenance("deployment_initialize", deployment, operation)
    fixture.maintenance(
        "deployment_prepare",
        deployment,
        operation,
        1,
        epoch,
        primary,
        token,
        digest,
        digest,
        digest,
    )
    pg = {
        "cluster_id": 123,
        "database_oid": 456,
        "database_name": "primary",
        "started_us": 789,
        "timeline": 1,
        "wal_position": 100,
    }
    fixture.maintenance(
        "deployment_store_progress_pin",
        deployment,
        operation,
        2,
        Jsonb(pg),
        Jsonb({"run_id": "a" * 40, "database": 0}),
    )
    fixture.maintenance("deployment_activate", deployment, operation, 2, digest)
    source = path.read_text()

    def refusal():
        before = fixture.call("deployment_state", deployment)
        error_text = None
        try:
            fixture.admin(source)
        except psycopg.errors.RaiseException as error:
            error_text = str(error)
        assert error_text is not None
        assert "maintenance migration requires drained fences" in error_text
        assert fixture.call("deployment_state", deployment) == before
        assert (
            fixture.admin(
                "SELECT to_regclass('organization_witness.maintenance_slots')"
            ).fetchone()[0]
            is None
        )

    refusal()
    slot = fixture.call("deployment_acquire", deployment, epoch, primary, token, uuid4())
    fixture.maintenance("deployment_fence", deployment, uuid4(), 3)
    refusal()
    fixture.call("deployment_release", *fixture.parent_args(slot))
    before = fixture.call("deployment_state", deployment)
    fixture.admin(source)
    assert fixture.call("deployment_state", deployment) == before
    assert not fixture.maintenance("maintenance_state", deployment)["pending"]
    fixture.passed.append(
        "v8 migration refuses active or pending work without mutation; "
        "drained upgrade preserves parent state"
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", required=True)
    parser.add_argument("--negative", action="store_true")
    parser.add_argument("--migration", type=Path)
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()
    fixture = Fixture(args.database)
    if args.migration:
        migration(fixture, args.migration)
    else:
        scenario(fixture, negative=args.negative)
    args.receipt.write_text(
        json.dumps(
            {
                "conditions": fixture.passed,
                "negative": args.negative,
                "actual_shutdown_and_supplier_qualified": False,
            },
            indent=2,
        )
        + "\n"
    )


if __name__ == "__main__":
    main()
