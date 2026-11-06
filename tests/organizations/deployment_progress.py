"""Exercise actual control SQL with manufactured store-observation inputs.

These are protocol boundary tests, not qualification of a physical data supplier.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from uuid import uuid4

import psycopg
from deployment_control import Fixture
from psycopg.types.json import Jsonb


def scenario(fixture):  # noqa: PLR0915 - ordered transition/replay acceptance fixture
    deployment, epoch, primary, token, operation = [uuid4() for _ in range(5)]
    digest = "a" * 64
    pg = {
        "cluster_id": 123,
        "database_oid": 456,
        "database_name": "primary",
        "started_us": 789,
        "timeline": 1,
        "wal_position": 100,
    }
    redis = {"run_id": "a" * 40, "database": 0}
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
    fixture.maintenance(
        "deployment_activate",
        deployment,
        operation,
        2,
        digest,
        refusal="store checkpoint required",
    )
    pin = (deployment, operation, 2, Jsonb(pg), Jsonb(redis))
    fixture.call("deployment_store_progress_pin", *pin, refusal="permission denied")
    checkpoint = fixture.maintenance("deployment_store_progress_pin", *pin)
    assert checkpoint == fixture.maintenance("deployment_store_progress_pin", *pin)
    fixture.maintenance(
        "deployment_store_progress_pin",
        *pin[:3],
        Jsonb(pg | {"timeline": 2}),
        pin[4],
        refusal="replay conflicts",
    )
    fixture.maintenance("deployment_activate", deployment, operation, 2, digest)
    fixture.passed.append("activation requires exact maintenance-pinned checkpoint")

    def acquire():
        return fixture.call("deployment_acquire", deployment, epoch, primary, token, uuid4())

    def begin(slot):
        return fixture.call("deployment_store_progress_begin", *fixture.parent_args(slot))

    def finish(slot, value=None, token_value=None, **kwargs):
        return fixture.call(
            "deployment_store_progress_finish",
            *fixture.parent_args(slot),
            Jsonb(pg if value is None else value),
            Jsonb(redis if token_value is None else token_value),
            **kwargs,
        )

    first = acquire()
    first_args = fixture.parent_args(first)
    fixture.call("deployment_pending_work", deployment, refusal="permission denied")
    pending = fixture.maintenance("deployment_pending_work", deployment)
    assert pending["state"]["pending"] == 1
    assert pending["admissions"] == [first]
    assert begin(first)["observation"]["minimum_wal"] == 100
    fixture.call(
        "deployment_store_progress_begin",
        *first_args,
        refusal="already begun",
    )
    fixture.call(
        "deployment_release",
        *first_args,
        refusal="store observation unfinished",
    )
    fixture.call(
        "deployment_store_progress_begin",
        *first_args,
        role="organization_runtime_other",
        refusal="admission refused",
    )
    finish(first, role="organization_runtime_other", refusal="completion refused")
    fixture.call(
        "deployment_store_progress_finish",
        uuid4(),
        *first_args[1:],
        Jsonb(pg),
        Jsonb(redis),
        refusal="query returned no rows",
    )
    fixture.passed.append("pending inspection is bounded/read-only; unfinished work cannot release")

    for field, value in [
        ("cluster_id", 124),
        ("database_oid", 457),
        ("database_name", "replacement"),
        ("started_us", 790),
        ("timeline", 2),
        ("wal_position", 99),
    ]:
        finish(first, pg | {field: value}, refusal="differs or regressed")
    for field, value in [("run_id", "b" * 40), ("database", 1)]:
        finish(first, token_value=redis | {field: value}, refusal="differs or regressed")
    for invalid in [None, [], {}, pg | {"extra": True}, pg | {"wal_position": -1}]:
        fixture.call(
            "deployment_store_progress_finish",
            *first_args,
            Jsonb(invalid),
            Jsonb(redis),
            refusal="invalid store observation",
        )
    fixture.passed.append("incarnation changes, rewind and malformed observations refuse")

    environment, child_epoch, child_operation = [uuid4() for _ in range(3)]
    fixture.maintenance("initialize", environment, deployment, child_operation)
    fixture.maintenance(
        "prepare",
        environment,
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
    fixture.maintenance("deployment_bind_child", deployment, epoch, environment, child_epoch)
    fixture.maintenance("activate", environment, deployment, child_operation, 2, digest)
    child = fixture.call(
        "deployment_acquire_child",
        *first_args,
        environment,
        child_epoch,
        primary,
        token,
        uuid4(),
    )

    second = acquire()
    assert begin(second)["observation"]["minimum_wal"] == 100
    result = finish(first, pg | {"wal_position": 200})
    assert result == finish(first, pg | {"wal_position": 200})
    finish(first, pg | {"wal_position": 201}, refusal="differs or regressed")
    fixture.call("deployment_release", *first_args, refusal="child still pending")
    fixture.call(
        "release",
        environment,
        deployment,
        child["slot"],
        child["generation"],
        child_epoch,
        child["worker_id"],
    )
    fixture.call("deployment_release", *first_args)
    fixture.call("deployment_release", *first_args)
    third = acquire()
    assert third["slot"] == first["slot"]
    assert third["generation"] == first["generation"] + 1
    assert begin(third)["observation"]["minimum_wal"] == 200
    fixture.call("deployment_release", *first_args, refusal="completion refused")
    finish(first, refusal="completion refused")
    assert finish(second, pg | {"wal_position": 150})["checkpoint"]["wal_position"] == 200
    fixture.call("deployment_release", *fixture.parent_args(second))
    finish(third, pg | {"wal_position": 199}, refusal="differs or regressed")
    fixture.passed.append(
        "concurrent completion retains maximum; replay never permits stale generation"
    )

    fence = fixture.maintenance("deployment_fence", deployment, uuid4(), 3)
    fixture.call(
        "deployment_acquire",
        deployment,
        epoch,
        primary,
        token,
        uuid4(),
        refusal="inactive deployment selection",
    )
    finish(third, pg | {"wal_position": 210})
    fixture.call("deployment_release", *fixture.parent_args(third))
    pending = fixture.maintenance("deployment_pending_work", deployment)
    assert pending["state"]["phase"] == "fenced"
    assert pending["admissions"] == []
    next_epoch = uuid4()
    fixture.maintenance("fence", environment, deployment, uuid4(), 3)
    fixture.maintenance(
        "deployment_prepare",
        deployment,
        fence["operation_id"],
        4,
        next_epoch,
        primary,
        token,
        digest,
        digest,
        digest,
    )
    fixture.maintenance(
        "deployment_activate",
        deployment,
        fence["operation_id"],
        5,
        digest,
        refusal="store checkpoint required",
    )
    fixture.maintenance(
        "deployment_store_progress_pin",
        deployment,
        fence["operation_id"],
        5,
        Jsonb(pg | {"started_us": 900, "wal_position": 50}),
        Jsonb(redis | {"run_id": "b" * 40}),
    )
    fixture.maintenance("deployment_activate", deployment, fence["operation_id"], 5, digest)
    fixture.passed.append("fence permits owned completion; fresh epoch requires a fresh checkpoint")


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
    fixture.maintenance("deployment_activate", deployment, operation, 2, digest)
    source = path.read_text()

    def refused():
        try:
            fixture.admin(source)
        except psycopg.errors.RaiseException as error:
            if "migration requires drained fences" not in str(error):
                raise
        else:
            message = "unsafe observation migration accepted"
            raise AssertionError(message)
        assert (
            fixture.admin(
                "SELECT to_regclass('organization_witness.deployment_store_checkpoints')"
            ).fetchone()[0]
            is None
        )

    refused()
    slot = fixture.call("deployment_acquire", deployment, epoch, primary, token, uuid4())
    fixture.maintenance("deployment_fence", deployment, uuid4(), 3)
    refused()
    fixture.call("deployment_release", *fixture.parent_args(slot))
    query = """SELECT jsonb_build_array(
      (SELECT jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text)
       FROM organization_witness.deployments t),
      (SELECT jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text)
       FROM organization_witness.deployment_operations t),
      (SELECT jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text)
       FROM organization_witness.deployment_epochs t),
      (SELECT jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text)
       FROM organization_witness.deployment_slots t))"""
    before = fixture.admin(query).fetchone()[0]
    fixture.admin(source)
    assert fixture.admin(query).fetchone()[0] == before
    fixture.passed.append(
        "active/pending migration refuses atomically; drained migration preserves rows"
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--negative", action="store_true")
    parser.add_argument("--migration", type=Path)
    args = parser.parse_args()
    fixture = Fixture(args.database)
    try:
        if args.migration:
            migration(fixture, args.migration)
        else:
            scenario(fixture)
    except AssertionError as error:
        if (
            not args.negative
            or str(error) != "deployment_release accepted: store observation unfinished"
        ):
            raise
        result = {"negative_control": "release before observed completion detected"}
    else:
        if args.negative:
            message = "negative control unexpectedly passed"
            raise AssertionError(message)
        result = {"passed": fixture.passed, "supplier_qualification": False}
    args.receipt.write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
