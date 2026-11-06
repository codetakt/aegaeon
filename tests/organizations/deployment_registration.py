"""Actual child registration, least privilege, replay and parent-lock regressions."""

from __future__ import annotations

import argparse
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from uuid import uuid4

import psycopg
from deployment_control import Fixture


def parent_lock(fixture, environment, deployment, operation):
    # A parent lifecycle transaction must exclude child registration. The actual
    # statement times out under a separately held row lock and leaves no child.
    with fixture.connection("postgres") as owner, owner.transaction():
        owner.execute(
            "SELECT 1 FROM organization_witness.deployments WHERE deployment_id=%s FOR UPDATE",
            (deployment,),
        )
        with fixture.connection("organization_maintenance") as blocked:
            blocked.execute("SET lock_timeout='150ms'")
            try:
                blocked.execute(
                    "SELECT organization_witness.initialize(%s,%s,%s)",
                    (environment, deployment, operation),
                )
            except psycopg.errors.LockNotAvailable:
                pass
            else:
                message = "registration ignored parent lock"
                raise AssertionError(message)
    assert (
        fixture.admin(
            "SELECT count(*) FROM organization_witness.authorities WHERE environment_id=%s",
            (environment,),
        ).fetchone()[0]
        == 0
    )


def scenario(fixture):
    environment, deployment, operation = [uuid4() for _ in range(3)]
    fixture.call("initialize", environment, deployment, operation, refusal="permission denied")
    fixture.maintenance(
        "initialize",
        environment,
        deployment,
        operation,
        refusal="matching deployment registration required",
    )
    assert (
        fixture.admin(
            "SELECT count(*) FROM organization_witness.authorities WHERE environment_id=%s",
            (environment,),
        ).fetchone()[0]
        == 0
    )
    fixture.maintenance("deployment_initialize", deployment, uuid4())

    parent_lock(fixture, environment, deployment, operation)

    def create(_):
        try:
            return fixture.maintenance("initialize", environment, deployment, operation)
        except psycopg.errors.UniqueViolation:
            return None

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(create, range(2)))
    accepted = [row for row in results if row is not None]
    assert len(accepted) == 1
    child = accepted[0]
    assert child["deployment_id"] == str(deployment)
    assert child["phase"] == "fenced"
    assert child["pending"] == 0
    fixture.maintenance(
        "initialize",
        environment,
        deployment,
        operation,
        refusal="duplicate key",
    )
    other = uuid4()
    fixture.maintenance(
        "deployment_initialize", other, uuid4(), refusal="conflicts with existing child ownership"
    )
    fixture.maintenance(
        "initialize",
        environment,
        other,
        uuid4(),
        refusal="matching deployment registration required",
    )
    assert fixture.call("current_state", environment, deployment) == child
    fixture.call("current_state", environment, other, refusal="query returned no rows")
    assert fixture.admin(
        "SELECT (SELECT count(*) FROM organization_witness.operations WHERE environment_id=%s),"
        "(SELECT count(*) FROM organization_witness.slots WHERE environment_id=%s)",
        (environment, environment),
    ).fetchone() == (1, 64)
    fixture.passed.extend(
        [
            "runtime cannot register; missing parent refuses atomically",
            "parent lock excludes registration; timeout leaves no child",
            "concurrent creation has one owner, operation and 64 slots",
            "replay and replacement deployment cannot rebind an existing child",
        ]
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--negative", action="store_true")
    args = parser.parse_args()
    fixture = Fixture(args.database)
    try:
        scenario(fixture)
    except AssertionError as error:
        if not args.negative or str(error) != (
            "initialize accepted: matching deployment registration required"
        ):
            raise
        result = {"negative_control": "actual v7 initializer accepts unregistered parent"}
    else:
        if args.negative:
            message = "negative control unexpectedly passed"
            raise AssertionError(message)
        result = {"passed": fixture.passed, "supplier_qualification": False}
    args.receipt.write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
