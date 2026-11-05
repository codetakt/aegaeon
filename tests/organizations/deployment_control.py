"""Real control catalog/role checks. No runtime or supplier qualification claim."""

from __future__ import annotations

import argparse
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from uuid import uuid4

import psycopg
from psycopg import sql


class Fixture:
    def __init__(self, database):
        self.database = database
        self.passed = []

    def connection(self, role="organization_runtime"):
        return psycopg.connect(dbname=self.database, user=role, autocommit=True)

    def call(self, name, *args, role="organization_runtime", refusal=None):
        query = sql.SQL("SELECT organization_witness.{}({})").format(
            sql.Identifier(name), sql.SQL(",").join(sql.Placeholder() for _ in args)
        )
        try:
            with self.connection(role) as connection:
                result = connection.execute(query, args).fetchone()[0]
        except psycopg.Error as error:
            if refusal is None or refusal not in str(error):
                raise
            return None
        if refusal is not None:
            message = f"{name} accepted: {refusal}"
            raise AssertionError(message)
        return result

    def maintenance(self, name, *args, **kwargs):
        return self.call(name, *args, role="organization_maintenance", **kwargs)

    def admin(self, query, params=None):
        with self.connection("postgres") as connection:
            return connection.execute(query, params)

    def parent_args(self, slot):
        return tuple(
            slot[key] for key in ("deployment_id", "slot", "generation", "epoch", "worker_id")
        )

    def migration(self, path):
        environment, deployment, operation, epoch, primary, token = [uuid4() for _ in range(6)]
        digest = "a" * 64
        self.maintenance("initialize", environment, deployment, operation)
        self.maintenance(
            "prepare",
            environment,
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
        self.maintenance("activate", environment, deployment, operation, 2, digest)
        migration = path.read_text()

        def refused():
            try:
                self.admin(migration)
            except psycopg.errors.RaiseException as error:
                if "requires drained child fences" not in str(error):
                    raise
            else:
                message = "unsafe migration accepted"
                raise AssertionError(message)
            with self.connection("postgres") as connection:
                assert (
                    connection.execute(
                        "SELECT to_regclass('organization_witness.deployments')"
                    ).fetchone()[0]
                    is None
                )

        refused()
        child = self.call("acquire", environment, deployment, epoch, primary, token, uuid4())
        self.maintenance("fence", environment, deployment, uuid4(), 3)
        refused()
        self.call(
            "release",
            environment,
            deployment,
            child["slot"],
            child["generation"],
            epoch,
            child["worker_id"],
        )

        def snapshot():
            with self.connection("postgres") as connection:
                return [
                    connection.execute(
                        sql.SQL(
                            "SELECT coalesce(jsonb_agg(to_jsonb(t) "
                            "ORDER BY to_jsonb(t)::text),'[]'::jsonb) "
                            "FROM organization_witness.{} t"
                        ).format(sql.Identifier(table))
                    ).fetchone()[0]
                    for table in ("authorities", "operations", "epochs", "slots")
                ]

        before = snapshot()
        self.admin(migration)
        assert snapshot() == before
        self.maintenance(
            "deployment_initialize",
            uuid4(),
            uuid4(),
            refusal="conflicts with existing child ownership",
        )
        self.maintenance("deployment_initialize", deployment, uuid4())
        self.passed.extend(
            [
                "migration refuses active children",
                "migration refuses fenced pending work",
                "drained migration preserves all existing authority/operation/epoch/slot rows",
            ]
        )

    def exhaustion(self, deployment, epoch, primary, token):
        self.admin(
            "UPDATE organization_witness.deployment_slots SET generation=9223372036854775807 "
            "WHERE deployment_id=%s",
            (deployment,),
        )
        self.call(
            "deployment_acquire",
            deployment,
            epoch,
            primary,
            token,
            uuid4(),
            refusal="query returned no rows",
        )
        self.admin(
            "INSERT INTO organization_witness.deployment_operations"
            "(deployment_id,operation_id,fence_from) "
            "SELECT %s,gen_random_uuid(),0 FROM generate_series(1,65536-(SELECT count(*) "
            "FROM organization_witness.deployment_operations WHERE deployment_id=%s))",
            (deployment, deployment),
        )
        state = self.maintenance("deployment_fence", deployment, uuid4(), 6)
        assert state["revision"] == 9223372036854775807
        assert state["pending"] == 0
        self.maintenance(
            "deployment_fence", deployment, uuid4(), state["revision"], refusal="revision refused"
        )
        self.passed.append(
            "generation exhaustion refuses; full transition history retains a terminal fence"
        )

    def scenario(self, negative):  # noqa: PLR0915 - ordered state-machine acceptance fixture
        deployment, epoch, primary, token, operation, environment = [uuid4() for _ in range(6)]
        digest = "a" * 64
        prepare = (deployment, operation, 1, epoch, primary, token, digest, digest, digest)
        self.call("deployment_initialize", deployment, operation, refusal="permission denied")
        self.maintenance("deployment_initialize", deployment, operation)
        self.maintenance("deployment_initialize", deployment, operation, refusal="duplicate key")
        self.maintenance("deployment_initialize", uuid4(), uuid4(), refusal="duplicate key")
        self.maintenance("deployment_prepare", *prepare)
        self.maintenance("deployment_prepare", *prepare)
        self.maintenance(
            "deployment_prepare", *prepare[:-1], "b" * 64, refusal="preparation boundary"
        )
        self.maintenance("deployment_activate", deployment, operation, 2, digest)
        self.maintenance("deployment_activate", deployment, operation, 2, digest)
        self.passed.append("initialization and exact transition receipt replay")

        child_operation, child_epoch = uuid4(), uuid4()
        self.maintenance("initialize", environment, deployment, child_operation)
        self.maintenance(
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
        self.maintenance("deployment_bind_child", deployment, epoch, environment, child_epoch)
        self.maintenance("activate", environment, deployment, child_operation, 2, digest)
        selection = (deployment, epoch, primary, token)
        parent = self.call("deployment_acquire", *selection, uuid4())
        parent_args = self.parent_args(parent)
        child_args = (*parent_args, environment, child_epoch, primary, token, uuid4())
        self.call(
            "acquire",
            environment,
            deployment,
            child_epoch,
            primary,
            token,
            uuid4(),
            refusal="permission denied",
        )
        child = self.call("deployment_acquire_child", *child_args)
        if negative:
            # Only the tested parent-release guard is removed in a separate DB.
            # The unchanged regression must detect premature parent completion.
            self.call("deployment_release", *parent_args, refusal="child still pending")
            message = "negative control did not detect its target defect"
            raise AssertionError(message)
        self.call("deployment_release", *parent_args, refusal="child still pending")
        self.call("deployment_acquire_child", *child_args, refusal="already pending")
        self.call(
            "deployment_acquire_child",
            *child_args,
            role="organization_runtime_other",
            refusal="parent admission refused",
        )
        self.call(
            "deployment_acquire_child",
            *parent_args,
            uuid4(),
            child_epoch,
            primary,
            token,
            uuid4(),
            refusal="parent admission refused",
        )
        self.call(
            "deployment_release",
            *parent_args,
            role="organization_runtime_other",
            refusal="completion refused",
        )
        child_release = (
            environment,
            deployment,
            child["slot"],
            child["generation"],
            child_epoch,
            child["worker_id"],
        )
        self.call("release", *child_release)
        self.call("deployment_release", *parent_args)
        self.call("deployment_release", *parent_args)
        self.call(
            "deployment_acquire_child",
            *parent_args,
            environment,
            child_epoch,
            primary,
            token,
            uuid4(),
            refusal="parent admission refused",
        )
        self.passed.append(
            "parent retained through child; direct, foreign, duplicate "
            "and completed ownership refused"
        )

        # Reuse a child slot under a different parent while the old parent waits.
        old = self.call("deployment_acquire", *selection, uuid4())
        new = self.call("deployment_acquire", *selection, uuid4())
        old_child = self.call(
            "deployment_acquire_child",
            *self.parent_args(old),
            environment,
            child_epoch,
            primary,
            token,
            uuid4(),
        )
        self.call(
            "release",
            environment,
            deployment,
            old_child["slot"],
            old_child["generation"],
            child_epoch,
            old_child["worker_id"],
        )
        new_child = self.call(
            "deployment_acquire_child",
            *self.parent_args(new),
            environment,
            child_epoch,
            primary,
            token,
            uuid4(),
        )
        self.call("deployment_release", *self.parent_args(old))
        self.call("deployment_release", *self.parent_args(new), refusal="child still pending")
        self.call(
            "release",
            environment,
            deployment,
            new_child["slot"],
            new_child["generation"],
            child_epoch,
            new_child["worker_id"],
        )
        self.call("deployment_release", *self.parent_args(new))
        self.call("deployment_release", *parent_args, refusal="completion refused")
        self.passed.append("parent and child generation reuse cannot release another owner")

        # Distinct database sessions race for the last available slot.
        owners = [self.call("deployment_acquire", *selection, uuid4()) for _ in range(63)]

        def race():
            try:
                return self.call("deployment_acquire", *selection, uuid4())
            except psycopg.errors.NoDataFound:
                return None

        with ThreadPoolExecutor(max_workers=2) as executor:
            outcomes = list(executor.map(lambda _: race(), range(2)))
        assert sum(result is not None for result in outcomes) == 1
        owners.extend(result for result in outcomes if result is not None)
        self.call("deployment_acquire", *selection, uuid4(), refusal="query returned no rows")
        fence = uuid4()
        state = self.maintenance("deployment_fence", deployment, fence, 3)
        assert state["pending"] == 64
        assert state["phase"] == "fenced"
        self.call("deployment_acquire", *selection, uuid4(), refusal="inactive deployment")
        self.call(
            "deployment_acquire_child",
            *self.parent_args(owners[0]),
            environment,
            child_epoch,
            primary,
            token,
            uuid4(),
            refusal="parent admission refused",
        )
        for owner in owners:
            self.call("deployment_release", *self.parent_args(owner))
        self.passed.append("last-slot race, finite capacity and fencing with pending work")

        next_epoch = uuid4()
        next_prepare = (deployment, fence, 4, next_epoch, primary, token, digest, digest, digest)
        self.maintenance("deployment_prepare", *next_prepare, refusal="preparation boundary")
        child_fence = uuid4()
        self.maintenance("fence", environment, deployment, child_fence, 3)
        self.maintenance(
            "deployment_prepare",
            deployment,
            fence,
            4,
            epoch,
            primary,
            token,
            digest,
            digest,
            digest,
            refusal="duplicate key",
        )
        self.maintenance("deployment_prepare", *next_prepare)
        self.maintenance("deployment_activate", deployment, fence, 5, digest)
        self.call("deployment_acquire", *selection, uuid4(), refusal="inactive deployment")
        fresh = self.call("deployment_acquire", deployment, next_epoch, primary, token, uuid4())
        self.call(
            "deployment_acquire_child",
            *self.parent_args(fresh),
            environment,
            child_epoch,
            primary,
            token,
            uuid4(),
            refusal="parent admission refused",
        )
        self.call("deployment_release", *self.parent_args(fresh))
        self.passed.append(
            "new parent epoch requires drained child fences and fresh child association"
        )

        for role in ("organization_runtime", "organization_maintenance"):
            with self.connection(role) as connection:
                try:
                    connection.execute("DELETE FROM organization_witness.deployment_slots")
                except psycopg.errors.InsufficientPrivilege:
                    pass
                else:
                    message = "service principal can delete durable pending work"
                    raise AssertionError(message)
        self.passed.append("least privilege excludes direct pending-row mutation")
        self.exhaustion(deployment, next_epoch, primary, token)


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
            fixture.migration(args.migration)
        else:
            fixture.scenario(args.negative)
    except AssertionError as error:
        if not args.negative or str(error) != "deployment_release accepted: child still pending":
            raise
        result = {"negative_control": "premature parent release detected"}
    else:
        if args.negative:
            message = "negative control unexpectedly passed"
            raise AssertionError(message)
        result = {"passed": fixture.passed}
    args.receipt.write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
