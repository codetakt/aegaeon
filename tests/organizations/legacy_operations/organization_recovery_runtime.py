"""Offline exact-generation runtime reconciliation; never activates authority."""

from __future__ import annotations

import hashlib
import json
import re
from typing import TYPE_CHECKING, Any
from uuid import UUID

from organization_recovery_store import require
from psycopg.types.json import Jsonb

if TYPE_CHECKING:
    from organization_recovery_store import Store

VERSION = 2
SQL_STORES = 2
MAX_PORT = 65535
MAX_STATE = 32 * 1024 * 1024
MAX_RECOVERIES = 1024


def settings(config: dict) -> None:
    require(
        set(config) == {"version", "runtime", "stores", "services", "token"},
        "unknown runtime recovery fields",
    )
    expected = config["runtime"]
    require(
        set(expected)
        == {"deployment_id", "recovery_id", "fence_operation_id", "fence_revision", "state_sha256"},
        "exact runtime recovery identity required",
    )
    for name in ("deployment_id", "recovery_id", "fence_operation_id"):
        require(
            str(UUID(expected[name])) == expected[name] and UUID(expected[name]).int != 0,
            "canonical nonnil runtime identity required",
        )
    require(
        type(expected["fence_revision"]) is int and 0 < expected["fence_revision"] < 2**63,
        "invalid runtime fence revision",
    )
    require(re.fullmatch(r"[0-9a-f]{64}", expected["state_sha256"]), "invalid runtime state digest")
    require(len(config["stores"]) == SQL_STORES, "dedicated control and primary required")
    token = config["token"]
    require(
        set(token) == {"identity", "connection", "old_logins"}, "explicit token supplier required"
    )
    connection = token["connection"]
    require(
        set(connection) == {"host", "port", "user", "password_file", "ca_file"},
        "explicit token TLS connection required",
    )
    require(
        re.fullmatch(r"[A-Za-z0-9.-]+", connection["host"])
        and type(connection["port"]) is int
        and 1 <= connection["port"] <= MAX_PORT,
        "explicit token destination required",
    )
    require(
        type(token["old_logins"]) is list
        and all(re.fullmatch(r"[a-z][a-z0-9_]{0,62}", name) for name in token["old_logins"]),
        "invalid token login inventory",
    )


def digest(value: dict) -> str:
    data = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    require(len(data) <= MAX_STATE, "runtime recovery state budget exceeded")
    return hashlib.sha256(data).hexdigest()


def state(control: Store, deployment: str) -> dict[str, Any]:
    """Call inside one transaction; parent-before-child locks exclude transitions."""
    parents = control.rows(
        "SELECT to_jsonb(d) FROM organization_witness.deployments d "
        "WHERE deployment_id=%s FOR UPDATE",
        (deployment,),
    )
    require(
        len(parents) == 1 and parents[0][0]["phase"] == "fenced",
        "runtime deployment fence required",
    )
    parent = parents[0][0]
    children = control.rows(
        "SELECT to_jsonb(a) FROM organization_witness.authorities a "
        "WHERE deployment_id=%s ORDER BY environment_id FOR UPDATE",
        (deployment,),
    )
    require(all(row[0]["phase"] == "fenced" for row in children), "runtime child fences required")
    require(
        not control.one(
            "SELECT EXISTS(SELECT FROM organization_witness.maintenance_slots WHERE "
            "deployment_id=%s AND pending)",
            (deployment,),
        ),
        "maintenance ownership cannot be cleared as runtime",
    )
    result = {
        "parent": parent,
        "children": [row[0] for row in children],
        **retained(control, deployment),
    }
    digest(result)
    return result


def retained(control: Store, deployment: str) -> dict[str, Any]:
    """Read pending work under the caller's parent/child locks; never clear it."""
    result = {}
    queries = {
        "bindings": (
            "SELECT to_jsonb(b) FROM organization_witness.deployment_children b "
            "WHERE deployment_id=%s ORDER BY environment_id,child_epoch"
        ),
        "parent_slots": (
            "SELECT to_jsonb(s) FROM organization_witness.deployment_slots s WHERE "
            "deployment_id=%s AND pending ORDER BY slot FOR UPDATE"
        ),
        "child_slots": (
            "SELECT to_jsonb(s) FROM organization_witness.slots s JOIN "
            "organization_witness.authorities a USING(environment_id) WHERE "
            "a.deployment_id=%s AND s.pending ORDER BY environment_id,slot FOR "
            "UPDATE OF s"
        ),
        "parent_progress": (
            "SELECT to_jsonb(o) FROM "
            "organization_witness.deployment_store_observations o WHERE "
            "deployment_id=%s ORDER BY slot"
        ),
        "child_progress": (
            "SELECT to_jsonb(o) FROM organization_witness.store_observations o JOIN "
            "organization_witness.authorities a USING(environment_id) WHERE "
            "a.deployment_id=%s ORDER BY environment_id,slot"
        ),
        "parent_checkpoint": (
            "SELECT to_jsonb(c) FROM "
            "organization_witness.deployment_store_checkpoints c JOIN "
            "organization_witness.deployments d USING(deployment_id,epoch) WHERE "
            "deployment_id=%s"
        ),
        "child_checkpoints": (
            "SELECT to_jsonb(c) FROM organization_witness.store_checkpoints c JOIN "
            "organization_witness.authorities a USING(environment_id,epoch) WHERE "
            "a.deployment_id=%s ORDER BY environment_id"
        ),
    }
    for name, query in queries.items():
        result[name] = [row[0] for row in control.rows(query, (deployment,))]
    digest(result)
    return result


def selection(
    snapshot: dict, expected: dict, control: Store, primary: Store, token_identity: dict
) -> None:
    parent = snapshot["parent"]
    require(
        parent["deployment_id"] == expected["deployment_id"]
        and parent["operation_id"] == expected["fence_operation_id"]
        and parent["revision"] == expected["fence_revision"]
        and digest(snapshot) == expected["state_sha256"],
        "runtime recovery state differs",
    )
    slots = snapshot["parent_slots"] + snapshot["child_slots"]
    require(
        slots and all(row["principal"] in control.old_logins for row in slots),
        "pending runtime principal not excluded",
    )
    children = {row["environment_id"]: row for row in snapshot["children"]}
    require(
        all(row["epoch"] == parent["epoch"] for row in snapshot["parent_slots"])
        and all(
            row["epoch"] == children[row["environment_id"]]["epoch"]
            for row in snapshot["child_slots"]
        ),
        "pending runtime epoch differs from selected authority",
    )
    require(len(snapshot["parent_checkpoint"]) == 1, "current deployment checkpoint required")
    checkpoints = snapshot["parent_checkpoint"] + snapshot["child_checkpoints"]
    require(
        len(snapshot["child_checkpoints"])
        == sum(row["epoch"] is not None for row in snapshot["children"]),
        "current child checkpoints incomplete",
    )
    for row in checkpoints:
        physical = row["primary_incarnation"]
        # PostgreSQL's system identifier is exposed as signed bigint by the native
        # observation adapter; compare its exact unsigned bit pattern here.
        require(
            row["primary_id"] == parent["primary_id"]
            and row["token_store_id"] == parent["token_store_id"]
            and str(int(physical["cluster_id"]) % (2**64)) == primary.identity["cluster"]
            and physical["database_oid"] == primary.identity["database_oid"]
            and physical["database_name"] == primary.identity["database"]
            and row["token_incarnation"] == token_identity,
            "runtime recovery selected store differs",
        )


def completed(control: Store, expected: dict, plan: str) -> dict | None:
    rows = control.rows(
        "SELECT to_jsonb(r) FROM organization_witness.runtime_recoveries r WHERE "
        "deployment_id=%s AND recovery_id=%s",
        (expected["deployment_id"], expected["recovery_id"]),
    )
    if not rows:
        return None
    result = rows[0][0]
    require(
        all(
            result[key] == expected[key]
            for key in (
                "deployment_id",
                "recovery_id",
                "fence_operation_id",
                "fence_revision",
                "state_sha256",
            )
        )
        and result["plan_sha256"] == plan,
        "runtime recovery replay conflicts",
    )
    return result


def release(control: Store, expected: dict, plan: str, snapshot: dict, receipt: str) -> dict:
    """Own-Pre: all selected workers/credentials/store work were actually excluded.

    Only the offline coordinator may call this conditional SQL transition.
    It preserves unfinished observations and does not assert successful work.
    """
    require(
        digest(snapshot) == expected["state_sha256"]
        and snapshot["parent"]["deployment_id"] == expected["deployment_id"]
        and snapshot["parent"]["operation_id"] == expected["fence_operation_id"]
        and snapshot["parent"]["revision"] == expected["fence_revision"],
        "runtime recovery identity differs",
    )
    require(completed(control, expected, plan) is None, "runtime recovery already recorded")
    require(
        state(control, expected["deployment_id"]) == snapshot,
        "runtime state changed during exclusion",
    )
    require(
        control.one(
            "SELECT count(*) FROM organization_witness.runtime_recoveries WHERE deployment_id=%s",
            (expected["deployment_id"],),
        )
        < MAX_RECOVERIES,
        "runtime recovery receipt capacity exhausted",
    )
    for row in snapshot["child_slots"]:
        require(
            control.one(
                "UPDATE organization_witness.slots SET pending=false WHERE "
                "environment_id=%s AND slot=%s AND generation=%s AND worker_id=%s AND "
                "epoch=%s AND pending RETURNING true",
                (
                    row["environment_id"],
                    row["slot"],
                    row["generation"],
                    row["worker_id"],
                    row["epoch"],
                ),
            ),
            "runtime child generation differs",
        )
    for row in snapshot["parent_slots"]:
        require(
            control.one(
                "UPDATE organization_witness.deployment_slots SET pending=false WHERE "
                "deployment_id=%s AND slot=%s AND generation=%s AND worker_id=%s AND "
                "epoch=%s AND pending RETURNING true",
                (
                    row["deployment_id"],
                    row["slot"],
                    row["generation"],
                    row["worker_id"],
                    row["epoch"],
                ),
            ),
            "runtime parent generation differs",
        )
    control.connection.execute(
        "INSERT INTO organization_witness.runtime_recoveries("
        "deployment_id,recovery_id,fence_operation_id,fence_revision,"
        "plan_sha256,state_sha256,completion_sha256,prior_state) "
        "VALUES(%s,%s,%s,%s,%s,%s,%s,%s)",
        (
            expected["deployment_id"],
            expected["recovery_id"],
            expected["fence_operation_id"],
            expected["fence_revision"],
            plan,
            expected["state_sha256"],
            receipt,
            Jsonb(snapshot),
        ),
    )
    return completed(control, expected, plan)
