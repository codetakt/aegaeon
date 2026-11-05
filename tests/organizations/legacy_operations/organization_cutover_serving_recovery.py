"""Stop, exclude and fence without resetting application data or pending owners."""

from __future__ import annotations

from typing import TYPE_CHECKING

import organization_cutover_epoch_inputs as inputs
import organization_cutover_serving_checks as checks
import organization_cutover_serving_credentials as credentials
import organization_cutover_serving_phase as phase
import organization_cutover_serving_units as units
import organization_cutover_startup_units as startup_units
import organization_recovery as recovery
import organization_recovery_runtime as runtime
import organization_restore_inspect as restore
from organization_recovery_store import require

if TYPE_CHECKING:
    from organization_cutover_serving import Work

MAX_ATTEMPTS = 64


def completion(digest: str) -> dict:
    return {
        "version": 1,
        "aborted": True,
        "completed": False,
        "workersStarted": False,
        "receiptSha256": digest,
        "supplierQualified": False,
    }


def replay(work: Work, manifest: dict, intent: dict) -> dict | None:
    with work.locked() as (row, _):
        require(
            row["step"] in (phase.START_INTENT, phase.STARTED) and not row["completed"],
            "only unfinished serving start can be closed",
        )
        require(
            inputs.read(work.directory, "serving-intent.json")[0] == intent,
            "closure intent differs",
        )
        if not row["aborted"]:
            return None
        receipt, digest = inputs.read(work.directory, "serving-aborted.json")
        require(
            digest == row["abort_receipt_sha256"]
            and receipt["state"] == runtime.state(work.stores[0], work.epoch["deployment_id"]),
            "completed abort state or receipt differs",
        )
        for worker in manifest["workers"]:
            startup_units.definition(worker)
            recovery.stopped(worker["worker"]["unit"])
        startup_units.no_processes({worker["account"]["uid"] for worker in manifest["workers"]})
        checks.exclusions(work, enabled=False)
        for store in work.stores:
            restore.drained(store)
        return completion(digest)


def close(work: Work, manifest: dict, intent: dict) -> dict:  # noqa: PLR0912,PLR0915 — attempt all independent exclusions before exact fenced closure
    completed = replay(work, manifest, intent)
    if completed is not None:
        return completed
    paths = sorted(work.directory.glob("serving-closure-attempt-*.json"))
    require(
        len(paths) < MAX_ATTEMPTS
        and all(
            path.name == f"serving-closure-attempt-{index:04d}.json"
            for index, path in enumerate(paths)
        ),
        "serving closure attempt budget exhausted",
    )
    index = len(paths)
    intent_digest = inputs.read(work.directory, "serving-intent.json")[1]
    inputs.retain(
        work.directory,
        work.context.descriptor,
        f"serving-closure-attempt-{index:04d}.json",
        {"version": 1, "planSha256": work.context.plan.sha256, "intentSha256": intent_digest},
    )
    failures = []
    receipt = {"version": 1, "intentSha256": intent_digest, "sql": []}
    try:
        receipt["workers"] = units.stop(manifest)
    except Exception:  # noqa: BLE001 — attempt every independent exclusion
        failures.append("worker exit unconfirmed")
    context = work.context
    for number, selected in enumerate(checks.names(work)):
        try:
            receipt["sql"].append(
                credentials.sql_disable(context.stores[number], context.plan.sql(number), selected)
            )
        except Exception:  # noqa: BLE001 — uncertainty never becomes successful closure
            failures.append(f"SQL exclusion {number} unconfirmed")
    try:
        receipt["token"] = credentials.token_disable(
            context.new, context.old.identity["run_id"], context.plan.redis()
        )
    except Exception:  # noqa: BLE001 — retain all independent outcomes
        failures.append("token exclusion unconfirmed")
    receipt["failures"] = failures
    inputs.retain(
        work.directory, context.descriptor, f"serving-closure-result-{index:04d}.json", receipt
    )
    require(not failures, "serving closure remains unconfirmed")
    checks.exclusions(work, enabled=False)
    for store in work.stores:
        restore.drained(store)
    with work.locked() as (row, _):
        require(
            row["step"] in (phase.START_INTENT, phase.STARTED) and not row["completed"],
            "completed serving operation cannot be aborted",
        )
        before = runtime.retained(work.stores[0], work.epoch["deployment_id"])
        archive, _ = inputs.read(work.directory, "epoch-activated.json")
        selection = archive["native"]["selection"]
        states = [selection["parent"], *selection["children"]]
        for number, (state, fence) in enumerate(zip(states, intent["fences"], strict=True)):
            if number == 0:
                work.stores[0].one(
                    "SELECT organization_witness.deployment_fence(%s,%s,%s)",
                    (work.epoch["deployment_id"], fence["operation_id"], state["revision"]),
                )
            else:
                work.stores[0].one(
                    "SELECT organization_witness.fence(%s,%s,%s,%s)",
                    (
                        state["environment_id"],
                        work.epoch["deployment_id"],
                        fence["operation_id"],
                        state["revision"],
                    ),
                )
        require(
            runtime.retained(work.stores[0], work.epoch["deployment_id"]) == before,
            "closure changed retained work",
        )
        after = runtime.state(work.stores[0], work.epoch["deployment_id"])
        require(not phase.observations(work, row)["active"], "complete closure fences missing")
        result = {
            "version": 1,
            "planSha256": context.plan.sha256,
            "intentSha256": intent_digest,
            "state": after,
            "workersStopped": True,
            "runtimeCredentialsDisabled": True,
            "pendingWorkPreserved": True,
            "completed": False,
            "aborted": True,
            "supplierQualified": False,
        }
        path = work.directory / "serving-aborted.json"
        require(not row["aborted"] or path.exists(), "completed abort receipt missing")
        digest = inputs.retain(work.directory, context.descriptor, path.name, result)
        if row["aborted"]:
            require(row["abort_receipt_sha256"] == digest, "abort replay differs")
        else:
            work.stores[0].one(
                "UPDATE organization_witness.cutover_operations "
                "SET aborted=true,abort_receipt_sha256=%s "
                "WHERE deployment_id=%s AND operation_id=%s RETURNING true",
                (digest, work.epoch["deployment_id"], work.epoch["cutover_operation_id"]),
            )
    return completion(digest)
