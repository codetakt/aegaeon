"""Resume the exact offline native epoch intent through journal step nine."""

from __future__ import annotations

import os
from contextlib import contextmanager
from dataclasses import dataclass
from typing import TYPE_CHECKING

import organization_cutover_epoch_checks as checks
import organization_cutover_epoch_inputs as inputs
import organization_cutover_epoch_native as native_call
import organization_cutover_journal as journal
import organization_cutover_phase as phase
import organization_cutover_plan as plans
import organization_cutover_validation as validation
import organization_recovery as recovery
import organization_recovery_runtime as runtime
from organization_recovery_store import Store, require

if TYPE_CHECKING:
    from pathlib import Path

    from organization_recovery_redis import RedisStore


@dataclass(repr=False)
class Work:
    config: dict
    context: validation.Context
    stores: list
    directory: Path
    original: dict
    native: dict
    epoch: dict
    intent_sha256: str
    native_sha256: str
    step: int

    @contextmanager
    def locked(self):
        context = self.context
        control = self.stores[0]
        principal = context.principals["control_maintenance"]["new"]
        if self.step == validation.NATIVE_VALIDATED:
            with journal.locked(control, context.expected):
                key = journal.identity(
                    context.expected, self.epoch["cutover_operation_id"], context.plan.sha256
                )
                row = journal.selected(control, key)
                require(
                    row is not None
                    and row["step"] == self.step
                    and row["receipts"][-1] == self.native_sha256,
                    "epoch validation predecessor changed",
                )
                yield row, phase.observations(control, self.original, self.epoch, principal)
        else:
            with phase.locked(
                control,
                context.expected,
                self.original,
                self.epoch,
                context.plan.sha256,
                self.intent_sha256,
                principal,
            ) as result:
                require(
                    result[0]["receipts"][6] == self.native_sha256, "epoch native receipt changed"
                )
                yield result


def predecessor(
    control: Store,
    expected: dict,
    operation: str,
    *,
    steps: tuple[int, ...] = (
        validation.NATIVE_VALIDATED,
        phase.EPOCH_INTENT,
        phase.EPOCH_PREPARED,
    ),
) -> dict:
    # No authority transition is made here. Allow retained validation logins so
    # recovery can disable them before the strict drained-state observer.
    recovery.checked_catalog(control)
    with control.connection.transaction():
        control.rows(
            "SELECT deployment_id FROM organization_witness.deployments "
            "WHERE deployment_id=%s FOR UPDATE",
            (expected["deployment_id"],),
        )
        rows = control.rows(
            "SELECT to_jsonb(c) FROM organization_witness.cutover_operations c "
            "WHERE deployment_id=%s AND operation_id=%s FOR UPDATE",
            (expected["deployment_id"], operation),
        )
        require(len(rows) == 1, "native validation must complete before epoch preparation")
        row = rows[0][0]
        key = journal.identity(expected, operation, row["plan_sha256"])
        require(
            all(row[name] == value for name, value in key.items())
            and row["principal"] == control.one("SELECT session_user::text")
            and row["step"] in steps
            and len(row["receipts"]) == row["step"]
            and not row["completed"]
            and not row["aborted"],
            "epoch journal predecessor differs",
        )
        for digest in row["receipts"]:
            journal.digest(digest)
        return row


def prepare(  # noqa: PLR0913,PLR0917,PLR0915 — ordered durable offline saga
    config: dict,
    configuration: dict,
    stores: list,
    old: RedisStore,
    new: RedisStore,
    directory: Path,
) -> dict:
    control, _, destination = stores
    inspection = config["inspection"]
    expected, operation = inspection["fence"], inspection["operation_id"]
    validation.settings(configuration)
    for index, store in enumerate([control, destination]):
        Store(
            store.connection, store.identity, [*store.old_logins, *config["names"][index].values()]
        ).check()
    row = predecessor(control, expected, operation)
    plan = plans.load(config, directory, row["plan_sha256"])
    descriptor = plans.directory(directory)
    context = validation.Context(
        configuration,
        validation.selected(plan, configuration),
        expected,
        [control, destination],
        plan,
        new,
        old,
        descriptor,
    )
    try:
        index = validation.recover_attempts(context, directory)
        original_path = directory / "original-state.json"
        if not original_path.exists():
            require(
                row["step"] == validation.NATIVE_VALIDATED,
                "registered original epoch snapshot missing",
            )
            with journal.locked(control, expected):
                original = runtime.state(control, expected["deployment_id"])
                recovery.retain(descriptor, original_path.name, original)
        original, original_hash = inputs.read(directory, original_path.name, runtime.MAX_STATE + 1)
        require(
            runtime.digest(original) == expected["state_sha256"],
            "retained original epoch state differs",
        )
        native, native_hash = inputs.read(directory, "native-validation.json")
        comparison, comparison_hash = inputs.read(directory, "comparison.json")
        require(
            native_hash == row["receipts"][6] and comparison_hash == row["receipts"][0],
            "epoch evidence receipt differs",
        )
        hashes = {
            "originalStateSha256": original_hash,
            "nativeValidationSha256": native_hash,
            "contentComparisonSha256": comparison_hash,
        }
        bound = inputs.binding(context, original, native, hashes)
        registered = row["step"] >= phase.EPOCH_INTENT
        require(
            not registered or (directory / "epoch-binding.json").exists(),
            "registered epoch binding missing",
        )
        binding_hash = inputs.retain(directory, descriptor, "epoch-binding.json", bound)
        epoch, intent_hash = inputs.intent(
            directory,
            descriptor,
            operation,
            original,
            native,
            comparison,
            binding_hash,
            registered=registered,
        )
        work = Work(
            config,
            context,
            stores,
            directory,
            original,
            native,
            epoch,
            intent_hash,
            native_hash,
            row["step"],
        )
        inspected = checks.inspect(work)
        if row["step"] == validation.NATIVE_VALIDATED:
            row = phase.register(control, expected, epoch, plan.sha256, intent_hash, native_hash)
            work.step = row["step"]
        if row["step"] == phase.EPOCH_INTENT:
            result = native_call.invoke(context, directory, intent_hash, index, work.locked)
            inspected = checks.inspect(work, complete=True)
            require(
                result == checks.native_receipt(work, inspected["observed"]),
                "native epoch response differs from actual prepared state",
            )
        require(
            inputs.binding(context, original, native, hashes) == bound,
            "epoch inputs changed during execution",
        )
        require(inspected["observed"]["prepared"], "epoch preparation remains incomplete")
        receipt = {
            "version": 1,
            "planSha256": plan.sha256,
            "intentSha256": intent_hash,
            "bindingSha256": binding_hash,
            "native": checks.native_receipt(work, inspected["observed"]),
            "activationAuthorized": False,
        }
        require(
            row["step"] != phase.EPOCH_PREPARED or (directory / "epoch-prepared.json").exists(),
            "completed epoch receipt missing",
        )
        digest = inputs.retain(directory, descriptor, "epoch-prepared.json", receipt)
        phase.complete(
            control,
            expected,
            original,
            epoch,
            plan.sha256,
            intent_hash,
            context.principals["control_maintenance"]["new"],
            digest,
        )
        return {
            "version": 1,
            "step": phase.EPOCH_PREPARED,
            "planSha256": plan.sha256,
            "intentSha256": intent_hash,
            "activationAuthorized": False,
        }
    finally:
        os.close(descriptor)
