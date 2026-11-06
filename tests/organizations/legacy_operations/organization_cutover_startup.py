"""Resume exact protected worker publication while all authority stays prepared."""

from __future__ import annotations

import os
from contextlib import contextmanager
from dataclasses import dataclass
from typing import TYPE_CHECKING

import organization_cutover_epoch_checks as checks
import organization_cutover_epoch_inputs as epoch_inputs
import organization_cutover_epochs as epochs
import organization_cutover_plan as plans
import organization_cutover_startup_manifest as manifests
import organization_cutover_startup_phase as phase
import organization_cutover_startup_units as units
import organization_cutover_validation as validation
import organization_recovery_runtime as runtime
from organization_recovery_store import require

if TYPE_CHECKING:
    from contextlib import AbstractContextManager
    from pathlib import Path

    from organization_recovery_redis import RedisStore
    from organization_recovery_store import Store


@dataclass(repr=False)
class Work(epochs.Work):
    manifest_sha256: str | None = None

    @staticmethod
    def predecessor(
        control: Store, expected: dict, operation: str, *, steps: tuple[int, ...]
    ) -> dict:
        return epochs.predecessor(control, expected, operation, steps=steps)

    @staticmethod
    def recover_attempts(context: validation.Context, directory: Path) -> int:
        return validation.recover_attempts(context, directory)

    def locked(self) -> AbstractContextManager:
        return phase.locked(self)

    def prepared_observation(self, observed: dict) -> dict:
        return observed


@contextmanager
def selected(  # noqa: PLR0913,PLR0917 — complete offline input binding
    config: dict,
    native: dict,
    stores: list,
    old: RedisStore,
    new: RedisStore,
    directory: Path,
    *,
    work_type: type[Work] = Work,
    steps: tuple[int, ...] = phase.STEPS,
):
    expected = config["inspection"]["fence"]
    row = work_type.predecessor(
        stores[0], expected, config["inspection"]["operation_id"], steps=steps
    )
    plan = plans.load(config, directory, row["plan_sha256"])
    descriptor = plans.directory(directory)
    context = validation.Context(
        native,
        validation.selected(plan, native),
        expected,
        [stores[0], stores[2]],
        plan,
        new,
        old,
        descriptor,
    )
    try:
        work_type.recover_attempts(context, directory)
        original, original_hash = epoch_inputs.read(
            directory, "original-state.json", runtime.MAX_STATE + 1
        )
        validated, native_hash = epoch_inputs.read(directory, "native-validation.json")
        comparison, comparison_hash = epoch_inputs.read(directory, "comparison.json")
        bound, binding_hash = epoch_inputs.read(directory, "epoch-binding.json")
        hashes = {
            "originalStateSha256": original_hash,
            "nativeValidationSha256": native_hash,
            "contentComparisonSha256": comparison_hash,
        }
        require(
            bound == epoch_inputs.binding(context, original, validated, hashes),
            "startup epoch binding differs",
        )
        require(
            native_hash == row["receipts"][6] and comparison_hash == row["receipts"][0],
            "startup evidence differs",
        )
        epoch, digest = epoch_inputs.intent(
            directory,
            descriptor,
            config["inspection"]["operation_id"],
            original,
            validated,
            comparison,
            binding_hash,
            registered=True,
        )
        work = work_type(
            config,
            context,
            stores,
            directory,
            original,
            validated,
            epoch,
            digest,
            native_hash,
            row["step"],
        )
        if row["step"] >= phase.STARTUP_INTENT:
            _, work.manifest_sha256 = epoch_inputs.read(directory, "startup-manifest.json")
        receipt, receipt_hash = epoch_inputs.read(directory, "epoch-prepared.json")
        with work.locked() as (locked, observed):
            require(
                receipt_hash == locked["receipts"][8]
                and receipt
                == {
                    "version": 1,
                    "planSha256": plan.sha256,
                    "intentSha256": digest,
                    "bindingSha256": binding_hash,
                    "native": checks.native_receipt(work, work.prepared_observation(observed)),
                    "activationAuthorized": False,
                },
                "prepared completion receipt differs",
            )
        yield work
    finally:
        os.close(descriptor)


def prepare(  # noqa: PLR0913,PLR0917 — fixed complete offline inputs
    config: dict,
    native: dict,
    stores: list,
    old: RedisStore,
    new: RedisStore,
    directory: Path,
    settings: dict,
) -> dict:
    with selected(config, native, stores, old, new, directory) as work:
        checks.inspect(work, complete=True)
        manifest, digest = manifests.prepare(work, settings)
        work.manifest_sha256 = digest
        row = phase.advance(work, phase.STARTUP_INTENT, digest)
        work.step = row["step"]
        for worker in manifest["workers"]:
            units.publish(worker)
        units.manager("daemon-reload")
        manifests.verify(work, settings, manifest)
        states = [units.stopped(worker) for worker in manifest["workers"]]
        checks.inspect(work, complete=True)
        receipt = {
            "version": 1,
            "manifestSha256": digest,
            "workers": states,
            "activationAuthorized": False,
            "supplierQualified": False,
        }
        path = directory / "startup-published.json"
        require(
            work.step != phase.STARTUP_PUBLISHED or path.exists(),
            "published completion receipt missing",
        )
        completion = epoch_inputs.retain(directory, work.context.descriptor, path.name, receipt)
        phase.advance(work, phase.STARTUP_PUBLISHED, completion)
        return {
            "version": 1,
            "step": phase.STARTUP_PUBLISHED,
            "manifestSha256": digest,
            "activationAuthorized": False,
            "supplierQualified": False,
        }
