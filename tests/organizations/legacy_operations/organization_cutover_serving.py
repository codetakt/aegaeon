"""Start one retained selection; an unfinished start can only proceed to closure."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

import organization_cutover_epoch_checks as epoch_checks
import organization_cutover_epoch_inputs as inputs
import organization_cutover_phase as epochs
import organization_cutover_serving_checks as checks
import organization_cutover_serving_credentials as credentials
import organization_cutover_serving_phase as phase
import organization_cutover_serving_recovery as closure
import organization_cutover_serving_units as serving_units
import organization_cutover_startup as startup
import organization_cutover_startup_inputs as configuration
import organization_cutover_startup_manifest as manifests
import organization_cutover_startup_units as units
import organization_cutover_validation as validation
import organization_recovery as recovery
import organization_recovery_runtime as runtime
from organization_recovery_store import require

if TYPE_CHECKING:
    from contextlib import AbstractContextManager
    from pathlib import Path

    from organization_recovery_redis import RedisStore
    from organization_recovery_store import Store


@dataclass(repr=False)
class Work(startup.Work):
    @staticmethod
    def predecessor(
        control: Store, expected: dict, operation: str, *, steps: tuple[int, ...]
    ) -> dict:
        return phase.predecessor(control, expected, operation, steps=steps)

    @staticmethod
    def recover_attempts(context: validation.Context, directory: Path) -> int:
        # Validation-only cleanup requires an empty token store. After serving
        # intent it must never be invoked on accepted application writes.
        attempts = sorted(directory.glob("validation-attempt-*.json"))
        require(len(attempts) <= validation.MAX_ATTEMPTS, "validation attempt bound exceeded")
        for index, path in enumerate(attempts):
            require(
                path.name == f"validation-attempt-{index:04d}.json", "validation sequence changed"
            )
            attempt, _ = inputs.read(directory, path.name)
            require(attempt["planSha256"] == context.plan.sha256, "validation plan changed")
            inputs.read(directory, f"validation-cleanup-{index:04d}.json")
        return len(attempts)

    def locked(self) -> AbstractContextManager:
        return phase.locked(self)

    def prepared_observation(self, observed: dict) -> dict:
        # locked() has checked the actual active or exact recovered selection and
        # monotone current highwater. This reconstructs only the archived receipt.
        previous = [self.original["parent"], *self.original["children"]]
        transitions = [self.epoch["parent"], *[row["transition"] for row in self.epoch["children"]]]
        prepared = [
            epochs.successor(old, transition)
            for old, transition in zip(previous, transitions, strict=True)
        ]
        return dict(
            observed,
            parent=prepared[0],
            children=prepared[1:],
            checkpoints=observed["initial"],
            prepared=True,
            active=False,
        )


def manifest(work: Work, settings: dict) -> dict:
    configuration.settings(settings, work.epoch)
    value, digest = inputs.read(work.directory, "startup-manifest.json")
    require(
        digest == work.manifest_sha256
        and value["version"] == 1
        and value["planSha256"] == work.context.plan.sha256
        and value["epochIntentSha256"] == work.intent_sha256
        and value["settingsSha256"] == runtime.digest(settings)
        and value["artifacts"]
        == [
            manifests.artifact(p)
            for p in (configuration.LAUNCHER, configuration.SERVER, configuration.SERVER_BINARY)
        ]
        and len(value["workers"]) == len(settings["workers"]),
        "complete serving manifest differs",
    )
    old = [recovery.stopped(name) for name in work.config["inspection"]["services"]]
    accounts = units.account_inventory(settings, old, work.config)
    changed = False
    for row, worker, account in zip(value["workers"], settings["workers"], accounts, strict=True):
        require(
            row["worker"] == worker and row["account"] == account,
            "serving account or settings differ",
        )
        for source in row["sources"]:
            require(
                hashlib.sha256(
                    recovery.private_file(source["source"], configuration.MAX_STARTUP)
                ).hexdigest()
                == source["sha256"],
                "serving credential source differs",
            )
        changed = changed or not (units.UNIT_DIRECTORY / worker["unit"]).exists()
        units.publish(row)
    if changed:
        units.manager("daemon-reload")
    for row in value["workers"]:
        units.definition(row)
    return value


def start_intent(work: Work, value: dict) -> tuple[dict, str]:
    name = "serving-intent.json"
    exists = (work.directory / name).exists()
    require(work.step < phase.START_INTENT or exists, "registered serving intent missing")
    scopes = [None, *[row["environment_id"] for row in work.epoch["children"]]]
    retained = inputs.read(work.directory, name)[0] if exists else None
    fences = (
        retained["fences"]
        if retained
        else [
            {"environment_id": environment, "operation_id": str(uuid4())} for environment in scopes
        ]
    )
    require(
        len(fences) == len(scopes) and len({row["operation_id"] for row in fences}) == len(scopes),
        "complete unique closure fences required",
    )
    for row, environment in zip(fences, scopes, strict=True):
        require(
            set(row) == {"environment_id", "operation_id"}
            and row["environment_id"] == environment
            and str(UUID(row["operation_id"])) == row["operation_id"]
            and UUID(row["operation_id"]).int != 0,
            "exact closure fence required",
        )
    document = {
        "version": 1,
        "planSha256": work.context.plan.sha256,
        "epochIntentSha256": work.intent_sha256,
        "manifestSha256": work.manifest_sha256,
        "settingsSha256": value["settingsSha256"],
        "artifacts": value["artifacts"],
        "fences": fences,
        "principals": {
            "control": work.context.principals["control_runtime"]["new"],
            "primary": work.context.principals["primary_runtime"]["new"],
            "token": work.context.plan.value["token"]["name"],
        },
        "activationSha256": inputs.read(work.directory, "epoch-activated.json")[1],
    }
    require(retained is None or retained == document, "serving intent binding differs")
    return document, inputs.retain(work.directory, work.context.descriptor, name, document)


def complete_replay(work: Work, value: dict) -> dict:
    with work.locked() as (row, _):
        require(row["completed"] and not row["aborted"], "serving completion missing")
        started, digest = inputs.read(work.directory, "serving-started.json")
        require(digest == row["receipts"][14], "registered start receipt differs")
        completed, digest = inputs.read(work.directory, "serving-completed.json")
        require(digest == row["receipts"][15], "registered completion receipt differs")
    require(serving_units.ready(value) == started["workers"], "completed serving custody differs")
    checks.current(work, enabled=True)
    return completed


def serve(  # noqa: PLR0913,PLR0917 — exact complete cutover context
    config: dict,
    native_config: dict,
    stores: list,
    old: RedisStore,
    new: RedisStore,
    directory: Path,
    settings: dict,
) -> dict:
    with startup.selected(
        config, native_config, stores, old, new, directory, work_type=Work, steps=phase.STEPS
    ) as work:
        value = manifest(work, settings)
        intent, digest = start_intent(work, value)
        if work.step == phase.COMPLETE:
            return complete_replay(work, value)
        if work.step >= phase.START_INTENT:
            return closure.close(work, value, intent)
        epoch_checks.inspect(work, complete=True)
        for worker in value["workers"]:
            units.stopped(worker)
        units.no_processes({worker["account"]["uid"] for worker in value["workers"]})
        checks.reserve_closure(work, intent)
        phase.advance(work, phase.START_INTENT, digest)
        work.step = phase.START_INTENT
        try:
            return first_start(work, value, digest)
        except (Exception, KeyboardInterrupt):
            closure.close(work, value, intent)
            raise


def first_start(work: Work, value: dict, digest: str) -> dict:
    context = work.context
    for index, selected in enumerate(checks.names(work)):
        credentials.sql_enable(context.stores[index], context.plan.sql(index), selected)
    credentials.token_enable(context.new, context.old.identity["run_id"], context.plan.redis())
    checks.current(work, enabled=True)
    workers = serving_units.start(value)
    observed = checks.current(work, enabled=True)
    # Revalidate retained bytes without another publication or process start.
    for row in value["workers"]:
        units.definition(row)
        for source in row["sources"]:
            require(
                hashlib.sha256(
                    recovery.private_file(source["source"], configuration.MAX_STARTUP)
                ).hexdigest()
                == source["sha256"],
                "serving credential changed during start",
            )
    started = {
        "version": 1,
        "intentSha256": digest,
        "workers": workers,
        "observed": observed,
        "workersStarted": True,
        "supplierQualified": False,
    }
    started_digest = inputs.retain(
        work.directory, context.descriptor, "serving-started.json", started
    )
    phase.advance(work, phase.STARTED, started_digest)
    work.step = phase.STARTED
    result = {
        "version": 1,
        "step": phase.COMPLETE,
        "planSha256": context.plan.sha256,
        "intentSha256": digest,
        "manifestSha256": work.manifest_sha256,
        "startedSha256": started_digest,
        "completed": True,
        "aborted": False,
        "workersStarted": True,
        "supplierQualified": False,
    }
    final = inputs.retain(work.directory, context.descriptor, "serving-completed.json", result)
    phase.advance(work, phase.COMPLETE, final)
    work.step = phase.COMPLETE
    return result
