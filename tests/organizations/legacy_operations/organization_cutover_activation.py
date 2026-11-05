"""One registered native activation transaction with stopped-worker reconciliation."""

from __future__ import annotations

import copy
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING

import organization_cutover_activation_phase as phase
import organization_cutover_epoch_checks as checks
import organization_cutover_epoch_inputs as inputs
import organization_cutover_epoch_native as native
import organization_cutover_startup as startup
import organization_cutover_startup_manifest as manifests
import organization_cutover_startup_units as units
import organization_cutover_validation as validation
from organization_recovery_store import require

if TYPE_CHECKING:
    from contextlib import AbstractContextManager
    from pathlib import Path

    from organization_recovery_redis import RedisStore


@dataclass(repr=False)
class Work(startup.Work):
    def locked(self) -> AbstractContextManager:
        return phase.locked(self)

    def prepared_observation(self, observed: dict) -> dict:
        if not observed["active"]:
            return observed

        def prepared(row: dict) -> dict:
            return dict(row, phase="prepared", revision=row["revision"] - 1)

        return dict(
            observed,
            parent=prepared(observed["parent"]),
            children=[prepared(row) for row in observed["children"]],
        )


def intent(work: Work, manifest: dict, publication: str) -> tuple[dict, str]:
    configurations = []
    for worker in manifest["workers"]:
        runtime = next(row for row in worker["sources"] if row["name"] == "runtime.json")
        environment = worker["worker"]["environment_id"]
        host = next(
            row["issuerHost"]
            for row in worker["native"]["startupSelectors"]
            if row["environmentId"] == environment
        )
        configurations.append(
            {
                "environment_id": environment,
                "runtime_file": runtime["source"],
                "runtime_sha256": runtime["sha256"],
                "issuer_host": host,
            }
        )
    value = {
        "version": 1,
        "epoch_sha256": work.intent_sha256,
        "manifest_sha256": work.manifest_sha256,
        "publication_sha256": publication,
        "root_cert_sha256": manifest["workers"][0]["native"]["rootCertSha256"],
        "configurations": configurations,
    }
    path = work.directory / "activation.json"
    require(
        work.step < phase.ACTIVATION_INTENT or path.exists(), "registered activation input missing"
    )
    return value, inputs.retain(work.directory, work.context.descriptor, path.name, value)


def native_receipt(work: Work, observed: dict, digest: str, publication: str) -> dict:
    require(observed["active"], "native activation remains uncommitted")
    return {
        "version": 1,
        "activationIntentSha256": digest,
        "epochIntentSha256": work.intent_sha256,
        "manifestSha256": work.manifest_sha256,
        "selection": {
            "parent": dict(observed["parent"], pending=0),
            "children": [dict(row, pending=0) for row in observed["children"]],
            "bindings": observed["bindings"],
            "parentCheckpoint": observed["checkpoints"][0],
            "childCheckpoints": observed["checkpoints"][1:],
            "publicationSha256": publication,
        },
        "workersStarted": False,
        "supplierQualified": False,
    }


def canonical_receipt(value: dict) -> dict:
    """Compare timestamptz instants without discarding association provenance."""
    result = copy.deepcopy(value)
    for row in result["selection"]["bindings"]:
        timestamp = row["bound_at"]
        require(
            type(timestamp) is str
            and re.fullmatch(
                r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?(?:Z|[+-][0-9]{2}:[0-9]{2})",
                timestamp,
            ),
            "exact association timestamp required",
        )
        parsed = datetime.fromisoformat(timestamp)
        row["bound_at"] = parsed.astimezone(UTC).isoformat(timespec="microseconds")
    return result


def activate(  # noqa: PLR0913,PLR0917 — complete offline input binding
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
        checked = checks.inspect(work, complete=True)
        manifest, _ = manifests.prepare(work, settings)
        # Runtime fragments may be lost at reboot; recreate only bound original bytes.
        for worker in manifest["workers"]:
            units.publish(worker)
        units.manager("daemon-reload")
        manifests.verify(work, settings, manifest)
        states = [units.stopped(worker) for worker in manifest["workers"]]
        published, publication_hash = inputs.read(directory, "startup-published.json")
        with work.locked() as (row, _):
            require(
                publication_hash == row["receipts"][10]
                and published
                == {
                    "version": 1,
                    "manifestSha256": work.manifest_sha256,
                    "workers": states,
                    "activationAuthorized": False,
                    "supplierQualified": False,
                },
                "published startup receipt differs",
            )
        _, digest = intent(work, manifest, publication_hash)
        row = phase.advance(work, phase.ACTIVATION_INTENT, digest)
        work.step = row["step"]
        if row["step"] == phase.ACTIVATION_INTENT:
            index = validation.recover_attempts(work.context, directory)
            actual = native.invoke(
                work.context, directory, work.intent_sha256, index, work.locked, activate=True
            )
            checked = checks.inspect(work, complete=True)
            require(
                canonical_receipt(actual)
                == canonical_receipt(
                    native_receipt(work, checked["observed"], digest, publication_hash)
                ),
                "native activation result differs from current stores",
            )
        manifests.verify(work, settings, manifest)
        require(
            [units.stopped(worker) for worker in manifest["workers"]] == states,
            "worker custody changed during activation",
        )
        receipt = {
            "version": 1,
            "planSha256": work.context.plan.sha256,
            "native": canonical_receipt(
                native_receipt(work, checked["observed"], digest, publication_hash)
            ),
            "workersStarted": False,
            "supplierQualified": False,
        }
        path = directory / "epoch-activated.json"
        require(
            work.step != phase.ACTIVATED or path.exists(), "completed activation receipt missing"
        )
        completion = inputs.retain(directory, work.context.descriptor, path.name, receipt)
        phase.advance(work, phase.ACTIVATED, completion)
        return {
            "version": 1,
            "step": phase.ACTIVATED,
            "activationIntentSha256": digest,
            "workersStarted": False,
            "supplierQualified": False,
        }
