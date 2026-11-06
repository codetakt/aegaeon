"""Retained exact startup bytes and actual native parser receipts."""

from __future__ import annotations

import hashlib
import os
from typing import TYPE_CHECKING

import organization_cutover_epoch_inputs as epochs
import organization_cutover_epoch_native as native
import organization_cutover_plan as plans
import organization_cutover_startup_inputs as inputs
import organization_cutover_startup_phase as phase
import organization_cutover_startup_units as units
import organization_recovery as recovery
import organization_recovery_runtime as runtime
from organization_recovery_store import require

if TYPE_CHECKING:
    from pathlib import Path

    from organization_cutover_startup import Work


def artifact(path: Path) -> dict:
    require(
        path.is_file() and str(path).startswith("/nix/store/"),
        "fixed packaged startup artifact required",
    )
    return {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


def document(work: Work, name: str, value: dict, *, existing: bool) -> dict:
    path = work.directory / name
    require(not existing or path.exists(), "registered startup input missing; never regenerate")
    digest = epochs.retain(work.directory, work.context.descriptor, name, value)
    return {"name": name.rsplit("-", 1)[-1], "source": str(path), "sha256": digest}


def derive(work: Work, settings: dict, *, existing: bool) -> dict:
    inputs.settings(settings, work.epoch)
    old = [recovery.stopped(name) for name in work.config["inspection"]["services"]]
    accounts = units.accounts(settings, old, work.config)
    certs = inputs.certificates(settings, work.context.configuration)
    workers = []
    for index, (worker, account) in enumerate(zip(settings["workers"], accounts, strict=True)):
        require(
            worker["unit"] not in work.config["inspection"]["services"], "retired unit name reused"
        )
        if not existing:
            require(
                not (units.UNIT_DIRECTORY / worker["unit"]).exists(),
                "fresh unit required",
            )
            units.absent(worker["unit"])
        built = inputs.documents(work, worker, certs)
        sources = [
            document(work, f"startup-{index:02d}-runtime.json", built["runtime"], existing=existing)
        ]
        actual = native.bounded(
            [
                str(epochs.NATIVE),
                "--intent",
                str(work.directory / "epochs.json"),
                "--root-cert",
                work.context.configuration["root_cert_file"],
                "--check-startup",
                sources[0]["source"],
            ],
            {"PATH": os.defpath, "LANG": "C.UTF-8"},
        )
        require(
            actual
            == {
                "version": 1,
                "kind": "startup-configuration",
                "intentSha256": work.intent_sha256,
                "configurationSha256": sources[0]["sha256"],
                "rootCertSha256": certs[0]["sha256"],
                "startupSelectors": actual.get("startupSelectors"),
                "activationAuthorized": False,
                "supplierQualified": False,
            },
            "actual native startup parser receipt differs",
        )
        inputs.bind_selectors(work, built, worker, actual["startupSelectors"])
        sources.append(
            document(work, f"startup-{index:02d}-launch.json", built["launch"], existing=existing)
        )
        sources += [{k: row[k] for k in ("name", "source", "sha256")} for row in certs]
        workers.append(
            {
                "worker": worker,
                "account": account,
                "sources": sources,
                "native": actual,
                "unitText": units.render(worker, account, sources),
            }
        )
    return {
        "version": 1,
        "settingsSha256": runtime.digest(settings),
        "planSha256": work.context.plan.sha256,
        "epochIntentSha256": work.intent_sha256,
        "artifacts": [artifact(p) for p in (inputs.LAUNCHER, inputs.SERVER, inputs.SERVER_BINARY)],
        "workers": workers,
        "activationAuthorized": False,
        "supplierQualified": False,
    }


def prepare(work: Work, settings: dict) -> tuple[dict, str]:
    path = work.directory / "startup-manifest.json"
    registered = work.step >= phase.STARTUP_INTENT
    require(not registered or path.exists(), "registered startup manifest missing")
    exists = path.exists()
    manifest = derive(work, settings, existing=exists)
    require(len(plans.canonical(manifest)) <= plans.MAX_PLAN, "startup manifest budget exceeded")
    digest = epochs.retain(work.directory, work.context.descriptor, path.name, manifest)
    require(not registered or digest == work.manifest_sha256, "registered startup manifest differs")
    return manifest, digest


def verify(work: Work, settings: dict, manifest: dict) -> None:
    require(derive(work, settings, existing=True) == manifest, "startup publication inputs changed")
