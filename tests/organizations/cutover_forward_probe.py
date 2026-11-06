"""Aborted accepted work through pending reconciliation to a second full cutover."""

from __future__ import annotations

import hashlib
import json
import os
import sys
from contextlib import ExitStack
from uuid import uuid4

from cutover_forward_store import negative_then_current
from cutover_forward_workers import accepted_work, workers
from cutover_serving_probe import command as serving_command, run


def read(path):
    import organization_recovery as recovery  # noqa: PLC0415

    return json.loads(recovery.private_file(path))


def retain(directory, name, value):
    import organization_cutover_plan as plans  # noqa: PLC0415
    import organization_recovery as recovery  # noqa: PLC0415

    descriptor = plans.directory(directory)
    try:
        recovery.retain(descriptor, name, value)
    finally:
        os.close(descriptor)
    return directory / name


def operations(args, module, *arguments, code=0):
    return run(
        sys.executable,
        "-E",
        "-s",
        str(args.package / "share/aegaeon/scripts/operations" / (module + ".py")),
        *map(str, arguments),
        code=code,
    )


def current_config(args):
    config = read(args.config)
    plan = read(args.directory / "plan.json")
    receipt = read(args.directory / "serving-aborted.json")
    manifest = read(args.directory / "startup-manifest.json")
    stores = [config["inspection"]["stores"][i] for i in (0, 2)]
    for store, replacements in zip(stores, plan["sql"], strict=True):
        store["old_logins"] = sorted(item["new"] for item in replacements["replacements"])
    token = config["preparation"]["destination_token"]
    token["old_logins"] = ["default", plan["token"]["name"]]
    return stores, token, receipt["state"], [row["worker"]["unit"] for row in manifest["workers"]]


def reconcile(args, stores, token, before, services):
    import organization_recovery as recovery  # noqa: PLC0415
    import organization_recovery_runtime as runtime  # noqa: PLC0415

    directory = args.directory.parent
    expected = {
        "deployment_id": before["parent"]["deployment_id"],
        "recovery_id": str(uuid4()),
        "fence_operation_id": before["parent"]["operation_id"],
        "fence_revision": before["parent"]["revision"],
        "state_sha256": runtime.digest(before),
    }
    config = {
        "version": 2,
        "runtime": expected,
        "stores": stores,
        "services": services,
        "token": token,
    }
    path = retain(directory, "forward-recovery.json", config)
    output = directory / "forward-recovery"
    operations(args, "organization_recovery", "--config", path, "--output", output)
    assert (
        operations(
            args, "organization_recovery", "--config", path, "--output", output, "--inspect"
        ).strip()
        == "completed"
    )
    recorded = read(output / "released.json")
    assert recorded["prior_state"] == before
    assert recorded["state_sha256"] == expected["state_sha256"]
    stale = config | {"runtime": expected | {"recovery_id": str(uuid4())}}
    stale_path = retain(directory, "forward-stale-recovery.json", stale)
    operations(
        args,
        "organization_recovery",
        "--config",
        stale_path,
        "--output",
        directory / "forward-stale-result",
        code=1,
    )
    assert not (directory / "forward-stale-result/reconciliation.json").exists()
    with ExitStack() as stack:
        control = recovery.connect(stack, stores[0])
        with control.connection.transaction():
            snapshot = runtime.state(control, expected["deployment_id"])
        assert not snapshot["parent_slots"]
        assert not snapshot["child_slots"]
        assert snapshot["parent_progress"] == before["parent_progress"]
        assert snapshot["child_progress"] == before["child_progress"]
        assert runtime.digest(snapshot) != expected["state_sha256"]
    # Replaying the old abort after reconciliation cannot silently undo progress.
    run(*serving_command(args), code=1)
    return snapshot, recorded


def configure(args, stores, token, snapshot, services, fixture, accepted):  # noqa: PLR0913,PLR0917 — exact current cutover inputs
    import organization_recovery_runtime as runtime  # noqa: PLC0415

    inspection = {
        "version": 1,
        "operation_id": str(uuid4()),
        "stores": stores,
        "services": services,
        "fence": {
            "deployment_id": snapshot["parent"]["deployment_id"],
            "operation_id": snapshot["parent"]["operation_id"],
            "revision": snapshot["parent"]["revision"],
            "state_sha256": runtime.digest(snapshot),
        },
    }
    comparison = negative_then_current(args.directory.parent, fixture, inspection, accepted)
    retain(args.directory.parent, "forward-comparison.json", comparison)
    names = [
        {name: "next_" + name for name in store["old_logins"]} for store in (stores[0], stores[2])
    ]
    config = {
        "inspection": inspection,
        "names": names,
        "redis": read(args.config)["redis"] | {"name": "next_worker"},
        "preparation": {
            "version": 1,
            "retired_token": token,
            "destination_token": fixture["token"],
        },
    }
    native = read(args.native)
    native["roles"] = {
        key: read(args.config)["names"][0 if key.startswith("control") else 1][value]
        for key, value in native["roles"].items()
    }
    native["primary"]["port"] = fixture["connection"]["port"]
    native["token"]["port"] = fixture["token"]["connection"]["port"]
    return config, native


def completed_history(stores, deployment, original, recovered):
    import organization_recovery as recovery  # noqa: PLC0415

    with ExitStack() as stack:
        control = recovery.connect(stack, stores[0])
        prior = control.one(
            "SELECT to_jsonb(c) FROM organization_witness.cutover_operations c "
            "WHERE deployment_id=%s AND operation_id=%s",
            (deployment, original["operation_id"]),
        )
        assert prior == original
        row = control.one(
            "SELECT to_jsonb(r) FROM organization_witness.runtime_recoveries r "
            "WHERE deployment_id=%s AND recovery_id=%s",
            (deployment, recovered["recovery_id"]),
        )
        assert row == recovered


def forward(args, closure):  # noqa: PLR0915 — ordered full forward lifecycle
    import organization_recovery as recovery  # noqa: PLC0415

    original_files = {
        str(path.relative_to(args.directory)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in args.directory.rglob("*")
        if path.is_file()
    }
    fixture = read(args.directory.parent / "forward-fixture.json")
    accepted = read(args.directory / "serving-accepted.json")
    stores, token, before, services = current_config(args)
    deployment = before["parent"]["deployment_id"]
    with ExitStack() as stack:
        control = recovery.connect(stack, stores[0])
        original = control.one(
            "SELECT to_jsonb(c) FROM organization_witness.cutover_operations c "
            "WHERE deployment_id=%s AND operation_id=%s",
            (deployment, read(args.config)["inspection"]["operation_id"]),
        )
    snapshot, recovered = reconcile(args, stores, token, before, services)
    config, native = configure(args, stores, token, snapshot, services, fixture, accepted)
    directory = args.directory.parent / "forward-plan"
    config_path = retain(args.directory.parent, "forward-config.json", config)
    native_path = retain(args.directory.parent, "forward-native.json", native)
    prepared = json.loads(
        operations(
            args, "organization_cutover_prepare", "--config", config_path, "--directory", directory
        )
    )
    assert prepared["step"] == 5
    command = [
        str(args.package / "bin/aegaeon-organization-cutover-validate"),
        "--config",
        str(config_path),
        "--validation-config",
        str(native_path),
        "--directory",
        str(directory),
    ]
    assert json.loads(run(*command))["step"] == 7
    assert json.loads(run(*command, "--prepare-epochs"))["step"] == 9
    with workers(directory) as selected:
        settings = str(directory / "startup-fixture.json")
        assert json.loads(run(*command, "--prepare-startup", settings))["step"] == 11
        assert json.loads(run(*command, "--activate-epochs", settings))["step"] == 13
        result = json.loads(run(*command, "--start-workers", settings))
        assert result["step"] == 16
        assert result["completed"]
        assert result["workersStarted"]
        work = accepted_work(selected, read(args.directory.parent / "bootstrap.json"), accepted)
        assert json.loads(run(*command, "--start-workers", settings)) == result
        completed_history(stores, deployment, original, recovered)
    assert original_files == {
        str(path.relative_to(args.directory)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in args.directory.rglob("*")
        if path.is_file()
    }
    return {
        "passed": True,
        "mode": "forward",
        "environmentCount": 2,
        "workersStarted": True,
        "closure": closure,
        "pendingReconciledWithHistory": True,
        "staleRecoveryRejected": True,
        "preWriteBackupRejected": True,
        "currentBackupRestored": True,
        "authenticatedHttpWrite": True,
        "priorAcceptedOrganizationPreserved": True,
        "oldSessionRejected": True,
        "explicitReconcileGrantRequired": True,
        "priorAbortAndFilesPreserved": True,
        "expectedPending": [],
        "minimumOwnedGenerations": [
            a + b
            for a, b in zip(
                closure["minimumOwnedGenerations"], work["minimumOwnedGenerations"], strict=True
            )
        ],
        "completedReplayWithoutStart": True,
        "supplierQualified": False,
    }
