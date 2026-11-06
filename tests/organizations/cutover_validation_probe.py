"""Root-only fixture probes for actual history mismatch and abandoned login leases."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import sys
from contextlib import ExitStack
from pathlib import Path

import pytest


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--native", type=Path, required=True)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--abandon-lease", action="store_true")
    args = parser.parse_args()
    sys.path.insert(0, str(args.package / "share/aegaeon/scripts/operations"))
    import organization_cutover_history as history  # noqa: PLC0415
    import organization_cutover_journal as journal  # noqa: PLC0415
    import organization_recovery as recovery  # noqa: PLC0415

    config = json.loads(recovery.private_file(args.config))
    with ExitStack() as stack:
        control = recovery.connect(stack, config["inspection"]["stores"][0])
        primary = recovery.connect(stack, config["inspection"]["stores"][2])
        receipt = json.loads(recovery.private_file(args.directory / "native-validation.json"))
        if args.abandon_lease:
            abandon(args, config, control, primary, receipt)
        with journal.locked(control, config["inspection"]["fence"]):
            native = receipt["results"][0]["native"]["history"]["history"]
            assert history.compare(control, primary, native)["subjects"] == 2
            mutation = tamper(args.package, args.directory, control, primary, native)
    print(
        json.dumps(
            {"historyMismatchRejected": True, "guardMutationDetected": True, "mutation": mutation}
        )
    )


def tamper(package, directory, control, primary, native):
    import organization_cutover_history as history  # noqa: PLC0415
    from organization_recovery_store import RecoveryRefusedError  # noqa: PLC0415

    environment = native["environment_id"]
    subject, owner = primary.rows(
        "SELECT subject,owner_id::text FROM aegaeon.end_user_subject_reservations "
        'WHERE environment_id=%s ORDER BY subject COLLATE "C" LIMIT 1',
        (environment,),
    )[0]
    other = primary.one(
        "SELECT owner_id::text FROM aegaeon.end_user_identity_owners "
        "WHERE environment_id=%s AND owner_id<>%s ORDER BY owner_id LIMIT 1",
        (environment, owner),
    )

    def replace(value):
        with primary.connection.transaction():
            primary.connection.execute("SET LOCAL session_replication_role=replica")
            primary.connection.execute(
                "UPDATE aegaeon.end_user_subject_reservations "
                "SET owner_id=%s WHERE environment_id=%s AND subject=%s",
                (value, environment, subject),
            )

    try:
        replace(other)
        with pytest.raises(RecoveryRefusedError, match="independent subject differs from primary"):
            history.compare(control, primary, native)
        source = (
            package / "share/aegaeon/scripts/operations/organization_cutover_history.py"
        ).read_text()
        guard = 'require(present == len(subjects), "independent subject differs from primary")'
        assert source.count(guard) == 1
        mutant = directory / "history-guard-mutant.py"
        mutant.write_text(source.replace(guard, 'require(True, "mutated subject guard")'))
        spec = importlib.util.spec_from_file_location("history_guard_mutant", mutant)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        assert module.compare(control, primary, native)["completePermanentFactsCompared"] is True
        mutation = {
            "removedGuard": guard,
            "sourceSha256": hashlib.sha256(source.encode()).hexdigest(),
            "mutantSha256": hashlib.sha256(mutant.read_bytes()).hexdigest(),
        }
    finally:
        replace(owner)
    assert history.compare(control, primary, native)["subjects"] == 2
    return mutation


def abandon(args, config, control, primary, receipt):
    import organization_cutover_journal as journal  # noqa: PLC0415
    import organization_cutover_login as login  # noqa: PLC0415
    import organization_cutover_plan as plans  # noqa: PLC0415
    import organization_cutover_validation as validation  # noqa: PLC0415
    import organization_recovery as recovery  # noqa: PLC0415

    plan = plans.load(config, args.directory, receipt["planSha256"])
    native = json.loads(recovery.private_file(args.native))
    selected = validation.selected(plan, native)
    names = [{selected["control_maintenance"]["new"]}, {selected["primary_runtime"]["new"]}]
    stores = [control, primary]
    leases = [login.plan(store, plan.sql(i), names[i]) for i, store in enumerate(stores)]
    index = len(list(args.directory.glob("validation-attempt-*.json")))
    descriptor = plans.directory(args.directory)
    recovery.retain(
        descriptor,
        f"validation-attempt-{index:04d}.json",
        {
            "version": 1,
            "planSha256": plan.sha256,
            "mode": "history",
            "environmentId": native["environments"][0]["id"],
            "leases": leases,
        },
    )
    with journal.locked(control, config["inspection"]["fence"]):
        for i, store in enumerate(stores):
            login.enable(store, plan.sql(i), leases[i])
    # Actual process loss after both SQL COMMITs, before native inspection/cleanup.
    # No production fault switch or replacement native executable is introduced.
    os._exit(91)


if __name__ == "__main__":
    main()
