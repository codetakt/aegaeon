"""Root fixture: actual native COMMIT loss and prepared coordinator refusal cases."""

from __future__ import annotations

import argparse
import json
import os
import sys
from contextlib import ExitStack
from pathlib import Path

import pytest


def main():  # noqa: PLR0915 — exact root fixture ownership
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("package", "config", "native", "directory"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--abandon", action="store_true")
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    sys.path.insert(0, str(args.package / "share/aegaeon/scripts/operations"))
    import organization_cutover_epoch_native as native_call  # noqa: PLC0415
    import organization_cutover_epochs as epochs  # noqa: PLC0415
    import organization_cutover_prepare as preparation  # noqa: PLC0415
    import organization_recovery as recovery  # noqa: PLC0415

    config = json.loads(recovery.private_file(args.config))
    native = json.loads(recovery.private_file(args.native))
    with ExitStack() as stack:
        stores = [recovery.connect(stack, value) for value in config["inspection"]["stores"]]
        old = preparation.connect_token(stack, config["preparation"]["retired_token"])
        new = preparation.connect_token(stack, config["preparation"]["destination_token"])
        if args.abandon:
            original = native_call.call

            def lose_reply(context, directory, **kwargs):
                result = original(context, directory, **kwargs)
                assert result["selection"]["parent"]["phase"] == "prepared"
                recovery.retain(
                    context.descriptor, "epoch-loss-probe.json", {"nativeCommitted": True}
                )
                os._exit(92)

            native_call.call = lose_reply
        execute = lambda: epochs.prepare(config, native, stores, old, new, args.directory)  # noqa: E731
        if args.abandon:
            execute()
            message = "process did not stop after actual native COMMIT"
            raise AssertionError(message)
        result = execute() if args.resume else probe(args, execute, stores, config)
    print(json.dumps(result))


def probe(args, execute, stores, config):  # noqa: PLR0915 — exact prepared recovery/refusal cases
    import organization_recovery as recovery  # noqa: PLC0415
    from organization_recovery_store import RecoveryRefusedError  # noqa: PLC0415

    assert json.loads(recovery.private_file(args.directory / "epoch-loss-probe.json"))[
        "nativeCommitted"
    ]
    attempts = sorted(args.directory.glob("validation-attempt-*.json"))
    epoch_attempts = [
        p for p in attempts if json.loads(recovery.private_file(p))["mode"] == "epochs"
    ]
    assert len(epoch_attempts) == 2
    for path in attempts:
        assert (args.directory / path.name.replace("attempt", "cleanup")).is_file()
    first = execute()
    assert first["step"] == 9
    assert execute() == first
    assert sorted(args.directory.glob("validation-attempt-*.json")) == attempts
    for name in ["original-state.json", "epoch-binding.json", "epochs.json", "epoch-prepared.json"]:
        path = args.directory / name
        saved = path.with_suffix(".saved")
        path.rename(saved)
        try:
            with pytest.raises((RecoveryRefusedError, FileNotFoundError)):
                execute()
            assert not path.exists()
        finally:
            saved.rename(path)
    primary = stores[2]
    environment, subject, owner = primary.rows(
        "SELECT environment_id::text,subject,owner_id::text "
        "FROM aegaeon.end_user_subject_reservations "
        'ORDER BY environment_id,subject COLLATE "C" LIMIT 1'
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
        with pytest.raises(RecoveryRefusedError):
            execute()
    finally:
        replace(owner)
    # An old checkpoint remains authoritative after new checkpoints were selected.
    original = json.loads(recovery.private_file(args.directory / "original-state.json"))
    control = stores[0]
    values = (config["inspection"]["fence"]["deployment_id"], original["parent"]["epoch"])
    control.connection.execute(
        "UPDATE organization_witness.deployment_store_checkpoints "
        "SET wal_position=wal_position+1 WHERE deployment_id=%s AND epoch=%s",
        values,
    )
    try:
        with pytest.raises(RecoveryRefusedError, match="original source checkpoint changed"):
            execute()
    finally:
        control.connection.execute(
            "UPDATE organization_witness.deployment_store_checkpoints "
            "SET wal_position=wal_position-1 WHERE deployment_id=%s AND epoch=%s",
            values,
        )
    assert execute() == first
    assert sorted(args.directory.glob("validation-attempt-*.json")) == attempts
    return {
        "passed": True,
        "activation": False,
        "cases": [
            "actual COMMIT/process loss and exact lease recovery",
            "complete prepared replay",
            "completed replay without new leases",
            "missing registered inputs never regenerated",
            "changed destination content refused",
            "original checkpoint still authoritative",
        ],
    }


if __name__ == "__main__":
    main()
