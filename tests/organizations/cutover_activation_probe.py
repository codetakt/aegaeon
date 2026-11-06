"""Real native rollback, lost activation COMMIT reply and exact root replay."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from contextlib import ExitStack
from pathlib import Path

import pytest


def run(*args, code=0):
    result = subprocess.run(args, capture_output=True, text=True, timeout=180, check=False)  # noqa: S603 — fixed owned fixture
    assert result.returncode == code, (result.returncode, result.stderr)
    return result.stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("package", "config", "native", "directory"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--abandon", action="store_true")
    parser.add_argument("--rollback", action="store_true")
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    sys.path.insert(0, str(args.package / "share/aegaeon/scripts/operations"))
    if args.abandon or args.rollback or args.resume:
        execute(args)
        return
    run(sys.executable, __file__, *sys.argv[1:], "--rollback")
    run(sys.executable, __file__, *sys.argv[1:], "--abandon", code=94)
    result = probe(args)
    print(json.dumps(result))


def execute(args):  # noqa: PLR0915 — bounded real transaction fault and recovery
    import organization_cutover_activation as activation  # noqa: PLC0415
    import organization_cutover_epoch_inputs as epoch_inputs  # noqa: PLC0415
    import organization_cutover_epoch_native as native_call  # noqa: PLC0415
    import organization_cutover_prepare as preparation  # noqa: PLC0415
    import organization_recovery as recovery  # noqa: PLC0415
    from organization_recovery_store import RecoveryRefusedError  # noqa: PLC0415

    config = json.loads(recovery.private_file(args.config))
    native = json.loads(recovery.private_file(args.native))
    settings = json.loads(recovery.private_file(args.directory / "startup-fixture.json"))
    original = native_call.call
    original_receipt = activation.native_receipt
    captured = []
    with ExitStack() as stack:
        stores = [recovery.connect(stack, value) for value in config["inspection"]["stores"]]
        old = preparation.connect_token(stack, config["preparation"]["retired_token"])
        new = preparation.connect_token(stack, config["preparation"]["destination_token"])
        epoch = json.loads(recovery.private_file(args.directory / "epochs.json"))
        control = stores[0]
        before = states(control, epoch)

        def call(context, directory, **kwargs):
            if args.rollback:
                # The actual last-child activation UPDATE waits on this owned row.
                # Parent activation and child binding have already executed within
                # the native transaction. The fixed SQL timeout must undo them all.
                child = epoch["children"][-1]
                with control.connection.transaction():
                    assert control.one(
                        "SELECT true FROM organization_witness.operations WHERE "
                        "environment_id=%s AND id=%s FOR UPDATE",
                        (child["environment_id"], child["transition"]["operation_id"]),
                    )
                    return original(context, directory, **kwargs)
            result = original(context, directory, **kwargs)
            captured.append(result)
            if args.abandon:
                assert result["selection"]["parent"]["phase"] == "active"
                recovery.retain(
                    context.descriptor, "activation-loss-probe.json", {"nativeCommitted": True}
                )
                os._exit(94)
            return result

        def receipt(work, observed, digest, publication):
            expected = original_receipt(work, observed, digest, publication)
            if captured:
                actual = captured[-1]
                assert activation.canonical_receipt(actual) == activation.canonical_receipt(
                    expected
                )
                epoch_inputs.retain(
                    work.directory,
                    work.context.descriptor,
                    "activation-timestamp-probe.json",
                    {
                        "sameInstant": True,
                        "differentRepresentation": actual["selection"]["bindings"][0]["bound_at"]
                        != expected["selection"]["bindings"][0]["bound_at"],
                    },
                )
            return expected

        activation.native_receipt = receipt
        native_call.call = call

        def operation():
            return activation.activate(config, native, stores, old, new, args.directory, settings)

        if args.rollback:
            with pytest.raises(RecoveryRefusedError, match="native epoch preparation refused"):
                operation()
            assert states(control, epoch) == before
            descriptor = os.open(args.directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                recovery.retain(descriptor, "activation-rollback-probe.json", {"passed": True})
            finally:
                os.close(descriptor)
        else:
            print(json.dumps(operation()))


def states(control, epoch):
    return {
        "parent": control.one(
            "SELECT to_jsonb(d) FROM organization_witness.deployments d WHERE deployment_id=%s",
            (epoch["deployment_id"],),
        ),
        "children": control.rows(
            "SELECT to_jsonb(a) FROM organization_witness.authorities a "
            "WHERE deployment_id=%s ORDER BY environment_id",
            (epoch["deployment_id"],),
        ),
        "bindings": control.rows(
            "SELECT to_jsonb(b) FROM organization_witness.deployment_children b "
            "WHERE deployment_id=%s ORDER BY environment_id,child_epoch",
            (epoch["deployment_id"],),
        ),
    }


def probe(args):  # noqa: PLR0915 — ordered replay and retained-input fault matrix
    import organization_recovery as recovery  # noqa: PLC0415

    assert json.loads(recovery.private_file(args.directory / "activation-rollback-probe.json"))[
        "passed"
    ]
    assert json.loads(recovery.private_file(args.directory / "activation-loss-probe.json"))[
        "nativeCommitted"
    ]
    command = [
        str(args.package / "bin/aegaeon-organization-cutover-validate"),
        "--config",
        str(args.config),
        "--validation-config",
        str(args.native),
        "--directory",
        str(args.directory),
        "--activate-epochs",
        str(args.directory / "startup-fixture.json"),
    ]
    # No registered input may be regenerated even after a COMMIT reply was lost.
    for name in ("activation.json", "startup-manifest.json", "startup-published.json"):
        path = args.directory / name
        saved = path.with_suffix(".saved")
        path.rename(saved)
        try:
            run(*command, code=1)
            assert not path.exists()
        finally:
            saved.rename(path)
    first = json.loads(run(sys.executable, __file__, *sys.argv[1:], "--resume"))
    timestamp = json.loads(
        recovery.private_file(args.directory / "activation-timestamp-probe.json")
    )
    assert timestamp["sameInstant"]
    assert timestamp["differentRepresentation"]
    assert json.loads(run(*command)) == first
    assert first["step"] == 13
    assert not first["workersStarted"]
    activated = json.loads(recovery.private_file(args.directory / "epoch-activated.json"))
    selection = activated["native"]["selection"]
    assert len(selection["children"]) == 2
    assert len(selection["bindings"]) == 2
    assert len(selection["childCheckpoints"]) == 2
    assert all(row["phase"] == "active" for row in selection["children"])
    assert {row["environment_id"] for row in selection["children"]} == {
        row["environment_id"] for row in selection["bindings"]
    }
    attempts = sorted(args.directory.glob("validation-attempt-*.json"))
    assert json.loads(run(*command)) == first
    assert sorted(args.directory.glob("validation-attempt-*.json")) == attempts
    path = args.directory / "epoch-activated.json"
    saved = path.with_suffix(".saved")
    path.rename(saved)
    try:
        run(*command, code=1)
        assert not path.exists()
    finally:
        saved.rename(path)
    config = json.loads(recovery.private_file(args.config))
    original = json.loads(recovery.private_file(args.directory / "original-state.json"))
    assert original["bindings"]
    with ExitStack() as stack:
        control = recovery.connect(stack, config["inspection"]["stores"][0])
        old = original["bindings"][0]
        control.connection.execute(
            "DELETE FROM organization_witness.deployment_children "
            "WHERE environment_id=%s AND child_epoch=%s",
            (old["environment_id"], old["child_epoch"]),
        )
        # Close the fixture admin while the production command requires drain.
    try:
        run(*command, code=1)
    finally:
        with ExitStack() as stack:
            control = recovery.connect(stack, config["inspection"]["stores"][0])
            control.connection.execute(
                "INSERT INTO organization_witness.deployment_children "
                "(environment_id,child_epoch,deployment_id,deployment_epoch,principal,bound_at) "
                "VALUES(%s,%s,%s,%s,%s,%s)",
                tuple(
                    old[key]
                    for key in (
                        "environment_id",
                        "child_epoch",
                        "deployment_id",
                        "deployment_epoch",
                        "principal",
                        "bound_at",
                    )
                ),
            )
    assert json.loads(run(*command)) == first
    # The prepared-only public entry must still reject an active selection.
    prior = [*command[:-2], "--prepare-startup", command[-1]]
    run(*prior, code=1)
    return {
        "passed": True,
        "environmentCount": len(selection["children"]),
        "workersStarted": False,
        "supplierQualified": False,
        "cases": [
            "last-child SQL lock timeout rolls back parent and associations",
            "actual native COMMIT then root process loss and exact restart",
            "registered missing inputs refused without regeneration",
            "completed replay does not enable new login leases",
            "missing activation completion refused",
            "historical association removal refused",
            "native UTC and administrator local timestamp instants agree",
            "prepared-only entry rejects active",
        ],
    }


if __name__ == "__main__":
    main()
