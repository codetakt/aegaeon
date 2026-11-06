"""Actual fixed native epoch transaction under fixture-owned root authority."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from contextlib import ExitStack
from pathlib import Path
from urllib.parse import quote
from uuid import uuid4

import pytest
from psycopg.types.json import Jsonb


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("package", "server", "config", "native", "directory"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    sys.path.insert(0, str(args.package / "share/aegaeon/scripts/operations"))
    import organization_cutover_plan as plans  # noqa: PLC0415
    import organization_cutover_prepare as preparation  # noqa: PLC0415
    import organization_cutover_validation as validation  # noqa: PLC0415
    import organization_recovery as recovery  # noqa: PLC0415
    import organization_recovery_runtime as runtime  # noqa: PLC0415

    configured = json.loads(recovery.private_file(args.config))
    native = json.loads(recovery.private_file(args.native))
    receipt = json.loads(recovery.private_file(args.directory / "native-validation.json"))
    plan = plans.load(configured, args.directory, receipt["planSha256"])
    descriptor = plans.directory(args.directory)
    try:
        with ExitStack() as stack:
            stores = [
                recovery.connect(stack, configured["inspection"]["stores"][i]) for i in (0, 2)
            ]
            old = preparation.connect_token(stack, configured["preparation"]["retired_token"])
            new = preparation.connect_token(stack, configured["preparation"]["destination_token"])
            context = validation.Context(
                native,
                validation.selected(plan, native),
                configured["inspection"]["fence"],
                stores,
                plan,
                new,
                old,
                descriptor,
            )
            before = runtime.state(stores[0], context.expected["deployment_id"])
            value = intent(configured, receipt, before)
            result = scenario(args, context, value, before)
        print(json.dumps(result))
    finally:
        os.close(descriptor)


def intent(configured, receipt, state):
    import organization_recovery_runtime as runtime  # noqa: PLC0415

    primary, token = str(uuid4()), str(uuid4())
    digest = runtime.digest(receipt)

    def transition(before):
        return {
            "operation_id": before["operation_id"],
            "revision": before["revision"],
            "selection": {
                "epoch": str(uuid4()),
                "primary": primary,
                "token_store": token,
                "source_sha256": digest,
                "history_sha256": digest,
                "acceptance_sha256": digest,
            },
        }

    observed = receipt["results"][0]["native"]["runtime"]
    namespaces = {v["namespace"]["id"]: v["namespace"] for v in receipt["results"]}
    return {
        "version": 1,
        "deployment_id": state["parent"]["deployment_id"],
        "cutover_operation_id": configured["inspection"]["operation_id"],
        "parent": transition(state["parent"]),
        "children": [
            {
                "environment_id": child["environment_id"],
                "issuer": namespaces[child["environment_id"]]["issuer"],
                "transition": transition(child),
            }
            for child in state["children"]
        ],
        "stores": {
            "primary": observed["primary"],
            "control": observed["control"],
            "token": observed["tokenStore"],
        },
    }


def scenario(args, context, value, before):  # noqa: PLR0915 — finite native transition cases
    import organization_cutover_phase as phase  # noqa: PLC0415
    import organization_recovery as recovery  # noqa: PLC0415
    import organization_recovery_runtime as runtime  # noqa: PLC0415

    control = context.stores[0]
    receipts = control.one(
        "SELECT receipts FROM organization_witness.cutover_operations WHERE operation_id=%s",
        (value["cutover_operation_id"],),
    )
    assert len(receipts) == 7
    invocation = 0
    last_intent = None

    def call(name, candidate, *, registered=None, success=False):
        nonlocal invocation, last_intent
        filename = f"epoch-probe-{invocation:04d}.json"
        invocation += 1
        digest = recovery.retain(context.descriptor, filename, candidate)
        last_intent = args.directory / filename
        if name == "complete atomic preparation":
            # Discard only the fixture's deliberately rejected previous intents.
            control.connection.execute(
                "UPDATE organization_witness.cutover_operations SET step=7,receipts=%s "
                "WHERE operation_id=%s",
                (Jsonb(receipts), value["cutover_operation_id"]),
            )
            registered_row = phase.register(
                control, context.expected, candidate, context.plan.sha256, digest, receipts[-1]
            )
            assert registered_row["step"] == 8
        else:
            control.connection.execute(
                "UPDATE organization_witness.cutover_operations SET step=8,receipts=%s "
                "WHERE operation_id=%s",
                (Jsonb([*receipts, registered or digest]), value["cutover_operation_id"]),
            )
        response = invoke(args, context, args.directory / filename, invocation)
        assert (response.returncode == 0) == success, name
        if not success:
            assert runtime.state(control, value["deployment_id"]) == before, name
            assert not control.one(
                "SELECT EXISTS(SELECT FROM organization_witness.deployment_store_checkpoints "
                "WHERE epoch=%s)",
                (value["parent"]["selection"]["epoch"],),
            ), name
        if success:
            with phase.locked(
                control,
                context.expected,
                before,
                candidate,
                context.plan.sha256,
                digest,
                context.principals["control_maintenance"]["new"],
            ) as (_, observed):
                assert observed["prepared"] is True
                assert len(observed["checkpoints"]) == len(candidate["children"]) + 1
        return json.loads(response.stdout) if success else None

    call("unregistered bytes", value, registered="f" * 64)
    wrong = json.loads(json.dumps(value))
    wrong["stores"]["primary"]["started_us"] += 1
    call("changed physical primary", wrong)
    wrong = json.loads(json.dumps(value))
    wrong["children"][0]["issuer"] = "https://foreign.example/"
    call("foreign namespace", wrong)
    wrong = json.loads(json.dumps(value))
    wrong["parent"]["revision"] += 1
    call("stale revision", wrong)
    child = value["children"][0]
    epoch = child["transition"]["selection"]["epoch"]
    # A historical child epoch conflicts only after the parent and its checkpoint
    # were written. The actual transaction must roll all of them back.
    control.connection.execute(
        "INSERT INTO organization_witness.epochs(environment_id,epoch,operation_id) "
        "VALUES(%s,%s,%s)",
        (child["environment_id"], epoch, child["transition"]["operation_id"]),
    )
    call("child failure rolls back prepared parent and checkpoint", value)
    control.connection.execute(
        "DELETE FROM organization_witness.epochs WHERE environment_id=%s AND epoch=%s",
        (child["environment_id"], epoch),
    )
    first = call("complete atomic preparation", value, success=True)
    assert first["activationAuthorized"] is False
    assert first["selection"]["parent"]["phase"] == "prepared"
    assert all(row["phase"] == "prepared" for row in first["selection"]["children"])
    # Actual corruption of an OLD selected checkpoint must not disappear merely
    # because the new epoch now selects a different checkpoint row.
    control.connection.execute(
        "UPDATE organization_witness.deployment_store_checkpoints SET wal_position=wal_position+1 "
        "WHERE deployment_id=%s AND epoch=%s",
        (value["deployment_id"], before["parent"]["epoch"]),
    )
    try:
        with (
            control.connection.transaction(),
            pytest.raises(Exception, match="original source checkpoint changed"),
        ):
            phase.observations(
                control, before, value, context.principals["control_maintenance"]["new"]
            )
    finally:
        control.connection.execute(
            "UPDATE organization_witness.deployment_store_checkpoints "
            "SET wal_position=wal_position-1 "
            "WHERE deployment_id=%s AND epoch=%s",
            (value["deployment_id"], before["parent"]["epoch"]),
        )
    repeated = call("lost reply exact replay", value, success=True)
    assert repeated == first
    assert (
        control.one(
            "SELECT count(*) FROM organization_witness.deployment_store_checkpoints WHERE epoch=%s",
            (value["parent"]["selection"]["epoch"],),
        )
        == 1
    )
    assert last_intent is not None
    digest = hashlib.sha256(recovery.private_file(last_intent)).hexdigest()
    receipt_digest = recovery.retain(context.descriptor, "epoch-completed-probe.json", repeated)
    completion = phase.complete(
        control,
        context.expected,
        before,
        value,
        context.plan.sha256,
        digest,
        context.principals["control_maintenance"]["new"],
        receipt_digest,
    )
    assert completion["step"] == 9
    assert (
        phase.complete(
            control,
            context.expected,
            before,
            value,
            context.plan.sha256,
            digest,
            context.principals["control_maintenance"]["new"],
            receipt_digest,
        )
        == completion
    )
    with pytest.raises(Exception, match="completion receipt differs"):
        phase.complete(
            control,
            context.expected,
            before,
            value,
            context.plan.sha256,
            digest,
            context.principals["control_maintenance"]["new"],
            "f" * 64,
        )
    assert invoke(args, context, last_intent, invocation + 1).returncode != 0
    return {
        "passed": True,
        "cases": [
            "registered intent binding",
            "actual primary identity",
            "namespace",
            "revision",
            "child error rolls back parent and checkpoint",
            "atomic preparation",
            "lost reply replay",
            "root observer keeps original checkpoint authority",
            "registered phase completion and exact replay; native refused after step9",
        ],
        "activation": False,
        "native_sha256": hashlib.sha256(
            (args.server / "bin/aegaeon-organization-epoch-prepare").read_bytes()
        ).hexdigest(),
    }


def invoke(args, context, intent_path, index):
    import organization_cutover_login as login  # noqa: PLC0415
    import organization_cutover_token as token  # noqa: PLC0415
    import organization_cutover_validation as validation  # noqa: PLC0415
    import organization_recovery as recovery  # noqa: PLC0415

    names = [
        {context.principals["control_maintenance"]["new"]},
        {context.principals["primary_runtime"]["new"]},
    ]
    leases = [
        login.plan(store, context.plan.sql(i), names[i]) for i, store in enumerate(context.stores)
    ]
    attempt = {"leases": leases}
    recovery.retain(context.descriptor, f"epoch-lease-{index:04d}.json", attempt)
    principal = context.plan.value["token"]
    target = context.configuration["token"]
    environment = {
        "PATH": os.defpath,
        "LANG": "C.UTF-8",
        "AEGAEON_KEY_ENCRYPTION_KEY": recovery.private_file(
            context.configuration["key_encryption_key_file"]
        )
        .decode()
        .rstrip("\n"),
        "AEGAEON_ORGANIZATION_WITNESS_DATABASE_URL": validation.endpoint(
            context.configuration["control"], context.principals["control_maintenance"]
        ),
        "AEGAEON_ORGANIZATION_OBSERVATION_DATABASE_URL": validation.endpoint(
            context.configuration["primary"], context.principals["primary_runtime"]
        ),
        "AEGAEON_ORGANIZATION_OBSERVATION_REDIS_URL": (
            f"rediss://{quote(principal['name'], safe='')}:{quote(principal['password'], safe='')}"
            f"@{target['host']}:{target['port']}/{context.new.identity['database']}"
        ),
    }
    try:
        for i, store in enumerate(context.stores):
            login.enable(store, context.plan.sql(i), leases[i])
        token.validation_enable(context.new, context.old.identity["run_id"], context.plan.redis())
        return subprocess.run(  # noqa: S603 — fixed packaged fixture executable
            [
                str(args.server / "bin/aegaeon-organization-epoch-prepare"),
                "--intent",
                str(intent_path),
                "--root-cert",
                context.configuration["root_cert_file"],
            ],
            env=environment,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=60,
            check=False,
        )
    finally:
        cleaned = validation.cleanup(context, attempt)
        recovery.retain(context.descriptor, f"epoch-cleanup-{index:04d}.json", cleaned)


if __name__ == "__main__":
    main()
