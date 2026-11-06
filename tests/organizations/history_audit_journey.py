"""Native diagnostic reads real independent history without creating work owners."""

from __future__ import annotations

import json
import re
from uuid import uuid4


def exercise(directory, package, helpers, scope, *, pending=False):
    env, run, sql, records = helpers
    deployment, environment, parent_op, child_op, parent, child = scope
    fixture = json.loads((directory / "fixture.json").read_text())
    bootstrap = json.loads((directory / "bootstrap.json").read_text())
    command = [
        package / "bin/aegaeon-organization-store-inspect",
        "history",
        "--root-cert",
        fixture["ca"],
        "--environment-id",
        str(environment),
        "--issuer",
        bootstrap["issuer"],
        "--deployment-id",
        str(deployment),
        "--operation-id",
        str(child_op),
        "--expected-revision",
        str(child["revision"]),
        "--parent-operation-id",
        str(parent_op),
        "--parent-expected-revision",
        str(parent["revision"]),
    ]
    environment_vars = env | {
        "AEGAEON_ORGANIZATION_WITNESS_DATABASE_URL": fixture["maintenance"],
        "AEGAEON_ORGANIZATION_OBSERVATION_DATABASE_URL": fixture["primary"],
    }

    def call(label, *, refused=False, argument=None, changes=None):
        args = list(command)
        if argument:
            args[args.index(argument[0]) + 1] = argument[1]
        result = run(args, environment=environment_vars | (changes or {}), timeout=35)
        records.append({"case": label, "returncode": result.returncode})
        if (result.returncode != 0) != refused:
            message = f"native history audit {label} unexpected outcome"
            raise RuntimeError(message)
        if refused:
            assert not result.stdout
            return None
        observed = json.loads(result.stdout)
        assert observed["activationAuthorized"] is False
        value = observed["observation"]
        assert value["controlClosed"] is True
        assert value["primaryClosed"] is True
        assert value["history"]["sequence"] == 260
        return value

    if pending:
        call("native history refuses pending maintenance", refused=True)
        return
    state = sql("control", f"SELECT organization_witness.maintenance_state('{deployment}')")
    first = call("native history checks exact catalogs and complete multi-page chain")
    negative_cases(call, sql, environment, parent, fixture["control"])
    assert (
        call("native history recovers after fixture corruption removed")["history"]
        == first["history"]
    )
    assert sql("control", f"SELECT organization_witness.maintenance_state('{deployment}')") == state


def negative_cases(call, sql, environment, parent, control_url):
    call(
        "native history refuses wrong child fence",
        refused=True,
        argument=("--operation-id", str(uuid4())),
    )
    call(
        "native history refuses wrong parent fence",
        refused=True,
        argument=("--parent-expected-revision", str(parent["revision"] + 1)),
    )
    call(
        "native history refuses runtime control role",
        refused=True,
        changes={"AEGAEON_ORGANIZATION_WITNESS_DATABASE_URL": control_url},
    )
    call(
        "native history refuses foreign issuer",
        refused=True,
        argument=("--issuer", "https://foreign.example"),
    )
    # Only parsed UUIDs and validated hex enter this disposable fixture mutation.
    selected = f"environment_id='{environment}' AND sequence=1"
    original = sql(
        "control",
        "SELECT encode(digest,'hex') FROM organization_witness.history_entries WHERE " + selected,  # noqa: S608 — UUID only
    )
    assert re.fullmatch(r"[0-9a-f]{64}", original)

    def change(digest):
        sql(
            "control",
            "SET session_replication_role=replica; "  # noqa: S608 — UUID and hex only
            "UPDATE organization_witness.history_entries "
            f"SET digest=decode('{digest}','hex') WHERE " + selected,
        )

    try:
        change("0" * 64)
        call("native history detects corrupt retained chain", refused=True)
    finally:
        change(original)
