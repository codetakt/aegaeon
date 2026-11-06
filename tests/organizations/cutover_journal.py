"""Actual independent SQL journal, replay, stale-plan and lost-reply boundaries."""

from __future__ import annotations

import importlib.util
import json
from uuid import uuid4

import psycopg
import pytest


def scenario(control, deployment, output, operator):  # noqa: PLR0915 — finite ordered journal cases
    import organization_cutover_journal as journal  # noqa: PLC0415
    import organization_recovery_runtime as runtime  # noqa: PLC0415

    with control.connection.transaction():
        current = runtime.state(control, deployment)
    expected = {
        "deployment_id": deployment,
        "operation_id": current["parent"]["operation_id"],
        "revision": current["parent"]["revision"],
        "state_sha256": runtime.digest(current),
    }
    operation, plan = str(uuid4()), "c" * 64

    class InjectedRollbackError(Exception):
        pass

    with pytest.raises(InjectedRollbackError), control.connection.transaction():  # noqa: PT012
        journal.register(control, expected, operation, plan)
        raise InjectedRollbackError
    with pytest.raises(Exception, match="not registered"):
        journal.inspect(control, expected, operation, plan)
    registered = journal.register(control, expected, operation, plan)
    # Ignore the first return as if COMMIT's reply were lost. The same exact plan
    # observes the retained row without creating another operation or new secret.
    assert journal.inspect(control, expected, operation, plan) == registered
    assert journal.register(control, expected, operation, plan) == registered
    with pytest.raises(Exception, match="plan or administrator conflicts"):
        journal.register(control, expected, operation, "d" * 64)
    with pytest.raises(Exception, match="another cutover"):
        journal.register(control, expected, str(uuid4()), plan)
    with pytest.raises(Exception, match="predecessor differs"):
        journal.advance(control, expected, operation, plan, "sql-intent", "e" * 64)
    with pytest.raises(InjectedRollbackError), control.connection.transaction():  # noqa: PT012
        journal.advance(control, expected, operation, plan, "registered", "e" * 64)
        raise InjectedRollbackError
    assert journal.inspect(control, expected, operation, plan) == registered
    advanced = journal.advance(control, expected, operation, plan, "registered", "e" * 64)
    assert journal.inspect(control, expected, operation, plan) == advanced
    assert journal.advance(control, expected, operation, plan, "registered", "e" * 64) == advanced
    with pytest.raises(Exception, match="receipt conflicts"):
        journal.advance(control, expected, operation, plan, "registered", "f" * 64)
    with pytest.raises(Exception, match="fence changed"):
        journal.inspect(control, dict(expected, revision=expected["revision"] + 1), operation, plan)
    with (
        psycopg.connect(control.connection.info.dsn, autocommit=True),
        pytest.raises(Exception, match="another live client"),
    ):
        journal.advance(control, expected, operation, plan, "content-checked", "f" * 64)
    assert journal.inspect(control, expected, operation, plan) == advanced
    # A real permission test under the old maintenance principal, not a role-name
    # assertion. The role stays NOLOGIN; SET SESSION AUTHORIZATION is fixture-only.
    for group in [
        "aegaeon_organization_witness_runtime",
        "aegaeon_organization_witness_maintenance",
    ]:
        with control.connection.transaction():
            control.connection.execute(f"SET LOCAL ROLE {group}")
            with (
                pytest.raises(psycopg.errors.InsufficientPrivilege),
                control.connection.transaction(),
            ):
                control.connection.execute("SELECT * FROM organization_witness.cutover_operations")
    # The exact conflicting-plan assertion detects removing the actual equality
    # guard. This is a manufactured negative control, not an historical defect.
    source = operator / "share/aegaeon/scripts/operations/organization_cutover_journal.py"
    original = source.read_text()
    guard = "all(row[name] == value for name, value in key.items())"
    assert original.count(guard) == 1
    mutation = output / "journal-plan-mutant.py"
    mutation.write_text(original.replace(guard, "True"))
    spec = importlib.util.spec_from_file_location("cutover_journal_mutant", mutation)
    mutant = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mutant)
    with (
        pytest.raises(pytest.fail.Exception, match="DID NOT RAISE"),
        pytest.raises(Exception, match="plan or administrator conflicts"),
    ):
        mutant.register(control, expected, operation, "d" * 64)
    for predecessor in journal.PREPARATION[1:-1]:
        advanced = journal.advance(control, expected, operation, plan, predecessor, "f" * 64)
    assert advanced["step"] == len(journal.PREPARATION) - 1
    assert advanced["completed"] is False
    with pytest.raises(InjectedRollbackError), control.connection.transaction():  # noqa: PT012
        aborted_successor(control, expected, operation, plan, journal)
        raise InjectedRollbackError
    with pytest.raises(Exception, match="unsupported cutover transition"):
        journal.advance(control, expected, operation, plan, "native-validated", "f" * 64)
    with pytest.raises(InjectedRollbackError), control.connection.transaction():  # noqa: PT012
        with pytest.raises(psycopg.errors.CheckViolation), control.connection.transaction():
            control.connection.execute(
                "UPDATE organization_witness.cutover_operations SET completed=true"
            )
        # Populate the actual finite history limit only inside a rolled-back
        # fixture transaction. No production completion operation exists here.
        control.connection.execute(
            "UPDATE organization_witness.cutover_operations SET step=16,completed=true,"
            "receipts=(SELECT jsonb_agg(repeat('a',64)) FROM generate_series(1,16))"
        )
        control.connection.execute(
            "INSERT INTO organization_witness.cutover_operations "
            "(deployment_id,operation_id,fence_operation_id,fence_revision,fence_sha256,"
            "plan_sha256,step,receipts,completed,principal,registered_at) "
            "SELECT deployment_id,gen_random_uuid(),fence_operation_id,fence_revision,"
            "fence_sha256,plan_sha256,step,receipts,completed,principal,registered_at "
            "FROM organization_witness.cutover_operations CROSS JOIN generate_series(1,4095)"
        )
        with pytest.raises(Exception, match="capacity exhausted"):
            journal.register(control, expected, str(uuid4()), plan)
        raise InjectedRollbackError
    assert journal.inspect(control, expected, operation, plan) == advanced
    (output / "journal-result.json").write_text(
        json.dumps(
            {
                "status": "passed",
                "conditions": [
                    "registration rollback and lost reply retain exact identity",
                    "same plan replay; changed plan and competing operation refused",
                    "ordered CAS; skipped predecessor and conflicting receipt refused",
                    "advance rollback and lost reply reconcile without replaying effects",
                    "changed fence and concurrent administrator refused",
                    "runtime and maintenance groups cannot read journal",
                    "identical plan-conflict assertion detects guard-removal mutant",
                    "preparation cannot activate or complete",
                    "aborted history allows fresh intent but refuses operation reuse",
                    "4096 retained-operation capacity refuses new work",
                ],
                "activation": False,
                "newCompositeDischarges": 0,
            },
            indent=2,
        )
        + "\n"
    )


def aborted_successor(control, expected, operation, plan, journal):
    deployment, successor = expected["deployment_id"], str(uuid4())
    assert journal.pending_or_registered(control, deployment, successor)
    # Manufacture only the terminal journal row inside the caller's rollback.
    # Actual external closure is covered by the root serving fixture.
    control.connection.execute(
        "UPDATE organization_witness.cutover_operations SET step=14,aborted=true,"
        "abort_receipt_sha256=repeat('a',64),"
        "receipts=(SELECT jsonb_agg(repeat('a',64)) FROM generate_series(1,14)) "
        "WHERE operation_id=%s",
        (operation,),
    )
    assert not journal.pending_or_registered(control, deployment, successor)
    assert journal.pending_or_registered(control, deployment, operation)
    # The original plan-creation predicate incorrectly keeps the slot occupied.
    assert control.one(
        "SELECT EXISTS(SELECT FROM organization_witness.cutover_operations "
        "WHERE deployment_id=%s AND (operation_id=%s OR NOT completed))",
        (deployment, successor),
    )
    registered = journal.register(control, expected, successor, plan)
    assert registered["step"] == 0
    assert journal.pending_or_registered(control, deployment, successor)
