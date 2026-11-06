"""Actual native export to packaged inactive import; no source ID rewriting."""

from __future__ import annotations

import json
from uuid import UUID


def projection(sql, scope, database):
    domain = UUID(scope["domain_id"])
    environment = UUID(scope["environment_id"])
    where = f"environment_id='{environment}' AND domain_id='{domain}'"
    relations = [
        "application_organizations",
        "authorization_domain_targets",
        "organization_role_definitions",
        "organization_operator_grants",
        "organization_authority_events",
        "organization_authority_receipts",
    ]
    rows = {
        relation: json.loads(
            sql(
                "primary",
                f"SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]') "  # noqa: S608 — fixed relations and parsed UUIDs
                f"FROM aegaeon.{relation} r WHERE {where}",
                database,
            )
        )
        for relation in relations
    }
    state = json.loads(
        sql(
            "primary",
            f"SELECT to_jsonb(d) FROM aegaeon.authorization_domains d WHERE id='{domain}'",  # noqa: S608 — parsed UUID
            database,
        )
    )
    return state, rows


def exercise(call, sql, deployment, scope, databases):
    source, target = databases
    assert sql("primary", "SELECT count(*) FROM aegaeon.authorization_domains", target) == "0"
    original, original_rows = projection(sql, scope, source)
    assert original["enabled"] is True
    call("foreign deployment refused before target", refused=True, wrong_scope=True)
    output = call("native export prepared in absent inactive target")
    receipt = json.loads((output / "receipt.json").read_text())["inspection"]
    assert receipt["state"] == "prepared"
    assert receipt["activationAuthorized"] is False
    assert receipt["cutoverDependenciesChecked"] is False
    state, copied = projection(sql, scope, target)
    assert state == original | {"enabled": False, "import_operation_id": receipt["operationId"]}
    assert copied == original_rows
    assert {row["external_id"] for row in copied["application_organizations"]} == {
        "tenant/A",
        "Tenant/A",
        "組織/é",
        "組織/e\u0301",
    }
    released = json.loads((output / "maintenance-released.json").read_text())
    assert (released["pending"], released["generation"]) == (False, 1)
    replay = call("same operation and digest returns retained preparation")
    assert json.loads((replay / "receipt.json").read_text())["inspection"] == receipt
    released = json.loads((replay / "maintenance-released.json").read_text())
    assert (released["pending"], released["generation"]) == (False, 2)
    recovered = call("prepared rows and current independent history agree", recovery=True)
    check_recovery(recovered, receipt)
    call("different operation cannot replace prepared scope", refused=True, conflict=True)
    call("uncertain maintenance owner excludes another invocation", refused=True)
    assert projection(sql, scope, target) == (state, copied)
    assert projection(sql, scope, source) == (original, original_rows)
    pending = json.loads(
        sql("control", f"SELECT organization_witness.maintenance_state('{deployment}')")
    )
    assert (pending["pending"], pending["generation"]) == (True, 4)
    return released, pending


def check_recovery(output, preparation):
    inspection = json.loads((output / "receipt.json").read_text())["inspection"]
    recovery = inspection["recovery"]
    assert recovery["preparedOperationId"] == preparation["operationId"]
    assert recovery["preparedRowsChecked"] > 0
    assert recovery["relevantOwnerHistoryChecked"] is True
    assert recovery["activationAuthorized"] is False
    assert inspection["activationAuthorized"] is False
    assert (recovery["sourceOwners"], recovery["sourceSubjects"]) == (0, 0)
    released = json.loads((output / "maintenance-released.json").read_text())
    assert (released["pending"], released["generation"]) == (False, 3)
