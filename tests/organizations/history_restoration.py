"""Release CLI restores retained facts without reviving users or authority."""

from __future__ import annotations

import hashlib
import json
from functools import partial
from urllib.parse import urlencode, urlsplit
from uuid import UUID, uuid4


def setup(directory, config):
    owners = sorted([uuid4() for _ in range(258)])
    owner = owners[-1]
    fixture = directory / "restoration-facts.json"
    fixture.write_text(json.dumps({"owner": str(owner), "owners": list(map(str, owners))}))
    fixture.chmod(0o600)
    return {
        "issuer": urlsplit(config["environments"][0]["issuer"]).hostname,
        "seed": partial(seed_history, owners),
    }


def seed_history(owners, sql, scope, issuer):
    """Explicit test journal; this does not attest external history completeness."""
    environment, deployment, operation, revision = scope
    owner = owners[-1]
    entries = [{"kind": "owner", "owner_id": str(item), "subject": None} for item in owners] + [
        {"kind": "reservation", "owner_id": str(owner), "subject": f"Restored-{owner}"},
        {"kind": "reservation", "owner_id": str(owner), "subject": f"restored-{owner}"},
    ]
    assert issuer
    assert "'" not in issuer
    digest = hashlib.sha256(
        b"aegaeon-permanent-history-v1\0"
        + environment.bytes
        + len(issuer.encode()).to_bytes(4, "big")
        + issuer.encode()
    ).digest()
    for sequence, entry in enumerate(entries, 1):
        subject = (entry["subject"] or "").encode()
        digest = hashlib.sha256(
            digest
            + sequence.to_bytes(8, "big")
            + bytes([int(entry["kind"] == "reservation")])
            + UUID(entry["owner_id"]).bytes
            + len(subject).to_bytes(4, "big")
            + subject
        ).digest()
    selected = f"'{environment}','{deployment}','{operation}',{revision}"
    sql(
        "control",
        "SELECT organization_witness.history_begin("
        f"{selected},'{issuer}','{uuid4()}','{'1' * 64}','{'2' * 64}',"
        f"{len(owners)},2,'{digest.hex()}')",
    )
    for after in range(0, len(entries), 256):
        page = json.dumps(entries[after : after + 256])
        sql(
            "control",
            f"SELECT organization_witness.history_batch({selected},{after},"
            f"$fixture${page}$fixture$::jsonb)",
        )
    sql("control", f"SELECT organization_witness.history_seal({selected})")


def target(directory):
    fixture = json.loads((directory / "fixture.json").read_text())
    suppliers = json.loads((directory / "primary-fixture/suppliers.json").read_text())
    maintenance = urlsplit(suppliers["urls"]["maintenance"])
    primary = urlsplit(fixture["primary"])
    endpoint = (
        f"postgresql://{maintenance.username}:{maintenance.password}@localhost:{primary.port}"
        f"{primary.path}?{urlencode({'sslrootcert': fixture['ca']})}"
    )
    return primary.path.removeprefix("/"), suppliers["names"]["runtime"], endpoint


def facts(sql, database, owner):
    # Only a parsed UUID enters these fixed observer queries.
    owners = json.loads(
        sql(
            "primary",
            "SELECT COALESCE(jsonb_agg(owner_id ORDER BY owner_id),'[]') "
            "FROM aegaeon.end_user_identity_owners",
            database,
        )
    )
    subjects = json.loads(
        sql(
            "primary",
            f"SELECT COALESCE(jsonb_agg(subject ORDER BY subject COLLATE \"C\"),'[]') "  # noqa: S608 — parsed UUID
            f"FROM aegaeon.end_user_subject_reservations WHERE owner_id='{owner}'",
            database,
        )
    )
    users = int(sql("primary", "SELECT count(*) FROM aegaeon.end_users", database))
    return owners, subjects, users


def exercise(call, sql, deployment, directory, audit):
    database, runtime, endpoint = target(directory)
    expected = json.loads((directory / "restoration-facts.json").read_text())
    owner = UUID(expected["owner"])
    before = facts(sql, database, owner)
    assert before[:2] == ([], [])
    operation = uuid4()
    command = [
        "restore",
        "--target-runtime-role",
        runtime,
        "--restoration-operation-id",
        str(operation),
    ]
    call(
        "explicit parent fence required", command, refused=True, omit_parent=True, primary=endpoint
    )
    call(
        "runtime control role cannot restore",
        command,
        refused=True,
        login="control",
        primary=endpoint,
    )
    inspected = call("inspect nonempty retained history", ["inspect"])
    assert json.loads((inspected / "receipt.json").read_text())["history"]["sequence"] == 260
    output = call("restore missing owner and case-distinct reservations", command, primary=endpoint)
    receipt = json.loads((output / "receipt.json").read_text())["restoration"]
    check_restored(receipt)
    assert facts(sql, database, owner) == (
        expected["owners"],
        [f"Restored-{owner}", f"restored-{owner}"],
        before[2],
    )
    replay = call("exact restoration replay creates no duplicate facts", command, primary=endpoint)
    assert json.loads((replay / "receipt.json").read_text())["restoration"] == receipt
    assert facts(sql, database, owner) == (
        expected["owners"],
        [f"Restored-{owner}", f"restored-{owner}"],
        before[2],
    )
    released = json.loads((replay / "maintenance-released.json").read_text())
    assert (released["pending"], released["generation"]) == (False, 3)
    audit()
    call(
        "primary opening failure retains restoration owner",
        command,
        refused=True,
        primary="postgresql://unreachable_runtime@localhost:1/unreachable",
    )
    call(
        "uncertain predecessor excludes another restoration",
        command,
        refused=True,
        primary=endpoint,
    )
    pending = json.loads(
        sql("control", f"SELECT organization_witness.maintenance_state('{deployment}')")
    )
    assert (pending["pending"], pending["generation"]) == (True, 4)
    audit(pending=True)
    return {
        "passed": True,
        "maintenance_pending": pending,
        "normal_released": released,
        "expected_generations": [0, 0],
        "actual_primary_restoration_tested": True,
        "fixture_history_owners": 258,
        "fixture_history_subjects": 2,
        "end_users_created": False,
        "activation_tested": False,
        "supplier_qualified": False,
    }


def check_restored(receipt):
    assert receipt["activationAuthorized"] is False
    assert receipt["independentFactsPresent"] is True
    assert receipt["pages"] == 2
    assert receipt["historySequence"] == 260
