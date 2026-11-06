"""Packaged subject inventory/adoption under retained Organizations maintenance."""

from __future__ import annotations

import hashlib
import json
from urllib.parse import urlsplit
from uuid import uuid4

from history_journey import identity, prepare, tree_identity


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def manifest(directory, inventory_path):
    inventory = json.loads(inventory_path.read_text())
    findings = [f for f in inventory["findings"] if f["class"] != "outside_target"]
    for finding in findings:
        if not (
            finding["class"] == "malformed_event"
            and finding["origin"] in {"MANAGEMENT_INITIALIZED", "ENVIRONMENT_CREATED"}
            and not finding["preserved_fact_ids"]
            and not finding["observed_subjects"]
        ):
            message = f"fixture requires explicit review: {finding['class']}/{finding['origin']}"
            raise RuntimeError(message)
    environment = inventory["namespace"]["environment_id"]
    facts = [f for f in inventory["facts"] if f["environment_id"] == environment]
    attestation = directory / "fixture-attestation.txt"
    attestation.write_bytes(b"Disposable constructed legacy fixture; no supplier qualification.\n")
    snapshot = inventory_path.with_name("database-snapshot.jsonl")
    review = directory / "fixture-review.json"
    review.write_text(
        json.dumps(
            {
                "fixtureOnly": True,
                "events": ["MANAGEMENT_INITIALIZED", "ENVIRONMENT_CREATED"],
                "reason": "Creates Environment and administrator, without end-user identities.",
                "sources": [
                    "crates/server/src/web/management/initialization.rs",
                    "crates/server/src/web/management/topology_support/environment_creation/audit.rs",
                ],
                "findings": findings,
            }
        )
    )
    sources = []
    for name, kind, path in [
        ("attestation", "completeness_attestation", attestation),
        ("current", "current_snapshot", snapshot),
        ("review", "reconstruction", review),
    ]:
        sources.append(
            {
                "source_id": name,
                "kind": kind,
                "sha256": digest(path),
                "byte_length": path.stat().st_size,
                "private_reference": "retained fixture bytes",
                "provenance_reference": "isolated fixture construction",
                "environment_ids": [environment],
                "coverage_start_reference": "fixture creation",
                "coverage_end_reference": "fenced fixture",
            }
        )
    owners = sorted({f["owner_id"] for f in facts})
    reservations = sorted({(f["subject"], f["owner_id"]) for f in facts if f["valid"]})
    value = {
        "format": "aegaeon-subject-ownership-adoption",
        "version": 1,
        "receipt_id": str(uuid4()),
        "namespace": inventory["namespace"],
        "target": inventory["target"],
        "inventory": {
            "artifact_sha256": digest(inventory_path),
            "state_sha256": inventory["state_sha256"],
            "findings_sha256": inventory["findings_sha256"],
        },
        "sources": sources,
        "owners": [
            {"owner_id": o, "environment_id": environment, "source_refs": ["current"]}
            for o in owners
        ],
        "reservations": [
            {"subject": s, "owner_id": o, "source_refs": ["current"]} for s, o in reservations
        ],
        "invalid_history": [],
        "resolutions": [
            {
                "kind": "no_ownership_effect",
                "finding_id": f["finding_id"],
                "source_refs": ["review"],
                "review_reference": "fixture initialization source inspection",
            }
            for f in findings
        ],
        "completeness": {
            "assertion": "complete-history-for-this-namespace",
            "namespace_start_reference": "fixture creation",
            "coverage_end_reference": "fenced fixture",
            "complete_valid_subject_history": True,
            "complete_owner_uuid_history": True,
            "owner_uuid_environment_bindings_complete": True,
            "sources_exhaustive": True,
            "unresolved_findings": 0,
            "asserted_by": "fixture",
            "authority_reference": "isolated fixture construction",
            "attestation_source": "attestation",
        },
        "maintenance_reference": "retained parent maintenance fixture",
    }
    path = directory / "fixture-adoption.json"
    path.write_text(json.dumps(value))
    return path, [
        "--source",
        f"attestation={attestation}",
        "--source",
        f"current={snapshot}",
        "--source",
        f"review={review}",
    ]


def calls(directory, run, parameters, report):
    (
        fixture,
        suppliers,
        env,
        primary_url,
        executable,
        source,
        dirty,
        deployment,
        environment,
        parent_op,
        parent,
    ) = parameters
    records = []

    def call(
        label,
        operation="inventory",
        extra=(),
        **options,
    ):
        refused = options.get("refused", False)
        parent_dir = directory / f"subject-custody-{len(records)}"
        parent_dir.mkdir(mode=0o700)
        output = parent_dir / "output"
        args = [
            executable,
            "--maintenance-work-id",
            str(uuid4()),
            "--witness-ca",
            fixture["ca"],
            "--primary-ca",
            fixture["ca"],
        ]
        if not options.get("omit_parent"):
            args += [
                "--parent-operation-id",
                str(parent_op),
                "--parent-expected-revision",
                str(parent["revision"]),
            ]
        args += [
            operation,
            "--deployment-id",
            str(uuid4() if options.get("wrong_scope") else deployment),
            "--runtime-role",
            suppliers["names"]["runtime"],
            "--output-dir",
            output,
            "--tool-source-record",
            source,
            "--dirty-input-record",
            dirty,
        ]
        if operation == "inventory":
            args += ["--environment-id", str(environment)]
        process_env = env | {
            "AEGAEON_ORGANIZATION_WITNESS_DATABASE_URL": fixture[
                options.get("login", "maintenance")
            ],
            "AEGAEON_DATABASE_URL": "postgresql://unreachable@localhost:1/unreachable"
            if options.get("broken_primary")
            else primary_url,
        }
        result = run([*args, *extra], environment=process_env, timeout=100)
        records.append({"case": label, "returncode": result.returncode, "stderr": result.stderr})
        report["subject_journey"] = {"cases": records, "passed": False}
        if (result.returncode != 0) != refused or (refused and result.stdout):
            message = f"subject {label} returned an unexpected outcome"
            raise RuntimeError(message)
        if not refused:
            released = json.loads((output / "maintenance/maintenance-released.json").read_text())
            assert released["pending"] is False
            assert released["kind"] == f"subject-{operation}"
            assert json.loads((output / "maintenance/receipt.json").read_text())["primaryClosed"]
        return output

    return call, records


def journey(directory, package, helpers, report, mode):
    root, env, run, sql = helpers
    fixture = json.loads((directory / "fixture.json").read_text())
    suppliers = json.loads((directory / "primary-fixture/suppliers.json").read_text())
    deployment, environment, parent_op, _, parent, _ = prepare(
        sql, json.loads((directory / "runtime.json").read_text())
    )
    executable, binary_digest, source, dirty = identity(
        directory, package, tree_identity(root), "aegaeon-organization-subject-ownership"
    )
    maintenance, primary = urlsplit(suppliers["urls"]["maintenance"]), urlsplit(fixture["primary"])
    primary_url = f"postgresql://{maintenance.username}:{maintenance.password}@localhost:{primary.port}{primary.path}"
    # Retain both the first and renamed subject under one actual permanent UUID.
    sql(
        "primary",
        (  # parsed UUID and generated role from this owned fixture only
            f"BEGIN; SET LOCAL ROLE {suppliers['names']['runtime']}; "  # noqa: S608 — owned role/UUID
            "INSERT INTO aegaeon.end_users(environment_id,subject,status) "
            f"VALUES('{environment}','permanent-owner-first','ACTIVE'); "
            "UPDATE aegaeon.end_users SET subject='permanent-owner-renamed' "
            f"WHERE environment_id='{environment}' AND subject='permanent-owner-first'; COMMIT;"
        ),
        suppliers["names"]["database"],
    )
    # This is a constructed legacy state, not a migration test. The disposable
    # fixture administrator supplies it before opening any tested connection.
    # All triggers/constraints/catalog entries remain enabled in the CLI session.
    sql(
        "primary",
        "BEGIN; SET LOCAL session_replication_role=replica; "  # noqa: S608 — parsed fixture UUID
        f"DELETE FROM aegaeon.subject_ownership_adoptions WHERE environment_id='{environment}'; "
        "UPDATE aegaeon.subject_ownership_namespaces SET origin='legacy' "
        f"WHERE environment_id='{environment}'; COMMIT;",
        suppliers["names"]["database"],
    )
    call, records = calls(
        directory,
        run,
        (
            fixture,
            suppliers,
            env,
            primary_url,
            executable,
            source,
            dirty,
            deployment,
            environment,
            parent_op,
            parent,
        ),
        report,
    )
    call("missing parent refused", refused=True, omit_parent=True)
    call("wrong role refused", refused=True, login="control")
    call("foreign deployment refused", refused=True, wrong_scope=True)
    if mode == "normal":
        exercise(call, directory, sql, suppliers, environment)
        expected_generation = 4
    else:
        call("failed primary retains ownership", refused=True, broken_primary=True)
        expected_generation = 1
    call("pending predecessor excludes next invocation", refused=True)
    pending = json.loads(
        sql("control", f"SELECT organization_witness.maintenance_state('{deployment}')")
    )
    assert pending["pending"] is True
    assert pending["generation"] == expected_generation
    report["subject_journey"] = {
        "passed": True,
        "cases": records,
        "binary_sha256": binary_digest,
        "maintenance_pending": pending,
        "constructed_legacy_fixture": True,
        "migration_test": False,
        "supplier_qualified": False,
    }


def exercise(call, directory, sql, suppliers, environment):
    inventory_dir = call("normal inventory")
    inventory_path = inventory_dir / "inventory.json"
    observed = json.loads(inventory_path.read_text())
    assert {f["subject"] for f in observed["facts"] if f["valid"]} == {
        "permanent-owner-first",
        "permanent-owner-renamed",
    }
    assert len({f["owner_id"] for f in observed["facts"]}) == 1
    path, sources = manifest(directory, inventory_path)
    extra = ["--manifest", path, "--inventory", inventory_path, *sources]
    output = call("normal dry-run adoption", "adopt", extra)
    assert (
        json.loads((output / "disposition.json").read_text())["status"]
        == "validated-and-rolled-back"
    )
    count_sql = (
        "SELECT count(*) FROM aegaeon.subject_ownership_adoptions "  # noqa: S608 — parsed fixture UUID
        f"WHERE environment_id='{environment}'"
    )
    assert sql("primary", count_sql, suppliers["names"]["database"]) == "0"
    commit = [
        *extra,
        "--commit",
        "--expected-manifest-sha256",
        digest(path),
        "--expected-inventory-sha256",
        digest(inventory_path),
    ]
    output = call("normal committed adoption", "adopt", commit)
    assert json.loads((output / "disposition.json").read_text())["status"] == "committed"
    assert sql("primary", count_sql, suppliers["names"]["database"]) == "1"
    call("replayed adoption refused and retained", "adopt", commit, refused=True)
    assert sql("primary", count_sql, suppliers["names"]["database"]) == "1"
