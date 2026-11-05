"""Actual packaged snapshot ownership, TLS stores and durable failure."""

from __future__ import annotations

import hashlib
import json
import time
from urllib.parse import urlencode, urlsplit
from uuid import uuid4

from history_journey import identity, prepare, tree_identity
from snapshot_preparation import exercise as prepare_exercise

TARGET_DATABASE = "organization_import_target"


def capture_dependencies(directory, sql, database, child):
    """Clone only fixture dependencies, without rewriting native snapshot bytes."""
    deadline = time.monotonic() + 30
    while not (directory / "snapshot-dependencies-ready").exists():
        if child.poll() is not None or time.monotonic() >= deadline:
            message = "native snapshot dependency barrier did not arrive"
            raise RuntimeError(message)
        time.sleep(0.02)
    # Names come from the owned fixture, never snapshot input. Connections are
    # closed before this barrier and the later native source pool is lazy.
    assert database.replace("_", "").isalnum()
    sql("primary", f'CREATE DATABASE {TARGET_DATABASE} TEMPLATE "{database}"', timeout=20)
    ready = directory / "snapshot-dependencies-captured"
    ready.touch(mode=0o600, exist_ok=False)


def primary_connection(directory, preparing):
    fixture = json.loads((directory / "fixture.json").read_text())
    suppliers = json.loads((directory / "primary-fixture/suppliers.json").read_text())
    maintenance = urlsplit(suppliers["urls"]["maintenance"])
    primary = urlsplit(fixture["primary"])
    database_path = f"/{TARGET_DATABASE}" if preparing else primary.path
    primary_url = (
        f"postgresql://{maintenance.username}:{maintenance.password}@localhost:{primary.port}"
        f"{database_path}?{urlencode({'sslrootcert': fixture['ca']})}"
    )
    return suppliers, primary_url, primary.path.removeprefix("/")


def source_issuer(directory):
    for line in (directory / "source-snapshot.jsonl").read_text().splitlines():
        record = json.loads(line)
        if record.get("section") == "namespace":
            return record["data"]["issuer_host"]
    message = "native snapshot namespace is missing"
    raise RuntimeError(message)


def journey(directory, package, helpers, report, *, preparing=False):
    root, env, run, sql = helpers
    fixture = json.loads((directory / "fixture.json").read_text())
    deployment, environment, parent_op, child_op, parent, child = prepare(
        sql,
        json.loads((directory / "runtime.json").read_text()),
        issuer=source_issuer(directory),
    )
    executable, binary_digest, source, dirty = identity(
        directory,
        package,
        tree_identity(root),
        "aegaeon-organization-import-prepare"
        if preparing
        else "aegaeon-organization-import-inspect",
    )
    scope = json.loads((directory / "snapshot-scope.json").read_text())
    snapshot = directory / "source-snapshot.jsonl"
    digest = hashlib.sha256(snapshot.read_bytes()).hexdigest()
    suppliers, primary_url, source_database = primary_connection(directory, preparing)
    records = []

    operation = uuid4()

    def call(label, **options):
        refused = options.get("refused", False)
        parent_dir = directory / f"snapshot-custody-{len(records)}"
        parent_dir.mkdir(mode=0o700)
        output = parent_dir / "output"
        args = [
            executable,
            "--snapshot",
            snapshot,
            "--expected-sha256",
            digest,
            "--environment-id",
            str(environment),
            "--domain-id",
            scope["domain_id"],
            "--deployment-id",
            str(uuid4() if options.get("wrong_scope") else deployment),
            "--parent-operation-id",
            str(parent_op),
            "--parent-expected-revision",
            str(parent["revision"]),
            "--maintenance-work-id",
            str(uuid4()),
            "--witness-ca",
            fixture["ca"],
            "--output-dir",
            output,
            "--tool-source-record",
            source,
            "--dirty-input-record",
            dirty,
        ]
        if preparing:
            preparation_arguments(
                args,
                parent_dir,
                (package, root),
                options,
                (suppliers["names"]["runtime"], operation, deployment, child_op, child["revision"]),
            )
        process_env = env | {
            "AEGAEON_ORGANIZATION_WITNESS_DATABASE_URL": fixture["maintenance"],
            "AEGAEON_DATABASE_URL": (
                "postgresql://unreachable_runtime@localhost:1/unreachable"
                if options.get("broken_primary")
                else primary_url
            ),
        }
        result = run(args, environment=process_env, timeout=40)
        records.append({"case": label, "returncode": result.returncode, "stderr": result.stderr})
        report["snapshot_journey"] = {"cases": records, "passed": False}
        if (result.returncode != 0) != refused or (refused and result.stdout):
            message = f"snapshot {label} returned an unexpected outcome"
            raise RuntimeError(message)
        return output

    if preparing:
        released, pending = prepare_exercise(
            call,
            sql,
            deployment,
            scope,
            (source_database, TARGET_DATABASE),
        )
    else:
        released, pending = exercise(call, sql, deployment)
    report["snapshot_journey"] = {
        "passed": True,
        "cases": records,
        "binary_sha256": binary_digest,
        "source_sha256": digest,
        "normal_released": released,
        "maintenance_pending": pending,
        "inactive_preparation_tested": preparing,
        "source_bytes_rewritten": False,
        "activation_tested": False,
        "prepared_history_inspection_tested": preparing,
        "fixture_history_owners": 0,
        "supplier_qualified": False,
    }


def exercise(call, sql, deployment):
    call("foreign deployment refused before primary", refused=True, wrong_scope=True)
    output = call("normal native source inspection")
    released = json.loads((output / "maintenance-released.json").read_text())
    receipt = json.loads((output / "receipt.json").read_text())
    assert released["pending"] is False
    assert released["generation"] == 1
    assert receipt["inspection"]["sourceGraphChecked"] is True
    assert receipt["inspection"]["activationAuthorized"] is False
    call("primary failure retains owner", refused=True, broken_primary=True)
    call("uncertain predecessor excludes next invocation", refused=True)
    pending = json.loads(
        sql("control", f"SELECT organization_witness.maintenance_state('{deployment}')")
    )
    assert pending["pending"] is True
    assert pending["generation"] == 2
    return released, pending


def recovery_arguments(args, directory, source, fence, operation):
    package, root = source
    deployment, child_op, revision = fence
    inspector, _, inspector_source, inspector_dirty = identity(
        directory,
        package,
        tree_identity(root),
        "aegaeon-organization-import-inspect",
    )
    args[0] = inspector
    args[args.index("--tool-source-record") + 1] = inspector_source
    args[args.index("--dirty-input-record") + 1] = inspector_dirty
    args += [
        "--recovery-operation-id",
        str(child_op),
        "--recovery-deployment-id",
        str(deployment),
        "--recovery-revision",
        str(revision),
        "--prepared-operation-id",
        str(operation),
    ]


def preparation_arguments(args, directory, source, options, target):
    runtime, operation, deployment, child_op, revision = target
    args += ["--target-runtime-role", runtime]
    if options.get("recovery"):
        recovery_arguments(args, directory, source, (deployment, child_op, revision), operation)
    else:
        args += ["--operation-id", str(uuid4() if options.get("conflict") else operation)]
