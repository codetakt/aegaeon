"""Actual packaged history coordinator, TLS catalog and durable uncertainty."""

from __future__ import annotations

import hashlib
import json
import os
import re
from functools import partial
from pathlib import Path
from uuid import UUID, uuid4

from history_audit_journey import exercise as audit_exercise
from history_restoration import exercise as restore_exercise, setup as restore_setup


def tree_identity(root):
    """Git object hash of the actual fixture source tree, including dirty bytes."""

    def object_hash(kind, data):
        # Git tree labels use SHA-1; executable/source evidence also records SHA-256.
        return hashlib.sha1(kind + b" " + str(len(data)).encode() + b"\0" + data).digest()  # noqa: S324

    entries = []
    for child in root.iterdir():
        if child.name in {".git", "target", "__pycache__", ".direnv"}:
            continue
        name = os.fsencode(child.name)
        if child.is_symlink():
            mode, digest = b"120000", object_hash(b"blob", os.fsencode(child.readlink()))
        elif child.is_dir():
            mode, digest = b"40000", bytes.fromhex(tree_identity(child))
        else:
            mode = b"100755" if child.stat().st_mode & 0o111 else b"100644"
            digest = object_hash(b"blob", child.read_bytes())
        entries.append(
            (name + (b"/" if mode == b"40000" else b""), mode + b" " + name + b"\0" + digest)
        )
    return object_hash(b"tree", b"".join(data for _, data in sorted(entries))).hex()


def prepare(sql, config, *, issuer="history.example.test", seed=None):
    deployment = UUID(config["deployment_id"])
    environment = UUID(config["environments"][0]["id"])
    parent_op, child_op = uuid4(), uuid4()
    parent = json.loads(
        sql("control", f"SELECT organization_witness.deployment_state('{deployment}')")
    )
    child = json.loads(
        sql("control", f"SELECT organization_witness.current_state('{environment}','{deployment}')")
    )
    parent = json.loads(
        sql(
            "control",
            "SELECT organization_witness.deployment_fence("
            f"'{deployment}','{parent_op}',{parent['revision']})",
        )
    )
    child = json.loads(
        sql(
            "control",
            "SELECT organization_witness.fence("
            f"'{environment}','{deployment}','{child_op}',{child['revision']})",
        )
    )
    scope = environment, deployment, child_op, child["revision"]
    if seed is None:
        empty_history(sql, scope, issuer)
    else:
        seed(sql, scope, issuer)
    return deployment, environment, parent_op, child_op, parent, child


def empty_history(sql, scope, issuer):
    environment, deployment, child_op, revision = scope
    initial = hashlib.sha256(
        b"aegaeon-permanent-history-v1\x00"
        + environment.bytes
        + len(issuer).to_bytes(4, "big")
        + issuer.encode()
    ).hexdigest()
    sql(
        "control",
        "SELECT organization_witness.history_begin("
        f"'{environment}','{deployment}','{child_op}',{revision},"
        f"'{issuer}','{uuid4()}','{'1' * 64}','{'2' * 64}',0,0,'{initial}')",
    )
    sql(
        "control",
        "SELECT organization_witness.history_seal("
        f"'{environment}','{deployment}','{child_op}',{revision})",
    )


def identity(directory, package, source_tree, name="aegaeon-organization-history"):
    executable = package / "bin" / name
    paths = re.findall(rf"/nix/store/[a-z0-9.+-]+/bin/{re.escape(name)}", executable.read_text())
    if len(paths) != 1:
        message = "history wrapper must name exactly one immutable executable"
        raise RuntimeError(message)
    actual = Path(paths[0])
    binary_digest = hashlib.sha256(actual.read_bytes()).hexdigest()
    dirty = json.dumps(
        {"binarySha256": binary_digest, "fixture": "history owner finite test"}
    ).encode()
    dirty_path = directory / "history-source-input.json"
    dirty_path.write_bytes(dirty)
    dirty_path.chmod(0o600)
    source = directory / "history-tool-source.json"
    source.write_text(
        json.dumps(
            {
                "tool_sha256": binary_digest,
                "source_commit": None,
                "source_tree": source_tree,
                "dirty_input_sha256": hashlib.sha256(dirty).hexdigest(),
            }
        )
    )
    source.chmod(0o600)
    return executable, binary_digest, source, dirty_path


def journey(directory, package, helpers, report, *, restoring=False):
    root, env, run, sql = helpers
    fixture = json.loads((directory / "fixture.json").read_text())
    deployment, environment, parent_op, child_op, parent, child = prepare_journey(
        directory,
        sql,
        restoring,
    )
    executable, binary_digest, source, dirty_path = identity(
        directory, package, tree_identity(root)
    )
    records = []

    def call(label, action, **options):
        refused = options.get("refused", False)
        login = options.get("login", "maintenance")
        omit_parent = options.get("omit_parent", False)
        primary = options.get("primary")
        parent_dir = directory / f"custody-{len(records)}"
        parent_dir.mkdir(mode=0o700)
        output = parent_dir / "output"
        args = [
            executable,
            "--environment-id",
            str(environment),
            "--deployment-id",
            str(deployment),
            "--operation-id",
            str(child_op),
            "--expected-revision",
            str(child["revision"]),
            "--maintenance-work-id",
            str(uuid4()),
            "--root-cert",
            fixture["ca"],
            "--output-dir",
            output,
            "--tool-source-record",
            source,
            "--dirty-input-record",
            dirty_path,
        ]
        if not omit_parent:
            args += [
                "--parent-operation-id",
                str(parent_op),
                "--parent-expected-revision",
                str(parent["revision"]),
            ]
        process_env = env | {"AEGAEON_ORGANIZATION_WITNESS_DATABASE_URL": fixture[login]}
        if primary:
            process_env["AEGAEON_DATABASE_URL"] = primary
        result = run([*args, *action], environment=process_env, timeout=40)
        records.append({"case": label, "returncode": result.returncode, "stderr": result.stderr})
        report["history_journey"] = {"cases": records, "passed": False}
        if (result.returncode != 0) != refused:
            message = f"history {label} returned an unexpected outcome"
            raise RuntimeError(message)
        if refused and result.stdout:
            message = "refused history command emitted success"
            raise RuntimeError(message)
        return output

    passed = (
        restore_exercise(
            call,
            sql,
            deployment,
            directory,
            partial(
                audit_exercise,
                directory,
                package,
                (env, run, sql, records),
                (deployment, environment, parent_op, child_op, parent, child),
            ),
        )
        if restoring
        else exercise(call, sql, deployment)
    )
    report["history_journey"] = passed | {"cases": records, "binary_sha256": binary_digest}


def exercise(call, sql, deployment):
    call("explicit parent fence required", ["inspect"], refused=True, omit_parent=True)
    call("runtime role refused", ["inspect"], refused=True, login="control")
    output = call("normal retained inspection", ["inspect"])
    released = json.loads((output / "maintenance-released.json").read_text())
    assert released["pending"] is False
    assert released["generation"] == 1
    assert (output / "receipt.json").is_file()
    assert (output / "history.jsonl").is_file()
    call(
        "primary opening failure retains owner",
        [
            "restore",
            "--target-runtime-role",
            "unreachable_runtime",
            "--restoration-operation-id",
            str(uuid4()),
        ],
        refused=True,
        primary="postgresql://unreachable_runtime@localhost:1/unreachable?sslmode=disable",
    )
    call("uncertain predecessor excludes next invocation", ["inspect"], refused=True)
    pending = json.loads(
        sql("control", f"SELECT organization_witness.maintenance_state('{deployment}')")
    )
    assert pending["pending"] is True
    assert pending["generation"] == 2
    return {
        "passed": True,
        "maintenance_pending": pending,
        "normal_released": released,
        "expected_generations": [0, 0],
        "actual_primary_restoration_tested": False,
        "supplier_qualified": False,
    }


def prepare_journey(directory, sql, restoring):
    config = json.loads((directory / "runtime.json").read_text())
    options = restore_setup(directory, config) if restoring else {}
    return prepare(sql, config, **options)
