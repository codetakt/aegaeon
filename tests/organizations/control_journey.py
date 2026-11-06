"""Actual packaged v9 control operations, separated parent/child scopes and roles."""

from __future__ import annotations

import hashlib
import json
import urllib.parse
from uuid import uuid4


def journey(directory, package, env, run, report):
    fixture = json.loads((directory / "fixture.json").read_text())
    config = json.loads((directory / "runtime.json").read_text())
    deployment = config["deployment_id"]
    executable = package / "bin/aegaeon-organization-witness"
    records = []
    secrets = [
        urllib.parse.unquote(urllib.parse.urlsplit(fixture[k]).password)
        for k in ("control", "maintenance")
    ]

    def call(label, action, **options):
        role = options.get("role", "maintenance")
        child = options.get("child")
        target = options.get("target", deployment)
        refused = options.get("refused", False)
        login = options.get("login")
        args = [executable, "--deployment-id", target, "--root-cert", fixture["ca"], "--role", role]
        if child is not None:
            args += ["--environment-id", child]
        result = run(
            [*args, *action],
            environment=env
            | {
                "AEGAEON_ORGANIZATION_WITNESS_DATABASE_URL": fixture[
                    login or ("control" if role == "runtime" else "maintenance")
                ]
            },
            timeout=35,
        )
        if any(secret in result.stdout + result.stderr for secret in secrets):
            message = "control command disclosed a credential"
            raise RuntimeError(message)
        records.append({"case": label, "returncode": result.returncode})
        report["control_journey"] = {"cases": records, "passed": False}
        if (result.returncode != 0) != refused:
            message = f"control command {label} had an unexpected outcome"
            raise RuntimeError(message)
        if refused:
            if result.stdout:
                message = "refused control command emitted a success receipt"
                raise RuntimeError(message)
            return None
        return json.loads(result.stdout)

    checks(call, deployment, config["environments"][0]["id"])
    report["control_journey"] = {
        "passed": True,
        "cases": records,
        "binary_sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
        "expected_generations": [0, 0],
        "activation_authorized": False,
    }


def checks(call, deployment, environment):
    child_state = call("current child catalog", ["status"], role="runtime", child=environment)
    assert child_state["environment_id"] == environment
    assert child_state["deployment_id"] == deployment
    parent = call("current parent", ["deployment", "status"], role="runtime")
    assert parent["deployment_id"] == deployment
    assert parent["phase"] == "active"
    call(
        "parent cannot take child selector",
        ["deployment", "status"],
        child=environment,
        refused=True,
    )
    call("child selector required", ["status"], refused=True)
    call("foreign parent", ["status"], child=environment, target=str(uuid4()), refused=True)
    call(
        "runtime cannot impersonate maintenance",
        ["deployment", "status"],
        login="control",
        refused=True,
    )
    call("runtime cannot inspect pending", ["deployment", "pending"], role="runtime", refused=True)
    pending = call("maintenance pending", ["deployment", "pending"])
    assert pending["state"]["pending"] == 0
    assert pending["admissions"] == []
    fence_checks(call, parent)


def fence_checks(call, parent):
    operation = str(uuid4())
    fence = [
        "deployment",
        "fence",
        "--operation-id",
        operation,
        "--expected-revision",
        str(parent["revision"]),
    ]
    call("runtime cannot fence", fence, role="runtime", refused=True)
    assert call("failed fence preserves parent", ["deployment", "status"], role="runtime") == parent
    fenced = call("maintenance parent fence", fence)
    assert fenced["phase"] == "fenced"
    assert fenced["pending"] == 0
    assert call("exact fence replay", fence) == fenced
    stale = [
        "deployment",
        "fence",
        "--operation-id",
        str(uuid4()),
        "--expected-revision",
        str(parent["revision"]),
    ]
    call("stale conflicting fence", stale, refused=True)
    assert call("stale fence preserves receipt", ["deployment", "status"]) == fenced
    call(
        "parent identity cannot be replaced",
        ["deployment", "initialize", "--operation-id", str(uuid4())],
        refused=True,
    )
    new_child = str(uuid4())
    initialized = call(
        "initialize fenced child", ["initialize", "--operation-id", str(uuid4())], child=new_child
    )
    assert initialized["environment_id"] == new_child
    assert initialized["phase"] == "fenced"
    call(
        "child initialization cannot replay or replace",
        ["initialize", "--operation-id", str(uuid4())],
        child=new_child,
        refused=True,
    )
