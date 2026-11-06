"""Actual selected-state ownership CLI, including active-worker exclusion."""

from __future__ import annotations

import json
from urllib.parse import urlsplit
from uuid import uuid4

import psycopg
from history_journey import identity, tree_identity


def exercise(directory, package, suppliers, admin_url, helpers):
    root, env, run = helpers
    selected = json.loads((directory / "runtime.json").read_text())
    runtime = urlsplit(selected["primary"]["url"])
    maintenance = urlsplit(suppliers["urls"]["maintenance"])
    endpoint = (
        f"postgresql://{maintenance.username}:{maintenance.password}"
        f"@localhost:{runtime.port}{runtime.path}"
    )
    executable, _, source, dirty = identity(
        directory, package, tree_identity(root), "aegaeon-organization-subject-ownership"
    )
    results = []
    with psycopg.connect(admin_url, autocommit=True) as lock:
        for label in ("active-worker", "wrong-generation", "inventory"):
            if label == "active-worker":
                lock.execute("SELECT pg_advisory_lock_shared(1095189836,1)")
            output = directory / ("maintenance-" + label)
            command = [
                executable,
                "--generation",
                str(uuid4()) if label == "wrong-generation" else selected["generation"],
                "--primary-ca",
                selected["primary"]["root_cert"],
                "inventory",
                "--deployment-id",
                selected["deployment_id"],
                "--runtime-role",
                suppliers["names"]["runtime"],
                "--environment-id",
                selected["environments"][0]["id"],
                "--output-dir",
                output,
                "--tool-source-record",
                source,
                "--dirty-input-record",
                dirty,
            ]
            result = run(command, environment=env | {"AEGAEON_DATABASE_URL": endpoint}, timeout=100)
            results.append({"case": label, "returncode": result.returncode})
            expected = label == "inventory"
            assert (result.returncode == 0) == expected, result.stderr
            if expected:
                receipt = json.loads((output / "selected-runtime.json").read_text())
                assert receipt["generation"] == selected["generation"]
                assert receipt["activationAuthorized"] is False
                assert (output / "inventory.json").is_file()
            else:
                assert not result.stdout
                assert not (output / "inventory.json").exists()
            if label == "active-worker":
                lock.execute("SELECT pg_advisory_unlock_shared(1095189836,1)")
    return results
