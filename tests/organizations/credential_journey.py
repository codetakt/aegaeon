"""Actual distributed credential inspector on the production TLS/runtime fixture."""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
from urllib.parse import unquote, urlsplit
from uuid import uuid4


def journey(directory, package, env, run, report):
    fixture = json.loads((directory / "fixture.json").read_text())
    bootstrap = json.loads((directory / "bootstrap.json").read_text())
    executable = package / "bin/aegaeon-organization-store-inspect"
    records = []
    private = [unquote(urlsplit(fixture["primary"]).password), env["AEGAEON_KEY_ENCRYPTION_KEY"]]

    def call(label, *, refused=False, environment=None, issuer=None, changes=None):
        result = run(
            [
                executable,
                "credentials",
                "--root-cert",
                fixture["ca"],
                "--environment-id",
                environment or bootstrap["environment"],
                "--issuer",
                issuer or bootstrap["issuer"],
            ],
            environment=env
            | {"AEGAEON_ORGANIZATION_OBSERVATION_DATABASE_URL": fixture["primary"]}
            | (changes or {}),
            timeout=35,
        )
        assert not any(secret in result.stdout + result.stderr for secret in private)
        records.append({"case": label, "returncode": result.returncode})
        report["credential_journey"] = {"cases": records, "passed": False}
        if (result.returncode != 0) != refused:
            message = f"credential command {label} had an unexpected outcome"
            raise RuntimeError(message)
        if refused:
            assert not result.stdout
            return None
        observed = json.loads(result.stdout)
        assert observed["kind"] == "credentials"
        assert observed["activationAuthorized"] is False
        assert observed["observation"]["primaryClosed"] is True
        assert observed["observation"]["environmentId"] == bootstrap["environment"]
        assert observed["observation"]["compatibility"]["runtimeKeysValidated"] > 0
        return observed

    first = call("current native keys and exact runtime catalog")
    call(
        "wrong decryption key",
        refused=True,
        changes={
            "AEGAEON_KEY_ENCRYPTION_KEY": base64.urlsafe_b64encode(secrets.token_bytes(32))
            .decode()
            .rstrip("="),
        },
    )
    call("foreign issuer", refused=True, issuer="https://foreign.example")
    call("foreign Environment", refused=True, environment=str(uuid4()))
    call(
        "unrelated control principal",
        refused=True,
        changes={"AEGAEON_ORGANIZATION_OBSERVATION_DATABASE_URL": fixture["control"]},
    )
    last = call("recovered key repeats readonly inspection")
    assert first["observation"]["compatibility"] == last["observation"]["compatibility"]
    report["credential_journey"] = {
        "passed": True,
        "cases": records,
        "wrapper_sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
        "native_observation": last,
        "activation": False,
        "supplier_qualification": False,
    }
