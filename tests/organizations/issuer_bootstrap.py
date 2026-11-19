"""Initialize the actual protocol fixture with its packaged, schema-guarded CLI."""

from __future__ import annotations

import hashlib
import json
from urllib.parse import quote

HOST = "auth.example.test"


def initialize(package, directory, primary_url, environment, run):
    launcher = package / "bin/aegaeon-management-init"
    manifest = package / "share/aegaeon/aegaeon-management-init.json"
    payload = {
        "ownerEmail": "owner@example.test",
        "ownerPassword": "Independent-Fixture-Password-7!",
        "allowedOrigins": ["https://admin.example.test"],
        "issuerBaseDomain": "generated.example.test",
        "issuerHost": HOST,
    }
    selected = environment | {
        "AEGAEON_DATABASE_URL": primary_url
        + "?sslmode=verify-full&sslrootcert="
        + quote(str(directory / "trusted.crt"), safe=""),
    }
    invalid = [
        json.dumps(payload | {"issuerHost": None}),
        json.dumps(payload | {"issuerHost": "127.1"}),
        json.dumps(payload | {"issuerUrl": "https://other.example.test"}),
        json.dumps(payload)[:-1] + ',"issuerHost":"other.example.test"}',
        "x" * 16_385,
    ]
    for data in invalid:
        refused = run([launcher], environment=selected, data=data, timeout=30)
        if refused.returncode == 0 or payload["ownerPassword"] in refused.stdout + refused.stderr:
            message = "invalid initialization was accepted or exposed its password"
            raise RuntimeError(message)
    result = run([launcher], environment=selected, data=json.dumps(payload), timeout=60)
    if result.returncode != 0:
        message = "packaged issuer initialization failed"
        raise RuntimeError(message)
    initialized = json.loads(result.stdout)
    if (
        initialized["issuerHost"] != HOST
        or payload["ownerPassword"] in result.stdout + result.stderr
    ):
        message = "initializer issuer or secret-output contract failed"
        raise RuntimeError(message)
    receipt = directory / "initialization-receipt.json"
    with receipt.open("x") as stream:
        json.dump(initialized, stream)
    return {
        "issuer": "https://" + HOST,
        "environment": initialized["environmentId"],
        "initialization": initialized,
        "launcher_sha256": hashlib.sha256(launcher.read_bytes()).hexdigest(),
        "manifest": json.loads(manifest.read_text()),
        "invalid_inputs_refused": len(invalid),
        "passed": True,
    }
