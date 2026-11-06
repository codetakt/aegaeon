"""Bounded startup inventory and fresh-runtime credential derivation regressions."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from uuid import uuid4

import pytest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--operations", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--store-inventory", type=Path, required=True)
    args = parser.parse_args()
    sys.path.insert(0, str(args.operations))
    import organization_cutover_startup_inputs as inputs  # noqa: PLC0415
    from organization_recovery_store import RecoveryRefusedError  # noqa: PLC0415

    assert (
        sorted(
            set(re.findall(r'"(AEGAEON_[A-Z0-9_]+_REDIS_URL)"', args.store_inventory.read_text()))
        )
        == inputs.SHARED_STORES
    )
    assert "AEGAEON_TOKEN_STORE_REDIS_URL" in inputs.SHARED_STORES
    ids = [str(uuid4()), str(uuid4())]
    epoch = {"children": [{"environment_id": value} for value in ids]}
    workers = [
        {
            "unit": f"aegaeon-organization-runtime-fixture-{index}.service",
            "user": f"fixture{index}",
            "environment_id": value,
            "host": "127.0.0.1",
            "port": 18080 + index,
        }
        for index, value in enumerate(ids)
    ]
    settings = {"version": 1, "workers": workers, "delivery_trust": []}
    inputs.settings(settings, epoch)
    for field, value in [
        ("unit", "../../foreign.service"),
        ("unit", "aegaeon-organization-runtime-x.service\nExecStart=evil"),
        ("user", "root"),
        ("port", True),
        ("port", 65536),
        ("host", "localhost"),
        ("host", "127.0.0.1 --injected"),
        ("environment_id", str(uuid4())),
        ("url", "postgresql://maintenance@foreign.example/primary"),
    ]:
        changed = json.loads(json.dumps(settings))
        changed["workers"][0][field] = value
        with pytest.raises((RecoveryRefusedError, ValueError)):
            inputs.settings(changed, epoch)
    for selected in [workers[:1], [workers[0], workers[0]]]:
        with pytest.raises(RecoveryRefusedError):
            inputs.settings(dict(settings, workers=selected), epoch)
    for origin in [
        "http://example.test",
        "https://localhost",
        "https://x.example:8443",
        "https://u:p@x.example",
        "https://x.example/path",
    ]:
        with pytest.raises(RecoveryRefusedError):
            inputs.settings(
                dict(
                    settings, delivery_trust=[{"origin": origin, "root_cert_file": "/unused.pem"}]
                ),
                epoch,
            )
    revision_capacity()
    activation_timestamps()
    inventory_bound(inputs, workers[0])
    derive(inputs, settings, epoch)
    args.output.write_text(
        json.dumps(
            {
                "passed": True,
                "invalid_worker_inputs": 11,
                "invalid_trust_origins": 5,
                "derived_runtime_inventory": 2,
                "supplierQualification": False,
            }
        )
        + "\n"
    )


def inventory_bound(inputs, template):
    import organization_cutover_validation as validation  # noqa: PLC0415
    from organization_recovery_store import RecoveryRefusedError  # noqa: PLC0415

    config = {
        "version": 1,
        "roles": {
            key: key for key in ("control_runtime", "control_maintenance", "primary_runtime")
        },
        "root_cert_file": "/private/ca",
        "key_encryption_key_file": "/private/key",
        "control": {"host": "control.example", "port": 5432, "database": "control"},
        "primary": {"host": "primary.example", "port": 5432, "database": "primary"},
        "token": {"host": "token.example", "port": 6380},
    }
    for count in (32, 33):
        ids = sorted(str(uuid4()) for _ in range(count))
        config["environments"] = [
            {"id": value, "issuer": f"https://issuer{index}.example/"}
            for index, value in enumerate(ids)
        ]
        epoch = {"children": [{"environment_id": value} for value in ids]}
        workers = [
            dict(
                template,
                unit=f"aegaeon-organization-runtime-bound-{index}.service",
                user=f"fixture{index}",
                port=18080 + index,
                environment_id=value,
            )
            for index, value in enumerate(ids)
        ]
        settings = {"version": 1, "workers": workers, "delivery_trust": []}
        if count == 32:
            validation.settings(config)
            inputs.settings(settings, epoch)
        else:
            with pytest.raises(RecoveryRefusedError):
                validation.settings(config)
            with pytest.raises(RecoveryRefusedError):
                inputs.settings(settings, epoch)


def activation_timestamps():
    from organization_cutover_activation import canonical_receipt  # noqa: PLC0415
    from organization_recovery_store import RecoveryRefusedError  # noqa: PLC0415

    original = {
        "selection": {
            "bindings": [{"principal": "selected", "bound_at": "2026-11-04T09:00:00.123456+09:00"}]
        }
    }
    utc = {
        "selection": {
            "bindings": [{"principal": "selected", "bound_at": "2026-11-04T00:00:00.123456Z"}]
        }
    }
    assert original != utc  # Prior whole-JSON comparison refuses the same stored instant.
    assert canonical_receipt(original) == canonical_receipt(utc)
    for field, value in (("bound_at", "2026-11-04T00:00:00.123457Z"), ("principal", "foreign")):
        changed = json.loads(json.dumps(utc))
        changed["selection"]["bindings"][0][field] = value
        assert canonical_receipt(original) != canonical_receipt(changed)
    for value in ("2026-11-04T00:00:00", "2026-11-04T00:00:00.1234567Z", "invalid"):
        changed = json.loads(json.dumps(utc))
        changed["selection"]["bindings"][0]["bound_at"] = value
        with pytest.raises(RecoveryRefusedError):
            canonical_receipt(changed)


def revision_capacity():
    from organization_cutover_epoch_inputs import revision_capacity as check  # noqa: PLC0415
    from organization_recovery_store import RecoveryRefusedError  # noqa: PLC0415

    original = {"parent": {"revision": 2**63 - 4}, "children": [{"revision": 2**63 - 4}]}
    check(original)
    for row in [original["parent"], *original["children"]]:
        for value in (2**63 - 3, 2**63 - 2, 0, True):
            row["revision"] = value
            with pytest.raises(RecoveryRefusedError):
                check(original)
        row["revision"] = 2**63 - 4


def derive(inputs, settings, epoch):
    import organization_cutover_plan as plans  # noqa: PLC0415
    import organization_cutover_validation as validation  # noqa: PLC0415

    epoch["deployment_id"] = str(uuid4())
    selection = {
        "epoch": str(uuid4()),
        "primary": str(uuid4()),
        "token_store": str(uuid4()),
        "source_sha256": "a" * 64,
        "history_sha256": "b" * 64,
        "acceptance_sha256": "c" * 64,
    }
    epoch["parent"] = {"selection": selection}
    for index, row in enumerate(epoch["children"]):
        row.update(
            issuer=f"https://issuer{index}.example/",
            transition={"selection": dict(selection, epoch=str(uuid4()))},
        )
    configuration = {
        name: {"host": name + ".example", "port": 5432, "database": name}
        for name in ["control", "primary"]
    }
    configuration.update(
        token={"host": "token.example", "port": 6380}, key_encryption_key_file="/private/key"
    )
    principals = {
        name: {"new": name, "password": name + "-nonproduction-material"}
        for name in ["control_runtime", "control_maintenance", "primary_runtime"]
    }
    context = SimpleNamespace(
        configuration=configuration,
        principals=principals,
        plan=plans.Plan(
            {"token": {"name": "fresh_runtime", "password": "fixture-token-material"}}, "a" * 64
        ),
        new=SimpleNamespace(identity={"database": 0}),
    )
    work = SimpleNamespace(context=context, epoch=epoch)
    sources = [{"name": "root-cert", "sha256": "a" * 64}]
    with patch.object(
        inputs.recovery, "private_file", return_value=b"fixture-encryption-material\n"
    ):
        for worker in settings["workers"]:
            built = inputs.documents(work, worker, sources)
            assert all(
                built["launch"]["environment"][name] == built["runtime"]["token"]["url"]
                for name in inputs.SHARED_STORES
            )
            assert built["launch"]["environment"]["AEGAEON_RUNTIME_ISSUER_HOST"] == ""
            selectors = [
                {"environmentId": row["environment_id"], "issuerHost": f"issuer{index}.example"}
                for index, row in enumerate(epoch["children"])
            ]
            inputs.bind_selectors(work, built, worker, selectors)
            assert built["launch"]["environment"]["AEGAEON_RUNTIME_ISSUER_HOST"] == next(
                row["issuerHost"]
                for row in selectors
                if row["environmentId"] == worker["environment_id"]
            )
            selector_refusals(inputs, work, built, worker, selectors)
            assert built["runtime"]["selection"] == epoch["parent"]["selection"]
            assert len(built["runtime"]["environments"]) == 2
            assert built["runtime"]["control"]["url"] == validation.endpoint(
                configuration["control"], principals["control_runtime"]
            )
            assert principals["control_maintenance"]["password"] not in json.dumps(built)
            assert built["launch"]["environmentId"] == worker["environment_id"]
            assert (
                built["launch"]["environment"]["AEGAEON_ORGANIZATION_RUNTIME_CONFIG"]
                == f"/run/credentials/{worker['unit']}/runtime.json"
            )


def selector_refusals(inputs, work, built, worker, selectors):
    from organization_recovery_store import RecoveryRefusedError  # noqa: PLC0415

    invalid = [None, selectors[:1], list(reversed(selectors))]
    for field, value in [
        ("environmentId", str(uuid4())),
        ("issuerHost", ""),
        ("issuerHost", "foreign.example\nINJECTED=yes"),
        ("issuerHost", "bücher.example"),
        ("issuerHost", "issuer.example\x7f"),
        ("extra", "unregistered"),
    ]:
        changed = json.loads(json.dumps(selectors))
        changed[0][field] = value
        invalid.append(changed)
    before = json.dumps(built)
    for value in invalid:
        with pytest.raises(RecoveryRefusedError):
            inputs.bind_selectors(work, built, worker, value)
        assert json.dumps(built) == before


if __name__ == "__main__":
    main()
