"""Second dedicated worker group and HTTP checks after ordinary forward cutover."""

from __future__ import annotations

import json
import os
import pwd
import shutil
from contextlib import contextmanager
from uuid import uuid4

import pytest
from cutover_serving_probe import run
from delivery_journey import Management


@contextmanager
def workers(directory):
    import organization_cutover_plan as plans  # noqa: PLC0415
    import organization_cutover_startup_units as units  # noqa: PLC0415
    import organization_recovery as recovery  # noqa: PLC0415

    epoch = json.loads(recovery.private_file(directory / "epochs.json"))
    users, selected = [], []
    try:
        for index, child in enumerate(epoch["children"]):
            name = "aegtest_" + uuid4().hex[:16]
            run(
                "useradd",
                "--system",
                "--user-group",
                "--no-create-home",
                "--home-dir",
                "/nonexistent",
                "--shell",
                shutil.which("nologin"),
                name,
            )
            users.append(name)
            selected.append(
                {
                    "unit": "aegaeon-organization-runtime-forward-" + uuid4().hex + ".service",
                    "user": name,
                    "environment_id": child["environment_id"],
                    "host": "127.0.0.1",
                    "port": 19180 + index,
                }
            )
        descriptor = plans.directory(directory)
        try:
            recovery.retain(
                descriptor,
                "startup-fixture.json",
                {
                    "version": 1,
                    "workers": selected,
                    "delivery_trust": [],
                },
            )
        finally:
            os.close(descriptor)
        yield selected
    finally:
        for worker in selected:
            unit = units.UNIT_DIRECTORY / worker["unit"]
            if unit.exists():
                run("systemctl", "stop", worker["unit"])
                unit.unlink()
        run("systemctl", "daemon-reload")
        for name in users:
            run("userdel", name)
            with pytest.raises(KeyError):
                pwd.getpwnam(name)


def accepted_work(selected, bootstrap, accepted):
    worker = next(row for row in selected if row["environment_id"] == accepted["environmentId"])
    api = Management(worker["port"], bootstrap)
    api.path = api.base + "/organization-domains/" + accepted["domainId"]
    api.cookie = accepted["sessionCookie"]
    api.call("GET", api.path + "/operators", expected=401)
    api.cookie = ""
    api.call(
        "POST",
        "/api/v1/authentication/sessions",
        {
            "email": "owner@example.test",
            "password": "Independent-Fixture-Password-7!",
        },
        expected=204,
    )
    # Restore preserves the original configure/provision grant. Reading objects
    # requires a separate explicit reconcile capability, even for a Team owner.
    api.call("GET", api.path + "/organizations/" + accepted["organizationId"], expected=403)
    grants, _ = api.call("GET", api.path + "/operators")
    assert len(grants["operators"]) == 1
    grant = grants["operators"][0]
    assert set(grant["capabilities"]) == {"configure", "provision"}
    api.call(
        "PATCH",
        api.path + "/operators/" + grant["id"],
        {
            "active": True,
            "capabilities": ["configure", "provision", "reconcile"],
            "reason": "explicit reconciliation after restored authority check",
        },
        tag=f'"{grant["id"]}.{grant["revision"]}"',
        key="forward-reconcile",
    )
    previous, _ = api.call("GET", api.path + "/organizations/" + accepted["organizationId"])
    assert previous["id"] == accepted["organizationId"]
    assert previous["externalId"] == accepted["externalId"]
    external = "Forward/保持-" + uuid4().hex
    current, _ = api.call(
        "POST",
        api.path + "/organizations",
        {
            "externalId": external,
            "reason": "new work after forward recovery",
        },
        key="forward-organization",
    )
    assert current["externalId"] == external
    assert current["id"] != previous["id"]
    return {"http": api.journal, "minimumOwnedGenerations": api.counts}
