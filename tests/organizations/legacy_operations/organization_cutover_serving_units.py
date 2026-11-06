"""Bounded actual service start/readiness and closure for retained worker units."""

from __future__ import annotations

import http.client
import json
import time
from http import HTTPStatus
from pathlib import Path

import organization_cutover_startup_inputs as inputs
import organization_cutover_startup_units as units
import organization_recovery as recovery
from organization_recovery_store import require

READY_SECONDS = 60
MAX_RESPONSE = 65536


def running(row: dict) -> dict:
    actual = units.definition(row)
    state = recovery.service_state(row["worker"]["unit"])
    require(
        state["ActiveState"] == "active"
        and state["SubState"] == "running"
        and state["MainPID"].isdecimal()
        and int(state["MainPID"]) > 0
        and state["ControlPID"] == "0",
        "selected worker is not running",
    )
    process = Path("/proc") / state["MainPID"]
    require(
        str((process / "exe").readlink()) == str(inputs.SERVER_BINARY),
        "actual worker executable differs",
    )
    status = dict(line.split(":", 1) for line in (process / "status").read_text().splitlines())
    require(
        [int(v) for v in status["Uid"].split()] == [row["account"]["uid"]] * 4,
        "actual worker identity differs",
    )
    require(
        (process / "cgroup").read_text().strip() == "0::" + state["ControlGroup"],
        "actual worker cgroup differs",
    )
    return {"unit": row["worker"]["unit"], "loaded": actual, "state": state}


def custody(manifest: dict, states: list[dict]) -> None:
    expected = {
        row["account"]["uid"]: state["state"]["ControlGroup"]
        for row, state in zip(manifest["workers"], states, strict=True)
    }
    processes = [p for p in Path("/proc").iterdir() if p.name.isdecimal()]
    require(len(processes) <= units.MAX_PROCESSES, "serving process census bound exceeded")
    for process in processes:
        try:
            status = (process / "status").read_text()
            ids = [line.split()[1:] for line in status.splitlines() if line.startswith("Uid:")]
            require(
                len(ids) == 1 and len(ids[0]) == units.UID_FIELDS,
                "serving process identity incomplete",
            )
            selected = set(map(int, ids[0])).intersection(expected)
            if selected:
                group = (process / "cgroup").read_text().strip()
                require(
                    len(selected) == 1 and group == "0::" + expected[next(iter(selected))],
                    "worker process escaped selected service",
                )
        except FileNotFoundError:
            continue


def request(row: dict, path: str) -> tuple[int, bytes]:
    worker = row["worker"]
    host = {"0.0.0.0": "127.0.0.1", "::": "::1"}.get(worker["host"], worker["host"])  # noqa: S104 — connect to loopback for a configured wildcard listener
    issuer = next(
        item["issuerHost"]
        for item in row["native"]["startupSelectors"]
        if item["environmentId"] == worker["environment_id"]
    )
    connection = http.client.HTTPConnection(host, worker["port"], timeout=2)
    try:
        # The root observer is a trusted local ingress hop. This is an internal
        # readiness check, not evidence about an external TLS terminator.
        connection.request(
            "GET",
            path,
            headers={"Host": issuer, "Connection": "close", "X-Forwarded-Proto": "https"},
        )
        response = connection.getresponse()
        data = response.read(MAX_RESPONSE + 1)
        require(len(data) <= MAX_RESPONSE, "serving readiness response bound exceeded")
        return response.status, data
    finally:
        connection.close()


def ready(manifest: dict) -> list[dict]:
    deadline = time.monotonic() + READY_SECONDS
    for row in manifest["workers"]:
        while True:
            require(time.monotonic() < deadline, "complete worker readiness deadline")
            try:
                status, body = request(row, "/ready")
            except (OSError, http.client.HTTPException):
                status, body = 0, b""
            if status == HTTPStatus.NO_CONTENT and body == b"":
                break
            time.sleep(0.1)
        # Bind the responder to the retained namespace, beyond a generic healthy
        # HTTP status. The immutable native configuration supplied this issuer.
        status, body = request(row, "/.well-known/oauth-authorization-server")
        runtime_path = next(
            item["source"] for item in row["sources"] if item["name"] == "runtime.json"
        )
        runtime = json.loads(recovery.private_file(runtime_path, inputs.MAX_STARTUP))
        issuer = next(
            item["issuer"]
            for item in runtime["environments"]
            if item["id"] == row["worker"]["environment_id"]
        )
        require(
            status == HTTPStatus.OK and json.loads(body)["issuer"] == issuer,
            "serving issuer differs",
        )
    states = [running(row) for row in manifest["workers"]]
    custody(manifest, states)
    return states


def start(manifest: dict) -> list[dict]:
    # The caller has durably registered the complete start intent. systemd starts
    # this bounded group concurrently; no per-worker deadline replenishment.
    for row in manifest["workers"]:
        units.stopped(row)
    units.manager("start", *[row["worker"]["unit"] for row in manifest["workers"]])
    return ready(manifest)


def stop(manifest: dict) -> list[dict]:
    for row in manifest["workers"]:
        units.definition(row)
    units.manager("stop", *[row["worker"]["unit"] for row in manifest["workers"]])
    # Stop can leave an exited failure recorded. It is not execution permission;
    # confirm the unit's processes and cgroup are empty before resetting it.
    failed = []
    for row in manifest["workers"]:
        state = recovery.service_state(row["worker"]["unit"])
        require(state["MainPID"] == state["ControlPID"] == "0", "worker process exit unconfirmed")
        recovery.empty_group(state["ControlGroup"])
        if state["ActiveState"] == "failed":
            failed.append(row["worker"]["unit"])
    # An inactive never-started unit can be garbage-collected after show/stop.
    # reset-failed then rejects it as unloaded; there is no failure to reset.
    if failed:
        units.manager("reset-failed", *failed)
    result = [recovery.stopped(row["worker"]["unit"]) for row in manifest["workers"]]
    units.no_processes({row["account"]["uid"] for row in manifest["workers"]})
    return result
