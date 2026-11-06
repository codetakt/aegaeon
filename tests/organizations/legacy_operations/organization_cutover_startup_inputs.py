"""Derive complete, protected startup inputs from one prepared cutover selection."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import ssl
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import quote

import organization_cutover_plan as plans
import organization_cutover_validation as validation
import organization_recovery as recovery
from organization_recovery_store import require

if TYPE_CHECKING:
    from organization_cutover_epochs import Work

MAX_WORKERS = validation.MAX_ENVIRONMENTS
MAX_TRUST = 8
MAX_ORIGIN = 2048
MAX_CERT = 65536
MAX_STARTUP = 1024 * 1024
LAUNCHER = Path("@selectedWorkerLauncher@")
SERVER = Path("@selectedWorkerServer@")
SERVER_BINARY = Path("@selectedWorkerBinary@")
SHARED_STORES = json.loads(Path(__file__).with_name("organization_runtime_stores.json").read_text())


def settings(value: dict, epoch: dict) -> None:
    require(
        set(value) == {"version", "workers", "delivery_trust"} and value["version"] == 1,
        "exact startup settings required",
    )
    workers = value["workers"]
    require(
        type(workers) is list and 0 < len(workers) <= MAX_WORKERS,
        "bounded worker inventory required",
    )
    for row in workers:
        require(
            set(row) == {"unit", "user", "environment_id", "host", "port"}
            and re.fullmatch(r"aegaeon-organization-runtime-[a-z0-9-]{1,64}\.service", row["unit"])
            and re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", row["user"])
            and row["user"] != "root"
            and type(row["port"]) is int
            and 1 <= row["port"] <= validation.MAX_PORT,
            "explicit dedicated worker settings required",
        )
        require(
            str(ipaddress.ip_address(row["host"])) == row["host"] and "%" not in row["host"],
            "canonical listener address required",
        )
    require(
        len({row["unit"] for row in workers}) == len(workers)
        and len({row["environment_id"] for row in workers}) == len(workers)
        and {row["environment_id"] for row in workers}
        == {row["environment_id"] for row in epoch["children"]}
        and len({(row["host"], row["port"]) for row in workers}) == len(workers),
        "complete unique startup inventory required",
    )
    trust = value["delivery_trust"]
    require(type(trust) is list and len(trust) <= MAX_TRUST, "delivery trust budget exceeded")
    for row in trust:
        require(
            set(row) == {"origin", "root_cert_file"}
            and type(row["origin"]) is str
            and len(row["origin"]) <= MAX_ORIGIN
            and re.fullmatch(r"https://[a-z0-9-]+(?:\.[a-z0-9-]+)+", row["origin"]),
            "explicit canonical delivery origin required",
        )
        recovery.protected_path(row["root_cert_file"])
    require(len({row["origin"] for row in trust}) == len(trust), "duplicate delivery origin")


def certificates(settings: dict, configuration: dict) -> list[dict]:
    sources = [{"name": "root-cert", "source": configuration["root_cert_file"]}]
    sources += [
        {
            "name": f"delivery-root-{index:02d}",
            "source": row["root_cert_file"],
            "origin": row["origin"],
        }
        for index, row in enumerate(settings["delivery_trust"])
    ]
    for source in sources:
        data = recovery.private_file(source["source"], MAX_CERT)
        # Validate actual supplied certificate bytes before registering publication;
        # runtime still loads and validates the copied bytes with its own parser.
        trust = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        trust.load_verify_locations(cadata=data.decode())
        require(trust.get_ca_certs(binary_form=True), "empty startup certificate authority")
        source["sha256"] = hashlib.sha256(data).hexdigest()
    return sources


def documents(work: Work, worker: dict, certificate_sources: list[dict]) -> dict:
    context, epoch = work.context, work.epoch
    configuration = context.configuration
    directory = f"/run/credentials/{worker['unit']}"
    ca = directory + "/root-cert"
    primary = validation.endpoint(configuration["primary"], context.principals["primary_runtime"])
    control = validation.endpoint(configuration["control"], context.principals["control_runtime"])
    target, principal = configuration["token"], context.plan.value["token"]
    token = (
        f"rediss://{quote(principal['name'], safe='')}:{quote(principal['password'], safe='')}"
        f"@{target['host']}:{target['port']}/{context.new.identity['database']}"
    )
    runtime = {
        "version": 1,
        "deployment_id": epoch["deployment_id"],
        "selection": epoch["parent"]["selection"],
        "control": {"url": control, "root_cert": ca},
        "primary": {"url": primary, "root_cert": ca},
        "token": {"url": token, "root_cert": ca},
        "environments": [
            {
                "id": row["environment_id"],
                "issuer": row["issuer"],
                "selection": row["transition"]["selection"],
            }
            for row in epoch["children"]
        ],
        "delivery_trust": [
            {"origin": row["origin"], "root_cert": directory + "/" + row["name"]}
            for row in certificate_sources
            if "origin" in row
        ],
    }
    launch = {
        "version": 1,
        "unit": worker["unit"],
        "environmentId": worker["environment_id"],
        "host": worker["host"],
        "port": worker["port"],
        "runtimeSha256": hashlib.sha256(plans.canonical(runtime)).hexdigest(),
        "environment": {
            **dict.fromkeys(SHARED_STORES, token),
            "AEGAEON_DATABASE_URL": primary,
            # Filled only from the actual native parser's complete selector
            # receipt. A raw Python netloc differs for IDNA/default ports/case.
            "AEGAEON_RUNTIME_ISSUER_HOST": "",
            "AEGAEON_ORGANIZATION_RUNTIME_CONFIG": directory + "/runtime.json",
            "AEGAEON_KEY_ENCRYPTION_KEY": recovery.private_file(
                configuration["key_encryption_key_file"]
            )
            .decode()
            .rstrip("\n"),
        },
        "certificates": [
            {"name": row["name"], "sha256": row["sha256"]} for row in certificate_sources
        ],
    }
    require(
        len(plans.canonical(runtime)) <= MAX_STARTUP
        and len(plans.canonical(launch)) <= MAX_STARTUP,
        "startup document bound exceeded",
    )
    return {"runtime": runtime, "launch": launch}


def bind_selectors(work: Work, built: dict, worker: dict, selectors: list) -> None:
    require(
        type(selectors) is list
        and len(selectors) == len(work.epoch["children"])
        and all(set(row) == {"environmentId", "issuerHost"} for row in selectors)
        and [row["environmentId"] for row in selectors]
        == [row["environment_id"] for row in work.epoch["children"]]
        and all(
            type(row["issuerHost"]) is str
            and 0 < len(row["issuerHost"]) <= validation.MAX_ISSUER
            and row["issuerHost"].isascii()
            and all("!" <= c <= "~" for c in row["issuerHost"])
            for row in selectors
        ),
        "complete native startup selectors required",
    )
    selected = [row for row in selectors if row["environmentId"] == worker["environment_id"]]
    require(len(selected) == 1, "exact native worker selector required")
    built["launch"]["environment"]["AEGAEON_RUNTIME_ISSUER_HOST"] = selected[0]["issuerHost"]
