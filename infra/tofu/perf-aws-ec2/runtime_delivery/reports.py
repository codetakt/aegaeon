"""Fixed guest delivery reports responsibility."""

from __future__ import annotations

import hashlib
import json
import math
import re
import uuid
from typing import TYPE_CHECKING, Any, cast

if TYPE_CHECKING:
    from pathlib import Path

from runtime_delivery.common import (
    MAX_DURATION_SECONDS,
    absolute_path,
    duration_seconds,
    fail,
    https_origin,
    json_object,
    single_line,
)
from runtime_delivery.filesystem import atomic_write, protected_path

LOADTEST_NAMES = (
    "SERVER_URL",
    "SERVER_IMAGE",
    "ARTIFACT_BUCKET",
    "ARTIFACT_PREFIX",
    "WORKERS",
    "RPS",
    "RUN_TIME",
    "WARMUP",
    "SCENARIO",
    "LOADTEST_BIN",
)

SCENARIOS = {
    "smoke": "Smoke",
    "auth-code": "AuthorizationCode",
    "introspection": "Introspection",
    "revocation": "Revocation",
    "dpop": "DPoP",
    "userinfo": "Userinfo",
    "discovery": "Discovery",
    "jwks": "Jwks",
    "par": "PAR",
    "mixed": "Mixed",
    "policy-mixed": "PolicyMixed",
    "key-rotation": "KeyRotation",
}


MAX_WORKERS = 4294967295
REPORT_SCHEMA_VERSION = 2
REPORT_UUID_VERSION = 4


IMAGE_REGISTRY_LABEL = r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?"
IMAGE_PATH_COMPONENT = r"[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*"
IMAGE_REFERENCE = re.compile(
    rf"{IMAGE_REGISTRY_LABEL}(?:[.]{IMAGE_REGISTRY_LABEL})*(?::[0-9]+)?/"
    rf"(?P<repository>{IMAGE_PATH_COMPONENT}(?:/{IMAGE_PATH_COMPONENT})*)"
    r"@sha256:[0-9a-f]{64}"
)
MAX_IMAGE_REPOSITORY_LENGTH = 255


def validate_run_config(raw: str | bytes | bytearray, issuer: str) -> dict[str, Any]:
    config = json_object(raw)
    if set(config) != set(LOADTEST_NAMES) | {"artifact"} or not all(
        single_line(config[name]) for name in LOADTEST_NAMES
    ):
        fail("exact loadtest config required")
    if config["SERVER_URL"] != issuer or https_origin(config["SERVER_URL"]) != issuer:
        fail("loadtest issuer mismatch")
    image = IMAGE_REFERENCE.fullmatch(config["SERVER_IMAGE"])
    if image is None or len(image["repository"]) > MAX_IMAGE_REPOSITORY_LENGTH:
        fail("immutable loadgen image required")
    absolute_path(config["LOADTEST_BIN"])
    if not re.fullmatch("[1-9][0-9]*", config["WORKERS"]):
        fail("canonical positive worker integer required")
    if not re.fullmatch(
        "(?:0|[1-9][0-9]*)(?:\\.[0-9]+)?(?:e[+-]?(?:0|[1-9][0-9]*))?", config["RPS"]
    ):
        fail("canonical positive decimal RPS required")
    workers, rps = (int(config["WORKERS"]), float(config["RPS"]))
    if (
        workers > MAX_WORKERS
        or not math.isfinite(rps)
        or rps <= 0
        or (workers / rps > MAX_DURATION_SECONDS)
    ):
        fail("worker/rate outside CLI bounds")
    duration_seconds(config["RUN_TIME"])
    duration_seconds(config["WARMUP"], warmup=True)
    if config["SCENARIO"] not in SCENARIOS:
        fail("unsupported selection")
    if (
        not re.fullmatch("[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", config["ARTIFACT_BUCKET"])
        or any(v in {"", ".", ".."} for v in config["ARTIFACT_PREFIX"].rstrip("/").split("/"))
        or (not re.fullmatch("[A-Za-z0-9_./-]+/", config["ARTIFACT_PREFIX"]))
    ):
        fail("artifact destination")
    return config


def validate_config_witness(identity: dict[str, Any], config: dict[str, Any]) -> str:
    witness = identity.get("config_json")
    if not isinstance(witness, str) or not witness:
        fail("producer config byte witness required")
    if hashlib.sha256(witness.encode()).hexdigest() != identity.get("config_sha256"):
        fail("producer config witness digest")
    parsed = json_object(witness)
    keys = {
        "target_url",
        "discovery_expected_issuer",
        "workers",
        "duration",
        "target_rps",
        "warmup_duration",
        "scenario",
        "debug",
    }
    if set(parsed) != keys:
        fail("producer config schema")
    if (
        parsed["target_url"] != config["SERVER_URL"]
        or parsed["discovery_expected_issuer"] is not None
        or type(parsed["workers"]) is not int
        or (parsed["workers"] != int(config["WORKERS"]))
        or (parsed["debug"] is not False)
        or (parsed["scenario"] != SCENARIOS[config["SCENARIO"]])
    ):
        fail("producer config argv/default binding")
    rps = parsed["target_rps"]
    if (
        type(rps) not in {int, float}
        or not math.isfinite(float(rps))
        or float(rps) != float(config["RPS"])
    ):
        fail("producer f64 RPS binding")
    for name, field, warmup in (
        ("duration", "RUN_TIME", False),
        ("warmup_duration", "WARMUP", True),
    ):
        duration = parsed[name]
        if (
            not isinstance(duration, dict)
            or set(duration) != {"secs", "nanos"}
            or type(duration["secs"]) is not int
            or (type(duration["nanos"]) is not int)
            or (duration["secs"] != duration_seconds(config[field], warmup=warmup))
            or (duration["nanos"] != 0)
        ):
            fail("producer duration binding")
    return cast("str", identity["config_sha256"])


def verify_report(output: Path, generation: Path, run_id: str) -> None:
    config_raw = protected_path(output / "driver-config.json", regular=True).read_bytes()
    config = json_object(config_raw)
    report_raw = protected_path(output / "report.json", regular=True).read_bytes()
    report = json_object(report_raw)
    if (
        report.get("schema_version") != REPORT_SCHEMA_VERSION
        or type(report.get("schema_version")) is not int
        or report.get("request_unit") != "scenario_invocations"
        or (report.get("memory_subject") != "load_generator_process")
        or (report.get("selected_scenario") != SCENARIOS[config["SCENARIO"]])
    ):
        fail("report interface/selection")
    identity = report.get("identity")
    keys = {
        "source_sha256",
        "artifact_sha256",
        "config_sha256",
        "config_json",
        "report_id",
        "report_path",
        "profile_sha256",
        "session_provenance_sha256",
    }
    if not isinstance(identity, dict) or set(identity) != keys:
        fail("report identity schema")
    if (
        identity["source_sha256"] != config["artifact"]["source_manifest_sha256"]
        or identity["artifact_sha256"] != config["artifact"]["executable_sha256"]
        or identity["report_path"] != "/results/report.json"
    ):
        fail("report artifact/source/path binding")
    report_id = identity["report_id"]
    if (
        not isinstance(report_id, str)
        or str(uuid.UUID(report_id)) != report_id
        or uuid.UUID(report_id).version != REPORT_UUID_VERSION
    ):
        fail("report UUID")
    config_sha = validate_config_witness(identity, config)
    supply = json_object(
        protected_path(generation / "client.version.json", regular=True).read_bytes()
    )
    needs_profile = config["SCENARIO"] not in {"smoke", "discovery", "jwks", "key-rotation"}
    for field, receipt_field in (
        ("profile_sha256", "profile_sha256"),
        ("session_provenance_sha256", "provenance_sha256"),
    ):
        expected = supply[receipt_field] if needs_profile else None
        if identity[field] != expected:
            fail("report profile/provenance binding")
    receipt = {
        "schema_version": 1,
        "status": "identities-bound",
        "run_id": run_id,
        "report_id": report_id,
        "report_sha256": hashlib.sha256(report_raw).hexdigest(),
        "driver_config_sha256": hashlib.sha256(config_raw).hexdigest(),
        "producer_config_sha256": config_sha,
        "image": config["SERVER_IMAGE"],
        "entrypoint": config["LOADTEST_BIN"],
        "artifact": config["artifact"],
        "client_supply": supply,
        "qualification": (
            "Identity/config wiring only; actual build/supplier/runtime/performance "
            "acceptance is external"
        ),
    }
    atomic_write(output / "run-receipt.json", json.dumps(receipt).encode())
