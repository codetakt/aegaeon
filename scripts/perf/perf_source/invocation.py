"""Independent effective invocation and report identity bindings."""

from __future__ import annotations

import math
import os
import re
import uuid
from typing import TYPE_CHECKING, Any, Protocol

from .boundaries import checked_output, output_path, require_fresh_outputs
from .io import (
    MAX_RUN_SECONDS,
    NANOS_PER_SECOND,
    UUID_VERSION,
    canonical,
    digest,
    fail,
    load_json,
    publish,
    required,
    stamp,
    strict_json,
)

if TYPE_CHECKING:
    import pathlib

    from .dependencies import Dependencies

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

CONFIG_FIELDS = {
    "target_url",
    "discovery_expected_issuer",
    "workers",
    "duration",
    "target_rps",
    "warmup_duration",
    "scenario",
    "debug",
}

IDENTITY_FIELDS = {
    "source_sha256",
    "artifact_sha256",
    "config_sha256",
    "config_json",
    "report_id",
    "report_path",
    "profile_sha256",
    "session_provenance_sha256",
}


class Bindings(Protocol):
    runtime: Dependencies

    def verify_binary(
        self, root: pathlib.Path, evidence: pathlib.Path, expected: str, name: str
    ) -> str: ...


def validate_url_pair(target: str, issuer: str | None, *, runtime: Dependencies) -> None:
    if runtime.supplier is None:
        fail("immutable URL supplier is required")
    runtime.supplier.validate_urls(target, issuer)


def validate_config(value: object, *, runtime: Dependencies) -> dict[str, Any]:
    if not isinstance(value, dict) or value.keys() != CONFIG_FIELDS:
        fail("configuration fields are missing or unknown")
    if (
        type(value["target_url"]) is not str
        or not value["target_url"]
        or (
            value["discovery_expected_issuer"] is not None
            and (
                type(value["discovery_expected_issuer"]) is not str
                or not value["discovery_expected_issuer"]
            )
        )
        or (type(value["workers"]) is not int)
        or (not 0 < value["workers"] <= 2**32 - 1)
        or (type(value["target_rps"]) not in (int, float))
        or (not math.isfinite(value["target_rps"]))
        or (value["target_rps"] <= 0)
        or (type(value["debug"]) is not bool)
        or (type(value["scenario"]) is not str)
        or (value["scenario"] not in SCENARIOS.values())
    ):
        fail("invalid typed configuration field")
    for name in ("duration", "warmup_duration"):
        duration = value[name]
        if (
            not isinstance(duration, dict)
            or duration.keys() != {"secs", "nanos"}
            or type(duration["secs"]) is not int
            or (not 0 <= duration["secs"] <= MAX_RUN_SECONDS)
            or (type(duration["nanos"]) is not int)
            or (not 0 <= duration["nanos"] < NANOS_PER_SECOND)
            or (name == "duration" and duration == {"secs": 0, "nanos": 0})
        ):
            fail("invalid typed configuration duration")
    if runtime.supplier is None:
        fail("immutable configuration supplier is required")
    runtime.supplier.validate_config(value)
    return value


def effective_config(argv: list[str], *, runtime: Dependencies) -> dict[str, Any]:
    """Validate common effective options without executable or report bindings."""
    config, _ = _parse_config(argv, report=False, runtime=runtime)
    return config


def invocation_config(argv: list[str], *, runtime: Dependencies) -> tuple[dict[str, Any], str, str]:
    config, options = _parse_config(argv[1:], report=True, runtime=runtime)
    report_id = options["--report-id"]
    parsed_id = uuid.UUID(report_id)
    if parsed_id.version != UUID_VERSION or str(parsed_id) != report_id:
        fail("invocation requires canonical UUIDv4")
    return config, report_id, required(options["--report-file"])


def _parse_config(
    argv: list[str], *, report: bool, runtime: Dependencies
) -> tuple[dict[str, Any], dict[str, str]]:
    options: dict[str, str] = {}
    debug = False
    position = 0
    required_options = {"--url", "--workers", "--run-time", "--warmup", "--rps", "--scenario"}
    if report:
        required_options |= {"--report-file", "--report-id"}
    while position < len(argv):
        name = argv[position]
        if name == "--debug":
            if debug:
                fail("duplicate child option")
            debug = True
            position += 1
            continue
        if (
            name not in required_options | {"--discovery-expected-issuer"}
            or name in options
            or position + 1 >= len(argv)
        ):
            fail("unbound, duplicate or incomplete child option")
        options[name] = argv[position + 1]
        position += 2
    if not options.keys() >= required_options:
        fail("child invocation lacks required options")

    def duration(value: str) -> dict[str, int]:
        match = re.fullmatch("([0-9]+)([smh]?)", value.strip())
        if match is None:
            fail("invalid invocation duration")
        seconds = int(match[1]) * {"": 1, "s": 1, "m": 60, "h": 3600}[match[2]]
        return {"secs": seconds, "nanos": 0}

    if re.fullmatch("[0-9]+", options["--workers"]) is None:
        fail("invalid worker count")
    config = validate_config(
        {
            "target_url": options["--url"],
            "discovery_expected_issuer": options.get("--discovery-expected-issuer"),
            "workers": int(options["--workers"]),
            "duration": duration(options["--run-time"]),
            "target_rps": float(options["--rps"]),
            "warmup_duration": duration(options["--warmup"]),
            "scenario": SCENARIOS[options["--scenario"]],
            "debug": debug,
        },
        runtime=runtime,
    )
    return config, options


def freeze_invocation(
    root: pathlib.Path,
    evidence: pathlib.Path,
    expected: str,
    argv: list[str],
    *,
    bindings: Bindings,
) -> None:
    runtime = bindings.runtime
    binary = bindings.verify_binary(root, evidence, expected, "aegaeon-loadtest")
    if not argv or argv[0] != binary:
        fail("invocation executable differs from selected build")
    config, report_id, report_path = invocation_config(argv, runtime=runtime)
    require_fresh_outputs(root, [report_path])
    _, binding = load_json(evidence / "aegaeon-loadtest.json")
    publish(
        evidence / "INVOCATION.json",
        canonical(
            {
                "schema_version": 1,
                "source_sha256": expected,
                "artifact_sha256": binding["artifact_sha256"],
                "argv": argv,
                "config": config,
                "report_id": report_id,
                "report_path": report_path,
                "normalized_report_path": str(output_path(root, report_path)),
            }
        ),
    )


def verify_report(
    root: pathlib.Path,
    evidence: pathlib.Path,
    expected: str,
    report: pathlib.Path,
    *,
    bindings: Bindings,
) -> None:
    runtime = bindings.runtime
    bindings.verify_binary(root, evidence, expected, "aegaeon-loadtest")
    _, binding = load_json(evidence / "aegaeon-loadtest.json")
    _, invocation = load_json(evidence / "INVOCATION.json")
    if (
        not isinstance(invocation, dict)
        or invocation.keys()
        != {
            "schema_version",
            "source_sha256",
            "artifact_sha256",
            "argv",
            "config",
            "report_id",
            "report_path",
            "normalized_report_path",
        }
        or type(invocation["schema_version"]) is not int
        or (invocation["schema_version"] != 1)
        or (not isinstance(invocation["argv"], list))
        or (not invocation["argv"])
        or any(type(arg) is not str for arg in invocation["argv"])
        or (invocation["argv"][0] != binding["executable"])
        or (binding["source_manifest_sha256"] != expected)
        or (invocation["source_sha256"] != expected)
        or (invocation["artifact_sha256"] != binding["artifact_sha256"])
    ):
        fail("invocation does not match independent build observations")
    config, report_id, report_path = invocation_config(invocation["argv"], runtime=runtime)
    if (
        validate_config(invocation["config"], runtime=runtime) != config
        or invocation["report_id"] != report_id
        or invocation["report_path"] != report_path
        or (invocation["normalized_report_path"] != str(output_path(root, report_path)))
        or (output_path(root, str(report)) != output_path(root, report_path))
    ):
        fail("invocation record or report destination mismatch")
    report = checked_output(root, str(report), directory=False)
    before = report.lstat()
    with os.fdopen(os.open(report, os.O_RDONLY | os.O_NOFOLLOW), "rb") as stream:
        raw = stream.read()
    if stamp(before) != stamp(report.lstat()):
        fail("report changed while reading")
    data = strict_json(raw)
    if not isinstance(data, dict):
        fail("report must be a JSON object")
    identity = data.get("identity")
    if isinstance(identity, dict):
        for name in ("profile_sha256", "session_provenance_sha256"):
            value = identity.get(name)
            if value is not None and (
                type(value) is not str or re.fullmatch("[0-9a-f]{64}", value) is None
            ):
                fail("invalid nullable supplier digest")
    if (
        not isinstance(identity, dict)
        or identity.keys() != IDENTITY_FIELDS
        or identity["source_sha256"] != expected
        or (identity["artifact_sha256"] != binding["artifact_sha256"])
        or (type(identity["config_json"]) is not str)
        or (digest(identity["config_json"].encode("utf-8")) != identity["config_sha256"])
        or (validate_config(strict_json(identity["config_json"]), runtime=runtime) != config)
        or (identity["report_id"] != report_id)
        or (identity["report_path"] != report_path)
        or (type(data.get("selected_scenario")) is not str)
        or (data["selected_scenario"] != config["scenario"])
    ):
        fail("report differs from the independent invocation")
