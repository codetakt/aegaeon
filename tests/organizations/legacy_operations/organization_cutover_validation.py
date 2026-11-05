"""Native cutover validation under retained short-lived replacement credentials."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import quote
from uuid import UUID

import organization_cutover_credentials as credentials
import organization_cutover_history as history
import organization_cutover_journal as journal
import organization_cutover_login as login
import organization_cutover_plan as plans
import organization_cutover_prepare as preparation
import organization_cutover_token as token
import organization_recovery as recovery
import organization_recovery_runtime as runtime
import organization_restore_inspect as restore
from organization_recovery_store import Store, fence, require

if TYPE_CHECKING:
    from organization_recovery_redis import RedisStore

# Nix replaces this with the immutable distribution entry. No caller executable.
NATIVE = Path("@nativeInspector@")
NATIVE_BINARY = Path("@nativeBinary@")
MAX_ATTEMPTS = 512
MAX_ENVIRONMENTS = 32
MAX_PORT = 65535
MAX_SQL_NAME = 63
MAX_ISSUER = 16384
MAX_OUTPUT = 65536
TOKEN_PREPARED = 5
NATIVE_INTENT = 6
NATIVE_VALIDATED = 7


@dataclass(repr=False)
class Context:
    configuration: dict
    principals: dict
    expected: dict
    stores: list[Store]
    plan: plans.Plan
    new: RedisStore
    old: RedisStore
    descriptor: int


def settings(value: dict) -> None:
    require(
        set(value)
        == {
            "version",
            "control",
            "primary",
            "roles",
            "root_cert_file",
            "key_encryption_key_file",
            "token",
            "environments",
        }
        and value["version"] == 1,
        "exact native validation configuration required",
    )
    require(
        set(value["roles"]) == {"control_runtime", "control_maintenance", "primary_runtime"}
        and all(re.fullmatch(r"[a-z][a-z0-9_]{0,62}", name) for name in value["roles"].values()),
        "explicit original role selectors required",
    )
    for name in ["control", "primary"]:
        endpoint = value[name]
        require(
            set(endpoint) == {"host", "port", "database"}
            and re.fullmatch(r"[A-Za-z0-9.-]+", endpoint["host"])
            and type(endpoint["port"]) is int
            and 1 <= endpoint["port"] <= MAX_PORT
            and isinstance(endpoint["database"], str)
            and 0 < len(endpoint["database"]) <= MAX_SQL_NAME,
            "explicit verified native endpoint required",
        )
    token_endpoint = value["token"]
    require(
        set(token_endpoint) == {"host", "port"}
        and re.fullmatch(r"[A-Za-z0-9.-]+", token_endpoint["host"])
        and type(token_endpoint["port"]) is int
        and 1 <= token_endpoint["port"] <= MAX_PORT,
        "explicit native token endpoint required",
    )
    rows = value["environments"]
    require(
        type(rows) is list and 0 < len(rows) <= MAX_ENVIRONMENTS,
        "bounded complete namespace inventory required",
    )
    for row in rows:
        require(
            set(row) == {"id", "issuer"}
            and str(UUID(row["id"])) == row["id"]
            and UUID(row["id"]).int != 0
            and type(row["issuer"]) is str
            and 0 < len(row["issuer"]) <= MAX_ISSUER,
            "exact namespace selector required",
        )
    require(len({row["id"] for row in rows}) == len(rows), "duplicate namespace selector")


def selected(plan: plans.Plan, configuration: dict) -> dict:
    result = {}
    for key, old in configuration["roles"].items():
        index = int(key == "primary_runtime")
        rows = [item for item in plan.value["sql"][index]["replacements"] if item["old"] == old]
        require(len(rows) == 1, "selected role absent from original replacement plan")
        result[key] = rows[0]
    require(
        result["control_runtime"]["new"] != result["control_maintenance"]["new"],
        "runtime and maintenance control roles must differ",
    )
    return result


def endpoint(value: dict, principal: dict) -> str:
    return (
        f"postgresql://{quote(principal['new'], safe='')}:{quote(principal['password'], safe='')}"
        f"@{value['host']}:{value['port']}/{quote(value['database'], safe='')}"
    )


def binding(configuration: dict) -> dict:
    settings(configuration)
    ca = recovery.private_file(configuration["root_cert_file"])
    kek = recovery.private_file(configuration["key_encryption_key_file"])
    require(
        NATIVE.is_file() and str(NATIVE).startswith("/nix/store/"),
        "packaged native inspector required",
    )
    return {
        "version": 1,
        "configurationSha256": runtime.digest(configuration),
        "rootCertSha256": hashlib.sha256(ca).hexdigest(),
        "keyFileSha256": hashlib.sha256(kek).hexdigest(),
        "nativeExecutable": str(NATIVE),
        "nativeWrapperSha256": hashlib.sha256(NATIVE.read_bytes()).hexdigest(),
        "nativeBinary": str(NATIVE_BINARY),
        "nativeBinarySha256": hashlib.sha256(NATIVE_BINARY.read_bytes()).hexdigest(),
    }


def retain_binding(directory: Path, descriptor: int, value: dict) -> str:
    path = directory / "validation.json"
    if path.exists():
        raw = recovery.private_file(path, plans.MAX_PLAN)
        require(raw == plans.canonical(value), "retained native validation inputs changed")
        return hashlib.sha256(raw).hexdigest()
    return recovery.retain(descriptor, "validation.json", value)


def cleanup(context: Context, attempt: dict) -> dict:
    result = {"sql": [], "token": None}
    failed = False
    for index, lease in enumerate(attempt["leases"]):
        if lease is None:
            continue
        try:
            result["sql"].append(
                login.disable(context.stores[index], context.plan.sql(index), lease)
            )
        except Exception:  # noqa: BLE001 — attempt all exclusions, then refuse
            failed = True
    try:
        result["token"] = token.validation_disable(
            context.new, context.old.identity["run_id"], context.plan.redis()
        )
    except Exception:  # noqa: BLE001 — no failed exclusion becomes completion
        failed = True
    require(not failed, "native validation cleanup remains unconfirmed")
    return result


def recover_attempts(context: Context, directory: Path) -> int:
    paths = sorted(directory.glob("validation-attempt-*.json"))
    require(len(paths) <= MAX_ATTEMPTS, "validation attempts exhausted")
    for index, path in enumerate(paths):
        require(
            path.name == f"validation-attempt-{index:04d}.json",
            "validation attempt sequence changed",
        )
        attempt = json.loads(recovery.private_file(path, plans.MAX_PLAN))
        require(
            attempt["planSha256"] == context.plan.sha256,
            "validation attempt belongs to another plan",
        )
        completed = directory / f"validation-cleanup-{index:04d}.json"
        if not completed.exists():
            observed = cleanup(context, attempt)
            recovery.retain(context.descriptor, completed.name, observed)
    return len(paths)


def native_call(context: Context, namespace: dict, child: dict, mode: str) -> dict:
    environment = {
        "PATH": os.defpath,
        "LANG": "C.UTF-8",
        "AEGAEON_KEY_ENCRYPTION_KEY": recovery.private_file(
            context.configuration["key_encryption_key_file"]
        )
        .decode()
        .rstrip("\n"),
        "AEGAEON_ORGANIZATION_OBSERVATION_DATABASE_URL": endpoint(
            context.configuration["primary"], context.principals["primary_runtime"]
        ),
        "AEGAEON_ORGANIZATION_WITNESS_DATABASE_URL": endpoint(
            context.configuration["control"],
            context.principals["control_maintenance" if mode == "history" else "control_runtime"],
        ),
    }
    if mode == "runtime":
        target = context.configuration["token"]
        principal = context.plan.value["token"]
        environment["AEGAEON_ORGANIZATION_OBSERVATION_REDIS_URL"] = (
            f"rediss://{quote(principal['name'], safe='')}:{quote(principal['password'], safe='')}"
            f"@{target['host']}:{target['port']}/{context.new.identity['database']}"
        )
    args = [
        str(NATIVE),
        mode,
        "--root-cert",
        context.configuration["root_cert_file"],
        "--environment-id",
        namespace["id"],
        "--issuer",
        namespace["issuer"],
    ]
    if mode == "history":
        args += [
            "--deployment-id",
            context.expected["deployment_id"],
            "--operation-id",
            child["operation_id"],
            "--expected-revision",
            str(child["revision"]),
            "--parent-operation-id",
            context.expected["operation_id"],
            "--parent-expected-revision",
            str(context.expected["revision"]),
        ]
    result = subprocess.run(  # noqa: S603 — immutable Nix entry, explicit bounded argv
        args,
        env=environment,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=35,
        check=False,
    )
    require(
        result.returncode == 0 and len(result.stdout) <= MAX_OUTPUT, "native validation refused"
    )
    value = json.loads(result.stdout)
    require(
        value["version"] == 1
        and value["kind"] == mode
        and value["activationAuthorized"] is False
        and value["nonrollbackQualified"] is False,
        "native diagnostic response differs",
    )
    if mode != "runtime":
        require(
            value["observation"]["environmentId"] == namespace["id"], "native namespace differs"
        )
    return value["observation"]


def validate(  # noqa: PLR0913,PLR0917,PLR0915 — ordered retained saga
    config: dict,
    configuration: dict,
    stores: list[Store],
    old: RedisStore,
    new: RedisStore,
    directory: Path,
) -> dict:
    control, _, destination = stores
    expected = config["inspection"]["fence"]
    operation = config["inspection"]["operation_id"]
    settings(configuration)
    # A prior crash can leave the exact fresh validation roles enabled. Verify
    # the complete allowed inventory and fence before reading the bound plan;
    # drain these retained leases before ordinary journal transitions.
    for index, store in enumerate([control, destination]):
        Store(
            store.connection, store.identity, [*store.old_logins, *config["names"][index].values()]
        ).check()
    recovery.checked_catalog(control)
    with control.connection.transaction():
        fence(control, expected["deployment_id"])
        rows = control.rows(
            "SELECT plan_sha256 FROM organization_witness.cutover_operations "
            "WHERE deployment_id=%s AND operation_id=%s",
            (expected["deployment_id"], operation),
        )
        require(len(rows) == 1, "complete offline preparation first")
        snapshot = runtime.state(control, expected["deployment_id"])
        require(runtime.digest(snapshot) == expected["state_sha256"], "validation fence differs")
    plan = plans.load(config, directory, rows[0][0])
    principals = selected(plan, configuration)
    require(
        {row["id"] for row in configuration["environments"]}
        == {row["environment_id"] for row in snapshot["children"]},
        "complete child inventory required",
    )
    descriptor = plans.directory(directory)
    context = Context(
        configuration, principals, expected, [control, destination], plan, new, old, descriptor
    )
    try:
        # Recovery excludes actual validation backends before the normal drained
        # fence and full-current-content checks. It never clears pending work.
        index = recover_attempts(context, directory)
        preparation.retired(control, expected, old)
        preparation.comparison(directory, descriptor, restore.inspect(config["inspection"], stores))
        bound = binding(configuration)
        digest = retain_binding(directory, descriptor, bound)
        state = journal.inspect(control, expected, operation, plan.sha256)
        if state["step"] == TOKEN_PREPARED:
            state = journal.advance(
                control, expected, operation, plan.sha256, "token-prepared", digest
            )
        require(
            state["step"] in (NATIVE_INTENT, NATIVE_VALIDATED) and state["receipts"][5] == digest,
            "native validation intent differs",
        )
        results = []
        children = {row["environment_id"]: row for row in snapshot["children"]}
        for namespace in configuration["environments"]:
            observations = {}
            for mode in ["credentials", "history", "runtime"]:
                index, observed = invoke_owned(
                    context, namespace, children[namespace["id"]], mode, index
                )
                check_observation(context, observed, mode)
                observations[mode] = observed
            with journal.locked(control, expected):
                facts = history.compare(control, destination, observations["history"]["history"])
            results.append(
                {"namespace": namespace, "native": observations, "permanentFacts": facts}
            )
        require(
            binding(configuration) == bound, "native validation inputs changed during execution"
        )
        preparation.retired(control, expected, old)
        preparation.comparison(directory, descriptor, restore.inspect(config["inspection"], stores))
        token.check(new, old.identity["run_id"], plan.redis())
        receipt = {
            "version": 1,
            "planSha256": plan.sha256,
            "binding": bound,
            "results": results,
            "activationAuthorized": False,
        }
        path = directory / "native-validation.json"
        if path.exists():
            raw = recovery.private_file(path, plans.MAX_PLAN)
            reconcile_receipt(json.loads(raw), receipt)
            receipt_hash = hashlib.sha256(raw).hexdigest()
        else:
            receipt_hash = recovery.retain(descriptor, path.name, receipt)
        journal.advance(control, expected, operation, plan.sha256, "native-intent", receipt_hash)
        return {"step": 7, "planSha256": plan.sha256, "activationAuthorized": False}
    finally:
        os.close(descriptor)


def invoke_owned(
    context: Context, namespace: dict, child: dict, mode: str, index: int
) -> tuple[int, dict]:
    require(index < MAX_ATTEMPTS, "validation attempts exhausted")
    control_role = "control_runtime" if mode == "runtime" else "control_maintenance"
    names = [
        {context.principals[control_role]["new"]},
        {context.principals["primary_runtime"]["new"]},
    ]
    leases = [
        None
        if mode == "credentials" and i == 0
        else login.plan(store, context.plan.sql(i), names[i])
        for i, store in enumerate(context.stores)
    ]
    attempt = {
        "version": 1,
        "planSha256": context.plan.sha256,
        "mode": mode,
        "environmentId": namespace["id"],
        "leases": leases,
    }
    recovery.retain(context.descriptor, f"validation-attempt-{index:04d}.json", attempt)
    try:
        with journal.locked(context.stores[0], context.expected):
            for i, store in enumerate(context.stores):
                if leases[i] is not None:
                    login.enable(store, context.plan.sql(i), leases[i])
            if mode == "runtime":
                token.validation_enable(
                    context.new, context.old.identity["run_id"], context.plan.redis()
                )
        observation = native_call(context, namespace, child, mode)
    finally:
        cleaned = cleanup(context, attempt)
        recovery.retain(context.descriptor, f"validation-cleanup-{index:04d}.json", cleaned)
    with journal.locked(context.stores[0], context.expected):
        for i, store in enumerate(context.stores):
            require(
                credentials.status(store, context.plan.sql(i)) == "replaced-disabled",
                "validation roles remain active",
            )
    return index + 1, observation


def check_observation(context: Context, observed: dict, mode: str) -> None:
    for name, store in [
        ("primary", context.stores[1]),
        *([("control", context.stores[0])] if mode != "credentials" else []),
    ]:
        value = observed[name]
        expected = store.identity
        require(
            str(int(value["cluster_id"]) % 2**64) == expected["cluster"]
            and value["database_oid"] == expected["database_oid"]
            and value["database_name"] == expected["database"],
            "native SQL destination differs",
        )
        actual = store.rows(
            "SELECT (extract(epoch from pg_postmaster_start_time())*1000000)::bigint,"
            "(pg_control_checkpoint()).timeline_id"
        )[0]
        require(
            (value["started_us"], value["timeline"]) == actual, "native SQL incarnation changed"
        )
    if mode == "runtime":
        require(observed["tokenStore"] == context.new.identity, "native token destination differs")


def reconcile_receipt(previous: dict, current: dict) -> None:
    # Keep the originally retained receipt after an uncertain journal COMMIT.
    # Only current WAL advancement is permitted; all facts/configuration stay exact.
    previous = json.loads(json.dumps(previous))
    current = json.loads(json.dumps(current))
    require(len(previous["results"]) == len(current["results"]), "native inventory changed")
    for old, new in zip(previous["results"], current["results"], strict=True):
        for mode in ["credentials", "history", "runtime"]:
            for store in ["primary", *(["control"] if mode != "credentials" else [])]:
                before = old["native"][mode][store]
                after = new["native"][mode][store]
                require(after["wal_position"] >= before["wal_position"], "native WAL went backward")
                after["wal_position"] = before["wal_position"]
    require(previous == current, "uncertain native validation result differs")
