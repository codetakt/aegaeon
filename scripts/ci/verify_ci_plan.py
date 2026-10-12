"""Prepare and admit CI transport using protected bytes and literal Git objects.

This standalone file is extracted with its records from protected main. It uses
only the standard library and Git; it never imports or runs candidate tooling.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path, PurePosixPath
from typing import IO, Any

RECORD_PATHS = (
    "ci/pr-policy.json",
    "ci/ci-plan.schema.json",
    "ci/ci-input-union.schema.json",
    "ci/ci-input-authority.json",
    "ci/ci-expected-inventory.json",
    "ci/ci-result-contract.json",
)
LANES = [
    "docs",
    "integrity",
    "core",
    "lint",
    "security",
    "verification",
    "compliance",
    "kms",
    "container",
]
COMPONENTS = ["conformance", "development-tools", "infrastructure", "python-example"]
MODULES = ["aegaeon-aws-staging", "oidc-aws-kms-parity", "perf-aws-ec2"]
IDENTITY = ("path", "status", "old_mode", "new_mode")
BOUND_KEYS = ("event", "event_base", "base", "source_head", "test_sha", "test_tree")
PROVENANCE_KEYS = (*BOUND_KEYS, "classifier_sha256", "policy_sha256")
GIT_OVERRIDES = {
    "GIT_DIR",
    "GIT_COMMON_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_NAMESPACE",
    "GIT_CONFIG",
    "GIT_CONFIG_PARAMETERS",
    "GIT_CONFIG_COUNT",
    "GIT_REPLACE_REF_BASE",
    "GIT_SHALLOW_FILE",
}


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def reject_constant(value: str) -> None:
    raise ValueError(f"nonfinite JSON number: {value}")


def load(data: bytes) -> dict[str, Any]:
    result: dict[str, Any] = json.loads(
        data.decode("utf-8"), object_pairs_hook=unique_object, parse_constant=reject_constant
    )
    if not isinstance(result, dict):
        raise ValueError("transport document must be an object")  # noqa: TRY004 - invalid artifact
    return result


def encoded(value: object) -> bytes:
    return (json.dumps(value, indent=2, ensure_ascii=True, allow_nan=False) + "\n").encode("utf-8")


def type_matches(value: object, kind: str) -> bool:
    types = {
        "object": dict,
        "array": list,
        "string": str,
        "integer": int,
        "boolean": bool,
        "null": type(None),
    }
    if kind not in types:
        raise ValueError("unsupported protected schema type")
    return type(value) is types[kind]


def validate_object(value: dict[str, Any], schema: dict[str, Any]) -> None:
    properties = schema.get("properties", {})
    if not set(schema.get("required", [])) <= set(value):
        raise ValueError("missing required transport field")
    if schema.get("additionalProperties") is False and set(value) - set(properties):
        raise ValueError("unknown transport field")
    for key, item in value.items():
        if key in properties:
            validate_schema(item, properties[key])


def validate_array(value: list[Any], schema: dict[str, Any]) -> None:
    if len(value) < schema.get("minItems", 0) or len(value) > schema.get("maxItems", len(value)):
        raise ValueError("invalid transport array size")
    if schema.get("uniqueItems") and len({encoded(item) for item in value}) != len(value):
        raise ValueError("duplicate transport array entry")
    for item in value:
        validate_schema(item, schema["items"])


def validate_scalar(value: object, schema: dict[str, Any]) -> None:
    if isinstance(value, str):
        if len(value) < schema.get("minLength", 0):
            raise ValueError("empty transport string")
        if "pattern" in schema and not re.fullmatch(schema["pattern"], value):
            raise ValueError("invalid transport string")
    if type(value) is int and value < schema.get("minimum", value):
        raise ValueError("invalid transport integer")


def validate_alternatives(value: object, schemas: list[dict[str, Any]]) -> None:
    for schema in schemas:
        try:
            validate_schema(value, schema)
        except ValueError:
            continue
        return
    raise ValueError("transport value does not match schema alternatives")


def validate_schema(value: object, schema: dict[str, Any]) -> None:
    """The protected transport schemas deliberately use this bounded subset."""
    if "anyOf" in schema:
        validate_alternatives(value, schema["anyOf"])
        return
    kinds = schema.get("type", [])
    kinds = [kinds] if isinstance(kinds, str) else kinds
    if kinds and not any(type_matches(value, kind) for kind in kinds):
        raise ValueError("incorrect transport field type")
    allowed = schema.get("enum", [schema["const"]] if "const" in schema else None)
    if allowed is not None and not any(
        type(value) is type(item) and value == item for item in allowed
    ):
        raise ValueError("unsupported transport value or version")
    if isinstance(value, dict):
        validate_object(value, schema)
    elif isinstance(value, list):
        validate_array(value, schema)
    else:
        validate_scalar(value, schema)


def git_command(repo: Path, *args: str) -> list[str]:
    if GIT_OVERRIDES & os.environ.keys() or any(
        key.startswith("GIT_CONFIG_KEY_") for key in os.environ
    ):
        raise ValueError("inherited Git authority override is unsupported")
    return ["git", "--no-replace-objects", "-C", str(repo), *args]


def git(repo: Path, *args: str) -> bytes:
    return subprocess.check_output(git_command(repo, *args), stderr=subprocess.PIPE)


def batch_blob_metadata(stream: IO[bytes], oid: str, *, literal: bool) -> dict[str, str | None]:
    header = stream.readline(256)
    match = re.fullmatch(oid.encode("ascii") + rb" blob (0|[1-9][0-9]*)\n", header)
    if match is None:
        raise ValueError("invalid or missing Git batch blob header")
    remaining = int(match[1])
    hashed = hashlib.sha256()
    literal_parts = []
    carry = b""
    while remaining:
        chunk = stream.read(min(remaining, 65536))
        if not chunk or len(chunk) > remaining:
            raise ValueError("incomplete Git batch blob body")
        hashed.update(chunk)
        remaining -= len(chunk)
        if literal:
            chunk = carry + chunk
            complete = len(chunk) - len(chunk) % 3
            literal_parts.append(base64.b64encode(chunk[:complete]).decode("ascii"))
            carry = chunk[complete:]
    if stream.read(1) != b"\n":
        raise ValueError("invalid Git batch blob trailer")
    if literal and carry:
        literal_parts.append(base64.b64encode(carry).decode("ascii"))
    return {
        "sha256": hashed.hexdigest(),
        "symlink_target_base64": "".join(literal_parts) if literal else None,
    }


def close_batch_process(process: subprocess.Popen[bytes]) -> None:
    try:
        if process.stdin is not None:
            process.stdin.close()
    finally:
        try:
            if process.stdout is not None:
                process.stdout.close()
        finally:
            if process.poll() is None:
                try:
                    process.terminate()
                finally:
                    process.wait()


def read_blob_metadata(repo: Path, objects: dict[str, bool]) -> dict[str, dict[str, str | None]]:
    if any(not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", oid) for oid in objects):
        raise ValueError("invalid Git blob object identity")
    command = git_command(repo, "cat-file", "--batch")
    if not objects:
        return {}
    result = {}
    process = subprocess.Popen(
        command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
    )
    try:
        if process.stdin is None or process.stdout is None:
            raise ValueError("Git batch streams are unavailable")
        for oid, literal in objects.items():
            process.stdin.write(oid.encode("ascii") + b"\n")
            process.stdin.flush()
            result[oid] = batch_blob_metadata(process.stdout, oid, literal=literal)
        process.stdin.close()
        if process.stdout.read(1):
            raise ValueError("unexpected trailing Git batch output")
        if process.wait() != 0:
            raise ValueError("Git batch blob process failed")
    finally:
        close_batch_process(process)
    return result


def tree_entries(repo: Path, tree: str) -> dict[bytes, dict[str, Any]]:
    result = {}
    raw = git(repo, "ls-tree", "-r", "-z", "--full-tree", tree)
    for record in raw.split(b"\0")[:-1]:
        header, path = record.split(b"\t", 1)
        mode, kind, oid = header.decode("ascii").split()
        if not path or path in result or mode not in {"100644", "100755", "120000", "160000"}:
            raise ValueError("invalid or duplicate Git tree identity")
        is_gitlink = mode == "160000"
        if kind != ("commit" if is_gitlink else "blob"):
            raise ValueError("Git type and mode disagree")
        result[path] = {
            "present": True,
            "tree": tree,
            "mode": mode,
            "type": "gitlink" if is_gitlink else "symlink" if mode == "120000" else "regular",
            "object_id": oid,
            "sha256": None,
            "symlink_target_base64": None,
        }
    return result


def absent(tree: str) -> dict[str, Any]:
    return {
        "present": False,
        "tree": tree,
        "mode": "000000",
        "type": "absent",
        "object_id": None,
        "sha256": None,
        "symlink_target_base64": None,
    }


def decoded_path(raw: bytes) -> str | None:
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return None


def ambiguous_path(path: str | None) -> bool:
    if path is None or not path:
        return True
    pure = PurePosixPath(path)
    return (
        pure.is_absolute()
        or str(pure) != path
        or ".." in pure.parts
        or "\\" in path
        or any(ord(char) < 32 or ord(char) == 127 for char in path)
    )


def snapshot_entries(repo: Path, trees: dict[str, str]) -> dict[str, dict[bytes, dict[str, Any]]]:
    snapshots = {side: tree_entries(repo, tree) for side, tree in trees.items()}
    objects: dict[str, bool] = {}
    for snapshot in snapshots.values():
        for item in snapshot.values():
            if item["type"] != "gitlink":
                oid = item["object_id"]
                objects[oid] = objects.get(oid, False) or item["type"] == "symlink"
    blobs = read_blob_metadata(repo, objects)
    for snapshot in snapshots.values():
        for item in snapshot.values():
            if item["type"] != "gitlink":
                metadata = blobs[item["object_id"]]
                item["sha256"] = metadata["sha256"]
                if item["type"] == "symlink":
                    item["symlink_target_base64"] = metadata["symlink_target_base64"]
    return snapshots


def union_entries(repo: Path, trees: dict[str, str], graph: dict[str, Any]) -> list[dict[str, Any]]:
    snapshots = snapshot_entries(repo, trees)
    paths = sorted({path for snapshot in snapshots.values() for path in snapshot})
    entries = []
    for path in paths:
        decoded = decoded_path(path)
        sides = {
            side: snapshot.get(path, absent(trees[side])) for side, snapshot in snapshots.items()
        }
        unresolved = list(graph["holds"])
        if ambiguous_path(decoded):
            unresolved.append("ambiguous-path")
        if any(item["type"] in {"symlink", "gitlink"} for item in sides.values()):
            unresolved.append("literal-link-or-gitlink")
        entries.append(
            {
                "raw_path_base64": base64.b64encode(path).decode("ascii"),
                "decoded_path": decoded,
                **sides,
                "protected_producers": graph["producers"],
                "protected_expected_ids": graph["inventory_families"],
                "unresolved": sorted(unresolved),
            }
        )
    return entries


def read_records(directory: Path) -> dict[str, bytes]:
    return {path: (directory / path).read_bytes() for path in RECORD_PATHS}


def check_protected_source(repo: Path, bound: dict[str, str], records: dict[str, bytes]) -> None:
    if set(bound) != set(BOUND_KEYS):
        raise ValueError("unknown or missing event context field")
    for key in ("event_base", "base", "source_head", "test_sha"):
        sha = bound[key]
        if (
            not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", sha)
            or git(repo, "cat-file", "-t", sha).strip() != b"commit"
        ):
            raise ValueError("event identity is not a full commit")
        git(repo, "merge-base", "--is-ancestor", sha, bound["test_sha"])
    if git(repo, "rev-parse", "HEAD").decode().strip() != bound["test_sha"]:
        raise ValueError("checkout differs from tested commit")
    for path, data in records.items():
        if data != git(repo, "show", f"{bound['base']}:{path}"):
            raise ValueError("transport record differs from protected base")
    if Path(__file__).read_bytes() != git(
        repo, "show", f"{bound['base']}:scripts/ci/verify_ci_plan.py"
    ):
        raise ValueError("transport verifier differs from protected base")


def validate_authority(records: dict[str, bytes]) -> dict[str, Any]:
    graph = load(records["ci/ci-input-authority.json"])
    if set(graph) != {
        "version",
        "repository",
        "coverage",
        "producers",
        "inventory_families",
        "holds",
        "external_inputs",
        "narrowing_adopted",
    }:
        raise ValueError("unknown protected input authority field")
    if (
        graph["version"] != "1"
        or graph["repository"] != "codetakt/aegaeon"
        or graph["narrowing_adopted"] is not False
    ):
        raise ValueError("unsupported protected input authority")
    if graph["coverage"] != "whole-repository-base-head-tested-union":
        raise ValueError("unsupported input coverage envelope")
    for key in ("producers", "inventory_families", "holds", "external_inputs"):
        values = graph[key]
        if (
            not isinstance(values, list)
            or not values
            or any(not isinstance(x, str) or not x for x in values)
        ):
            raise ValueError("invalid protected authority inventory")
        if values != sorted(set(values)):
            raise ValueError("duplicate or unsorted protected authority inventory")
    inventory = load(records["ci/ci-expected-inventory.json"])
    results = load(records["ci/ci-result-contract.json"])
    if inventory["version"] != "1" or results["version"] != "1":
        raise ValueError("unsupported protected inventory or result contract")
    if (
        sorted(inventory["families"]) != graph["inventory_families"]
        or sorted(results["families"]) != graph["inventory_families"]
    ):
        raise ValueError("protected inventory/result family mismatch")
    return graph


def build_union(repo: Path, bound: dict[str, str], records: dict[str, bytes]) -> dict[str, Any]:
    graph = validate_authority(records)
    trees = {
        side: git(repo, "rev-parse", f"{bound[key]}^{{tree}}").decode().strip()
        for side, key in (("base", "base"), ("head", "source_head"), ("tested", "test_sha"))
    }
    if trees["tested"] != bound["test_tree"]:
        raise ValueError("tested tree differs from context")
    graph_hash = digest(records["ci/ci-input-authority.json"])
    union = {
        "version": 1,
        **{key: bound[key] for key in ("base", "source_head", "test_sha", "test_tree")},
        "protected_graph_sha256": graph_hash,
        "expected_inventory_sha256": digest(records["ci/ci-expected-inventory.json"]),
        "entries": union_entries(repo, trees, graph),
        "raw_diff": authoritative_raw_diff(repo, bound),
        "external_inputs": [
            {
                "id": name,
                "source_authority_sha256": graph_hash,
                "artifact_sha256": None,
                "scope": "all protected producers",
                "unresolved": True,
            }
            for name in graph["external_inputs"]
        ],
        "fallback": "unresolved protected semantic and external input holds: "
        + ",".join(graph["holds"]),
    }
    validate_schema(union, load(records["ci/ci-input-union.schema.json"]))
    return union


def authoritative_raw_diff(repo: Path, bound: dict[str, str]) -> dict[str, Any]:
    merge_base = git(repo, "merge-base", bound["base"], bound["source_head"]).decode().strip()
    if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", merge_base):
        raise ValueError("merge base is not a full commit identity")
    raw = git(
        repo,
        "diff",
        "--raw",
        "-z",
        "--no-abbrev",
        "--no-renames",
        "--ignore-submodules=none",
        "--no-ext-diff",
        "--no-textconv",
        merge_base,
        bound["source_head"],
        "--",
    )
    parse_raw_changes(raw)
    return {
        "version": 1,
        "merge_base": merge_base,
        "raw_base64": base64.b64encode(raw).decode("ascii"),
        "sha256": digest(raw),
    }


def checked_raw_diff(record: dict[str, Any]) -> bytes:
    if set(record) != {"version", "merge_base", "raw_base64", "sha256"}:
        raise ValueError("unknown or missing raw diff field")
    if type(record["version"]) is not int or record["version"] != 1:
        raise ValueError("unsupported raw diff version")
    for key, pattern in (
        ("merge_base", r"[0-9a-f]{40}|[0-9a-f]{64}"),
        ("sha256", r"[0-9a-f]{64}"),
    ):
        if not isinstance(record[key], str) or not re.fullmatch(pattern, record[key]):
            raise ValueError("invalid raw diff commit or digest")
    if not isinstance(record["raw_base64"], str):
        raise ValueError("incorrect raw diff encoding type")  # noqa: TRY004 - invalid artifact
    try:
        raw = base64.b64decode(record["raw_base64"], validate=True)
    except (ValueError, binascii.Error) as error:
        raise ValueError("invalid raw diff base64") from error
    if base64.b64encode(raw).decode("ascii") != record["raw_base64"]:
        raise ValueError("noncanonical raw diff base64")
    if digest(raw) != record["sha256"]:
        raise ValueError("raw diff digest mismatch")
    parse_raw_changes(raw)
    return raw


def parse_raw_changes(raw: bytes) -> tuple[list[dict[str, str]], str]:
    raw_fields = raw.split(b"\0")
    if raw_fields[-1] != b"" or (len(raw_fields) - 1) % 2:
        raise ValueError("incomplete authoritative Git diff")
    changes = []
    nonutf8 = False
    for header, path in zip(raw_fields[:-1:2], raw_fields[1::2], strict=True):
        match = re.fullmatch(
            rb":(000000|100644|100755|120000|160000) "
            rb"(000000|100644|100755|120000|160000) "
            rb"([0-9a-f]{40}|[0-9a-f]{64}) ([0-9a-f]{40}|[0-9a-f]{64}) ([ADMT])",
            header,
        )
        if match is None or not path:
            raise ValueError("unsupported authoritative Git change")
        old_mode, new_mode, _, _, status = (field.decode("ascii") for field in match.groups())
        decoded = decoded_path(path)
        if decoded is None:
            nonutf8 = True
            continue
        changes.append(
            {"path": decoded, "status": status, "old_mode": old_mode, "new_mode": new_mode}
        )
    if nonutf8:
        return (
            [],
            "nonUTF8 Git change path; complete literal identity retained in raw input union diff",
        )
    return sorted(changes, key=lambda item: tuple(item[key] for key in IDENTITY)), ""


def authoritative_changes(
    repo: Path, bound: dict[str, str]
) -> tuple[str, list[dict[str, str]], str]:
    record = authoritative_raw_diff(repo, bound)
    changes, error = parse_raw_changes(checked_raw_diff(record))
    return record["merge_base"], changes, error


def full_component_plan(changes: list[dict[str, str]], fallback: str) -> dict[str, Any]:
    return {
        "version": 1,
        "components": COMPONENTS,
        "infrastructure_modules": MODULES,
        "fallback": fallback,
        "changes": [
            {
                **change,
                "components": COMPONENTS,
                "infrastructure_modules": MODULES,
                "reason": "conservative protected whole-repository input envelope",
            }
            for change in changes
        ],
    }


def commitment(data: bytes, version: str, base: str, authority: bytes) -> dict[str, str]:
    return {
        "version": version,
        "sha256": digest(data),
        "authority_commit": base,
        "authority_record_sha256": digest(authority),
    }


def validate_transport_policy(policy: dict[str, Any]) -> None:
    if type(policy.get("version")) is not int or policy["version"] != 1:
        raise ValueError("unsupported protected policy version")
    scopes = {"docs": ["docs"], "integrity": ["docs", "integrity"], "full": LANES}
    if policy.get("scopes") != scopes:
        raise ValueError("protected original lane inventory mismatch")
    if type(policy.get("plan_envelope_version")) is not int or policy["plan_envelope_version"] != 2:
        raise ValueError("protected policy does not adopt envelope v2")
    if (
        type(policy.get("component_plan_version")) is not int
        or policy["component_plan_version"] != 1
    ):
        raise ValueError("unsupported protected component plan version")
    if policy.get("components") != COMPONENTS or policy.get("infrastructure_modules") != MODULES:
        raise ValueError("protected component target inventory mismatch")


def prepare(
    repo: Path, bound: dict[str, str], records: dict[str, bytes], producer: dict[str, Any]
) -> tuple[dict[str, Any], bytes]:
    check_protected_source(repo, bound, records)
    policy = load(records["ci/pr-policy.json"])
    validate_transport_policy(policy)
    merge_base, changes, change_error = authoritative_changes(repo, bound)
    union_bytes = encoded(build_union(repo, bound, records))
    union = load(union_bytes)
    if union["raw_diff"]["merge_base"] != merge_base:
        raise ValueError("raw diff and plan merge base differ")
    fallback = union["fallback"]
    if change_error:
        fallback += "; " + change_error
    source = git(repo, "show", f"{bound['base']}:scripts/ci/pr_plan.py")
    source_hashes = {
        "classifier_sha256": digest(source),
        "policy_sha256": digest(records["ci/pr-policy.json"]),
    }
    provenance = {**bound, **source_hashes}
    plan = {
        "version": 2,
        **bound,
        "merge_base": merge_base,
        "scope": "full",
        "selected": LANES,
        "fallback": fallback,
        "changes": [
            {**change, "scope": "full", "reason": "conservative protected input envelope"}
            for change in changes
        ],
        **source_hashes,
        "component_plan": full_component_plan(changes, fallback),
        "component_plan_provenance": provenance,
        "verifier_sha256": digest(Path(__file__).read_bytes()),
        "schema_sha256": digest(records["ci/ci-plan.schema.json"]),
        "input_union": commitment(
            union_bytes, "1", bound["base"], records["ci/ci-input-authority.json"]
        ),
        "expected_inventory": commitment(
            records["ci/ci-expected-inventory.json"],
            "1",
            bound["base"],
            records["ci/ci-expected-inventory.json"],
        ),
        "result_contract": commitment(
            records["ci/ci-result-contract.json"],
            "1",
            bound["base"],
            records["ci/ci-result-contract.json"],
        ),
        "producer": producer,
    }
    validate_schema(plan, load(records["ci/ci-plan.schema.json"]))
    return plan, union_bytes


def projection(plan: dict[str, Any]) -> dict[str, Any]:
    return {
        key: plan["component_plan"][key]
        for key in ("version", "components", "infrastructure_modules", "fallback")
    }


def verify(  # noqa: PLR0913, PLR0917 - separate artifacts and protected authority inputs
    repo: Path,
    bound: dict[str, str],
    records: dict[str, bytes],
    producer: dict[str, Any],
    plan_bytes: bytes,
    union_bytes: bytes,
    outputs: dict[str, Any],
) -> dict[str, Any]:
    if digest(plan_bytes) != outputs.get("component_plan_sha256"):
        raise ValueError("exact full plan artifact digest mismatch")
    plan, union = load(plan_bytes), load(union_bytes)
    validate_schema(plan, load(records["ci/ci-plan.schema.json"]))
    validate_schema(union, load(records["ci/ci-input-union.schema.json"]))
    checked_raw_diff(union["raw_diff"])
    if union["raw_diff"]["merge_base"] != plan["merge_base"]:
        raise ValueError("raw diff and plan merge base differ")
    expected, expected_union = prepare(repo, bound, records, producer)
    if plan_bytes != encoded(expected) or union != load(expected_union):
        raise ValueError("plan or input union differs from protected Git-object authority")
    if plan["input_union"]["sha256"] != digest(union_bytes):
        raise ValueError("exact input union artifact digest mismatch")
    if projection(plan) != outputs.get("component_targets") or plan[
        "component_plan_provenance"
    ] != outputs.get("component_plan_provenance"):
        raise ValueError("compact output or provenance differs from retained full plan")
    return {
        "version": 1,
        "admission": "protected-v2-conservative-full",
        "component_plan_sha256": digest(plan_bytes),
        "input_union_sha256": digest(union_bytes),
        "producer": producer,
        **bound,
    }


def require_outputs(path: Path | None) -> Path:
    if path is None:
        raise ValueError("artifact admission requires compact outputs")
    return path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepare", action="store_true")
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--records", type=Path, required=True)
    parser.add_argument("--context", type=Path, required=True)
    parser.add_argument("--producer", type=Path, required=True)
    parser.add_argument("--plan", type=Path, default=Path("ci-plan.json"))
    parser.add_argument("--union", type=Path, default=Path("ci-input-union.json"))
    parser.add_argument("--outputs", type=Path)
    args = parser.parse_args()
    try:
        bound, producer = load(args.context.read_bytes()), load(args.producer.read_bytes())
        records = read_records(args.records)
        if args.prepare:
            plan, union_bytes = prepare(args.repo, bound, records, producer)
            args.union.write_bytes(union_bytes)
            args.plan.write_bytes(encoded(plan))
        else:
            outputs = require_outputs(args.outputs)
            receipt = verify(
                args.repo,
                bound,
                records,
                producer,
                args.plan.read_bytes(),
                args.union.read_bytes(),
                load(outputs.read_bytes()),
            )
            print(json.dumps(receipt, sort_keys=True))
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print(f"CI plan transport rejected: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
