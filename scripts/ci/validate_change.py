"""Bind PR/group validation to event commits and the protected base policy."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

BOOTSTRAP_BASE = "b162b7b8440307ad210ce2c3ef846c0a0cbd8e33"
COMMIT_ID = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")


def unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    # This verifier is extracted as a standalone protected-base file.
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


COMPONENTS = ["conformance", "development-tools", "infrastructure", "python-example"]
INFRASTRUCTURE_MODULES = ["aegaeon-aws-staging", "oidc-aws-kms-parity", "perf-aws-ec2"]
CHANGE_IDENTITY = ("path", "status", "old_mode", "new_mode")


def validate_targets(item: dict[str, Any]) -> None:
    for key, allowed in [
        ("components", COMPONENTS),
        ("infrastructure_modules", INFRASTRUCTURE_MODULES),
    ]:
        selected = item.get(key)
        if (
            not isinstance(selected, list)
            or any(not isinstance(name, str) for name in selected)
            or selected != sorted(set(selected))
            or not set(selected) <= set(allowed)
        ):
            raise ValueError("invalid or unsorted component targets")
    if bool(item["infrastructure_modules"]) != ("infrastructure" in item["components"]):
        raise ValueError("invalid infrastructure module relation")


def validate_component_records(records: list[Any], original: object) -> None:
    keys = []
    for item in records:
        if (
            not isinstance(item, dict)
            or set(item) != {*CHANGE_IDENTITY, "components", "infrastructure_modules", "reason"}
            or any(
                not isinstance(item[key], str) or not item[key]
                for key in (*CHANGE_IDENTITY, "reason")
            )
        ):
            raise ValueError("malformed component change record")
        validate_targets(item)
        keys.append(tuple(item[key] for key in CHANGE_IDENTITY))
    if keys != sorted(set(keys)):
        raise ValueError("component change records must be sorted and unique")
    if (
        not isinstance(original, list)
        or any(not isinstance(item, dict) for item in original)
        or any(
            any(not isinstance(item.get(key), str) for key in CHANGE_IDENTITY) for item in original
        )
    ):
        raise ValueError("missing classified changes")
    if keys != sorted(tuple(item[key] for key in CHANGE_IDENTITY) for item in original):
        raise ValueError("component change records differ from classified changes")


def validate_component_plan(plan: dict[str, Any], policy: dict[str, Any]) -> None:
    """Reject incomplete outputs instead of interpreting them as empty selection."""
    if "component_plan_version" not in policy:
        return  # Legacy protected classifiers have no component output contract.
    if (
        type(policy["component_plan_version"]) is not int
        or policy["component_plan_version"] != 1
        or policy.get("components") != COMPONENTS
        or policy.get("infrastructure_modules") != INFRASTRUCTURE_MODULES
    ):
        raise ValueError("invalid protected component policy")
    value = plan.get("component_plan")
    if (
        not isinstance(value, dict)
        or set(value) != {"version", "components", "infrastructure_modules", "changes", "fallback"}
        or type(value["version"]) is not int
        or value["version"] != 1
        or not isinstance(value["changes"], list)
        or not isinstance(value["fallback"], str)
    ):
        raise ValueError("missing or malformed component plan")
    validate_targets(value)
    records = value["changes"]
    validate_component_records(records, plan.get("changes"))
    for key, all_targets in [
        ("components", COMPONENTS),
        ("infrastructure_modules", INFRASTRUCTURE_MODULES),
    ]:
        expected = sorted({target for item in records for target in item[key]})
        if not records or value["fallback"]:
            expected = all_targets
        if value[key] != expected:
            raise ValueError("component targets do not match the complete change union")
    if (not records or value["fallback"]) and plan.get("scope") != "full":
        raise ValueError("empty or failed classification must retain full scope")


def git(*args: str) -> str:
    return subprocess.check_output(["git", *args], text=True, stderr=subprocess.PIPE).strip()


def commit_id(value: object) -> str:
    if not isinstance(value, str) or not COMMIT_ID.fullmatch(value):
        raise ValueError("expected a full commit ID")
    if git("cat-file", "-t", value) != "commit":
        raise ValueError("event revision is not a commit")
    return value


def event_range(
    event: dict[str, Any], event_name: str, test_sha: str, trusted_base: str
) -> tuple[str, str]:
    if event_name == "pull_request":
        change = event["pull_request"]
        if change["base"]["ref"] != "main":
            raise ValueError("PR must target protected main")
        base, head = change["base"]["sha"], change["head"]["sha"]
        if base != trusted_base:
            raise ValueError("PR policy authority differs from event base")
    elif event_name == "merge_group":
        change = event["merge_group"]
        if event["action"] != "checks_requested" or change["base_ref"] != "refs/heads/main":
            raise ValueError("group must request checks for protected main")
        base, head = change["base_sha"], change["head_sha"]
        if head != test_sha:
            raise ValueError("group head differs from GITHUB_SHA")
        if not isinstance(change["head_ref"], str) or not change["head_ref"].startswith(
            "refs/heads/gh-readonly-queue/main/"
        ):
            raise ValueError("group head ref is not a main queue ref")
    else:
        raise ValueError("only PR and merge_group validation is supported")
    return commit_id(base), commit_id(head)


def context(
    event: dict[str, Any], event_name: str, test_sha: str, trusted_base: str
) -> dict[str, str]:
    """PR heads may diverge from base; both must be ancestors of the tested merge."""
    test_sha = commit_id(test_sha)
    trusted_base = commit_id(trusted_base)
    base, head = event_range(event, event_name, test_sha, trusted_base)
    for ancestor in (base, head, trusted_base):
        git("merge-base", "--is-ancestor", ancestor, test_sha)
    if git("rev-parse", "HEAD") != test_sha:
        raise ValueError("checkout does not match the event test commit")
    return {
        "event": event_name,
        "event_base": base,
        "base": trusted_base,
        "source_head": head,
        "test_sha": test_sha,
        "test_tree": git("rev-parse", f"{test_sha}^{{tree}}"),
    }


def bootstrap_allowed(event: dict[str, Any], bound: dict[str, str]) -> bool:
    return (
        bound["event"] == "pull_request"
        and bound["base"] == BOOTSTRAP_BASE
        and event["pull_request"]["head"]["ref"] == "ci/merge-queue-validation"
        and event["pull_request"]["head"]["repo"]["full_name"] == event["repository"]["full_name"]
    )


def verify_signatures(base: str, head: str, repository: str) -> list[dict[str, Any]]:
    """Ask GitHub about every introduced commit, including synthetic group commits."""
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise ValueError("invalid GitHub repository")
    commits = git("rev-list", "--reverse", f"{base}..{head}").splitlines()
    if not commits:
        raise ValueError("no introduced commits")
    records = []
    for sha in commits:
        commit_id(sha)
        response = subprocess.check_output(
            ["gh", "api", f"repos/{repository}/commits/{sha}"], text=True, timeout=60
        )
        data = json.loads(response)
        verification = data["commit"]["verification"]
        if (
            data["sha"] != sha
            or verification.get("verified") is not True
            or verification.get("reason") != "valid"
        ):
            raise ValueError(f"commit {sha} lacks valid GitHub signature verification")
        records.append({"sha": sha, "verified": True, "reason": "valid"})
    return records


def classify(bound: dict[str, str], output: Path) -> dict[str, Any]:
    """Only protected-base classifier/policy bytes determine the selected lanes."""
    base, head = bound["base"], bound["source_head"]
    paths = ("scripts/ci/pr_plan.py", "ci/pr-policy.json")
    try:
        sources = [
            subprocess.check_output(["git", "show", f"{base}:{path}"], stderr=subprocess.PIPE)
            for path in paths
        ]
    except subprocess.CalledProcessError:
        return {"scope": "full", "fallback": "base revision has no PR classification policy"}
    protected_policy = json.loads(sources[1], object_pairs_hook=unique_json_object)
    if "plan_envelope_version" in protected_policy:
        return classify_v2(bound, output, protected_policy)
    with tempfile.TemporaryDirectory() as temporary:
        trusted = Path(temporary)
        script, policy = trusted / "pr_plan.py", trusted / "policy.json"
        script.write_bytes(sources[0])
        policy.write_bytes(sources[1])
        subprocess.run(
            [
                sys.executable,
                "-I",
                str(script),
                "--base",
                base,
                "--head",
                head,
                "--policy",
                str(policy),
                "--output",
                str(output),
            ],
            check=True,
            # Publish scope only after signatures and context have succeeded.
            env={key: value for key, value in os.environ.items() if key != "GITHUB_OUTPUT"},
        )
        result: dict[str, Any] = json.loads(
            output.read_text(), object_pairs_hook=unique_json_object
        )
        protected_policy = json.loads(sources[1], object_pairs_hook=unique_json_object)
        validate_component_plan(result, protected_policy)
        if "component_plan_version" in protected_policy:
            for field, source in [("classifier_sha256", sources[0]), ("policy_sha256", sources[1])]:
                if result.get(field) != hashlib.sha256(source).hexdigest():
                    raise ValueError("component plan source hash mismatch")
            if result.get("base") != base or result.get("head") != head:
                raise ValueError("component plan source range mismatch")
            result["component_plan_provenance"] = {
                **bound,
                "classifier_sha256": result["classifier_sha256"],
                "policy_sha256": result["policy_sha256"],
            }
        validate_component_plan(result, protected_policy)
        return result


def classify_v2(bound: dict[str, str], output: Path, policy: dict[str, Any]) -> dict[str, Any]:
    """A protected policy adopts v2 only with all protected transport inputs."""
    if type(policy["plan_envelope_version"]) is not int or policy["plan_envelope_version"] != 2:
        raise ValueError("unsupported protected plan envelope version")
    records = (
        "scripts/ci/verify_ci_plan.py",
        "ci/pr-policy.json",
        "ci/ci-plan.schema.json",
        "ci/ci-input-union.schema.json",
        "ci/ci-input-authority.json",
        "ci/ci-expected-inventory.json",
        "ci/ci-result-contract.json",
    )
    event_bytes = Path(os.environ["GITHUB_EVENT_PATH"]).read_bytes()
    attempt = os.environ["GITHUB_RUN_ATTEMPT"]
    if not re.fullmatch(r"[1-9][0-9]*", attempt):
        raise ValueError("invalid run attempt")
    producer = {
        "repository": os.environ["GITHUB_REPOSITORY"],
        "run_id": os.environ["GITHUB_RUN_ID"],
        "run_attempt": int(attempt),
        "job": "plan",
        "event_payload_sha256": hashlib.sha256(event_bytes).hexdigest(),
    }
    with tempfile.TemporaryDirectory() as temporary:
        trusted = Path(temporary)
        for path in records:
            destination = trusted / path
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(
                subprocess.check_output(
                    ["git", "show", f"{bound['base']}:{path}"], stderr=subprocess.PIPE
                )
            )
        context_file, producer_file = trusted / "context.json", trusted / "producer.json"
        context_file.write_text(json.dumps(bound))
        producer_file.write_text(json.dumps(producer))
        subprocess.run(
            [
                sys.executable,
                "-I",
                str(trusted / records[0]),
                "--prepare",
                "--records",
                str(trusted),
                "--context",
                str(context_file),
                "--producer",
                str(producer_file),
                "--plan",
                str(output),
                "--union",
                "ci-input-union.json",
            ],
            check=True,
            env={key: value for key, value in os.environ.items() if key != "GITHUB_OUTPUT"},
        )
    result: dict[str, Any] = json.loads(output.read_bytes(), object_pairs_hook=unique_json_object)
    validate_component_plan(result, policy)
    return result


def run(*, bootstrap: bool) -> None:
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    bound = context(
        event,
        os.environ["GITHUB_EVENT_NAME"],
        os.environ["GITHUB_SHA"],
        os.environ["TRUSTED_BASE_SHA"],
    )
    if bootstrap and not bootstrap_allowed(event, bound):
        raise ValueError("protected-base verifier missing outside the preparation PR")
    evidence: dict[str, Any] = {
        **bound,
        "verifier_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "verifier_authority": "bootstrap candidate: mandatory manual signature gate"
        if bootstrap
        else "protected base",
    }
    output = Path("ci-validation.json")
    output.write_text(json.dumps(evidence, indent=2) + "\n")
    evidence["signatures"] = verify_signatures(
        bound["base"], bound["source_head"], os.environ["GITHUB_REPOSITORY"]
    )
    evidence["signatures_valid"] = True
    output.write_text(json.dumps(evidence, indent=2) + "\n")
    plan = classify(bound, Path("ci-plan.json"))
    plan.update(bound)
    Path("ci-plan.json").write_text(json.dumps(plan, indent=2) + "\n")
    with Path(os.environ["GITHUB_OUTPUT"]).open("a") as stream:
        stream.write(f"scope={plan['scope']}\nbase={bound['base']}\n")
        stream.write(f"source_head={bound['source_head']}\ntest_sha={bound['test_sha']}\n")
        if "component_plan" in plan:
            # Retain complete records in ci-plan.json; job outputs carry only
            # bounded targets and a digest of that exact retained artifact.
            targets = {
                key: plan["component_plan"][key]
                for key in ("version", "components", "infrastructure_modules", "fallback")
            }
            stream.write("component_targets=" + json.dumps(targets, separators=(",", ":")) + "\n")
            stream.write(
                "component_plan_sha256="
                + hashlib.sha256(Path("ci-plan.json").read_bytes()).hexdigest()
                + "\n"
            )
            stream.write(
                "component_plan_provenance="
                + json.dumps(plan["component_plan_provenance"], separators=(",", ":"))
                + "\n"
            )
        if type(plan.get("version")) is int and plan["version"] == 2:
            stream.write("transport_version=2\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bootstrap", action="store_true")
    args = parser.parse_args()
    try:
        run(bootstrap=args.bootstrap)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print(f"Change validation failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
