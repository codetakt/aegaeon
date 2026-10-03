"""Additive component selection and protected-source output controls."""

from __future__ import annotations

import hashlib
import json
import runpy
import subprocess
import sys
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

import pytest
import test_merge_queue
import validate_change
from pr_plan import (
    COMPONENTS,
    INFRASTRUCTURE_MODULES,
    build_plan,
    classify,
    parse_changes,
    validate_policy,
)
from validate_change import validate_component_plan

ROOT = Path(__file__).resolve().parents[2]
POLICY = json.loads((ROOT / "ci/pr-policy.json").read_text())


def change(path, status="M", old_mode="100644", new_mode="100644"):
    return {"path": path, "status": status, "old_mode": old_mode, "new_mode": new_mode}


def plan(*changes):
    result = classify(list(changes), POLICY)
    validate_component_plan(result, POLICY)
    return result


@pytest.mark.parametrize(
    ("path", "components", "modules"),
    [
        ("examples/minimal-rp/requirements.txt", ["python-example"], []),
        ("examples/minimal-rp/app.py", ["python-example"], []),
        ("tests/examples/minimal_rp/check_flow.py", ["python-example"], []),
        ("scripts/oidf_conformance/suite/Dockerfile", ["conformance"], []),
        ("tests/ci/test_conformance_runner.py", ["conformance"], []),
        (".github/workflows/oidf-conformance.yml", ["conformance"], []),
        ("crates/server/tests/process_local_runtime_state_guard_test.rs", ["conformance"], []),
        ("package-lock.json", ["development-tools"], []),
        ("package.json", ["development-tools"], []),
        ("tsconfig.json", ["development-tools"], []),
        ("spec/server-strict-types.current.json", ["development-tools"], []),
        ("tests/verified_core_wasm/workflow_inventory_policy_test.ts", ["development-tools"], []),
        ("SECURITY.md", [], []),
        ("docs/verification/claims/check.md", [], []),
        *[
            (f"infra/tofu/{module}/{name}", ["infrastructure"], [module])
            for module in INFRASTRUCTURE_MODULES
            for name in ["main.tf", ".terraform.lock.hcl", "user_data.sh.tftpl"]
        ],
    ],
)
def test_exact_inputs(path, components, modules):
    result = plan(change(path))
    assert result["component_plan"]["components"] == components
    assert result["component_plan"]["infrastructure_modules"] == modules
    assert result["selected"] == POLICY["scopes"][result["scope"]]
    if components:
        assert result["scope"] == "full"


@pytest.mark.parametrize(
    "path",
    [
        "flake.nix",
        "flake.lock",
        "rust-toolchain.toml",
        "nix/flake/checks.nix",
        ".github/actions/setup-nix-ci/action.yml",
        ".github/workflows/pr.yml",
        "ci/pr-policy.json",
        "scripts/ci/pr_plan.py",
        "scripts/ci/validate_python_example.py",
        "examples/minimal-rp/README.md",
        "examples/minimal-rp/unknown.py",
        "README.md",
        "infra/tofu/unknown/main.tf",
        "infra/tofu/perf-aws-ec2/unknown.json",
        "infra/tofu/perf-aws-ec2/nested/main.tf",
        "unknown.java",
        "docs/configurations/environment/a.md",
        "../docs/a.md",
        "docs//a.md",
        "docs/a\n.md",
        "docs/./a.md",
        "",
    ],
)
def test_unknown_shared_and_ambiguous_inputs_select_all(path):
    result = plan(change(path)) if path else classify([change(path)], POLICY)
    assert result["scope"] == "full"
    assert result["component_plan"]["components"] == list(COMPONENTS)
    assert result["component_plan"]["infrastructure_modules"] == list(INFRASTRUCTURE_MODULES)


@pytest.mark.parametrize(
    ("status", "old", "new"),
    [("A", "000000", "100644"), ("D", "100644", "000000"), ("M", "100644", "100644")],
)
def test_add_delete_modify_preserve_targets(status, old, new):
    assert plan(change("examples/minimal-rp/app.py", status, old, new))["component_plan"][
        "components"
    ] == ["python-example"]


@pytest.mark.parametrize(
    ("old", "new"),
    [("100644", "100755"), ("120000", "120000"), ("000000", "160000"), ("000000", "000000")],
)
def test_mode_anomalies_select_all(old, new):
    assert plan(change("examples/minimal-rp/app.py", "T", old, new))["component_plan"][
        "components"
    ] == list(COMPONENTS)


def test_empty_mixed_cumulative_and_rename_union():
    assert plan()["component_plan"]["components"] == list(COMPONENTS)
    python = change("examples/minimal-rp/app.py", "D", "100644", "000000")
    infra = change("infra/tofu/perf-aws-ec2/main.tf", "A", "000000", "100644")
    docs = change("SECURITY.md")
    mixed = plan(infra, docs, python)
    assert mixed["component_plan"]["components"] == ["infrastructure", "python-example"]
    assert mixed["component_plan"] == plan(python, infra, docs)["component_plan"]
    assert plan(python, infra, change("unknown"))["component_plan"]["components"] == list(
        COMPONENTS
    )
    # A group includes an earlier Python change and the next infrastructure change.
    assert (
        plan(python, infra)["component_plan"]["components"]
        != plan(infra)["component_plan"]["components"]
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("component_plan_version", True),
        ("component_plan_version", 2),
        ("components", []),
        ("components", ["unknown"]),
        ("infrastructure_modules", ["unknown"]),
    ],
)
def test_bad_policy_rejected(field, value):
    policy = deepcopy(POLICY)
    policy[field] = value
    with pytest.raises(ValueError, match="component"):
        validate_policy(policy)
    with pytest.raises(ValueError, match="component"):
        validate_component_plan(plan(), policy)


def test_malformed_and_incomplete_outputs_rejected():
    baseline = plan(change("examples/minimal-rp/app.py"))
    cases = []
    missing = deepcopy(baseline)
    del missing["component_plan"]
    cases.append(missing)
    for key, value in [
        ("version", True),
        ("version", 2),
        ("components", []),
        ("components", ["unknown"]),
        ("components", ["python-example", "python-example"]),
        ("infrastructure_modules", ["perf-aws-ec2"]),
        ("infrastructure_modules", ["unknown"]),
        ("components", ["python-example", "infrastructure"]),
        ("changes", []),
        ("fallback", None),
    ]:
        mutated = deepcopy(baseline)
        mutated["component_plan"][key] = value
        cases.append(mutated)
    mutated = deepcopy(baseline)
    mutated["component_plan"]["changes"][0]["path"] = "other"
    cases.append(mutated)
    for mutated in cases:
        with pytest.raises(ValueError, match=r"component|infrastructure"):
            validate_component_plan(mutated, POLICY)
    for parser in [validate_change.unique_json_object]:
        with pytest.raises(ValueError, match="duplicate JSON key"):
            json.loads('{"version":1,"version":1}', object_pairs_hook=parser)


def test_raw_diff_rejects_incomplete_duplicate_and_unsupported_records():
    record = b":100644 100644 1234567 2345678 M\0examples/minimal-rp/app.py\0"
    assert len(parse_changes(record)) == 1
    for invalid in [
        record[:-1],
        record + record,
        record.replace(b" M", b" R100"),
        record.replace(b"100644", b"garbage"),
    ]:
        with pytest.raises(ValueError, match="Git"):
            parse_changes(invalid)


def test_classifier_cli_failure_keeps_all_targets(tmp_path):
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps(POLICY))
    output = tmp_path / "plan.json"
    subprocess.run(  # noqa: S603 - fixed classifier with isolated JSON arguments
        [
            sys.executable,
            str(ROOT / "scripts/ci/pr_plan.py"),
            "--base",
            "invalid",
            "--head",
            "invalid",
            "--policy",
            str(policy),
            "--output",
            str(output),
        ],
        check=True,
        capture_output=True,
    )
    result = json.loads(output.read_text())
    validate_component_plan(result, POLICY)
    assert result["scope"] == "full"
    assert result["component_plan"]["components"] == list(COMPONENTS)


def test_output_published_only_after_context_and_signatures(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    event = tmp_path / "event.json"
    event.write_text("{}")
    output = tmp_path / "output"
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event))
    monkeypatch.setenv("GITHUB_EVENT_NAME", "merge_group")
    monkeypatch.setenv("GITHUB_SHA", "a" * 40)
    monkeypatch.setenv("TRUSTED_BASE_SHA", "b" * 40)
    monkeypatch.setenv("GITHUB_REPOSITORY", "owner/repo")
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    bound = {"base": "b" * 40, "source_head": "a" * 40, "test_sha": "a" * 40, "test_tree": "c" * 40}
    with (
        patch.object(validate_change, "context", return_value=bound),
        patch.object(validate_change, "verify_signatures", side_effect=ValueError("bad signature")),
        pytest.raises(ValueError, match="bad signature"),
    ):
        validate_change.run(bootstrap=False)
    assert not output.exists()
    classified = plan(change("package.json"))
    classified["component_plan_provenance"] = {
        **bound,
        "classifier_sha256": "1" * 64,
        "policy_sha256": "2" * 64,
    }
    with (
        patch.object(validate_change, "context", return_value=bound),
        patch.object(validate_change, "verify_signatures", return_value=[]),
        patch.object(validate_change, "classify", return_value=classified),
    ):
        validate_change.run(bootstrap=False)
    lines = output.read_text().splitlines()
    component_lines = [
        line.removeprefix("component_targets=")
        for line in lines
        if line.startswith("component_targets=")
    ]
    assert len(component_lines) == 1
    assert json.loads(component_lines[0])["components"] == ["development-tools"]
    outputs = dict(line.split("=", 1) for line in lines)
    assert (
        json.loads(outputs["component_plan_provenance"]) == classified["component_plan_provenance"]
    )


def test_protected_classifier_ignores_candidate_policy_and_binds_source(tmp_path, monkeypatch):
    # Preserve protected bytes before installing a malicious candidate working directory.
    source = (ROOT / "scripts/ci/pr_plan.py").read_bytes()
    policy = (ROOT / "ci/pr-policy.json").read_bytes()
    (tmp_path / "scripts/ci").mkdir(parents=True)
    (tmp_path / "ci").mkdir()
    (tmp_path / "scripts/ci/pr_plan.py").write_text('raise RuntimeError("candidate executed")')
    (tmp_path / "ci/pr-policy.json").write_text('{"components":[]}')
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("GITHUB_OUTPUT", str(tmp_path / "output"))
    bound = {"base": "b" * 40, "source_head": "a" * 40, "test_sha": "c" * 40, "test_tree": "d" * 40}

    def protected_read(argv, **_kwargs):
        assert argv[:2] == ["git", "show"]
        return {
            bound["base"] + ":scripts/ci/pr_plan.py": source,
            bound["base"] + ":ci/pr-policy.json": policy,
        }[argv[2]]

    def protected_execution(argv, **kwargs):
        assert "GITHUB_OUTPUT" not in kwargs["env"]
        script = Path(argv[1])
        trusted_policy = Path(argv[argv.index("--policy") + 1])
        assert script.read_bytes() == source
        assert trusted_policy.read_bytes() == policy
        protected = runpy.run_path(str(script))
        result = protected["classify"]([change("examples/minimal-rp/app.py")], json.loads(policy))
        result.update(
            {
                "base": bound["base"],
                "head": bound["source_head"],
                "classifier_sha256": hashlib.sha256(source).hexdigest(),
                "policy_sha256": hashlib.sha256(policy).hexdigest(),
            }
        )
        Path(argv[argv.index("--output") + 1]).write_text(json.dumps(result))

    with (
        patch.object(validate_change.subprocess, "check_output", side_effect=protected_read),
        patch.object(validate_change.subprocess, "run", side_effect=protected_execution),
    ):
        result = validate_change.classify(bound, tmp_path / "plan.json")
    validate_component_plan(json.loads(json.dumps(result)), json.loads(policy))
    assert result["component_plan"]["components"] == ["python-example"]
    value = result["component_plan_provenance"]
    assert all(value[key] == expected for key, expected in bound.items())
    assert value["policy_sha256"] == hashlib.sha256(policy).hexdigest()
    assert value["classifier_sha256"] == hashlib.sha256(source).hexdigest()
    assert not (tmp_path / "output").exists()


def test_complete_group_diff_uses_protected_main_not_event_parent():
    base, head, ancestor = "a" * 40, "b" * 40, "c" * 40
    raw = (
        b":100644 100644 1234567 2345678 M\0examples/minimal-rp/app.py\0"
        b":100644 100644 3456789 4567890 M\0infra/tofu/perf-aws-ec2/main.tf\0"
    )
    with patch("pr_plan.git", side_effect=[ancestor.encode(), raw]) as git:
        result = build_plan(ROOT, base, head, POLICY)
    assert git.call_args_list[0].args == (ROOT, "merge-base", base, head)
    assert git.call_args_list[1].args == (
        ROOT,
        "diff",
        "--raw",
        "-z",
        "--no-renames",
        "--no-ext-diff",
        ancestor,
        head,
        "--",
    )
    assert result["component_plan"]["components"] == ["infrastructure", "python-example"]
    validate_component_plan(result, POLICY)


def test_published_component_plan_and_provenance_remain_separate():
    bound = {"base": test_merge_queue.BASE, "source_head": test_merge_queue.HEAD}
    classified = plan(change("examples/minimal-rp/app.py"))
    classified["component_plan_provenance"] = {**bound, "classifier_sha256": "1" * 64}
    case = test_merge_queue.RunTests()
    case.setUp()
    try:
        with (
            patch.object(validate_change, "git", side_effect=test_merge_queue.graph),
            patch.object(validate_change, "classify", return_value=classified),
            patch.object(validate_change, "verify_signatures", return_value=[]),
        ):
            validate_change.run(bootstrap=False)
        recorded = json.loads(Path("ci-plan.json").read_text())
        validate_component_plan(recorded, POLICY)
        outputs = dict(line.split("=", 1) for line in case.output.read_text().splitlines())
        component = json.loads(outputs["component_targets"])
        provenance = json.loads(outputs["component_plan_provenance"])
        assert component == {
            key: recorded["component_plan"][key]
            for key in ("version", "components", "infrastructure_modules", "fallback")
        }
        assert (
            outputs["component_plan_sha256"]
            == hashlib.sha256(Path("ci-plan.json").read_bytes()).hexdigest()
        )
        assert "component_plan" not in outputs
        assert provenance == recorded["component_plan_provenance"]
        assert provenance == classified["component_plan_provenance"]
    finally:
        case.doCleanups()


def test_large_complete_plan_has_compact_outputs_bound_to_retained_file():
    bound = {"base": test_merge_queue.BASE, "source_head": test_merge_queue.HEAD}
    classified = plan(*(change(f"crates/server/src/shared_{i:04d}.rs") for i in range(3000)))
    classified["component_plan_provenance"] = {**bound, "classifier_sha256": "1" * 64}
    case = test_merge_queue.RunTests()
    case.setUp()
    try:
        with (
            patch.object(validate_change, "git", side_effect=test_merge_queue.graph),
            patch.object(validate_change, "classify", return_value=classified),
            patch.object(validate_change, "verify_signatures", return_value=[]),
        ):
            validate_change.run(bootstrap=False)
        raw = Path("ci-plan.json").read_bytes()
        recorded = json.loads(raw)
        validate_component_plan(recorded, POLICY)
        assert len(recorded["component_plan"]["changes"]) == 3000
        outputs_raw = case.output.read_text()
        assert len(outputs_raw.encode("utf-16-le")) < 8192
        outputs = dict(line.split("=", 1) for line in outputs_raw.splitlines())
        assert "component_plan" not in outputs
        assert "changes" not in json.loads(outputs["component_targets"])
        assert outputs["component_plan_sha256"] == hashlib.sha256(raw).hexdigest()
        assert json.loads(outputs["component_targets"]) == {
            key: recorded["component_plan"][key]
            for key in ("version", "components", "infrastructure_modules", "fallback")
        }
        assert (
            json.loads(outputs["component_plan_provenance"])
            == classified["component_plan_provenance"]
        )
    finally:
        case.doCleanups()
