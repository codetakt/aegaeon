#!/usr/bin/env python3
"""Check the approved native Cargo subject and workflow wiring without publishing."""

from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any, cast

import yaml

RELEASE_FIELDS = ("RELEASE_PACKAGE", "RELEASE_BIN", "RELEASE_PROFILE", "RELEASE_BINARY")
CARGO_OUTPUT_OVERRIDES = ("CARGO_BUILD_TARGET", "CARGO_TARGET_DIR")
SUBJECT_INPUT = "${{ env.RELEASE_BINARY }}"
BUILD_COMMAND = (
    "nix develop .#ci --command cargo build --locked "
    '--profile "$RELEASE_PROFILE" --package "$RELEASE_PACKAGE" --bin "$RELEASE_BIN"'
)


def require(condition: bool, message: str) -> None:  # noqa: FBT001 - predicate assertion, not a mode flag
    if not condition:
        raise ValueError(message)


def read_workflow(path: Path) -> dict[str, Any]:
    workflow = yaml.safe_load(path.read_text())
    require(isinstance(workflow, dict), f"not a workflow mapping: {path}")
    return dict(workflow)


def step(workflow: dict[str, Any], job: str, name: str) -> dict[str, Any]:
    matches = [item for item in workflow["jobs"][job]["steps"] if item.get("name") == name]
    require(len(matches) == 1, f"expected one {job}/{name} step")
    return cast("dict[str, Any]", matches[0])


def release_environment(workflow: dict[str, Any]) -> dict[str, str]:
    environment = workflow["env"]
    require(
        all(isinstance(environment.get(key), str) and environment[key] for key in RELEASE_FIELDS),
        "release package/bin/profile/subject must be explicit nonempty strings",
    )
    require(environment["RELEASE_PROFILE"] == "release", "only the release profile is assessed")
    return {key: str(environment[key]) for key in RELEASE_FIELDS}


def check_native_configuration(repo: Path) -> None:
    """An implicit cross target changes Cargo's output layout; require explicit review."""
    require(sys.platform == "linux", "this workflow's approved output is native Linux")
    require(not os.environ.get("CARGO_BUILD_TARGET"), "CARGO_BUILD_TARGET is outside this policy")
    cargo_config = Path(os.environ.get("CARGO_HOME", str(Path.home() / ".cargo")))
    directories = {cargo_config, *(parent / ".cargo" for parent in (repo, *repo.parents))}
    for directory in directories:
        for name in ("config", "config.toml"):
            path = directory / name
            if path.is_file():
                config = tomllib.loads(path.read_text())
                require(
                    "target" not in config.get("build", {})
                    and "CARGO_BUILD_TARGET" not in config.get("env", {}),
                    f"implicit target configuration is outside this policy: {path}",
                )


def expected_subject(metadata: dict[str, Any], environment: dict[str, str], repo: Path) -> Path:
    require(Path(metadata["workspace_root"]).resolve() == repo, "metadata is for another workspace")
    packages = [
        package
        for package in metadata["packages"]
        if package["id"] in metadata["workspace_members"]
        and package["name"] == environment["RELEASE_PACKAGE"]
    ]
    require(len(packages) == 1, "approved package must identify one workspace member")
    targets = [
        target
        for target in packages[0]["targets"]
        if target["name"] == environment["RELEASE_BIN"] and target["kind"] == ["bin"]
    ]
    require(len(targets) == 1, "approved bin must identify one executable, not a library")
    require(not targets[0].get("required-features"), "feature-gated bins need an explicit policy")
    output = (
        Path(metadata["target_directory"]) / environment["RELEASE_PROFILE"] / targets[0]["name"]
    )
    subject = Path(environment["RELEASE_BINARY"])
    require(
        not subject.is_absolute() and ".." not in subject.parts,
        "subject must be a workspace-relative path without traversal",
    )
    require(
        (repo / subject).resolve() == output.resolve(), "subject differs from Cargo output path"
    )
    return subject


def check_overrides(workflow: dict[str, Any]) -> None:
    require(
        not set(CARGO_OUTPUT_OVERRIDES).intersection(workflow.get("env", {})),
        "workflow Cargo output overrides need an explicit policy",
    )
    for job in workflow["jobs"].values():
        for scope in (job, *job.get("steps", [])):
            require(
                not {*RELEASE_FIELDS, *CARGO_OUTPUT_OVERRIDES}.intersection(scope.get("env", {})),
                "job/step environment must not override the approved release target",
            )


def check_bindings(workflow: dict[str, Any], subject: Path) -> None:
    check_overrides(workflow)
    attestation_jobs = [
        name
        for name, job in workflow["jobs"].items()
        for item in job.get("steps", [])
        if item.get("uses", "").startswith("actions/attest")
    ]
    require(
        sorted(attestation_jobs) == ["sbom-generation", "slsa-provenance"],
        "unexpected attestation job or subject set",
    )
    build = step(workflow, "build", "Build release server")["run"]
    require(
        shlex.split(build) == shlex.split(BUILD_COMMAND), "build selection/flags differ from policy"
    )
    upload = step(workflow, "build", "Upload release binary")["with"]
    require(upload["path"] == SUBJECT_INPUT, "upload must use the exact approved subject")
    require(upload["if-no-files-found"] == "error", "missing upload subjects must fail")
    for job in ("slsa-provenance", "sbom-generation"):
        require(workflow["jobs"][job]["needs"] == "build", f"{job} must consume the build job")
        download = step(workflow, job, "Download release binary")["with"]
        require(download["name"] == upload["name"], f"{job} downloads a different artifact")
        require(
            Path(download["path"]) == subject.parent, f"{job} downloads into a different directory"
        )
        attestations = [
            item
            for item in workflow["jobs"][job]["steps"]
            if item.get("uses", "").startswith("actions/attest@")
        ]
        require(len(attestations) == 1, f"{job} must have one attestation for the approved set")
        require(
            attestations[0]["with"]["subject-path"] == SUBJECT_INPUT,
            f"{job} has an extra, omitted or different subject",
        )


def check_packaging(workflow: dict[str, Any], subject: Path) -> None:
    package = step(workflow, "build-release", "Package artifacts")["run"]
    copies = [shlex.split(line) for line in package.splitlines() if line.strip().startswith("cp ")]
    require(
        copies == [["cp", subject.as_posix(), "release-artifacts/"]],
        "tag packaging must copy exactly the approved binary without an ignored failure",
    )


def validate(
    compliance: dict[str, Any], release: dict[str, Any], metadata: dict[str, Any], repo: Path
) -> Path:
    environment = release_environment(compliance)
    subject = expected_subject(metadata, environment, repo)
    check_bindings(compliance, subject)
    check_packaging(release, subject)
    return subject


def main() -> int:
    repo = Path(__file__).resolve().parents[2]
    try:
        check_native_configuration(repo)
        metadata = json.loads(
            subprocess.check_output(
                ["cargo", "metadata", "--no-deps", "--format-version", "1", "--locked"], cwd=repo
            )
        )
        subject = validate(
            read_workflow(repo / ".github/workflows/compliance.yml"),
            read_workflow(repo / ".github/workflows/release.yml"),
            metadata,
            repo,
        )
    except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError) as error:
        print(f"Release subject check failed: {error}", file=sys.stderr)
        return 1
    print(f"Release subject matches Cargo bin metadata and workflow bindings: {subject}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
