"""CLI regressions for preserving the historical claim-index snapshot."""

from __future__ import annotations

import pathlib
import shlex
import shutil
import subprocess
import sys

import pytest

SNAPSHOT_PATH = pathlib.Path("docs/verification/claims/claim-index.md")
SNAPSHOT_BYTES = b"Preserved historical snapshot.\n"
MATRIX_PATH = pathlib.Path("spec/compliance-matrix.yaml")
MATRIX_BYTES = b"metadata: {}\n"


@pytest.fixture
def report_repo(tmp_path: pathlib.Path) -> pathlib.Path:
    root = tmp_path / "report repo"
    scripts = root / "scripts/validation"
    scripts.mkdir(parents=True)
    for name in ("generate_claim_index.py", "proof_classification.py"):
        shutil.copyfile(pathlib.Path(__file__).with_name(name), scripts / name)
    (root / "spec").mkdir()
    (root / MATRIX_PATH).write_bytes(MATRIX_BYTES)
    snapshot = root / SNAPSHOT_PATH
    snapshot.parent.mkdir(parents=True)
    snapshot.write_bytes(SNAPSHOT_BYTES)
    return root


def run_cli(
    root: pathlib.Path, *args: str, cwd: pathlib.Path | None = None
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        [sys.executable, str(root / "scripts/validation/generate_claim_index.py"), *args],
        cwd=cwd or root,
        capture_output=True,
        text=True,
        check=False,
    )
    assert (root / SNAPSHOT_PATH).read_bytes() == SNAPSHOT_BYTES
    return result


@pytest.mark.parametrize("mode", [[], ["--check"]])
def test_output_is_required(report_repo: pathlib.Path, mode: list[str]) -> None:
    result = run_cli(report_repo, *mode)
    assert result.returncode == 2
    assert "required: --output" in result.stderr


@pytest.mark.parametrize("mode", [[], ["--check"]])
@pytest.mark.parametrize(
    "alias", ["relative", "absolute", "dotdot", "symlink", "parent", "hardlink"]
)
def test_historical_output_and_aliases_are_rejected(
    report_repo: pathlib.Path, mode: list[str], alias: str
) -> None:
    snapshot = report_repo / SNAPSHOT_PATH
    paths = {
        "relative": SNAPSHOT_PATH,
        "absolute": snapshot,
        "dotdot": SNAPSHOT_PATH.parent / "../claims/claim-index.md",
    }
    if alias == "symlink":
        output = report_repo / "linked-report.md"
        output.symlink_to(snapshot)
    elif alias == "parent":
        parent = report_repo / "linked-claims"
        parent.symlink_to(snapshot.parent, target_is_directory=True)
        output = parent / snapshot.name
    elif alias == "hardlink":
        output = report_repo / "hardlinked-report.md"
        output.hardlink_to(snapshot)
    else:
        output = paths[alias]
    result = run_cli(report_repo, *mode, "--output", str(output))
    assert result.returncode == 2
    assert "historical claim index is protected" in result.stderr


@pytest.mark.parametrize("mode", [[], ["--check"]])
def test_protection_is_bound_to_script_repository(
    report_repo: pathlib.Path, mode: list[str]
) -> None:
    result = run_cli(
        report_repo,
        *mode,
        "--output",
        str(report_repo / SNAPSHOT_PATH),
        cwd=report_repo.parent,
    )
    assert result.returncode == 2
    assert "historical claim index is protected" in result.stderr


@pytest.mark.parametrize("mode", [[], ["--check"]], ids=["generate", "check"])
@pytest.mark.parametrize(
    "alias", ["relative", "absolute", "dotdot", "symlink", "parent", "hardlink"]
)
def test_matrix_output_and_aliases_are_rejected(
    report_repo: pathlib.Path, mode: list[str], alias: str
) -> None:
    matrix = report_repo / MATRIX_PATH
    paths = {
        "relative": MATRIX_PATH,
        "absolute": matrix,
        "dotdot": MATRIX_PATH.parent / "../spec/compliance-matrix.yaml",
    }
    if alias == "symlink":
        output = report_repo / "linked-matrix.md"
        output.symlink_to(matrix)
    elif alias == "parent":
        parent = report_repo / "linked-spec"
        parent.symlink_to(matrix.parent, target_is_directory=True)
        output = parent / matrix.name
    elif alias == "hardlink":
        output = report_repo / "hardlinked-matrix.md"
        output.hardlink_to(matrix)
    else:
        output = paths[alias]
    result = run_cli(report_repo, *mode, "--output", str(output))
    assert matrix.read_bytes() == MATRIX_BYTES
    assert result.returncode == 2
    assert "compliance matrix input is protected" in result.stderr


@pytest.mark.parametrize("mode", [[], ["--check"]], ids=["generate", "check"])
@pytest.mark.parametrize("alias", ["symlink", "hardlink"])
def test_matrix_input_alias_target_is_protected(
    report_repo: pathlib.Path, mode: list[str], alias: str
) -> None:
    matrix = report_repo / MATRIX_PATH
    source = report_repo / "matrix-source.yaml"
    source.write_bytes(MATRIX_BYTES)
    matrix.unlink()
    if alias == "symlink":
        matrix.symlink_to(source)
    else:
        matrix.hardlink_to(source)
    result = run_cli(report_repo, *mode, "--output", str(source))
    assert source.read_bytes() == matrix.read_bytes() == MATRIX_BYTES
    assert result.returncode == 2
    assert "compliance matrix input is protected" in result.stderr


@pytest.mark.parametrize("mode", [[], ["--check"]], ids=["generate", "check"])
@pytest.mark.parametrize("absolute", [False, True])
def test_matrix_protection_uses_the_actual_working_directory_input(
    report_repo: pathlib.Path, mode: list[str], absolute: bool
) -> None:
    working_directory = report_repo.parent / "another working directory"
    matrix = working_directory / MATRIX_PATH
    matrix.parent.mkdir(parents=True)
    matrix.write_bytes(MATRIX_BYTES)
    output = matrix if absolute else MATRIX_PATH
    result = run_cli(report_repo, *mode, "--output", str(output), cwd=working_directory)
    assert matrix.read_bytes() == (report_repo / MATRIX_PATH).read_bytes() == MATRIX_BYTES
    assert result.returncode == 2
    assert "compliance matrix input is protected" in result.stderr


@pytest.mark.parametrize("mode", [[], ["--check"]])
def test_unresolvable_output_is_rejected(report_repo: pathlib.Path, mode: list[str]) -> None:
    output = report_repo / "loop"
    output.symlink_to(output)
    result = run_cli(report_repo, *mode, "--output", str(output))
    assert result.returncode == 2
    assert "cannot validate --output path" in result.stderr


def test_separate_report_can_be_generated_and_checked(report_repo: pathlib.Path) -> None:
    output = "reports/current inventory.md"
    generated = run_cli(report_repo, "--output", output)
    assert generated.returncode == 0, generated.stderr
    assert "# Claim Index" in (report_repo / output).read_text()
    checked = run_cli(report_repo, "--check", "--output", output)
    assert checked.returncode == 0, checked.stderr
    assert "is up to date" in checked.stdout


@pytest.mark.parametrize("existing", [False, True])
def test_check_error_retains_explicit_output_in_regeneration_command(
    report_repo: pathlib.Path, existing: bool
) -> None:
    output = "report with spaces.md"
    if existing:
        (report_repo / output).write_text("stale report\n")
    result = run_cli(report_repo, "--check", "--output", output)
    assert result.returncode == 1
    command = shlex.split(result.stderr.splitlines()[-1])
    assert command == [
        "python3",
        str(report_repo / "scripts/validation/generate_claim_index.py"),
        "--output",
        output,
    ]
    regenerated = run_cli(report_repo, *command[2:])
    assert regenerated.returncode == 0, regenerated.stderr
    assert run_cli(report_repo, "--check", "--output", output).returncode == 0
