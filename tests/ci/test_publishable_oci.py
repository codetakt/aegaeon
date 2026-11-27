"""Verify the build boundary used before publishing an OCI archive."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/ci/build_publishable_oci.sh"
ARCHIVE = "/nix/store/" + "a" * 32 + "-aegaeon.tar.gz"


@pytest.mark.parametrize("case", ["success", "occupied", "failed", "missing", "multiple"])
def test_only_one_fresh_build_can_supply_result(tmp_path: Path, case: str) -> None:
    nix = tmp_path / "nix"
    nix.write_text(
        f"#!{sys.executable}\n"
        "import json, os, sys\nfrom pathlib import Path\n"
        "args = sys.argv[1:]\n"
        "with Path('calls').open('a') as log:\n"
        "    print(json.dumps(args), file=log)\n"
        "case, archive = os.environ['CASE'], os.environ['ARCHIVE']\n"
        "if 'path-info' in args:\n"
        "    if case == 'occupied': print(archive)\n"
        "elif 'build' in args:\n"
        "    if case == 'failed': sys.exit(1)\n"
        "    output = Path(args[args.index('--store')+1].removeprefix('local?root=') + archive)\n"
        "    if case != 'missing':\n"
        "        output.parent.mkdir(parents=True)\n"
        "        output.write_bytes(b'archive')\n"
        "    print(archive)\n"
        "    if case == 'multiple': print(archive)\n"
        "else: sys.exit(2)\n"
    )
    nix.chmod(0o755)
    bash = shutil.which("bash")
    assert bash is not None
    run = subprocess.run(  # noqa: S603 - fixed helper and locally generated test double
        [bash, str(SCRIPT)],
        cwd=tmp_path,
        check=False,
        env=dict(
            os.environ,
            PATH=f"{tmp_path}:{os.environ['PATH']}",
            RUNNER_TEMP=str(tmp_path),
            CASE=case,
            ARCHIVE=ARCHIVE,
        ),
    )
    calls = [json.loads(line) for line in (tmp_path / "calls").read_text().splitlines()]
    assert calls[0][-2:] == ["path-info", "--all"]
    store = calls[0][calls[0].index("--store") + 1]
    assert store.startswith(f"local?root={tmp_path}/")
    for args in calls:
        assert args[args.index("--store") + 1] == store
        options = {args[i + 1]: args[i + 2] for i, arg in enumerate(args) if arg == "--option"}
        assert options["builders"] == ""
        assert options["substituters"] == "https://cache.nixos.org"
        assert options["trusted-public-keys"].split() == [
            "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY="
        ]
        assert options["require-sigs"] == "true"
        assert options["accept-flake-config"] == "false"
        assert not any(
            options[k]
            for k in ("extra-substituters", "trusted-substituters", "extra-trusted-public-keys")
        )
    assert len(calls) == (1 if case == "occupied" else 2)
    if len(calls) == 2:
        assert "--no-update-lock-file" in calls[1]
        assert calls[1][-1] == ".#docker-image"
    result = tmp_path / "result"
    if case == "success":
        assert run.returncode == 0
        assert result.read_bytes() == b"archive"
        assert result.resolve() == Path(store.removeprefix("local?root=") + ARCHIVE)
    else:
        assert run.returncode != 0
        assert not result.is_symlink()


def test_publishing_jobs_use_the_isolated_build_before_docker_load() -> None:
    workflows = ROOT / ".github/workflows"
    main = yaml.safe_load((workflows / "docker-build.yml").read_text())["jobs"]["build-and-push"]
    release = yaml.safe_load((workflows / "release.yml").read_text())["jobs"]["publish-container"]
    command = "bash scripts/ci/build_publishable_oci.sh"
    for job in (main, release):
        steps = job["steps"]
        (build,) = (step for step in steps if step.get("name") == "Build OCI image (Nix)")
        assert command in build["run"]
        commands = "\n".join(step.get("run", "") for step in steps)
        assert (
            commands.index(command) < commands.index("docker load") < commands.index("docker push")
        )
    by_name = {s["name"]: s for s in main["steps"] if "name" in s}
    assert by_name["Setup Nix CI"]["with"]["enable-flakehub-cache"] == (
        "${{ env.PUBLISH_MAIN_IMAGE != 'true' }}"
    )
    assert 'if [[ "$PUBLISH_MAIN_IMAGE" == true ]]' in by_name["Build OCI image (Nix)"]["run"]
    for name in ("Log in to GitHub Container Registry", "Tag and push OCI image"):
        assert by_name[name]["if"] == "env.PUBLISH_MAIN_IMAGE == 'true'"
    assert "nix build .#docker-image" not in next(
        step["run"] for step in release["steps"] if step.get("name") == "Build OCI image (Nix)"
    )
