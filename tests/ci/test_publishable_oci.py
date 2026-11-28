"""Verify the build boundary used before publishing an OCI archive."""

from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/ci/build_publishable_oci.sh"
ARCHIVE = "/nix/store/" + "a" * 32 + "-aegaeon.tar.gz"


def write_image_archive(archive: Path, record: bytes, config: bytes | None) -> None:
    with tarfile.open(archive, "w:gz" if archive.name == "result" else "w") as tar:
        for path, data in (("manifest.json", record), ("config.json", config)):
            if data is not None:
                info = tarfile.TarInfo(path)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))


class ImportedImageTests(unittest.TestCase):
    def test_docker_must_import_the_single_tagged_configuration(self) -> None:
        config = b'{"architecture":"amd64","os":"linux"}'
        image_id = "sha256:" + hashlib.sha256(config).hexdigest()
        manifest = {"Config": "config.json", "RepoTags": ["aegaeon:latest"]}
        valid = json.dumps([manifest]).encode()
        cases = (
            ("match", valid, config, image_id, 0),
            ("manifest-id", valid, config, "sha256:" + "1" * 64, 0),
            ("different-image", valid, config, "sha256:" + "0" * 64, 0),
            ("export-with-wrong-tag", valid, config, "sha256:" + "1" * 64, 0),
            ("export-failed", valid, config, "sha256:" + "1" * 64, 0),
            (
                "wrong-tag",
                json.dumps([{**manifest, "RepoTags": ["other:latest"]}]).encode(),
                config,
                image_id,
                0,
            ),
            ("multiple-images", json.dumps([manifest, manifest]).encode(), config, image_id, 0),
            ("malformed-manifest", b"{", config, image_id, 0),
            ("missing-config", valid, None, image_id, 0),
            ("broken-archive", None, config, image_id, 0),
            ("inspect-failed", valid, config, image_id, 1),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            docker = root / "docker"
            docker.write_text(
                f"#!{sys.executable}\nimport os, shutil, sys\n"
                "if sys.argv[1:3] == ['image', 'save']:\n"
                "    assert sys.argv[3] == '--output' and sys.argv[5:] == ['aegaeon:latest']\n"
                "    shutil.copyfile('export.tar', sys.argv[4])\n"
                "    sys.exit(0)\n"
                "assert sys.argv[1:] == ['image', 'inspect', 'aegaeon:latest', "
                "'--format', '{{.Id}}']\n"
                "print(os.environ['IMAGE_ID'])\nsys.exit(int(os.environ['INSPECT_EXIT']))\n"
            )
            docker.chmod(0o755)
            for name, record, member, loaded, status in cases:
                with self.subTest(case=name):
                    archive = root / "result"
                    if record is None:
                        archive.write_bytes(b"broken gzip stream")
                    else:
                        write_image_archive(archive, record, member)
                    exported = root / "export.tar"
                    exported.unlink(missing_ok=True)
                    if name == "manifest-id":
                        write_image_archive(exported, valid, config)
                    if name == "different-image":
                        write_image_archive(exported, valid, b"different config")
                    if name == "export-with-wrong-tag":
                        write_image_archive(exported, valid.replace(b"aegaeon", b"other"), config)
                    bash = shutil.which("bash")
                    assert bash is not None
                    result = subprocess.run(  # noqa: S603 - real helper with a local Docker double
                        [bash, str(ROOT / "scripts/ci/verify_imported_oci.sh")],
                        cwd=root,
                        env=dict(
                            os.environ,
                            PATH=f"{root}:{os.environ['PATH']}",
                            IMAGE_ID=loaded,
                            INSPECT_EXIT=str(status),
                        ),
                        capture_output=True,
                        check=False,
                    )
                    assert (result.returncode == 0) == (name in {"match", "manifest-id"}), (
                        result.stderr
                    )


def install_fake_nix(tmp_path: Path) -> None:
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
        "    root = args[args.index('--store')+1].removeprefix('local?root=')\n"
        "    output = Path(root + archive)\n"
        "    if case != 'missing':\n"
        "        output.parent.mkdir(parents=True)\n"
        "        output.write_bytes(b'archive')\n"
        "    print(archive)\n"
        "    if case == 'multiple': print(archive)\n"
        "else: sys.exit(2)\n"
    )
    nix.chmod(0o755)


class PublishableOciTests(unittest.TestCase):
    def test_fresh_build_supplies_archive(self) -> None:
        self.check_build("success")

    def test_occupied_store_fails(self) -> None:
        self.check_build("occupied")

    def test_build_failure_reaches_caller(self) -> None:
        self.check_build("failed")

    def test_missing_archive_fails(self) -> None:
        self.check_build("missing")

    def test_multiple_outputs_fail(self) -> None:
        self.check_build("multiple")

    def test_hosted_manager_builds_only_the_checked_out_public_revision(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            scratch = Path(directory)
            sudo = scratch / "sudo"
            sudo.write_text(
                f"#!{sys.executable}\n"
                "import json, os, sys\n"
                "with open(os.environ['SUDO_LOG'], 'a') as log:\n"
                "    print(json.dumps(sys.argv[1:]), file=log)\n"
                "if '/usr/bin/mktemp' in sys.argv:\n"
                "    print('/var/lib/aegaeon-oci-store.01234567')\n"
                "if 'build' in sys.argv: sys.exit(37)\n"
            )
            sudo.chmod(0o755)
            log = scratch / "sudo.jsonl"
            env = dict(os.environ, PATH=f"{scratch}:{os.environ['PATH']}", SUDO_LOG=str(log))
            head = "a" * 40
            git = scratch / "git"
            git.write_text(
                f"#!{sys.executable}\nimport sys\n"
                f"assert sys.argv[1:] == ['rev-parse', 'HEAD']\nprint('{head}')\n"
            )
            git.chmod(0o755)
            bash = shutil.which("bash")
            assert bash is not None
            command = [bash, str(SCRIPT), "--hosted"]
            for revision in ("", "0" * 40, head):
                run = subprocess.run(  # noqa: S603 - fixed local helper, no real sudo
                    command, env=dict(env, GITHUB_SHA=revision), cwd=scratch, check=False
                )
                if revision != head:
                    assert run.returncode != 0
                    assert not log.exists()
            assert run.returncode == 37
            calls = [json.loads(line) for line in log.read_text().splitlines()]
            assert len(calls) == 4
            for call in calls[2:]:
                assert call[:4] == ["-n", "-H", "--", "/nix/var/nix/profiles/default/bin/nix"]
                assert "local?root=/var/lib/aegaeon-oci-store.01234567" in call
            assert calls[-1][-1] == f"github:codetakt/aegaeon/{head}#docker-image"

    def check_build(self, case: str) -> None:
        tmp_path = Path(self.enterContext(tempfile.TemporaryDirectory()))
        install_fake_nix(tmp_path)
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
            assert (options["sandbox"], options["sandbox-fallback"]) == ("true", "false")
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

    def test_publishing_jobs_use_the_isolated_build_before_docker_load(self) -> None:
        workflows = ROOT / ".github/workflows"
        main = yaml.safe_load((workflows / "docker-build.yml").read_text())["jobs"][
            "build-and-push"
        ]
        release = yaml.safe_load((workflows / "release.yml").read_text())["jobs"][
            "publish-container"
        ]
        command = "bash scripts/ci/build_publishable_oci.sh --hosted"
        for job in (main, release):
            steps = job["steps"]
            (build,) = (step for step in steps if step.get("name") == "Build OCI image (Nix)")
            assert command in build["run"]
            commands = "\n".join(step.get("run", "") for step in steps)
            assert (
                commands.index(command)
                < commands.index("docker load")
                < commands.index("bash scripts/ci/verify_imported_oci.sh")
                < commands.index("docker push")
            )
        by_name = {s["name"]: s for s in main["steps"] if "name" in s}
        assert by_name["Setup Nix CI"]["with"]["enable-flakehub-cache"] == (
            "${{ env.PUBLISH_MAIN_IMAGE != 'true' && github.event_name != 'workflow_dispatch' }}"
        )
        guard = '"$PUBLISH_MAIN_IMAGE" == true || "$GITHUB_EVENT_NAME" == workflow_dispatch'
        assert f"if [[ {guard} ]]" in by_name["Build OCI image (Nix)"]["run"]
        assert by_name["Check the imported publication image"]["if"] == (
            "env.PUBLISH_MAIN_IMAGE == 'true' || github.event_name == 'workflow_dispatch'"
        )
        for name in ("Log in to GitHub Container Registry", "Tag and push OCI image"):
            assert by_name[name]["if"] == "env.PUBLISH_MAIN_IMAGE == 'true'"
        assert "nix build .#docker-image" not in next(
            step["run"] for step in release["steps"] if step.get("name") == "Build OCI image (Nix)"
        )
