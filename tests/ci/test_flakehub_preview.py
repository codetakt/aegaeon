"""Exercise preview publication gates and fetched-artifact identity checks."""

from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/ci"))

import check_preview_ci as gate  # noqa: E402
import preview_inputs  # noqa: E402
import preview_manifest as manifest  # noqa: E402

REVISION = "a" * 40
REFERENCE = f"codetakt-inc/aegaeon/=0.1.42+rev-{REVISION}"
SOURCE = {"type": "github", "owner": "codetakt", "repo": "aegaeon", "rev": "b" * 40}
WORKFLOW = yaml.safe_load((ROOT / ".github/workflows/flakehub-preview.yml").read_text())
QUALIFICATION = yaml.safe_load(
    (ROOT / ".github/workflows/flakehub-preview-validation.yml").read_text()
)


def run_record(workflow="ci.yml", identifier=10):
    return {
        "id": identifier,
        "run_started_at": "2026-11-01T00:00:00Z",
        "updated_at": f"2026-11-01T00:00:{identifier % 60:02d}Z",
        "repository": {"full_name": gate.REPOSITORY},
        "head_repository": {"full_name": gate.REPOSITORY},
        "head_branch": "main",
        "head_sha": REVISION,
        "event": "push",
        "path": f".github/workflows/{workflow}",
        "status": "completed",
        "conclusion": "success",
        "html_url": f"https://github.com/codetakt/aegaeon/actions/runs/{identifier}",
    }


class PreviewGateTests(unittest.TestCase):
    def test_missing_run_is_rejected(self):
        with pytest.raises(ValueError, match="no main-push run"):
            gate.latest_run([], "ci.yml", REVISION)

    def test_wrong_revision_branch_event_workflow_or_repository_is_rejected(self):
        changes = (
            {"head_sha": "b" * 40},
            {"head_branch": "preview"},
            {"event": "pull_request"},
            {"path": ".github/workflows/other.yml"},
            {"repository": {"full_name": "other/repo"}},
            {"head_repository": {"full_name": "other/repo"}},
        )
        for change in changes:
            with self.subTest(change=change), pytest.raises(ValueError, match="identity"):
                gate.latest_run([run_record() | change], "ci.yml", REVISION)

    def test_old_success_does_not_rescue_new_failure_or_pending_run(self):
        for status, conclusion in (("completed", "failure"), ("in_progress", None)):
            newer = run_record(identifier=20) | {"status": status, "conclusion": conclusion}
            with self.subTest(status=status), pytest.raises(ValueError, match="successful CI"):
                gate.require_success(gate.latest_run([newer, run_record()], "ci.yml", REVISION))

    def test_retry_order_missing_time_and_ambiguous_completion_are_not_ignored(self):
        newer = run_record(identifier=20)
        retried = run_record() | {
            "run_attempt": 2,
            "updated_at": "2026-11-02T00:00:00Z",
            "conclusion": "failure",
        }
        with pytest.raises(ValueError, match="successful CI"):
            gate.require_success(gate.latest_run([retried, newer], "ci.yml", REVISION))
        for stamp in ["invalid", "2026-11-02T00:00:00", None]:
            with pytest.raises((ValueError, TypeError)):
                gate.latest_run([retried | {"updated_at": stamp}, newer], "ci.yml", REVISION)
        with pytest.raises(ValueError, match="successful CI"):
            gate.latest_run(
                [retried, newer | {"updated_at": retried["updated_at"]}], "ci.yml", REVISION
            )
        assert (
            gate.latest_run([retried | {"conclusion": "success"}, newer], "ci.yml", REVISION)["id"]
            == retried["id"]
        )

    def test_overlapping_failure_requires_a_distinct_later_success(self):
        failed = run_record(identifier=20) | {
            "run_started_at": "2026-11-01T01:05:00Z",
            "updated_at": "2026-11-01T01:10:00Z",
            "conclusion": "failure",
        }
        success = run_record() | {
            "run_attempt": 2,
            "run_started_at": "2026-11-01T01:00:00Z",
            "updated_at": "2026-11-01T01:20:00Z",
        }
        with pytest.raises(ValueError, match="successful CI"):
            gate.require_success(gate.latest_run([failed, success], "ci.yml", REVISION))
        for start in [None, "invalid", "2026-11-01T01:11:00", "2026-11-01T01:21:00Z"]:
            with pytest.raises((ValueError, TypeError)):
                gate.latest_run([failed, success | {"run_started_at": start}], "ci.yml", REVISION)
        success["run_started_at"] = "2026-11-01T01:11:00Z"
        gate.require_success(gate.latest_run([failed, success], "ci.yml", REVISION))

    def test_complete_success_is_required(self):
        gate.require_success(run_record())
        for conclusion in ("skipped", "cancelled", "neutral", "timed_out", None):
            with (
                self.subTest(conclusion=conclusion),
                pytest.raises(ValueError, match="successful CI"),
            ):
                gate.require_success(run_record() | {"conclusion": conclusion})

    def test_current_main_is_checked_before_workflows(self):
        ref = [{"object": {"type": "commit", "sha": "b" * 40}}]
        with patch.object(gate, "api", return_value=ref) as api:
            with pytest.raises(ValueError, match="current main"):
                gate.check(REVISION, {"runs": []})
            assert api.call_count == 1

    def test_every_declared_main_workflow_is_required(self):
        replies = [[{"object": {"type": "commit", "sha": REVISION}}]]
        replies += [[{"workflow_runs": [run_record(name)]}] for name in gate.WORKFLOWS]
        record = {"runs": []}
        with patch.object(gate, "api", side_effect=replies):
            gate.check(REVISION, record)
        assert len(record["runs"]) == len(gate.WORKFLOWS)

    def test_publisher_only_runs_manually_on_main_and_consumer_cannot_build(self):
        triggers = WORKFLOW.get("on", WORKFLOW.get(True))
        assert triggers == {"workflow_dispatch": None}
        publish = WORKFLOW["jobs"]["publish"]
        assert "github.ref == 'refs/heads/main'" in publish["if"]
        assert "github.repository == 'codetakt/aegaeon'" in publish["if"]
        steps = publish["steps"]
        publisher = next(s for s in steps if s.get("id") == "publish")
        assert publisher["with"]["visibility"] == "private"
        assert publisher["with"]["directory"] == ".flakehub"
        assert publisher["with"]["name"] == "codetakt-inc/aegaeon"
        assert publisher["with"]["repository"] == "codetakt/aegaeon"
        assert publisher["with"]["include-output-paths"] is True
        assert publisher["with"]["source-branch"] == ""
        assert publisher["with"]["source-revision"] == publisher["uses"].split("@")[1]
        checks = [s for s in steps if "check_preview_ci.py" in s.get("run", "")]
        assert len(checks) == 2
        assert steps.index(checks[1]) < steps.index(publisher)
        consumer = WORKFLOW["jobs"]["consume"]
        assert consumer["needs"] == "publish"
        assert "max-jobs = 0" in consumer["env"]["NIX_CONFIG"]
        assert "builders =\n" in consumer["env"]["NIX_CONFIG"]

    def test_qualification_cannot_publish_to_the_rolling_preview_or_replay(self):
        workflow = QUALIFICATION
        assert workflow[True] == {"workflow_dispatch": None}
        publish = workflow["jobs"]["publish"]
        for guard in (
            "github.repository == 'codetakt/aegaeon'",
            "github.ref == 'refs/heads/main'",
            "github.event_name == 'workflow_dispatch'",
            "github.run_number == 1",
            "github.run_attempt == 1",
        ):
            assert guard in publish["if"]
        writes = [s for s in publish["steps"] if "flakehub-push@" in s.get("uses", "")]
        assert len(writes) == 1
        assert writes[0]["with"]["name"] == manifest.QUALIFICATION_FLAKE
        assert writes[0]["with"]["visibility"] == "private"
        assert writes[0]["with"]["repository"] == gate.REPOSITORY
        assert any("preview_inputs.py build --hosted" in s.get("run", "") for s in publish["steps"])
        consumer = workflow["jobs"]["consume"]
        assert consumer["needs"] == "publish"
        assert consumer["if"] == "github.run_number == 1 && github.run_attempt == 1"
        assert consumer["env"]["NIX_CONFIG"] == WORKFLOW["jobs"]["consume"]["env"]["NIX_CONFIG"]
        for operation, job in (("publish", publish), ("verify", consumer)):
            assert any(
                f"preview_manifest.py {operation} --qualification " in s.get("run", "")
                for s in job["steps"]
            )


class PreviewReferenceTests(unittest.TestCase):
    def test_complete_recursive_reference_is_required_for_each_output(self):
        server = "/nix/store/" + "1" * 32 + "-server"
        fh = "/nix/store/" + "2" * 32 + "-fh"
        lib = "/nix/store/" + "3" * 32 + "-lib"
        hashes = {server: "nar-server", lib: "nar-runtime"}
        with tempfile.TemporaryDirectory() as directory:
            reference = Path(directory) / "reference.json"
            reference.write_text(
                json.dumps(
                    {
                        "server": {"path": server, "closure": hashes},
                        "fh": {"path": fh, "closure": {fh: "nar-fh"}},
                    }
                )
            )
            with patch.object(preview_inputs, "closure", return_value=hashes):
                preview_inputs.verify_output(reference, "server", server)
                with pytest.raises(ValueError, match="output path"):
                    preview_inputs.verify_output(reference, "fh", server)
            for actual in (
                hashes | {lib: "different"},
                {server: "nar-server"},
                hashes | {fh: "unexpected"},
                {},
            ):
                with (
                    self.subTest(actual=actual),
                    patch.object(preview_inputs, "closure", return_value=actual),
                    pytest.raises(ValueError, match="independent closure"),
                ):
                    preview_inputs.verify_output(reference, "server", server)

    def test_nonempty_reference_store_stops_before_build(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.dict("os.environ", RUNNER_TEMP=directory),
            patch.object(
                preview_inputs.subprocess, "check_output", return_value=b"existing"
            ) as run,
            pytest.raises(ValueError, match="empty preview reference store"),
        ):
            preview_inputs.build_reference(Path(directory) / "reference.json")
        run.assert_called_once()
        (args,) = run.call_args.args
        assert args[-2:] == ["path-info", "--all"]
        assert args[args.index("substituters") + 1] == "https://cache.nixos.org"
        assert args[args.index("trusted-public-keys") + 1] == preview_inputs.UPSTREAM_KEY
        assert args[args.index("require-sigs") + 1] == "true"

    def test_workflow_checks_inputs_before_each_execution(self):
        steps = QUALIFICATION["jobs"]["publish"]["steps"]
        reference = next(
            i for i, s in enumerate(steps) if "preview_inputs.py build" in s.get("run", "")
        )
        cache = next(
            i for i, s in enumerate(steps) if "flakehub-cache-action@" in s.get("uses", "")
        )
        publish = next(i for i, s in enumerate(steps) if s.get("id") == "publish")
        assert reference < cache < publish
        runs = "\n".join(s.get("run", "") for s in steps[:publish])
        assert runs.index('reference.json" server') < runs.index("preview_manifest.py build")
        assert 'reference.json" fh' in runs
        fetch = next(
            s["run"]
            for s in QUALIFICATION["jobs"]["consume"]["steps"]
            if "fh_out/bin/fh" in s.get("run", "")
        )
        assert fetch.index('reference.json" fh') < fetch.index('"$fh_out/bin/fh" fetch')


class HostedReferenceTests(unittest.TestCase):
    def test_hosted_reference_uses_immutable_inputs_and_trusted_store(self):
        root = "/var/lib/aegaeon-preview-store.Abcd1234"
        with (
            patch.dict(preview_inputs.os.environ, {"GITHUB_SHA": REVISION}),
            patch.object(subprocess, "check_output", side_effect=[REVISION, root]) as call,
            patch.object(subprocess, "run") as chmod,
        ):
            nix, store, outputs = preview_inputs.hosted_store()
        assert call.call_args_list[0].args[0] == ["git", "rev-parse", "HEAD"]
        assert call.call_args_list[1].args[0] == [
            "sudo",
            "-n",
            "--",
            "/usr/bin/mktemp",
            "-d",
            "/var/lib/aegaeon-preview-store.XXXXXXXX",
        ]
        chmod.assert_called_once_with(
            ["sudo", "-n", "--", "/usr/bin/chmod", "0711", root], check=True
        )
        assert store == root
        assert nix == ("sudo", "-n", "-H", "--", "/nix/var/nix/profiles/default/bin/nix")
        flake = f"github:codetakt/aegaeon/{REVISION}"
        assert outputs == {
            "server": (f"{flake}?dir=.flakehub#packages.x86_64-linux.server",),
            "fh": ("--inputs-from", flake, "nixpkgs#fh"),
        }

    def test_hosted_reference_refuses_a_different_checkout_or_store(self):
        for replies, message in (
            (["b" * 40], "event revision"),
            ([REVISION, "/untrusted/aegaeon-preview-store.Abcd1234"], "reference store"),
        ):
            with (
                self.subTest(replies=replies),
                patch.dict(preview_inputs.os.environ, {"GITHUB_SHA": REVISION}),
                patch.object(subprocess, "check_output", side_effect=replies),
                patch.object(subprocess, "run") as chmod,
                pytest.raises(ValueError, match=message),
            ):
                preview_inputs.hosted_store()
            chmod.assert_not_called()


class PreviewManifestTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.output = self.root / "store-output"
        self.executable = self.output / manifest.EXECUTABLE
        self.executable.parent.mkdir(parents=True)
        self.executable.write_text("#!/bin/sh\nprintf 'fixture help\\n'\n")
        self.executable.chmod(0o755)
        (self.root / "flake.lock").write_text("fixture lock")
        (self.root / ".flakehub").mkdir()
        self.source_lock = self.root / ".flakehub/flake.lock"
        self.source_lock.write_text(
            json.dumps(
                {
                    "root": "root",
                    "nodes": {
                        "root": {"inputs": {"aegaeon": "aegaeon"}},
                        "aegaeon": {"locked": SOURCE},
                    },
                }
            )
        )
        self.paths = {str(self.output): "sha256-fixture", "/nix/store/runtime": "sha256-runtime"}
        self.enterContext(patch.object(manifest, "closure", return_value=self.paths.copy()))
        self.build = [{"drvPath": "/nix/store/fixture.drv", "outputs": {"out": str(self.output)}}]
        self.record = manifest.record_build(self.build, REVISION, self.root)
        manifest.bind_publication(self.record, REFERENCE)
        self.link = self.root / "aegaeon"
        self.link.symlink_to(self.output, target_is_directory=True)

    def test_exact_publication_and_fetch_are_accepted(self):
        manifest.verify_fetch(self.record, self.link)
        assert self.record["tooling_lock_sha256"] == manifest.digest(self.root / "flake.lock")
        assert self.record["distribution_lock_sha256"] == manifest.digest(self.source_lock)
        assert self.record["server_source"] == SOURCE
        assert self.record["repository"] == "codetakt/aegaeon"

    def test_source_repository_and_revision_are_pinned(self):
        for change in (
            {"repo": "other"},
            {"owner": "codetakt-inc"},
            {"rev": "main"},
            {"type": "path"},
        ):
            data = json.loads(self.source_lock.read_text())
            data["nodes"]["aegaeon"]["locked"] = SOURCE | change
            self.source_lock.write_text(json.dumps(data))
            with self.subTest(change=change), pytest.raises(ValueError, match="source"):
                gate.source_identity(self.source_lock)

    def test_qualification_and_ordinary_references_are_distinct(self):
        trial = REFERENCE.replace(manifest.FLAKE_NAME, manifest.QUALIFICATION_FLAKE)
        manifest.bind_publication(self.record, trial, qualification=True)
        manifest.verify_fetch(self.record, self.link, qualification=True)
        with pytest.raises(ValueError, match="exact"):
            manifest.verify_fetch(self.record, self.link)
        with pytest.raises(ValueError, match="exact"):
            manifest.bind_publication(self.record, REFERENCE, qualification=True)

    def test_wrong_or_floating_version_cannot_be_bound(self):
        for reference in (
            REFERENCE.replace("/=", "/"),
            REFERENCE.replace(REVISION, "b" * 40),
            REFERENCE.replace("codetakt-inc", "other"),
            REFERENCE.replace("codetakt-inc", "codetakt"),
            "codetakt-inc/aegaeon/*",
        ):
            with self.subTest(reference=reference), pytest.raises(ValueError, match="exact"):
                manifest.bind_publication(self.record, reference)

    def test_different_output_digest_or_closure_is_rejected(self):
        changes = (
            {"store_path": str(self.root / "other")},
            {"binary_sha256": "0" * 64},
            {"closure": {str(self.output): "sha256-other"}},
            {"closure": {str(self.output): "sha256-fixture"}},
            {"attribute": "packages.x86_64-linux.verified-core-wasm"},
            {"repository": "codetakt-inc/aegaeon"},
            {"distribution": "release-assurance"},
        )
        for change in changes:
            with (
                self.subTest(change=change),
                pytest.raises(ValueError, match=r"differs|unsupported"),
            ):
                manifest.verify_fetch(copy.deepcopy(self.record) | change, self.link)

    def test_missing_or_nonexecutable_binary_is_rejected(self):
        self.executable.chmod(0o644)
        with pytest.raises(ValueError, match="executable"):
            manifest.verify_fetch(self.record, self.link)
        self.executable.unlink()
        with pytest.raises(ValueError, match="executable"):
            manifest.record_build(self.build, REVISION, self.root)

    def test_extra_or_missing_build_outputs_are_rejected(self):
        for build in ([], self.build * 2, [{"outputs": {"out": "one", "dev": "two"}}]):
            with self.subTest(build=build), pytest.raises(ValueError, match="one server"):
                manifest.record_build(build, REVISION, self.root)


class PreviewManifestCliTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.manifest = self.root / "manifest.json"
        self.build_json = self.root / "build.json"
        # Invalid contents demonstrate that usage checks precede input parsing.
        self.manifest.write_text("existing manifest must remain untouched\n")
        self.build_json.write_text("build JSON must not be read\n")

    def assert_missing_argument(self, arguments, missing):
        before = {path.name: path.read_bytes() for path in self.root.iterdir()}
        result = subprocess.run(  # noqa: S603 - fixed CLI with temporary fixture arguments
            [
                sys.executable,
                "-B",
                str(ROOT / "scripts/ci/preview_manifest.py"),
                *arguments,
                "--manifest",
                str(self.manifest),
            ],
            cwd=self.root,
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 2, result.stderr
        assert "usage:" in result.stderr
        assert f"{arguments[0]} requires {missing}" in result.stderr
        assert "Traceback" not in result.stderr
        assert result.stdout == ""
        assert {path.name: path.read_bytes() for path in self.root.iterdir()} == before

    def test_build_requires_build_json_before_reading_inputs(self):
        self.assert_missing_argument(["build", "--revision", REVISION], "--build-json")

    def test_build_requires_revision_before_reading_inputs(self):
        self.assert_missing_argument(["build", "--build-json", str(self.build_json)], "--revision")

    def test_publish_requires_reference_before_reading_manifest(self):
        self.assert_missing_argument(["publish"], "--reference")

    def test_verify_requires_link_before_reading_manifest(self):
        self.assert_missing_argument(["verify"], "--link")


class ClosureFormatTests(unittest.TestCase):
    def test_nix_json_format_one_maps_each_path_to_its_nar_hash(self):
        response = {"/nix/store/one": {"narHash": "sha256-one", "narSize": 1}}
        with patch.object(manifest.subprocess, "check_output", return_value=json.dumps(response)):
            assert manifest.closure("/nix/store/one") == {"/nix/store/one": "sha256-one"}


if __name__ == "__main__":
    unittest.main()
