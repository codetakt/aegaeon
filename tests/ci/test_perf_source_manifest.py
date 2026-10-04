"""Direct source-producer and inert shared-runner controls; no product builds."""
# ruff: noqa: PT009, PT027 - unittest controls remain effective under Python -O

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

SOURCE = pathlib.Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "perf_source_manifest", SOURCE / "scripts/perf/source_manifest.py"
)
if SPEC is None or SPEC.loader is None:
    message = "source producer import unavailable"
    raise RuntimeError(message)
PRODUCER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PRODUCER)


class PerfSourceManifestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="aegaeon-source-controls-")
        self.addCleanup(self.temporary.cleanup)
        self.owner = pathlib.Path(self.temporary.name)
        self.root = self.owner / "source"
        self.root.mkdir()
        self.private = self.owner / "private"
        self.private.mkdir()
        self.environment = os.environ.copy()
        self.environment.pop("AEG_LOADTEST_SOURCE_SHA256", None)
        self.environment.pop("CARGO_TARGET_DIR", None)
        self.environment["TMPDIR"] = str(self.private)
        baseline = self.git(SOURCE, "rev-parse", "HEAD^{commit}").decode().strip()
        objects = self.git(SOURCE, "rev-parse", "--git-path", "objects").decode().strip()
        if not pathlib.Path(objects).is_absolute():
            objects = str(SOURCE / objects)
        self.git(self.root, "init", "--quiet")
        (self.root / ".git/objects/info/alternates").write_text(objects + "\n")
        self.git(self.root, "update-ref", "HEAD", baseline)
        for name in PRODUCER.MANDATORY:
            original = SOURCE / name
            self.write(name, original.read_bytes())
        self.write("tracked.txt", b"source bytes\n")
        self.write(
            "crates/loadtest/Cargo.toml", (SOURCE / "crates/loadtest/Cargo.toml").read_bytes()
        )
        self.write(".gitignore", b"ignored*\n")
        self.write(
            "scripts/flake/perf_load.sh",
            (SOURCE / "scripts/flake/perf_load.sh").read_bytes(),
            0o755,
        )
        self.restore_runner_mode()
        # Literal dangling links are source identities, not target contents.
        (self.root / "literal").symlink_to("missing-target")
        self.git(self.root, "add", "--all")
        self.evidence = self.root / "artifacts/perf/control/source"
        self.original_index = (self.root / ".git/index").read_bytes()
        self.original_head = self.git(self.root, "rev-parse", "HEAD")

    def restore_runner_mode(self) -> None:
        self.write(
            "scripts/perf/run_load_tests.sh",
            (SOURCE / "scripts/perf/run_load_tests.sh").read_bytes(),
            0o755,
        )

    def git(self, root: pathlib.Path, *args: str) -> bytes:
        result = subprocess.run(  # noqa: S603 - owned fixture Git commands
            [str(shutil.which("git")), "-C", str(root), *args],
            env=PRODUCER.environment(),
            check=True,
            capture_output=True,
        )
        return result.stdout

    def write(self, name: str, raw: bytes, mode: int = 0o644) -> pathlib.Path:
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        path.chmod(mode)
        return path

    def invoke(
        self, action: str, *args: str, env: dict[str, str] | None = None
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # noqa: S603 - owned local fixture commands
            [
                sys.executable,
                str(self.root / "scripts/perf/source_manifest.py"),
                action,
                "--root",
                str(self.root),
                "--evidence",
                str(self.evidence),
                *args,
            ],
            env=env or self.environment,
            capture_output=True,
            text=True,
            check=False,
        )

    def freeze(self) -> str:
        result = self.invoke("freeze", "--output-directory", str(self.evidence.parent))
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip()

    def test_complete_dirty_git_tree_raw_digest_private_retention_and_no_source_writes(
        self,
    ) -> None:
        self.write("tracked.txt", b"actual dirty bytes\n")
        sha = self.freeze()
        raw = (self.evidence / "SOURCE-MANIFEST.json").read_bytes()
        manifest = json.loads(raw)
        self.assertEqual(sha, hashlib.sha256(raw).hexdigest())
        self.assertEqual(
            set(manifest), {"candidate_tree", "files", "patch_sha256", "source_base_commit"}
        )
        domain = json.loads((self.evidence / "TRACKED-PATHS.json").read_bytes())
        self.assertEqual(set(manifest["files"]), set(domain["index"]))
        entry = manifest["files"]["tracked.txt"]
        self.assertEqual(entry["sha256"], hashlib.sha256(b"actual dirty bytes\n").hexdigest())
        self.assertEqual(entry["filesystem_mode"], 33188)
        self.assertEqual(manifest["files"]["literal"]["symlink"], "missing-target")
        self.assertEqual((self.root / ".git/index").read_bytes(), self.original_index)
        self.assertEqual(self.git(self.root, "rev-parse", "HEAD"), self.original_head)
        preimages = list(self.private.glob("aegaeon-perf-source-*"))
        self.assertEqual(len(preimages), 1)
        private = preimages[0]
        self.assertFalse(private.is_relative_to(self.evidence.parent))
        self.assertEqual(private.stat().st_mode & 0o777, 0o700)
        self.assertEqual((private / "source.patch").stat().st_mode & 0o777, 0o600)
        self.assertEqual(
            hashlib.sha256((private / "source.patch").read_bytes()).hexdigest(),
            manifest["patch_sha256"],
        )
        env = PRODUCER.environment()
        env["GIT_OBJECT_DIRECTORY"] = str(private / "objects")
        env["GIT_ALTERNATE_OBJECT_DIRECTORIES"] = str(self.root / ".git/objects")
        tree = PRODUCER.command(
            self.root, "ls-tree", "-r", "--name-only", manifest["candidate_tree"], env=env
        )
        self.assertEqual(set(tree.decode().splitlines()), set(manifest["files"]))
        self.assertEqual(self.invoke("verify", "--sha256", sha).returncode, 0)

    def test_index_new_and_staged_deletions_are_explicit_complete_candidate(self) -> None:
        self.write("new-source", b"new\n")
        self.git(self.root, "add", "new-source")
        self.git(self.root, "rm", "--force", "--quiet", "tracked.txt")
        self.freeze()
        files = json.loads((self.evidence / "SOURCE-MANIFEST.json").read_bytes())["files"]
        self.assertIn("new-source", files)
        self.assertNotIn("tracked.txt", files)

    def test_unknown_ignored_unignored_and_special_additions_rejected(self) -> None:
        for name, special in [
            ("ignored-file", False),
            ("unknown-file", False),
            ("unknown-pipe", True),
        ]:
            with self.subTest(name=name):
                path = self.root / name
                if special:
                    os.mkfifo(path)
                else:
                    path.write_text("unknown")
                result = self.invoke("freeze")
                self.assertNotEqual(result.returncode, 0)
                path.unlink()
                if self.evidence.exists():
                    self.evidence.rmdir()

    def test_missing_mandatory_unresolved_sparse_and_gitlink_rejected(self) -> None:
        domain = PRODUCER.git_domain(self.root)
        missing = self.root / "Cargo.lock"
        original = missing.read_bytes()
        missing.unlink()
        self.assertNotEqual(self.invoke("freeze").returncode, 0)
        if self.evidence.exists():
            self.evidence.rmdir()
        self.write("Cargo.lock", original)
        blob = domain["index"]["tracked.txt"]["git_blob"]
        self.git(self.root, "update-index", "--force-remove", "tracked.txt")
        payload = f"100644 {blob} 1\ttracked.txt\n".encode()
        subprocess.run(  # noqa: S603 - owned fixture index input
            [str(shutil.which("git")), "-C", str(self.root), "update-index", "--index-info"],
            input=payload,
            env=PRODUCER.environment(),
            capture_output=True,
            check=True,
        )
        self.assertNotEqual(self.invoke("freeze").returncode, 0)
        self.git(self.root, "update-index", "--force-remove", "tracked.txt")
        baseline = self.git(self.root, "rev-parse", "HEAD").decode().strip()
        self.git(self.root, "update-index", "--add", "--cacheinfo", "160000", baseline, "submodule")
        self.assertNotEqual(self.invoke("freeze").returncode, 0)

    def test_canonical_modes_required_without_chmod_and_no_git_rejected(self) -> None:
        path = self.root / "tracked.txt"
        path.chmod(0o600)
        self.assertNotEqual(self.invoke("freeze").returncode, 0)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        other = self.owner / "not-git"
        other.mkdir()
        with self.assertRaises(PRODUCER.SourceError):
            PRODUCER.root_path(str(other))

    def test_source_mutations_bytes_modes_links_and_index_block_verify(self) -> None:
        sha = self.freeze()
        path = self.root / "tracked.txt"
        path.write_bytes(b"changed")
        self.assertNotEqual(self.invoke("verify", "--sha256", sha).returncode, 0)
        self.write("tracked.txt", b"source bytes\n", 0o755)
        self.assertNotEqual(self.invoke("verify", "--sha256", sha).returncode, 0)
        self.write("tracked.txt", b"source bytes\n")
        link = self.root / "literal"
        link.unlink()
        link.symlink_to("another-target")
        self.assertNotEqual(self.invoke("verify", "--sha256", sha).returncode, 0)
        link.unlink()
        link.symlink_to("missing-target")
        path.unlink()
        path.symlink_to("literal")
        self.assertNotEqual(self.invoke("verify", "--sha256", sha).returncode, 0)
        path.unlink()
        self.write("tracked.txt", b"source bytes\n")
        self.git(self.root, "update-index", "--chmod=+x", "tracked.txt")
        self.assertNotEqual(self.invoke("verify", "--sha256", sha).returncode, 0)

    def test_manifest_raw_bytes_omission_injection_and_link_tampering_rejected(self) -> None:
        sha = self.freeze()
        path = self.evidence / "SOURCE-MANIFEST.json"
        raw = path.read_bytes()
        for change in ["whitespace", "omission", "injection", "symlink"]:
            with self.subTest(change=change):
                path.chmod(0o644)
                data = json.loads(raw)
                if change == "whitespace":
                    replacement = raw + b" "
                elif change == "omission":
                    del data["files"]["Cargo.lock"]
                    replacement = PRODUCER.canonical(data)
                elif change == "injection":
                    data["files"]["injected"] = data["files"]["Cargo.lock"]
                    replacement = PRODUCER.canonical(data)
                else:
                    path.unlink()
                    path.symlink_to(self.root / "Cargo.lock")
                    self.assertNotEqual(self.invoke("verify", "--sha256", sha).returncode, 0)
                    path.unlink()
                    path.write_bytes(raw)
                    path.chmod(0o444)
                    continue
                path.write_bytes(replacement)
                path.chmod(0o444)
                self.assertNotEqual(self.invoke("verify", "--sha256", sha).returncode, 0)
        path.chmod(0o644)
        path.write_bytes(raw)
        path.chmod(0o444)

    def test_supplied_digest_empty_or_arbitrary_rejected_and_stale_manifest_preserved(self) -> None:
        for value in ["", "0" * 64]:
            env = self.environment | {"AEG_LOADTEST_SOURCE_SHA256": value}
            self.assertNotEqual(self.invoke("freeze", env=env).returncode, 0)
        self.freeze()
        original = (self.evidence / "SOURCE-MANIFEST.json").read_bytes()
        self.assertNotEqual(self.invoke("freeze").returncode, 0)
        self.assertEqual((self.evidence / "SOURCE-MANIFEST.json").read_bytes(), original)

    def test_output_exclusion_collisions_symlinks_and_traversal_rejected(self) -> None:
        for output in ["crates", ".", "artifacts/perf/../../crates"]:
            with self.subTest(output=output):
                self.assertNotEqual(
                    self.invoke("paths", "--output-directory", output).returncode, 0
                )
        (self.root / "target").symlink_to(self.private, target_is_directory=True)
        self.assertNotEqual(self.invoke("freeze").returncode, 0)
        (self.root / "target").unlink()
        self.write("artifacts/perf/tracked", b"tracked")
        self.git(self.root, "add", "-f", "artifacts/perf/tracked")
        self.assertNotEqual(self.invoke("freeze").returncode, 0)

    def test_previous_performance_outputs_allowed_for_second_freeze(self) -> None:
        self.write("artifacts/perf/previous/report.json", b"prior evidence")
        self.write("artifacts/load-test-report.json", b"legacy evidence")
        sha = self.freeze()
        self.assertEqual(self.invoke("verify", "--sha256", sha).returncode, 0)

    def build_record(
        self, executable: pathlib.Path, name: str = "aegaeon-loadtest"
    ) -> pathlib.Path:
        log = self.evidence.parent / "build.jsonl"
        log.write_text(
            json.dumps(
                {
                    "reason": "compiler-artifact",
                    "target": {"name": name, "kind": ["bin"]},
                    "executable": str(executable),
                }
            )
            + "\n"
            + json.dumps({"reason": "build-finished", "success": True})
            + "\n"
        )
        return log

    def test_actual_executable_selection_and_report_binding(self) -> None:
        sha = self.freeze()
        binary = self.write("target/release/aegaeon-loadtest", b"inert executable", 0o755)
        log = self.build_record(binary)
        result = self.invoke(
            "bind", "--sha256", sha, "--name", "aegaeon-loadtest", "--build-log", str(log)
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), str(binary))
        report = self.evidence.parent / "report.json"
        report.write_text(
            json.dumps(
                {
                    "identity": {
                        "source_sha256": sha,
                        "artifact_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                    }
                }
            )
        )
        self.assertEqual(
            self.invoke("report", "--sha256", sha, "--report", str(report)).returncode, 0
        )
        report.write_text(
            json.dumps({"identity": {"source_sha256": "0" * 64, "artifact_sha256": "0" * 64}})
        )
        self.assertNotEqual(
            self.invoke("report", "--sha256", sha, "--report", str(report)).returncode, 0
        )
        binary.write_bytes(b"different")
        self.assertNotEqual(
            self.invoke("binary", "--sha256", sha, "--name", "aegaeon-loadtest").returncode, 0
        )

    def test_build_missing_duplicate_failed_or_symlink_executables_rejected(self) -> None:
        sha = self.freeze()
        binary = self.write("target/release/aegaeon-loadtest", b"inert", 0o755)
        log = self.build_record(binary)
        original = log.read_text()
        for value in [
            "",
            original + original,
            original.replace('"success": true', '"success": false'),
        ]:
            log.write_text(value)
            self.assertNotEqual(
                self.invoke(
                    "bind", "--sha256", sha, "--name", "aegaeon-loadtest", "--build-log", str(log)
                ).returncode,
                0,
            )
        log.write_text(original)
        binary.unlink()
        binary.symlink_to(self.root / "tracked.txt")
        self.assertNotEqual(
            self.invoke(
                "bind", "--sha256", sha, "--name", "aegaeon-loadtest", "--build-log", str(log)
            ).returncode,
            0,
        )

    def runner(
        self,
        mode: str = "success",
        *,
        managed: bool = False,
        wrapper: bool = False,
        artifact: str = "artifacts/perf/runner",
    ) -> subprocess.CompletedProcess[str]:
        tools = self.owner / "tools"
        tools.mkdir(exist_ok=True)
        cargo = tools / "cargo"
        cargo.write_text("""#!/usr/bin/env python3
import json,os,pathlib,sys
pathlib.Path(os.environ["FIXTURE_CALLS"]).open("a").write("cargo\\n")
root=pathlib.Path.cwd();name=sys.argv[sys.argv.index("--bin")+1]
expected=(["build","--release","--locked","--bin",name] if name=="aegaeon-server" else
 ["build","--release","-p","aegaeon-loadtest","--bin",name])+["--message-format=json-render-diagnostics"]
if sys.argv[1:]!=expected:raise SystemExit(23)
mode=os.environ["FIXTURE_MODE"]
if mode=="build-failure":raise SystemExit(19)
if mode=="mutate-"+name:(root/"tracked.txt").write_text("mutated during stub build")
target=pathlib.Path(os.environ.get("CARGO_TARGET_DIR",str(root/"target")))
binary=target/"release"/name;binary.parent.mkdir(parents=True,exist_ok=True)
binary.write_text(os.environ["FIXTURE_PROGRAM"]);binary.chmod(0o755)
print(json.dumps({"reason":"compiler-artifact","target":{"name":name,"kind":["bin"]},"executable":str(binary)}))
print(json.dumps({"reason":"build-finished","success":True}))
""")
        cargo.chmod(0o755)
        for name in ["curl", "atlas", "sleep"]:
            path = tools / name
            path.write_text(
                "#!/usr/bin/env python3\nimport os,pathlib,sys\n"
                'pathlib.Path(os.environ["FIXTURE_CALLS"]).open("a").write(pathlib.Path(sys.argv[0]).name+"\\n")\n'
                'sys.exit(1 if os.environ.get("FIXTURE_MODE")=="readiness-failure" and '
                'sys.argv[0].endswith("curl") else 0)\n'
            )
            path.chmod(0o755)
        program = """#!/usr/bin/env python3
import hashlib,json,os,pathlib,sys
if pathlib.Path(sys.argv[0]).name=="aegaeon-server":raise SystemExit(0)
mode=os.environ["FIXTURE_MODE"]
report=pathlib.Path(sys.argv[sys.argv.index("--report-file")+1])
identity={"source_sha256":os.environ["AEG_LOADTEST_SOURCE_SHA256"],"artifact_sha256":hashlib.sha256(pathlib.Path(sys.argv[0]).read_bytes()).hexdigest()}
if mode=="mismatch":identity["source_sha256"]="0"*64
if mode!="no-report":report.write_text(json.dumps({"identity":identity}))
raise SystemExit(17 if mode=="workload-failure" else 0)
"""
        env = self.environment | {
            "PATH": str(tools) + os.pathsep + self.environment["PATH"],
            "FIXTURE_MODE": mode,
            "FIXTURE_CALLS": str(self.owner / "tool-calls"),
            "FIXTURE_PROGRAM": program,
            "ARTIFACT_DIR": artifact,
            "REPORT_PATH": artifact + "/report.json",
            "LOADTEST_LOG": artifact + "/loadtest.log",
            "SERVER_LOG": artifact + "/server.log",
            "LEGACY_REPORT": "artifacts/load-test-report.json",
            "PERF_MANAGE_SERVER": "1" if managed else "0",
            "PERF_BASE_URL": "https://example.invalid",
            "PERF_SERVER_PORT": "18095",
            "AEGAEON_DATABASE_URL": "fixture-only",
            "AEGAEON_RUNTIME_ISSUER_HOST": "example.invalid",
        }
        script = self.root / (
            "scripts/flake/perf_load.sh" if wrapper else "scripts/perf/run_load_tests.sh"
        )
        return subprocess.run(  # noqa: S603 - owned local fixture commands
            [str(shutil.which("bash")), str(script)],
            cwd=self.root,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_runner_success_produces_real_digest_and_same_nix_wrapper_route(self) -> None:
        result = self.runner(wrapper=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        directory = self.root / "artifacts/perf/runner"
        raw = (directory / "source/SOURCE-MANIFEST.json").read_bytes()
        report = json.loads((directory / "report.json").read_bytes())
        self.assertEqual(report["identity"]["source_sha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(
            json.loads((directory / "source-status.json").read_bytes())["stage"], "complete"
        )

    def test_runner_source_mutation_during_build_prevents_launch(self) -> None:
        result = self.runner("mutate-aegaeon-loadtest")
        self.assertNotEqual(result.returncode, 0)
        directory = self.root / "artifacts/perf/runner"
        self.assertTrue((directory / "source/SOURCE-MANIFEST.json").is_file())
        self.assertFalse((directory / "report.json").exists())

    def test_managed_server_source_mutation_blocks_server_launch(self) -> None:
        result = self.runner("mutate-aegaeon-server", managed=True)
        self.assertNotEqual(result.returncode, 0)
        directory = self.root / "artifacts/perf/runner"
        self.assertFalse((directory / "server.log").exists())
        self.assertTrue((directory / "source/SOURCE-MANIFEST.json").is_file())

    def test_runner_build_failure_preserves_manifest_and_original_exit(self) -> None:
        result = self.runner("build-failure")
        self.assertEqual(result.returncode, 19)
        directory = self.root / "artifacts/perf/runner"
        self.assertTrue((directory / "source/SOURCE-MANIFEST.json").exists())
        self.assertEqual(
            json.loads((directory / "source-status.json").read_bytes())["exit_status"], 19
        )

    def test_runner_workload_failure_preserves_report_and_original_exit(self) -> None:
        result = self.runner("workload-failure")
        self.assertEqual(result.returncode, 17, result.stderr)
        directory = self.root / "artifacts/perf/runner"
        self.assertTrue((directory / "source/SOURCE-MANIFEST.json").exists())
        self.assertTrue((directory / "report.json").exists())

    def test_runner_report_identity_mismatch_blocks_success(self) -> None:
        result = self.runner("mismatch")
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue((self.root / "artifacts/perf/runner/report.json").exists())

    def test_runner_rejected_output_does_not_mutate_source(self) -> None:
        result = self.runner(artifact="crates/loadtest")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "crates/loadtest/source-status.json").exists())

    def test_runner_readiness_failure_retains_manifest_before_loadtest_build(self) -> None:
        result = self.runner("readiness-failure")
        self.assertNotEqual(result.returncode, 0)
        directory = self.root / "artifacts/perf/runner"
        self.assertTrue((directory / "source/SOURCE-MANIFEST.json").is_file())
        self.assertFalse((directory / "loadtest-build.jsonl").exists())

    def test_runner_caller_digest_rejected_without_stale_output_reuse(self) -> None:
        self.environment["AEG_LOADTEST_SOURCE_SHA256"] = ""
        result = self.runner()
        self.assertEqual(result.returncode, 2)
        self.assertFalse((self.root / "artifacts/perf/runner/source/SOURCE-MANIFEST.json").exists())

    def test_runner_zero_exit_missing_report_blocks_success(self) -> None:
        result = self.runner("no-report")
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue((self.root / "artifacts/perf/runner/source/SOURCE-MANIFEST.json").exists())

    def test_private_retention_cannot_enter_source_or_upload_root(self) -> None:
        self.environment["TMPDIR"] = str(self.root)
        self.assertNotEqual(self.invoke("freeze").returncode, 0)
        self.assertEqual(list(self.root.glob("aegaeon-perf-source-*")), [])
        self.evidence.rmdir()
        self.environment["TMPDIR"] = str(self.evidence.parent)
        self.assertNotEqual(self.invoke("freeze").returncode, 0)
        self.assertEqual(list(self.evidence.parent.glob("aegaeon-perf-source-*")), [])

    def test_external_cargo_target_is_selected_for_managed_server_and_loadtest(self) -> None:
        self.environment["CARGO_TARGET_DIR"] = str(self.owner / "external-target")
        result = self.runner(managed=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        evidence = self.root / "artifacts/perf/runner/source"
        for name in ["aegaeon-server", "aegaeon-loadtest"]:
            binding = json.loads((evidence / (name + ".json")).read_bytes())
            self.assertTrue(
                pathlib.Path(binding["executable"]).is_relative_to(self.owner / "external-target")
            )

    def test_removing_mandatory_index_entry_rejected(self) -> None:
        self.git(self.root, "rm", "--force", "--quiet", "Cargo.lock")
        self.assertNotEqual(self.invoke("freeze").returncode, 0)

    def test_runner_stale_report_rejected_before_build_and_preserved(self) -> None:
        path = self.write("artifacts/perf/runner/report.json", b"prior report")
        result = self.runner()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(path.read_bytes(), b"prior report")
        self.assertFalse((path.parent / "loadtest-build.jsonl").exists())

    def test_external_cargo_traversal_rejected_before_status_or_build(self) -> None:
        original = (self.root / "tracked.txt").read_bytes()
        for target in [
            str(self.owner / "outside/../source"),
            str(self.owner / "outside/../external-target"),
            "target/../crates",
        ]:
            with self.subTest(target=target):
                self.environment["CARGO_TARGET_DIR"] = target
                result = self.runner()
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((self.root / "artifacts/perf/runner").exists())
                self.assertEqual((self.root / "tracked.txt").read_bytes(), original)
                self.assertEqual(list(self.private.iterdir()), [])

    def make_guard_destination(self, destination: pathlib.Path, kind: str) -> None:
        if kind == "link":
            destination.symlink_to(self.root / "tracked.txt")
        elif kind == "hardlink":
            os.link(self.root / "tracked.txt", destination)
        elif kind == "fifo":
            os.mkfifo(destination)
        elif kind == "directory":
            destination.mkdir()
        else:
            destination.write_bytes(b"prior output")

    def test_all_fixed_redirects_reject_links_special_and_stale_before_build(self) -> None:
        original = (self.root / "tracked.txt").read_bytes()
        self.environment["PERF_APPLY_DATABASE_MIGRATIONS"] = "1"
        names = [
            "server-build.jsonl",
            "build.log",
            "loadtest-build.jsonl",
            "loadtest-build.log",
            "db-migrate.log",
        ]
        for number, (name, kind) in enumerate(
            (name, kind)
            for name in names
            for kind in ["link", "hardlink", "fifo", "directory", "stale"]
        ):
            with self.subTest(name=name, kind=kind):
                artifact = f"artifacts/perf/guard-{number}"
                directory = self.root / artifact
                directory.mkdir(parents=True)
                destination = directory / name
                self.make_guard_destination(destination, kind)
                result = self.runner(managed=True, artifact=artifact)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual((self.root / "tracked.txt").read_bytes(), original)
                self.assertFalse((directory / "source").exists())
                self.assertFalse((self.root / "target").exists())
                self.assertFalse((self.owner / "tool-calls").exists())
                self.assertEqual(
                    json.loads((directory / "source-status.json").read_bytes()),
                    {"stage": "paths", "exit_status": 1},
                )
                if kind == "stale":
                    self.assertEqual(destination.read_bytes(), b"prior output")
                if kind == "directory":
                    destination.rmdir()
                else:
                    destination.unlink()

    def test_prior_status_raw_link_and_hardlink_preserved_and_replaced_on_failure(self) -> None:
        prior = b'{"stage":"complete","exit_status":0}\n'
        original = (self.root / "tracked.txt").read_bytes()
        for number, kind in enumerate(["raw", "link", "hardlink"]):
            with self.subTest(kind=kind):
                artifact = f"artifacts/perf/status-{number}"
                directory = self.root / artifact
                directory.mkdir(parents=True)
                status = directory / "source-status.json"
                if kind == "link":
                    status.symlink_to("../../../tracked.txt")
                    expected = b"../../../tracked.txt"
                elif kind == "hardlink":
                    os.link(self.root / "tracked.txt", status)
                    expected = original
                else:
                    status.write_bytes(prior)
                    expected = prior
                (directory / "loadtest-build.log").write_bytes(b"stale")
                before, result = (
                    set(self.private.glob("aegaeon-perf-status-*")),
                    self.runner(artifact=artifact),
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(status.is_symlink())
                self.assertEqual(
                    json.loads(status.read_bytes()), {"stage": "paths", "exit_status": 1}
                )
                retained = set(self.private.glob("aegaeon-perf-status-*")) - before
                self.assertEqual(len(retained), 1)
                private = retained.pop()
                self.assertEqual(private.stat().st_mode & 0o777, 0o700)
                saved = private / ("source-status.link" if kind == "link" else "source-status.raw")
                self.assertEqual(saved.read_bytes(), expected)
                self.assertEqual(saved.stat().st_mode & 0o777, 0o600)
                self.assertEqual((self.root / "tracked.txt").read_bytes(), original)
                self.assertFalse((directory / "source").exists())

    def test_status_special_directory_and_unsafe_parent_stop_before_private_reads(self) -> None:
        original = (self.root / "tracked.txt").read_bytes()
        for number, kind in enumerate(["fifo", "directory", "parent-link", "tracked-overlap"]):
            with self.subTest(kind=kind):
                artifact = f"artifacts/perf/unsafe-status-{number}"
                directory = self.root / artifact
                directory.parent.mkdir(parents=True, exist_ok=True)
                if kind == "parent-link":
                    directory.symlink_to(self.root)
                elif kind == "tracked-overlap":
                    directory.mkdir()
                    (directory / "source-status.json").write_bytes(b"prior complete")
                    self.git(self.root, "add", artifact + "/source-status.json")
                else:
                    directory.mkdir()
                    status = directory / "source-status.json"
                    if kind == "fifo":
                        os.mkfifo(status)
                    else:
                        status.mkdir()
                result = self.runner(artifact=artifact)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(list(self.private.iterdir()), [])
                self.assertEqual((self.root / "tracked.txt").read_bytes(), original)
                self.assertFalse((self.root / "target").exists())
                if kind == "tracked-overlap":
                    self.assertEqual(
                        (directory / "source-status.json").read_bytes(), b"prior complete"
                    )
                    self.git(
                        self.root,
                        "update-index",
                        "--force-remove",
                        artifact + "/source-status.json",
                    )

    def test_legacy_and_custom_hardlinks_rejected_without_source_truncation(self) -> None:
        original = (self.root / "tracked.txt").read_bytes()
        for number, name in enumerate(["server.log", "loadtest.log", "report.json", "legacy"]):
            with self.subTest(name=name):
                artifact = f"artifacts/perf/custom-{number}"
                directory = self.root / artifact
                directory.mkdir(parents=True)
                destination = (
                    self.root / "artifacts/load-test-report.json"
                    if name == "legacy"
                    else directory / name
                )
                os.link(self.root / "tracked.txt", destination)
                result = self.runner(artifact=artifact)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual((self.root / "tracked.txt").read_bytes(), original)
                self.assertFalse((self.root / "target").exists())
                destination.unlink()

    def test_prior_complete_status_replaced_on_caller_failure_and_success(self) -> None:
        for number, caller_failure in enumerate([True, False]):
            with self.subTest(caller_failure=caller_failure):
                artifact = f"artifacts/perf/status-outcome-{number}"
                status = self.write(artifact + "/source-status.json", b"prior complete")
                if caller_failure:
                    self.environment["AEG_LOADTEST_SOURCE_SHA256"] = ""
                else:
                    self.environment.pop("AEG_LOADTEST_SOURCE_SHA256", None)
                result = self.runner(artifact=artifact)
                self.assertEqual(result.returncode, 2 if caller_failure else 0, result.stderr)
                self.assertEqual(
                    json.loads(status.read_bytes()),
                    {
                        "stage": "paths" if caller_failure else "complete",
                        "exit_status": result.returncode,
                    },
                )
                self.assertEqual(
                    len(list(self.private.glob("aegaeon-perf-status-*/source-status.raw"))),
                    number + 1,
                )

    def test_reserved_output_overlap_and_links_block_external_status_private_reads(self) -> None:
        for number, kind in enumerate(["tracked-target", "target-link", "perf-link"]):
            with self.subTest(kind=kind):
                directory = self.owner / f"external-artifact-{number}"
                directory.mkdir()
                status = directory / "source-status.json"
                status.write_bytes(b"prior complete")
                if kind == "tracked-target":
                    reserved = self.write("target/tracked", b"tracked target")
                    self.git(self.root, "add", "target/tracked")
                else:
                    reserved = self.root / ("target" if kind == "target-link" else "artifacts/perf")
                    reserved.parent.mkdir(parents=True, exist_ok=True)
                    reserved.symlink_to(self.root)
                result = self.runner(artifact=str(directory))
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(status.read_bytes(), b"prior complete")
                self.assertEqual(list(self.private.iterdir()), [])
                self.assertFalse((self.owner / "tool-calls").exists())
                if kind == "tracked-target":
                    self.git(self.root, "update-index", "--force-remove", "target/tracked")
                    reserved.unlink()
                    reserved.parent.rmdir()
                else:
                    reserved.unlink()

    def test_prior_status_and_private_retention_unsafe_tmpdir_rejected_without_replacement(
        self,
    ) -> None:
        status = self.write("artifacts/perf/runner/source-status.json", b"prior complete")
        for temporary in [self.root, status.parent]:
            with self.subTest(temporary=temporary):
                self.environment["TMPDIR"] = str(temporary)
                result = self.runner()
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(status.read_bytes(), b"prior complete")
                self.assertEqual(list(temporary.glob("aegaeon-perf-status-*")), [])

    def test_private_tree_does_not_execute_repo_hooks_or_external_diff(self) -> None:
        sentinel = self.owner / "unexpected-hook"
        script = self.owner / "hook"
        script.write_text("#!/bin/sh\ntouch '" + str(sentinel) + "'\nexit 1\n")
        script.chmod(0o755)
        self.git(self.root, "config", "core.hooksPath", str(self.owner))
        (self.owner / "post-index-change").symlink_to(script)
        self.git(self.root, "config", "diff.external", str(script))
        self.freeze()
        self.assertFalse(sentinel.exists())

    def test_workflow_always_uploads_both_manifest_parent_directories(self) -> None:
        workflow = (SOURCE / ".github/workflows/performance.yml").read_text()
        upload = workflow.split("      - name: Upload load test results", 1)[1].split(
            "  # Observability Testing", 1
        )[0]
        self.assertIn("if: always()", upload)
        self.assertIn("artifacts/perf/ci-load-smoke/", upload)
        self.assertIn("artifacts/perf/ci-policy-mixed/", upload)


if __name__ == "__main__":
    unittest.main()
