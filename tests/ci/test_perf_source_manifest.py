"""Direct source-producer and inert shared-runner controls; no product builds."""
# ruff: noqa: PT009, PT027 - unittest controls remain effective under Python -O

from __future__ import annotations

import copy
import hashlib
import importlib.util
import io
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
import uuid
from unittest import mock

from perf_supplier_fixture import module as supplier_module, prepare as prepare_supplier

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
        for name in PRODUCER.MANDATORY | {
            "scripts/perf/loadtest_supplier.py",
            "nix/build-source.nix",
        }:
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
        # Internal links resolve to bytes in the complete tracked source domain.
        (self.root / "literal").symlink_to("tracked.txt")
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
        path = (
            self.owner / "supplier/package/bin/aegaeon-loadtest"
            if name == "target/release/aegaeon-loadtest"
            else self.root / name
        )
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        path.chmod(mode)
        return path

    def invoke(
        self,
        action: str,
        *args: str,
        env: dict[str, str] | None = None,
        immutable: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        supplier_action = (
            immutable
            or action in {"urls", "config", "invocation", "report"}
            or (action in {"bind", "binary"} and "aegaeon-loadtest" in args)
        )
        entrypoint = self.root / "scripts/perf/source_manifest.py"
        if supplier_action:
            workload = self.owner / "supplier/package/bin/aegaeon-loadtest"
            if not workload.exists():
                workload.parent.mkdir(parents=True)
                workload.write_bytes(b"inert supplier executable\n")
                workload.chmod(0o755)
            prepare_supplier(
                SOURCE,
                self.root,
                self.owner,
                PRODUCER,
                workload,
                runtime_path=self.environment["PATH"],
            )
            entrypoint = self.owner / "supplier/controller/source-helper"
        return subprocess.run(  # noqa: S603 - owned local fixture commands
            [
                sys.executable,
                "-I",
                "-B",
                *(["-O"] if sys.flags.optimize else []),
                str(entrypoint),
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
        self.assertEqual(manifest["files"]["literal"]["symlink"], "tracked.txt")
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
        self.git(self.root, "rm", "--force", "--quiet", "tracked.txt", "literal")
        self.freeze()
        files = json.loads((self.evidence / "SOURCE-MANIFEST.json").read_bytes())["files"]
        self.assertIn("new-source", files)
        self.assertNotIn("tracked.txt", files)
        self.assertNotIn("literal", files)

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
        link.symlink_to("tracked.txt")
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
        report, data = self.invocation_report(sha, binary)
        report.write_text(json.dumps(data))
        self.assertEqual(
            self.invoke("report", "--sha256", sha, "--report", str(report)).returncode, 0
        )
        data["identity"]["source_sha256"] = "0" * 64
        report.write_text(json.dumps(data))
        self.assertNotEqual(
            self.invoke("report", "--sha256", sha, "--report", str(report)).returncode, 0
        )
        binary.write_bytes(b"different")
        self.assertNotEqual(
            self.invoke("binary", "--sha256", sha, "--name", "aegaeon-loadtest").returncode, 0
        )

    def invocation_report(
        self, sha: str, binary: pathlib.Path
    ) -> tuple[pathlib.Path, dict[str, object]]:
        report = self.evidence.parent / "report.json"
        report_id = str(uuid.uuid4())
        argv = [
            str(binary),
            "--url",
            "http://127.0.0.1:18095",
            "--workers",
            "2",
            "--run-time",
            "1m",
            "--warmup",
            "0",
            "--rps",
            "5.5",
            "--scenario",
            "discovery",
            "--report-file",
            str(report),
            "--report-id",
            report_id,
            "--discovery-expected-issuer",
            "https://issuer.example.test",
        ]
        result = self.invoke("invocation", "--sha256", sha, "--", *argv)
        self.assertEqual(result.returncode, 0, result.stderr)
        config = {
            "target_url": "http://127.0.0.1:18095",
            "discovery_expected_issuer": "https://issuer.example.test",
            "workers": 2,
            "duration": {"secs": 60, "nanos": 0},
            "target_rps": 5.5,
            "warmup_duration": {"secs": 0, "nanos": 0},
            "scenario": "Discovery",
            "debug": False,
        }
        witness = json.dumps(config, ensure_ascii=False)
        data = {
            "selected_scenario": "Discovery",
            "identity": {
                "source_sha256": sha,
                "artifact_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                "config_json": witness,
                "config_sha256": hashlib.sha256(witness.encode("utf-8")).hexdigest(),
                "report_id": report_id,
                "report_path": str(report),
                "profile_sha256": None,
                "session_provenance_sha256": None,
            },
        }
        invocation = self.evidence / "INVOCATION.json"
        self.assertEqual(invocation.stat().st_mode & 0o777, 0o444)
        retained = json.loads(invocation.read_bytes())
        self.assertEqual(retained["argv"], argv)
        self.assertEqual(retained["config"], config)
        self.assertEqual(retained["report_id"], report_id)
        self.assertEqual(retained["report_path"], str(report))
        return report, data

    def bound_invocation_report(self) -> tuple[str, pathlib.Path, dict[str, object]]:
        sha = self.freeze()
        binary = self.write("target/release/aegaeon-loadtest", b"inert executable", 0o755)
        result = self.invoke(
            "bind",
            "--sha256",
            sha,
            "--name",
            "aegaeon-loadtest",
            "--build-log",
            str(self.build_record(binary)),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        report, baseline = self.invocation_report(sha, binary)
        return sha, report, baseline

    def test_invocation_rejects_unbound_duplicate_nonfinite_and_missing_arguments(self) -> None:
        sha = self.freeze()
        binary = self.write("target/release/aegaeon-loadtest", b"inert executable", 0o755)
        self.assertEqual(
            self.invoke(
                "bind",
                "--sha256",
                sha,
                "--name",
                "aegaeon-loadtest",
                "--build-log",
                str(self.build_record(binary)),
            ).returncode,
            0,
        )
        report = self.evidence.parent / "report.json"
        argv = [
            str(binary),
            "--url",
            "https://issuer.example.test",
            "--workers",
            "2",
            "--run-time",
            "60s",
            "--warmup",
            "0",
            "--rps",
            "5.5",
            "--scenario",
            "smoke",
            "--report-file",
            str(report),
            "--report-id",
            str(uuid.uuid4()),
        ]
        cases = [
            [*argv, "--users", "1"],
            [*argv, "--workers", "3"],
            [*argv, "--debug", "--debug"],
            [*argv, "--unknown"],
            argv[:-2],
        ]
        for flag, replacement in [
            ("--rps", "nan"),
            ("--rps", "inf"),
            ("--rps", "0"),
            ("--workers", "0"),
            ("--workers", "4294967296"),
            ("--run-time", "0"),
            ("--run-time", "86401s"),
            ("--warmup", "invalid"),
            ("--report-id", "malformed"),
            ("--report-id", "00000000-0000-1000-8000-000000000000"),
        ]:
            changed = argv.copy()
            changed[changed.index(flag) + 1] = replacement
            cases.append(changed)
        for changed in cases:
            with self.subTest(argv=changed):
                self.assertNotEqual(
                    self.invoke("invocation", "--sha256", sha, "--", *changed).returncode, 0
                )
                self.assertFalse((self.evidence / "INVOCATION.json").exists())
        report.write_text("prior report")
        self.assertNotEqual(self.invoke("invocation", "--sha256", sha, "--", *argv).returncode, 0)
        self.assertEqual(report.read_text(), "prior report")
        self.assertFalse((self.evidence / "INVOCATION.json").exists())

    def test_invocation_rejects_secret_bearing_urls_before_record_creation(self) -> None:
        sha = self.freeze()
        binary = self.write("target/release/aegaeon-loadtest", b"inert executable", 0o755)
        self.assertEqual(
            self.invoke(
                "bind",
                "--sha256",
                sha,
                "--name",
                "aegaeon-loadtest",
                "--build-log",
                str(self.build_record(binary)),
            ).returncode,
            0,
        )
        argv = [
            str(binary),
            "--url",
            "http://127.0.0.1:18095",
            "--workers",
            "2",
            "--run-time",
            "60s",
            "--warmup",
            "0",
            "--rps",
            "5.5",
            "--scenario",
            "smoke",
            "--report-file",
            str(self.evidence.parent / "report.json"),
            "--report-id",
            str(uuid.uuid4()),
        ]
        for value in [
            "https://user:fixture-secret@issuer.example.test",
            "https://user%3Afixture-secret@issuer.example.test",
            "https://issuer.example.test?fixture-secret",
            "https://issuer.example.test?",
            "https://issuer.example.test#fixture-secret",
            "https://issuer.example.test#",
            "https://issuer.example.test/\nfixture-secret",
            "https://issuer.example.test/\u0085fixture-secret",
            "https://issuer.example.test/\u009ffixture-secret",
            "https://issuer.example.test/\u00a0fixture-secret",
            "https://issuer.example.test/\u2028fixture-secret",
            "not-a-url",
        ]:
            for flag in ["--url", "--discovery-expected-issuer"]:
                with self.subTest(flag=flag, value=value):
                    changed = argv.copy()
                    if flag == "--url":
                        changed[changed.index(flag) + 1] = value
                    else:
                        changed.extend([flag, value])
                    result = self.invoke("invocation", "--sha256", sha, "--", *changed)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertNotIn("fixture-secret", result.stdout + result.stderr)
                    self.assertFalse((self.evidence / "INVOCATION.json").exists())
        # URL semantics belong to the shared Rust supplier, not a Python parser.
        with self.assertRaises(PRODUCER.SourceError):
            PRODUCER.validate_url_pair("https://issuer.example.test/caf\u00e9", None)

    def test_early_url_helper_admits_safe_urls_without_source_or_output_effects(self) -> None:
        result = self.invoke(
            "urls",
            "--url=https://issuer.example.test/caf\u00e9",
            "--discovery-expected-issuer=https://issuer.example.test",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertFalse(self.evidence.exists())
        for option in (
            "--url=",
            "--url=https://[invalid.fixture-secret",
            "--discovery-expected-issuer=",
            "--discovery-expected-issuer=http://issuer.example.test",
            "--discovery-expected-issuer=https://issuer.example.test/",
            "--url=https://issuer.example.test:not-a-port",
            "--url=https://issuer.example.test:65536",
            "--discovery-expected-issuer=https://issuer.example.test:not-a-port",
            "--discovery-expected-issuer=https://issuer.example.test:65536",
        ):
            with self.subTest(option=option):
                rejected = self.invoke("urls", option)
                self.assertNotEqual(rejected.returncode, 0)
                self.assertNotIn("fixture-secret", rejected.stdout + rejected.stderr)
                self.assertFalse(self.evidence.exists())

    def test_early_url_helper_admits_valid_port_forms_without_source_or_output_effects(
        self,
    ) -> None:
        for value in (
            "https://issuer.example.test:0",
            "https://issuer.example.test:1",
            "https://issuer.example.test:443",
            "https://issuer.example.test:65535",
            "https://issuer.example.test:",
            "https://[::1]:65535",
        ):
            for flag in ("--url", "--discovery-expected-issuer"):
                with self.subTest(flag=flag, value=value):
                    arguments = [flag + "=" + value]
                    if flag == "--discovery-expected-issuer":
                        arguments.insert(0, "--url=http://127.0.0.1:18095")
                    result = self.invoke("urls", *arguments)
                    noncanonical = flag == "--discovery-expected-issuer" and value in {
                        "https://issuer.example.test:443",
                        "https://issuer.example.test:",
                    }
                    self.assertEqual(result.returncode, 1 if noncanonical else 0, result.stderr)
                    self.assertEqual(result.stdout, "")
                    self.assertFalse(self.evidence.exists())

    def test_internal_source_link_chains_freeze_and_target_mutation_blocks_verify(self) -> None:
        self.write("nested/target", b"frozen internal target")
        (self.root / "nested/chain").symlink_to("../literal")
        self.git(self.root, "add", "nested")
        sha = self.freeze()
        manifest = json.loads((self.evidence / "SOURCE-MANIFEST.json").read_bytes())
        self.assertEqual(manifest["files"]["nested/chain"]["symlink"], "../literal")
        self.assertEqual(self.invoke("verify", "--sha256", sha).returncode, 0)
        (self.root / "tracked.txt").write_bytes(b"changed internal target bytes")
        self.assertNotEqual(self.invoke("verify", "--sha256", sha).returncode, 0)

    def test_source_links_reject_escape_untracked_output_cycles_and_dangling(self) -> None:
        link = self.root / "literal"
        outside = self.owner / "outside-target"
        outside.write_bytes(b"owned nonsecret external target")
        for target in (
            str(outside),
            "../outside-target",
            "missing-target",
            "ignored-target",
            "target/release/unknown",
            "artifacts/perf/old/result",
            "literal",
            "crates/unknown/../tracked.txt",
            "tracked.txt/../Cargo.toml",
            "tracked.txt/",
            "tracked.txt/.",
            "crates/loadtest",
        ):
            with self.subTest(target=target):
                link.unlink()
                link.symlink_to(target)
                with self.assertRaises(PRODUCER.SourceError):
                    PRODUCER.read_source(self.root, PRODUCER.git_domain(self.root))
        self.assertEqual(outside.read_bytes(), b"owned nonsecret external target")

    def test_external_source_link_rejects_same_literal_before_and_after_target_mutation(
        self,
    ) -> None:
        outside = self.owner / "outside-mutation-target"
        outside.write_bytes(b"owned nonsecret external target before mutation")
        link = self.root / "literal"
        link.unlink()
        link.symlink_to(outside)
        domain = PRODUCER.git_domain(self.root)
        literal = os.readlink(link)  # noqa: PTH115 - preserve literal link spelling
        link_stamp = PRODUCER.stamp(link.lstat())
        for raw in (
            b"owned nonsecret external target before mutation",
            b"owned nonsecret external target after mutation",
        ):
            with self.subTest(raw=raw):
                outside.write_bytes(raw)
                self.assertEqual(os.readlink(link), literal)  # noqa: PTH115 - compare literal spelling
                self.assertEqual(PRODUCER.stamp(link.lstat()), link_stamp)
                self.assertEqual(PRODUCER.git_domain(self.root), domain)
                with self.assertRaises(PRODUCER.SourceError):
                    PRODUCER.read_source(self.root, domain)

    def test_source_link_cycles_and_aliased_ancestors_reject_before_target_reads(self) -> None:
        link = self.root / "literal"
        (self.root / "cycle-peer").symlink_to("literal")
        self.git(self.root, "add", "cycle-peer")
        link.unlink()
        link.symlink_to("cycle-peer")
        with self.assertRaises(PRODUCER.SourceError):
            PRODUCER.read_source(self.root, PRODUCER.git_domain(self.root))
        (self.root / "cycle-peer").unlink()
        self.git(self.root, "update-index", "--force-remove", "cycle-peer")
        owned = self.owner / "alias-input"
        owned.mkdir()
        (owned / "leaf").write_bytes(b"owned nonsecret alias target")
        (self.root / "alias").symlink_to(owned)
        self.git(self.root, "add", "alias")
        link.unlink()
        link.symlink_to("alias/leaf")
        with self.assertRaises(PRODUCER.SourceError):
            PRODUCER.read_source(self.root, PRODUCER.git_domain(self.root))
        self.assertEqual((owned / "leaf").read_bytes(), b"owned nonsecret alias target")

    def test_runner_invalid_urls_reject_before_output_or_any_probe(self) -> None:
        values = (
            "https://user:fixture-secret@issuer.example.test",
            "https://user%3Afixture-secret@issuer.example.test",
            "https://issuer.example.test?fixture-secret",
            "https://issuer.example.test#fixture-secret",
            "https://issuer.example.test/\nfixture-secret",
            "https://issuer.example.test/\u009ffixture-secret",
            "https://issuer.example.test/\u00a0fixture-secret",
            "https://issuer.example.test/\u2028fixture-secret",
            "ftp://issuer.example.test/fixture-secret",
            "https:///fixture-secret",
        )
        cases = [
            (flag, value, False)
            for flag in ("--url", "--discovery-expected-issuer")
            for value in values
        ]
        cases.extend(
            ("--discovery-expected-issuer", value, False)
            for value in (
                "http://issuer.example.test/fixture-secret",
                "https://issuer.example.test/fixture-secret/",
            )
        )
        cases.extend(
            (flag, value, managed)
            for flag in ("--url", "--discovery-expected-issuer")
            for value in (
                "https://issuer.example.test:not-a-port",
                "https://issuer.example.test:65536",
            )
            for managed in (False, True)
        )
        for index, (flag, value, managed) in enumerate(cases):
            with self.subTest(flag=flag, value=value, managed=managed):
                calls = self.owner / "tool-calls"
                calls.unlink(missing_ok=True)
                result = self.runner(
                    artifact=f"artifacts/perf/rejected-{index}",
                    arguments=(flag, value),
                    managed=managed,
                    overrides={"PERF_APPLY_DATABASE_MIGRATIONS": "1"},
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("fixture-secret", result.stdout + result.stderr)
                self.assertNotIn(value, result.stdout + result.stderr)
                self.assertFalse(calls.exists())
                self.assertFalse((self.root / f"artifacts/perf/rejected-{index}").exists())

    def test_runner_missing_unmanaged_target_rejects_before_output_or_source_changes(
        self,
    ) -> None:
        for existing in (False, True):
            for spelling in ("omitted", "empty-environment", "empty-option"):
                with self.subTest(existing=existing, spelling=spelling):
                    artifact = f"artifacts/perf/missing-{existing}-{spelling}"
                    directory = self.root / artifact
                    sentinel = b"preserved existing status bytes\n"
                    if existing:
                        directory.mkdir(parents=True)
                        (directory / "source-status.json").write_bytes(sentinel)
                    calls = self.owner / "tool-calls"
                    calls.unlink(missing_ok=True)
                    result = self.runner(
                        "build-failure",
                        artifact=artifact,
                        arguments=("--url", "") if spelling == "empty-option" else (),
                        overrides={
                            "PERF_BASE_URL": "" if spelling == "empty-environment" else None,
                            "PERF_APPLY_DATABASE_MIGRATIONS": "1",
                        },
                    )
                    self.assertEqual(result.returncode, 2)
                    self.assertEqual(result.stdout, "")
                    self.assertEqual(
                        result.stderr,
                        "[perf] PERF_BASE_URL or --url is required when PERF_MANAGE_SERVER=0\n",
                    )
                    self.assertFalse(calls.exists())
                    self.assertFalse((directory / "source").exists())
                    self.assertFalse((self.root / "target").exists())
                    if existing:
                        self.assertEqual((directory / "source-status.json").read_bytes(), sentinel)
                        self.assertEqual(
                            list(directory.iterdir()), [directory / "source-status.json"]
                        )
                    else:
                        self.assertFalse(directory.exists())
                    self.assertEqual((self.root / ".git/index").read_bytes(), self.original_index)
                    self.assertEqual(self.git(self.root, "rev-parse", "HEAD"), self.original_head)
                    self.assertEqual(list(self.private.iterdir()), [])

    def test_runner_missing_target_rejects_before_unavailable_source_helper(self) -> None:
        original_prepare = prepare_supplier

        def without_helper(*args, **kwargs):
            controller = original_prepare(*args, **kwargs)
            (controller.parent / "source-helper").unlink()
            return controller

        with mock.patch(f"{__name__}.prepare_supplier", side_effect=without_helper):
            result = self.runner(overrides={"PERF_BASE_URL": None})
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertEqual(
            result.stderr,
            "[perf] PERF_BASE_URL or --url is required when PERF_MANAGE_SERVER=0\n",
        )
        self.assertFalse((self.owner / "tool-calls").exists())
        self.assertFalse((self.root / "artifacts").exists())
        self.assertEqual(list(self.private.iterdir()), [])
        self.assertEqual((self.root / ".git/index").read_bytes(), self.original_index)
        self.assertEqual(self.git(self.root, "rev-parse", "HEAD"), self.original_head)

    def test_runner_noncanonical_issuers_reject_before_setup_and_status_writes(self) -> None:
        values = (
            "HTTPS://issuer.example.test",
            "https://ISSUER.example.test",
            "https://issuer.example.test:443",
            "https://issuer.example.test:",
            "https://issuer.example.test/",
            "https://issuer.example.test/caf\u00e9",
        )
        sentinel = b"preserved existing status bytes\n"
        for managed in (False, True):
            for existing in (False, True):
                for number, value in enumerate(values):
                    with self.subTest(managed=managed, existing=existing, issuer=value):
                        artifact = f"artifacts/perf/issuer-{managed}-{existing}-{number}"
                        directory = self.root / artifact
                        if existing:
                            directory.mkdir(parents=True)
                            (directory / "source-status.json").write_bytes(sentinel)
                        calls = self.owner / "tool-calls"
                        calls.unlink(missing_ok=True)
                        result = self.runner(
                            artifact=artifact,
                            managed=managed,
                            arguments=("--discovery-expected-issuer", value),
                            overrides={"PERF_APPLY_DATABASE_MIGRATIONS": "1"},
                        )
                        self.assertEqual(result.returncode, 1)
                        self.assertEqual(result.stdout, "")
                        self.assertEqual(
                            result.stderr,
                            "[perf] source or executable evidence validation failed\n",
                        )
                        self.assertFalse(calls.exists())
                        self.assertFalse((directory / "source").exists())
                        self.assertFalse((self.root / "target").exists())
                        self.assertEqual(list(self.private.iterdir()), [])
                        if existing:
                            self.assertEqual(
                                (directory / "source-status.json").read_bytes(), sentinel
                            )
                            self.assertEqual(
                                list(directory.iterdir()), [directory / "source-status.json"]
                            )
                        else:
                            self.assertFalse(directory.exists())
                        self.assertEqual(
                            (self.root / ".git/index").read_bytes(), self.original_index
                        )
                        self.assertEqual(
                            self.git(self.root, "rev-parse", "HEAD"), self.original_head
                        )

    def test_runner_url_precheck_preserves_valid_transport_normalization(self) -> None:
        for number, value in enumerate(
            (
                "HTTPS://issuer.example.test",
                "https://ISSUER.example.test",
                "https://issuer.example.test:443",
                "https://issuer.example.test/caf\u00e9",
            )
        ):
            with self.subTest(target=value):
                calls = self.owner / "tool-calls"
                calls.unlink(missing_ok=True)
                result = self.runner(
                    artifact=f"artifacts/perf/normalized-target-{number}",
                    arguments=("--url", value),
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(calls.read_text().splitlines(), ["curl"])

    def test_runner_target_precheck_preserves_managed_default_and_valid_external_target(
        self,
    ) -> None:
        for managed in (False, True):
            with self.subTest(managed=managed):
                calls = self.owner / "tool-calls"
                calls.unlink(missing_ok=True)
                artifact = f"artifacts/perf/valid-target-{managed}"
                result = self.runner(
                    "build-failure" if managed else "success",
                    managed=managed,
                    artifact=artifact,
                    overrides={"PERF_BASE_URL": ""} if managed else {},
                )
                self.assertEqual(result.returncode, 19 if managed else 0, result.stderr)
                self.assertEqual(calls.read_text().splitlines(), ["cargo"] if managed else ["curl"])
                self.assertTrue((self.root / artifact / "source/SOURCE-MANIFEST.json").exists())

    def test_runner_environment_urls_reject_before_managed_or_external_effects(self) -> None:
        for managed in (False, True):
            for key in ("PERF_BASE_URL", "PERF_DISCOVERY_EXPECTED_ISSUER"):
                with self.subTest(managed=managed, key=key):
                    calls = self.owner / "tool-calls"
                    calls.unlink(missing_ok=True)
                    result = self.runner(
                        managed=managed,
                        artifact=f"artifacts/perf/rejected-{managed}-{key}",
                        overrides={
                            key: "https://user:fixture-secret@issuer.example.test",
                            "PERF_APPLY_DATABASE_MIGRATIONS": "1",
                        },
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertNotIn("fixture-secret", result.stdout + result.stderr)
                    self.assertFalse(calls.exists())
                    self.assertFalse(
                        (self.root / f"artifacts/perf/rejected-{managed}-{key}").exists()
                    )

    def test_runner_generated_url_rejects_before_port_selection_or_managed_effects(self) -> None:
        result = self.runner(
            managed=True,
            overrides={
                "PERF_BASE_URL": "",
                "PERF_SERVER_PORT": "",
                "PERF_SERVER_HOST": "user:fixture-secret@127.0.0.1",
                "PERF_APPLY_DATABASE_MIGRATIONS": "1",
            },
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("fixture-secret", result.stdout + result.stderr)
        self.assertFalse((self.owner / "tool-calls").exists())
        self.assertFalse((self.root / "artifacts/perf/runner").exists())

    def test_report_all_config_fields_reject_mutation_even_with_recomputed_hash(self) -> None:
        sha, report, baseline = self.bound_invocation_report()
        original = json.loads(baseline["identity"]["config_json"])
        mutations = {
            "target_url": "https://other.example.test",
            "discovery_expected_issuer": None,
            "workers": 3,
            "duration": {"secs": 61, "nanos": 0},
            "target_rps": 6.0,
            "warmup_duration": {"secs": 1, "nanos": 0},
            "scenario": "Smoke",
            "debug": True,
        }
        witnesses = []
        for key, changed in mutations.items():
            config = copy.deepcopy(original)
            config[key] = changed
            witnesses.append(("changed-" + key, json.dumps(config)))
            config = copy.deepcopy(original)
            del config[key]
            witnesses.append(("missing-" + key, json.dumps(config)))
            config = copy.deepcopy(original)
            config[key] = []
            witnesses.append(("wrong-type-" + key, json.dumps(config)))
        witnesses.extend(
            (
                "duplicate-" + key,
                baseline["identity"]["config_json"][:-1]
                + ","
                + json.dumps(key)
                + ":"
                + json.dumps(original[key])
                + "}",
            )
            for key in original
        )
        for name, changes in [
            ("unknown", {"unknown": 0}),
            ("bool-workers", {"workers": True}),
            ("bool-rate", {"target_rps": True}),
            ("nan", {"target_rps": float("nan")}),
            ("infinite", {"target_rps": float("inf")}),
            ("float-seconds", {"duration": {"secs": 60.0, "nanos": 0}}),
            ("bool-nanos", {"duration": {"secs": 60, "nanos": False}}),
            ("unknown-duration", {"duration": {"secs": 60, "nanos": 0, "extra": 0}}),
            ("finite-rate-mismatch", {"target_rps": 1e308}),
            ("changed-nanos", {"duration": {"secs": 60, "nanos": 1}}),
            ("missing-nanos", {"duration": {"secs": 60}}),
            ("missing-seconds", {"warmup_duration": {"nanos": 0}}),
        ]:
            witnesses.append((name, json.dumps(original | changes)))
        witnesses.extend(
            [
                (
                    "nested-duplicate",
                    baseline["identity"]["config_json"].replace(
                        '"secs": 60', '"secs": 60, "secs": 60'
                    ),
                ),
                ("malformed", "{"),
                ("overflow-number", json.dumps(original).replace("5.5", "1e999")),
            ]
        )
        for name, witness in witnesses:
            with self.subTest(name=name):
                data = copy.deepcopy(baseline)
                if name == "changed-scenario":
                    data["selected_scenario"] = "Smoke"
                data["identity"]["config_json"] = witness
                data["identity"]["config_sha256"] = hashlib.sha256(witness.encode()).hexdigest()
                report.write_text(json.dumps(data))
                self.assertNotEqual(
                    self.invoke("report", "--sha256", sha, "--report", str(report)).returncode, 0
                )

    def test_report_hashes_exact_config_string_without_reserialization(self) -> None:
        sha, report, baseline = self.bound_invocation_report()
        # Hash exact bytes: harmless JSON whitespace remains valid with its own digest.
        data = copy.deepcopy(baseline)
        data["identity"]["config_json"] += " \n"
        data["identity"]["config_sha256"] = hashlib.sha256(
            data["identity"]["config_json"].encode()
        ).hexdigest()
        report.write_text(json.dumps(data))
        self.assertEqual(
            self.invoke("report", "--sha256", sha, "--report", str(report)).returncode, 0
        )
        data["identity"]["config_sha256"] = baseline["identity"]["config_sha256"]
        report.write_text(json.dumps(data))
        self.assertNotEqual(
            self.invoke("report", "--sha256", sha, "--report", str(report)).returncode, 0
        )

    def test_report_requires_independent_uuid_path_scenario_and_strict_identity(self) -> None:
        sha = self.freeze()
        binary = self.write("target/release/aegaeon-loadtest", b"inert executable", 0o755)
        self.assertEqual(
            self.invoke(
                "bind",
                "--sha256",
                sha,
                "--name",
                "aegaeon-loadtest",
                "--build-log",
                str(self.build_record(binary)),
            ).returncode,
            0,
        )
        report, baseline = self.invocation_report(sha, binary)
        cases = []
        for key in baseline["identity"]:
            data = copy.deepcopy(baseline)
            del data["identity"][key]
            cases.append(("missing-" + key, json.dumps(data)))
        for key, value in [
            ("report_id", str(uuid.uuid4())),
            ("report_path", str(report) + ".other"),
            ("config_json", {}),
            ("profile_sha256", []),
            ("session_provenance_sha256", "invalid"),
            ("config_sha256", "0" * 64),
            ("extra", None),
        ]:
            data = copy.deepcopy(baseline)
            data["identity"][key] = value
            cases.append(("changed-" + key, json.dumps(data)))
        cases.extend(
            ("selected-" + str(selected), json.dumps(baseline | {"selected_scenario": selected}))
            for selected in [None, "Smoke", {}, True]
        )
        raw = json.dumps(baseline)
        cases.append(
            (
                "duplicate-identity",
                raw[:-1] + ',"identity":' + json.dumps(baseline["identity"]) + "}",
            )
        )
        cases.append(
            (
                "duplicate-report-id",
                raw.replace('"report_id":', '"report_id":"duplicate","report_id":'),
            )
        )
        cases.append(
            (
                "legacy-two-hashes",
                json.dumps(
                    {
                        "identity": {
                            "source_sha256": sha,
                            "artifact_sha256": baseline["identity"]["artifact_sha256"],
                        }
                    }
                ),
            )
        )
        for name, raw in cases:
            with self.subTest(name=name):
                report.write_text(raw)
                self.assertNotEqual(
                    self.invoke("report", "--sha256", sha, "--report", str(report)).returncode, 0
                )
        alternate = self.evidence.parent / "another-report.json"
        alternate.write_text(json.dumps(baseline))
        self.assertNotEqual(
            self.invoke("report", "--sha256", sha, "--report", str(alternate)).returncode, 0
        )

    def test_build_missing_duplicate_failed_or_symlink_executables_rejected(self) -> None:
        sha = self.freeze()
        binary = self.write("target/release/aegaeon-server", b"inert", 0o755)
        log = self.build_record(binary, "aegaeon-server")
        original = log.read_text()
        for value in [
            "",
            original + original,
            original.replace('"success": true', '"success": false'),
        ]:
            log.write_text(value)
            self.assertNotEqual(
                self.invoke(
                    "bind", "--sha256", sha, "--name", "aegaeon-server", "--build-log", str(log)
                ).returncode,
                0,
            )
        log.write_text(original)
        binary.unlink()
        binary.symlink_to(self.root / "tracked.txt")
        self.assertNotEqual(
            self.invoke(
                "bind", "--sha256", sha, "--name", "aegaeon-server", "--build-log", str(log)
            ).returncode,
            0,
        )

    def runner(  # noqa: PLR0913 - independent owned process fixture controls
        self,
        mode: str = "success",
        *,
        managed: bool = False,
        wrapper: bool = False,
        artifact: str = "artifacts/perf/runner",
        overrides: dict[str, str | None] | None = None,
        arguments: tuple[str, ...] = (),
    ) -> subprocess.CompletedProcess[str]:
        tools = self.owner / "tools"
        tools.mkdir(exist_ok=True)
        cargo = tools / "cargo"
        cargo.write_text("""#!/usr/bin/env python3
import json,os,pathlib,sys,tomllib
pathlib.Path(os.environ["FIXTURE_CALLS"]).open("a").write("cargo\\n")
root=pathlib.Path.cwd();name=sys.argv[sys.argv.index("--bin")+1]
expected=(["build","--release","--locked","--bin",name] if name=="aegaeon-server" else
 ["build","--release","-p","aegaeon-loadtest","--bin",name])+["--message-format=json-render-diagnostics"]
arguments=sys.argv[1:];explicit_target=None
if "--target-dir" in arguments:
 position=arguments.index("--target-dir");explicit_target=arguments[position+1]
 del arguments[position:position+2]
if arguments!=expected:raise SystemExit(23)
mode=os.environ["FIXTURE_MODE"]
if mode=="build-failure":raise SystemExit(19)
if mode=="mutate-"+name:(root/"tracked.txt").write_text("mutated during stub build")
config_path=root/".cargo/config.toml"
config=tomllib.loads(config_path.read_text()) if config_path.exists() else {}
target=pathlib.Path(explicit_target or os.environ.get("CARGO_TARGET_DIR") or
 os.environ.get("CARGO_BUILD_TARGET_DIR") or
 config.get("build",{}).get("target-dir") or str(root/"target"))
pathlib.Path(os.environ["FIXTURE_CARGO_TARGET_RECORD"]).write_text(json.dumps({"argv":sys.argv[1:],"target":str(target)}))
binary=target/"release"/name;binary.parent.mkdir(parents=True,exist_ok=True)
binary.write_text(os.environ["FIXTURE_PROGRAM"]);binary.chmod(0o755)
retention=os.environ.get("FIXTURE_BINARY_RETENTION")
if retention:
 retained=pathlib.Path(retention)/name;retained.parent.mkdir(parents=True,exist_ok=True)
 retained.write_bytes(binary.read_bytes())
print(json.dumps({"reason":"compiler-artifact","target":{"name":name,"kind":["bin"]},"executable":str(binary)}))
print(json.dumps({"reason":"build-finished","success":True}))
""")
        cargo.chmod(0o755)
        for name in ["curl", "atlas", "sleep"]:
            path = tools / name
            path.write_text(
                "#!/usr/bin/env python3\nimport os,pathlib,sys\n"
                'pathlib.Path(os.environ["FIXTURE_CALLS"]).open("a").write(pathlib.Path(sys.argv[0]).name+"\\n")\n'
                'expected=os.environ.get("FIXTURE_CA_EXPECTED")\n'
                'if sys.argv[0].endswith("curl") and expected:\n'
                '    wanted=["-fsS"]+([] if expected=="absent" else ["--cacert",expected])+["https://example.invalid/health"]\n'
                "    if sys.argv[1:]!=wanted:sys.exit(29)\n"
                'sys.exit(1 if os.environ.get("FIXTURE_MODE")=="readiness-failure" and '
                'sys.argv[0].endswith("curl") else 0)\n'
            )
            path.chmod(0o755)
        program = """#!/usr/bin/env python3
import hashlib,json,os,pathlib,sys
if pathlib.Path(sys.argv[0]).name=="aegaeon-server":raise SystemExit(0)
mode=os.environ["FIXTURE_MODE"]
report=pathlib.Path(sys.argv[sys.argv.index("--report-file")+1])
def option(name):return sys.argv[sys.argv.index(name)+1]
def duration(value):
 unit=value[-1];count=value[:-1] if unit in "smh" else value
 return {"secs":int(count)*({"s":1,"m":60,"h":3600}.get(unit,1)),"nanos":0}
scenarios={"smoke":"Smoke","discovery":"Discovery","dpop":"DPoP",
 "auth-code":"AuthorizationCode","introspection":"Introspection","revocation":"Revocation",
 "userinfo":"Userinfo","jwks":"Jwks","par":"PAR","mixed":"Mixed",
 "policy-mixed":"PolicyMixed","key-rotation":"KeyRotation"}
config={"target_url":option("--url"),
 "discovery_expected_issuer":option("--discovery-expected-issuer")
 if "--discovery-expected-issuer" in sys.argv else None,
 "workers":int(option("--workers")),"duration":duration(option("--run-time")),
 "target_rps":float(option("--rps")),"warmup_duration":duration(option("--warmup")),
 "scenario":scenarios[option("--scenario")],"debug":"--debug" in sys.argv}
frozen=pathlib.Path(os.environ["ARTIFACT_DIR"])/"source/INVOCATION.json"
if frozen.stat().st_mode&0o222:raise SystemExit(31)
retained=json.loads(frozen.read_bytes())
if retained["argv"]!=sys.argv or retained["report_id"]!=option("--report-id"):raise SystemExit(32)
if mode.startswith("config-"):
 key=mode[7:];config[key]=({"target_url":"https://other.example.test","discovery_expected_issuer":"https://other.example.test","workers":7,"duration":{"secs":2,"nanos":0},"target_rps":7.0,"warmup_duration":{"secs":3,"nanos":0},"scenario":"Discovery","debug":True})[key]
witness=json.dumps(config)
identity={"source_sha256":os.environ["AEG_LOADTEST_SOURCE_SHA256"],"artifact_sha256":hashlib.sha256(pathlib.Path(sys.argv[0]).read_bytes()).hexdigest(),"config_json":witness,"config_sha256":hashlib.sha256(witness.encode()).hexdigest(),"report_id":option("--report-id"),"report_path":option("--report-file"),"profile_sha256":None,"session_provenance_sha256":None}
if mode=="mismatch":identity["source_sha256"]="0"*64
if mode=="stale-uuid":identity["report_id"]="00000000-0000-4000-8000-000000000000"
if mode=="wrong-path":identity["report_path"]+=".other"
if mode=="missing-config":del identity["config_json"]
if mode!="no-report":
 report.write_text(json.dumps({"selected_scenario":config["scenario"],
 "identity":identity}))
raise SystemExit(17 if mode=="workload-failure" else 0)
"""
        env = self.environment | {
            "PATH": str(tools) + os.pathsep + self.environment["PATH"],
            "FIXTURE_MODE": mode,
            "FIXTURE_CALLS": str(self.owner / "tool-calls"),
            "FIXTURE_PROGRAM": program,
            "FIXTURE_CARGO_TARGET_RECORD": str(self.owner / "cargo-target.json"),
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
        for key, value in (overrides or {}).items():
            if value is None:
                env.pop(key, None)
            else:
                env[key] = value
        workload = self.owner / "supplier/package/bin/aegaeon-loadtest"
        workload.parent.mkdir(parents=True, exist_ok=True)
        workload.write_text(program)
        workload.chmod(0o755)
        controller = prepare_supplier(
            SOURCE,
            self.root,
            self.owner,
            PRODUCER,
            workload,
            runtime_path=env["PATH"],
        )
        if wrapper:
            nix = tools / "nix"
            nix.write_text(
                f"#!{sys.executable}\nimport os,sys\n"
                f"os.execv({str(controller)!r},[{str(controller)!r},*sys.argv[4:]])\n"
            )
            nix.chmod(0o755)
            command = [str(shutil.which("bash")), str(self.root / "scripts/flake/perf_load.sh")]
        else:
            command = [str(controller)]
        self.last_runner_environment = env.copy()
        return subprocess.run(  # noqa: S603 - owned local fixture commands
            [*command, *arguments],
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

    def test_runner_effective_aliases_debug_and_discovery_bind_before_launch(self) -> None:
        result = self.runner(
            wrapper=True,
            arguments=(
                "--users",
                "2",
                "--duration",
                "1m",
                "--spawn_rate",
                "5.5",
                "--warmup",
                "0",
                "--scenario",
                "discovery",
                "--discovery-expected-issuer",
                "https://issuer.example.test",
                "--report_file",
                "artifacts/perf/runner/selected.json",
                "--",
                "--debug",
            ),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        retained = json.loads(
            (self.root / "artifacts/perf/runner/source/INVOCATION.json").read_bytes()
        )
        self.assertEqual(
            retained["config"],
            {
                "target_url": "https://example.invalid",
                "discovery_expected_issuer": "https://issuer.example.test",
                "workers": 2,
                "duration": {"secs": 60, "nanos": 0},
                "target_rps": 5.5,
                "warmup_duration": {"secs": 0, "nanos": 0},
                "scenario": "Discovery",
                "debug": True,
            },
        )
        self.assertEqual(retained["report_path"], "artifacts/perf/runner/selected.json")
        self.assertEqual(uuid.UUID(retained["report_id"]).version, 4)

    def test_runner_recomputed_config_uuid_and_path_mutations_cannot_pass(self) -> None:
        for number, mode in enumerate(
            [
                "config-" + field
                for field in (
                    "target_url",
                    "discovery_expected_issuer",
                    "workers",
                    "duration",
                    "target_rps",
                    "warmup_duration",
                    "scenario",
                    "debug",
                )
            ]
            + ["stale-uuid", "wrong-path", "missing-config"]
        ):
            with self.subTest(mode=mode):
                artifact = "artifacts/perf/mutation-" + str(number)
                result = self.runner(mode, artifact=artifact)
                self.assertNotEqual(result.returncode, 0, result.stderr)
                self.assertTrue((self.root / artifact / "report.json").is_file())
                self.assertTrue((self.root / artifact / "source/INVOCATION.json").is_file())
                self.assertEqual(
                    json.loads((self.root / artifact / "source-status.json").read_bytes())["stage"],
                    "report-binding",
                )

    def test_runner_rejects_unbound_extra_overrides_before_build(self) -> None:
        for arguments in [
            ("--", "--users", "1"),
            ("--", "--report_file", "other.json"),
            ("--", "-s", "discovery"),
            ("--", "--url", "http://other.invalid"),
            ("--", "--report-id", str(uuid.uuid4())),
            ("--", "--debug", "--debug"),
            ("--unknown",),
            ("--discovery-expected-issuer", ""),
            ("--", "--warmup", "0"),
        ]:
            with self.subTest(arguments=arguments):
                result = self.runner(arguments=arguments)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertFalse((self.owner / "tool-calls").exists())
                self.assertFalse(
                    (self.root / "artifacts/perf/runner/source/INVOCATION.json").exists()
                )

    def test_runner_uses_supplier_without_local_workload_build(self) -> None:
        result = self.runner()
        self.assertEqual(result.returncode, 0, result.stderr)
        directory = self.root / "artifacts/perf/runner"
        self.assertTrue((directory / "source/SOURCE-MANIFEST.json").is_file())
        self.assertTrue((directory / "source/LOADTEST-SUPPLIER-BUILD.jsonl").is_file())
        calls = (self.owner / "tool-calls").read_text().splitlines()
        self.assertNotIn("cargo", calls)

    def test_managed_server_source_mutation_blocks_server_launch(self) -> None:
        result = self.runner("mutate-aegaeon-server", managed=True)
        self.assertNotEqual(result.returncode, 0)
        directory = self.root / "artifacts/perf/runner"
        self.assertFalse((directory / "server.log").exists())
        self.assertTrue((directory / "source/SOURCE-MANIFEST.json").is_file())

    def test_runner_build_failure_preserves_manifest_and_original_exit(self) -> None:
        result = self.runner("build-failure", managed=True)
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

    def test_external_cargo_target_selects_server_while_workload_keeps_supplier(self) -> None:
        self.environment["CARGO_TARGET_DIR"] = str(self.owner / "external-target")
        result = self.runner(managed=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        evidence = self.root / "artifacts/perf/runner/source"
        server = json.loads((evidence / "aegaeon-server.json").read_bytes())
        self.assertTrue(
            pathlib.Path(server["executable"]).is_relative_to(self.owner / "external-target")
        )
        workload = json.loads((evidence / "aegaeon-loadtest.json").read_bytes())
        self.assertEqual(workload["schema_version"], 2)
        self.assertTrue(
            pathlib.Path(workload["executable"]).is_relative_to(self.owner / "supplier/package")
        )

    def test_server_binding_rejects_every_frozen_output_leaf(self) -> None:
        leaves = [
            "report.json",
            "legacy-report.json",
            "server.log",
            "loadtest.log",
            "server-build.jsonl",
            "build.log",
            "loadtest-build.jsonl",
            "loadtest-build.log",
            "db-migrate.log",
        ]
        for name in ["aegaeon-server"]:
            for leaf in leaves:
                with self.subTest(name=name, leaf=leaf):
                    directory = self.owner / name / leaf
                    self.evidence = directory / "source"
                    binary = directory / "release" / name
                    destination = str(binary.parent) + "/./" + binary.name
                    outputs = {
                        item: destination if item == leaf else str(directory / item)
                        for item in leaves
                    }
                    arguments = [
                        value for output in outputs.values() for value in ["--output-file", output]
                    ]
                    result = self.invoke(
                        "freeze",
                        "--output-directory",
                        str(directory),
                        *arguments,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    frozen_outputs = json.loads((self.evidence / "OUTPUTS.json").read_bytes())
                    self.assertEqual(len(frozen_outputs), len(leaves) + 1)
                    binary.parent.mkdir(parents=True)
                    raw = b"controlled selected executable bytes\n"
                    binary.write_bytes(raw)
                    binary.chmod(0o755)
                    result = self.invoke(
                        "bind",
                        "--sha256",
                        result.stdout.strip(),
                        "--name",
                        name,
                        "--build-log",
                        str(self.build_record(binary, name)),
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(binary.read_bytes(), raw)
                    self.assertFalse((self.evidence / (name + ".json")).exists())

    def test_executable_admission_rejects_reserved_evidence_and_status_leaves(self) -> None:
        self.evidence = self.owner / "external-evidence" / "source"
        self.freeze()
        for name in ["aegaeon-server"]:
            reserved = [
                self.evidence.parent / "source-status.json",
                self.evidence / "SOURCE-MANIFEST.json",
                self.evidence / "TRACKED-PATHS.json",
                self.evidence / "OUTPUTS.json",
                self.evidence / "ORIGIN.json",
                self.evidence / "INVOCATION.json",
                self.evidence / (name + ".json"),
                self.root / "artifacts/load-test-report.json",
                self.root / "artifacts/policy-mixed-report.json",
            ]
            for destination in reserved:
                with (
                    self.subTest(name=name, destination=destination.name),
                    self.assertRaises(PRODUCER.SourceError),
                ):
                    PRODUCER.admitted_executable(self.root, self.evidence, str(destination))

    def test_binary_readmission_rejects_output_alias_even_with_matching_artifact_hash(self) -> None:
        for name in ["aegaeon-server"]:
            with self.subTest(name=name):
                directory = self.owner / ("readmission-" + name)
                self.evidence = directory / "source"
                forbidden = directory / "release" / name
                frozen = self.invoke("freeze", "--output-file", str(forbidden))
                self.assertEqual(frozen.returncode, 0, frozen.stderr)
                sha = frozen.stdout.strip()
                selected = directory / "approved" / name
                selected.parent.mkdir(parents=True)
                raw = b"controlled selected executable bytes\n"
                selected.write_bytes(raw)
                selected.chmod(0o755)
                self.assertEqual(
                    self.invoke(
                        "bind",
                        "--sha256",
                        sha,
                        "--name",
                        name,
                        "--build-log",
                        str(self.build_record(selected, name)),
                    ).returncode,
                    0,
                )
                forbidden.parent.mkdir(parents=True)
                forbidden.write_bytes(raw)
                forbidden.chmod(0o755)
                binding_path = self.evidence / (name + ".json")
                binding = json.loads(binding_path.read_bytes())
                binding["executable"] = str(forbidden.parent) + "/./" + forbidden.name
                binding_path.chmod(0o600)
                binding_path.write_text(json.dumps(binding))
                binding_path.chmod(0o444)
                self.assertEqual(PRODUCER.load_json(binding_path)[1], binding)
                with self.assertRaisesRegex(
                    PRODUCER.SourceError,
                    "build executable overlaps an output or source evidence",
                ):
                    PRODUCER.verify_binary(self.root, self.evidence, sha, name)
                result = self.invoke("binary", "--sha256", sha, "--name", name)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(forbidden.read_bytes(), raw)
                self.assertEqual(selected.read_bytes(), raw)

    def test_wrapper_external_executable_aliases_preserve_compiled_bytes_before_launch(
        self,
    ) -> None:
        for role in ["aegaeon-server"]:
            for leaf in ["SERVER_LOG", "LOADTEST_LOG", "REPORT_PATH", "LEGACY_REPORT"]:
                with self.subTest(role=role, leaf=leaf):
                    label = role + "-" + leaf.lower()
                    target = self.owner / ("target-" + label)
                    selected = target / "release" / role
                    retained = self.owner / ("retained-" + label)
                    artifact = "artifacts/perf/executable-alias-" + label
                    result = self.runner(
                        managed=True,
                        wrapper=True,
                        artifact=artifact,
                        overrides={
                            "CARGO_TARGET_DIR": str(target),
                            leaf: str(selected.parent) + "/./" + selected.name,
                            "FIXTURE_BINARY_RETENTION": str(retained),
                        },
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(selected.read_bytes(), (retained / role).read_bytes())
                    self.assertTrue(selected.read_bytes().startswith(b"#!/usr/bin/env python3"))
                    evidence = self.root / artifact / "source"
                    self.assertFalse((evidence / (role + ".json")).exists())
                    self.assertFalse((evidence / "INVOCATION.json").exists())
                    status = json.loads((evidence.parent / "source-status.json").read_bytes())
                    self.assertEqual(
                        status["stage"],
                        "server-build" if role == "aegaeon-server" else "loadtest-build",
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

    def test_prior_complete_status_preserved_on_caller_rejection_and_replaced_on_success(
        self,
    ) -> None:
        prior = b"prior complete"
        for number, caller_failure in enumerate([True, False]):
            with self.subTest(caller_failure=caller_failure):
                artifact = f"artifacts/perf/status-outcome-{number}"
                status = self.write(artifact + "/source-status.json", prior)
                if caller_failure:
                    self.environment["AEG_LOADTEST_SOURCE_SHA256"] = ""
                else:
                    self.environment.pop("AEG_LOADTEST_SOURCE_SHA256", None)
                result = self.runner(artifact=artifact)
                self.assertEqual(result.returncode, 2 if caller_failure else 0, result.stderr)
                retained = list(self.private.glob("aegaeon-perf-status-*/source-status.raw"))
                if caller_failure:
                    self.assertEqual(status.read_bytes(), prior)
                    self.assertEqual(retained, [])
                else:
                    self.assertEqual(
                        json.loads(status.read_bytes()),
                        {"stage": "complete", "exit_status": 0},
                    )
                    self.assertEqual(len(retained), 1)
                    self.assertEqual(retained[0].read_bytes(), prior)

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

    def test_output_role_collisions_preserve_status_before_retention_or_build(self) -> None:
        roles = [
            "server.log",
            "loadtest.log",
            "server-build.jsonl",
            "build.log",
            "loadtest-build.jsonl",
            "loadtest-build.log",
            "db-migrate.log",
        ]
        for number, name in enumerate(
            [*roles, "source-status.json", "source/OUTPUTS.json", "source"]
        ):
            with self.subTest(role=name):
                artifact = f"artifacts/perf/collision-{number}"
                status = self.write(artifact + "/source-status.json", b"prior complete")
                result = self.runner(
                    artifact=artifact, overrides={"LEGACY_REPORT": artifact + "/" + name}
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(status.read_bytes(), b"prior complete")
                self.assertEqual(list(self.private.iterdir()), [])
                self.assertFalse((self.owner / "tool-calls").exists())
                self.assertFalse((status.parent / "source").exists())

    def supplier_input_snapshot(self) -> dict[pathlib.Path, tuple[int, bytes | str]]:
        return {
            path: (
                path.lstat().st_mode,
                str(path.readlink()) if path.is_symlink() else path.read_bytes(),
            )
            for path in (self.owner / "supplier").rglob("*")
            if path.is_symlink() or path.is_file()
        }

    def test_supplier_fixed_inputs_reject_output_aliases_before_status_and_tools(self) -> None:
        accepted = self.runner(artifact="artifacts/perf/supplier-accepted")
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        (self.owner / "tool-calls").unlink()
        supplier = self.owner / "supplier"
        inputs = [
            supplier / "package/bin/aegaeon-loadtest",
            supplier / "package/bin/aegaeon-loadtest-url-check",
            supplier / "context.json",
            supplier / "source.json",
            supplier / "source/scripts/perf/source_manifest.py",
            supplier / "source/nix/build-source.nix",
            supplier / "build.jsonl",
            supplier / "graph.json",
            supplier / "controller/aegaeon-perf-load",
            supplier / "controller/source-helper",
            supplier / "controller/runner.sh",
        ]
        cases = [("LEGACY_REPORT", path) for path in inputs]
        cases.extend(
            (role, path)
            for role in ["REPORT_PATH", "LOADTEST_LOG", "SERVER_LOG"]
            for path in inputs[:2]
        )
        before = self.supplier_input_snapshot()
        retained = set(self.private.iterdir())
        for number, (role, path) in enumerate(cases):
            with self.subTest(role=role, path=path):
                artifact = f"artifacts/perf/supplier-output-{number}"
                status = self.write(artifact + "/source-status.json", b"prior complete")
                result = self.runner(
                    artifact=artifact,
                    overrides={role: str(path.parent) + "/./" + path.name},
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(status.read_bytes(), b"prior complete")
                self.assertEqual(self.supplier_input_snapshot(), before)
                self.assertEqual(set(self.private.iterdir()), retained)
                self.assertFalse((self.owner / "tool-calls").exists())
                self.assertFalse((status.parent / "source").exists())
        self.assertEqual((self.root / ".git/index").read_bytes(), self.original_index)

    def test_supplier_directories_reject_artifact_cargo_and_private_writes(self) -> None:
        accepted = self.runner(artifact="artifacts/perf/supplier-directory-accepted")
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        (self.owner / "tool-calls").unlink()
        before = self.supplier_input_snapshot()
        retained = set(self.private.iterdir())
        for number, (role, directory) in enumerate(
            (role, self.owner / "supplier" / directory)
            for role in ["ARTIFACT_DIR", "CARGO_TARGET_DIR", "TMPDIR"]
            for directory in ["source", "package", "controller"]
        ):
            with self.subTest(role=role, directory=directory):
                artifact = f"artifacts/perf/supplier-directory-{number}"
                status = self.write(artifact + "/source-status.json", b"prior complete")
                result = self.runner(artifact=artifact, overrides={role: str(directory) + "/./"})
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(status.read_bytes(), b"prior complete")
                self.assertEqual(self.supplier_input_snapshot(), before)
                self.assertEqual(set(self.private.iterdir()), retained)
                self.assertFalse((self.owner / "tool-calls").exists())
        self.assertEqual((self.root / ".git/index").read_bytes(), self.original_index)

    def test_supplier_direct_status_and_evidence_reject_ancestor_and_descendant_aliases(
        self,
    ) -> None:
        accepted = self.runner()
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        (self.owner / "tool-calls").unlink()
        artifact = self.root / "artifacts/perf/runner"
        status = artifact / "source-status.json"
        before_status = status.read_bytes()
        before = self.supplier_input_snapshot()
        retained = set(self.private.iterdir())
        for directory in [
            self.owner / "supplier",
            self.owner / "supplier/package/bin",
            self.owner / "supplier/source/scripts/perf",
            self.owner / "supplier/controller",
            self.owner / "supplier/controller/nested",
        ]:
            alias = str(directory) + "/./"
            with self.subTest(action="status", artifact=alias):
                result = self.invoke(
                    "status",
                    "--artifact-directory",
                    alias,
                    "--stage",
                    "complete",
                    immutable=True,
                )
                self.assertNotEqual(result.returncode, 0)
            self.evidence = directory
            for action in ["paths", "freeze"]:
                with self.subTest(action=action, evidence=alias):
                    result = self.invoke(
                        action,
                        "--artifact-directory",
                        str(artifact),
                        "--evidence",
                        alias,
                        immutable=True,
                    )
                    self.assertNotEqual(result.returncode, 0)
            self.assertEqual(status.read_bytes(), before_status)
            self.assertEqual(self.supplier_input_snapshot(), before)
            self.assertEqual(set(self.private.iterdir()), retained)
            self.assertFalse((self.owner / "tool-calls").exists())
        self.assertEqual((self.root / ".git/index").read_bytes(), self.original_index)

    def test_supplier_fixed_runtime_tools_reject_output_aliases(self) -> None:
        accepted = self.runner()
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        supplier = self.owner / "supplier"
        runtime = supplier / "runtime"
        runtime.mkdir()
        tools = {}
        for name, original in [
            ("python", sys.executable),
            ("bash", str(shutil.which("bash"))),
            ("git", str(shutil.which("git"))),
        ]:
            path = runtime / (name + "-actual")
            path.write_text(
                f"#!{sys.executable}\nimport os,sys\n"
                f"os.execv({original!r},[{original!r},*sys.argv[1:]])\n"
            )
            path.chmod(0o755)
            alias = runtime / name
            alias.symlink_to(path.name)
            tools[name] = str(alias)
        supplier_module(SOURCE).generated_launchers(
            supplier / "source",
            supplier / "context.json",
            supplier / "controller",
            tools | {"runtime_path": self.last_runner_environment["PATH"]},
        )
        accepted = self.runner(artifact="artifacts/perf/runtime-accepted")
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        (self.owner / "tool-calls").unlink()
        before = self.supplier_input_snapshot()
        retained = set(self.private.iterdir())
        for name in ["python-actual", "bash-actual", "git-actual"]:
            with self.subTest(tool=name):
                artifact = "artifacts/perf/runtime-output-" + name
                status = self.write(artifact + "/source-status.json", b"prior complete")
                result = self.runner(
                    artifact=artifact,
                    overrides={"LEGACY_REPORT": str(runtime) + "/./" + name},
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(status.read_bytes(), b"prior complete")
                self.assertEqual(self.supplier_input_snapshot(), before)
                self.assertEqual(set(self.private.iterdir()), retained)
                self.assertFalse((self.owner / "tool-calls").exists())
                self.assertFalse((status.parent / "source").exists())
        self.assertEqual((self.root / ".git/index").read_bytes(), self.original_index)

    def test_supplier_binary_readmission_rejects_mutated_frozen_output_aliases(self) -> None:
        accepted = self.runner()
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        (self.owner / "tool-calls").unlink()
        self.evidence = self.root / "artifacts/perf/runner/source"
        sha = hashlib.sha256((self.evidence / "SOURCE-MANIFEST.json").read_bytes()).hexdigest()
        outputs_path = self.evidence / "OUTPUTS.json"
        origin_path = self.evidence / "ORIGIN.json"
        outputs = json.loads(outputs_path.read_bytes())
        origin = json.loads(origin_path.read_bytes())
        status = self.evidence.parent / "source-status.json"
        status_before = status.read_bytes()
        before = self.supplier_input_snapshot()
        retained = set(self.private.iterdir())
        for path in [
            self.owner / "supplier/package/bin/aegaeon-loadtest",
            self.owner / "supplier/package/bin/aegaeon-loadtest-url-check",
            self.owner / "supplier/context.json",
            self.owner / "supplier/graph.json",
            self.owner / "supplier/controller/source-helper",
        ]:
            with self.subTest(path=path):
                raw = PRODUCER.canonical([*outputs, [str(path.parent) + "/./" + path.name, False]])
                changed_origin = origin | {"outputs_sha256": hashlib.sha256(raw).hexdigest()}
                for leaf, contents in [
                    (outputs_path, raw),
                    (origin_path, PRODUCER.canonical(changed_origin)),
                ]:
                    leaf.chmod(0o600)
                    leaf.write_bytes(contents)
                    leaf.chmod(0o444)
                result = self.invoke("binary", "--sha256", sha, "--name", "aegaeon-loadtest")
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(status.read_bytes(), status_before)
                self.assertEqual(self.supplier_input_snapshot(), before)
                self.assertEqual(set(self.private.iterdir()), retained)
                self.assertFalse((self.owner / "tool-calls").exists())

    def test_report_legacy_alias_is_explicit_and_cannot_alias_a_third_role(self) -> None:
        artifact = "artifacts/perf/report-alias"
        result = self.runner(
            artifact=artifact, overrides={"LEGACY_REPORT": artifact + "/./report.json"}
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            json.loads((self.root / artifact / "source-status.json").read_text())["stage"],
            "complete",
        )
        status = self.write("artifacts/perf/triple-alias/source-status.json", b"prior complete")
        result = self.runner(
            artifact="artifacts/perf/triple-alias",
            overrides={
                "LEGACY_REPORT": "artifacts/perf/triple-alias/report.json",
                "SERVER_LOG": "artifacts/perf/triple-alias/report.json",
            },
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(status.read_bytes(), b"prior complete")

    def test_file_directory_and_normalized_alias_collisions_precede_status(self) -> None:
        status = self.write("artifacts/perf/control/source-status.json", b"prior complete")
        for outputs in [
            [
                "--output-file",
                str(self.evidence.parent / "leaf"),
                "--output-file",
                str(self.evidence.parent) + "/./leaf",
            ],
            [
                "--output-file",
                str(self.evidence.parent / "leaf"),
                "--output-directory",
                str(self.evidence.parent / "leaf/child"),
            ],
            ["--output-directory", str(self.evidence)],
            ["--output-file", str(self.evidence / "SOURCE-MANIFEST.json")],
            ["--output-file", str(status / "child")],
        ]:
            with self.subTest(outputs=outputs):
                result = self.invoke("paths", "--artifact-directory", str(status.parent), *outputs)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(status.read_bytes(), b"prior complete")
                self.assertEqual(list(self.private.iterdir()), [])

    def test_private_tmpdir_traversal_alias_and_upload_rejected_without_prior_status(self) -> None:
        upload = self.owner / "upload"
        upload.mkdir()
        alias = self.owner / "private-alias"
        alias.symlink_to(self.private, target_is_directory=True)
        for _number, temporary in enumerate(
            [
                str(self.private / "../upload"),
                str(self.private / "../source"),
                str(alias),
                str(upload),
                str(upload / "nested"),
            ]
        ):
            with self.subTest(temporary=temporary):
                result = self.runner(artifact=str(upload), overrides={"TMPDIR": temporary})
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(list(upload.rglob("aegaeon-perf-source-*")), [])
                self.assertEqual(list(upload.rglob("aegaeon-perf-status-*")), [])
                self.assertFalse((upload / "source-status.json").exists())
                self.assertFalse((self.owner / "tool-calls").exists())

    def test_explicit_artifact_status_and_private_root_guard_direct_freeze(self) -> None:
        artifact = self.owner / "separate-artifact"
        artifact.mkdir()
        status = artifact / "source-status.json"
        status.write_bytes(b"prior complete")
        for action in ["paths", "freeze"]:
            with self.subTest(action=action):
                result = self.invoke(
                    action, "--artifact-directory", str(artifact), "--output-file", str(status)
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(status.read_bytes(), b"prior complete")
                self.assertFalse(self.evidence.exists())
                self.assertEqual(list(self.private.iterdir()), [])
        self.environment["TMPDIR"] = str(artifact)
        for action in ["paths", "freeze"]:
            with self.subTest(action=action, private_root="artifact"):
                result = self.invoke(action, "--artifact-directory", str(artifact))
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(status.read_bytes(), b"prior complete")
                self.assertEqual(list(artifact.glob("aegaeon-perf-*")), [])

    def test_readiness_uses_consumer_ca_and_keeps_verified_tls(self) -> None:
        self.environment.pop("AEG_LOADTEST_CA_CERT", None)
        ca = self.owner / "fixture-ca.pem"
        ca.write_text("fixture CA bytes; no live TLS connection\n")
        for number, expected in enumerate([str(ca), "absent"]):
            with self.subTest(ca=expected):
                overrides = {"FIXTURE_CA_EXPECTED": expected}
                if expected != "absent":
                    overrides["AEG_LOADTEST_CA_CERT"] = expected
                result = self.runner(artifact=f"artifacts/perf/tls-{number}", overrides=overrides)
                self.assertEqual(result.returncode, 0, result.stderr)

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

    def test_helper_packages_are_fresh_and_bound_to_exact_source_location(self) -> None:
        supplier = supplier_module(SOURCE)
        first = supplier.source_module(self.root)
        first._helpers["io"].MAX_RUN_SECONDS = 7
        other = self.owner / "other"
        shutil.copytree(self.root / "scripts/perf", other / "scripts/perf")
        other_io = other / "scripts/perf/perf_source/io.py"
        other_io.write_text(other_io.read_text() + "\nMAX_RUN_SECONDS += 1\n")
        original_path = sys.path.copy()
        hostile_path = [str(other / "scripts/perf"), *original_path]
        with (
            mock.patch.object(sys, "path", hostile_path),
            mock.patch.dict(sys.modules, {"perf_source": first._helpers["io"]}),
        ):
            second = supplier.source_module(self.root)
            alternate = supplier.source_module(other)
            repeated = supplier.source_module(self.root)
            self.assertEqual(sys.path, hostile_path)
        self.assertEqual(sys.path, original_path)
        packages = [first, second, alternate, repeated]
        self.assertEqual(len({value._helpers["io"].__package__ for value in packages}), 4)
        self.assertEqual(second.MAX_RUN_SECONDS, PRODUCER.MAX_RUN_SECONDS)
        self.assertEqual(repeated.MAX_RUN_SECONDS, PRODUCER.MAX_RUN_SECONDS)
        self.assertEqual(alternate.MAX_RUN_SECONDS, PRODUCER.MAX_RUN_SECONDS + 1)
        for helper, source in ((second, self.root), (alternate, other), (repeated, self.root)):
            for name, value in helper._helpers.items():
                self.assertEqual(
                    pathlib.Path(value.__file__), source / f"scripts/perf/perf_source/{name}.py"
                )
                self.assertIs(value.fail, helper._helpers["io"].fail)
            self.assertEqual(helper._helpers["invocation"].MAX_RUN_SECONDS, helper.MAX_RUN_SECONDS)
            self.assertFalse(hasattr(helper, "SUPPLIER_CONTEXT"))

    def reference_git_tree(self, runtime, inputs):
        reference = self.private / "reference"
        reference.mkdir()
        (reference / "objects").mkdir()
        env = {
            **PRODUCER.environment(),
            "GIT_INDEX_FILE": str(reference / "index"),
            "GIT_OBJECT_DIRECTORY": str(reference / "objects"),
            "GIT_ALTERNATE_OBJECT_DIRECTORIES": str(self.root / ".git/objects"),
        }
        records = []
        for name, (mode, raw) in inputs.items():
            blob = (
                runtime.command(
                    self.root, "hash-object", "--no-filters", "-w", "--stdin", env=env, data=raw
                )
                .decode()
                .strip()
            )
            records.append(f"{mode} {blob}\t{name}\0".encode())
        runtime.command(self.root, "read-tree", "--empty", env=env)
        runtime.command(
            self.root, "update-index", "-z", "--index-info", env=env, data=b"".join(records)
        )
        tree = runtime.command(self.root, "write-tree", env=env).decode().strip()
        patch = runtime.command(
            self.root,
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "--binary",
            "--full-index",
            self.original_head.decode().strip(),
            tree,
            "--",
            env=env,
        )
        return tree, patch

    def reference_source_archive(self, inputs):
        raw_archive = io.BytesIO()
        with tarfile.open(fileobj=raw_archive, mode="w") as archive:
            for name, (mode, raw) in inputs.items():
                info = tarfile.TarInfo(name)
                info.mode = (self.root / name).lstat().st_mode & 0o777
                if mode == "120000":
                    info.type = tarfile.SYMTYPE
                    info.linkname = raw.decode()
                    archive.addfile(info)
                else:
                    info.size = len(raw)
                    archive.addfile(info, io.BytesIO(raw))
        return raw_archive.getvalue()

    def test_batched_blobs_preserve_independent_tree_patch_archive_and_source(self) -> None:
        for number in range(259):
            self.write(f"batch/member{number:03d}", f"member {number}\n".encode())
        self.write("batch/executable", b"executable bytes\0\n", 0o755)
        (self.root / "batch/link").symlink_to("./member000")
        self.git(self.root, "add", "batch")
        self.write("batch/member000", b"dirty after stage\0\xff\n")
        index = (self.root / ".git/index").read_bytes()
        names = self.git(self.root, "ls-files", "-z").decode().strip("\0").split("\0")
        links = {"literal": b"tracked.txt", "batch/link": b"./member000"}
        inputs = {
            name: (
                "120000"
                if name in links
                else ("100755" if (self.root / name).lstat().st_mode & 0o111 else "100644"),
                links[name] if name in links else (self.root / name).read_bytes(),
            )
            for name in sorted(names)
        }
        runtime = PRODUCER.select()
        expected_tree, expected_patch = self.reference_git_tree(runtime, inputs)
        domain = PRODUCER.git_domain(self.root, runtime=runtime)
        files, contents = PRODUCER.read_source(self.root, domain)
        selected = mock.Mock(wraps=runtime)
        selected.supplier = runtime.supplier
        with (
            mock.patch.dict(os.environ, self.environment, clear=True),
            mock.patch.object(
                PRODUCER, "select", side_effect=RuntimeError("ambient tool selection")
            ),
        ):
            tree, patch, private = PRODUCER.private_tree(
                self.root, domain, files, contents, [self.evidence.parent], runtime=selected
            )
        self.assertEqual((tree, patch), (expected_tree, expected_patch))
        self.assertEqual(
            (private / "source.tar").read_bytes(), self.reference_source_archive(inputs)
        )
        batches = [
            call for call in selected.command.call_args_list if call.args[1] == "hash-object"
        ]
        self.assertEqual(len(batches), (len(inputs) + 127) // 128)
        self.assertTrue(all(0 < len(call.args[5:]) <= 128 for call in batches))
        self.assertEqual((self.root / ".git/index").read_bytes(), index)
        self.assertEqual(self.git(self.root, "rev-parse", "HEAD"), self.original_head)
        self.assertEqual((self.root / "batch/member000").read_bytes(), inputs["batch/member000"][1])
        self.assertEqual((self.root / "batch/executable").lstat().st_mode & 0o777, 0o755)

    def test_blob_batches_reject_missing_or_mismatched_results_before_index(self) -> None:
        runtime = PRODUCER.select()
        domain = PRODUCER.git_domain(self.root, runtime=runtime)
        files, contents = PRODUCER.read_source(self.root, domain)
        for malformed in ("missing", "mismatch"):
            with self.subTest(result=malformed):

                def command(root, *args, malformed=malformed, **options):
                    raw = runtime.command(root, *args, **options)
                    if args[0] == "hash-object":
                        return b"" if malformed == "missing" else b"0" * 40 + raw[40:]
                    return raw

                selected = mock.Mock(wraps=runtime)
                selected.supplier = runtime.supplier
                selected.command.side_effect = command
                with (
                    mock.patch.dict(os.environ, self.environment, clear=True),
                    self.assertRaises(PRODUCER.SourceError),
                ):
                    PRODUCER.private_tree(
                        self.root, domain, files, contents, [self.evidence.parent], runtime=selected
                    )
                self.assertFalse(
                    any(
                        call.args[1] in {"read-tree", "update-index", "write-tree"}
                        for call in selected.command.call_args_list
                    )
                )
                self.assertEqual((self.root / ".git/index").read_bytes(), self.original_index)
                self.assertEqual(self.git(self.root, "rev-parse", "HEAD"), self.original_head)
                self.assertFalse(self.evidence.exists())
        for private in self.private.glob("aegaeon-perf-source-*"):
            self.assertFalse((private / "index").exists())
            self.assertFalse((private / "source.tar").exists())

    def test_each_fixed_helper_is_required_in_complete_selected_git_domain(self) -> None:
        for name in (*PRODUCER.MODULE_FILES, "scripts/perf/loadtest_supplier.py"):
            with self.subTest(missing=name):
                self.git(self.root, "rm", "--cached", "--quiet", name)
                result = self.invoke("freeze", "--output-directory", str(self.evidence.parent))
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.evidence.exists())
                self.assertFalse(list(self.private.iterdir()))
                self.git(self.root, "add", name)

    def test_runner_effective_invalid_config_precedes_all_managed_and_external_effects(self):
        cases = {
            "PERF_WORKERS": ("0", "1_0", " 1", "\uff11"),
            "PERF_RPS": (
                "inf",
                "1e308",
                "1e12",
                "1_0",
                " 1",
                "1 ",
                "1\t",
                "\u0661",
                "\uff11",
                "1e1_0",
                "nan",
                "NaN",
                "Infinity",
                "-inf",
                "0x1p0",
            ),
            "PERF_RUN_TIME": ("0s", "86401s", "fixture-secret"),
            "PERF_WARMUP": ("invalid", "86401s"),
            "PERF_SCENARIO": ("fixture-secret",),
        }
        for managed in (False, True):
            for key, values in cases.items():
                for value in values:
                    with self.subTest(managed=managed, key=key, value=value):
                        result = self.runner(
                            managed=managed,
                            overrides={
                                key: value,
                                "PERF_SERVER_PORT": "",
                                "PERF_APPLY_DATABASE_MIGRATIONS": "1",
                            },
                        )
                        self.assertNotEqual(result.returncode, 0)
                        self.assertNotIn("fixture-secret", result.stdout + result.stderr)
                        self.assertFalse((self.owner / "tool-calls").exists())
                        self.assertFalse((self.root / "artifacts").exists())
                        self.assertFalse(list(self.private.iterdir()))
                        self.assertEqual(
                            (self.root / ".git/index").read_bytes(), self.original_index
                        )

    def test_runner_duration_control_separators_reject_before_any_effects(self) -> None:
        for managed in (False, True):
            for key in ("PERF_RUN_TIME", "PERF_WARMUP"):
                for separator in "\x1c\x1d\x1e\x1f":
                    for value in (separator + "1s", "1s" + separator):
                        with self.subTest(managed=managed, key=key, value=value):
                            result = self.runner(
                                managed=managed,
                                overrides={
                                    key: value,
                                    "PERF_SERVER_PORT": "",
                                    "PERF_APPLY_DATABASE_MIGRATIONS": "1",
                                },
                            )
                            self.assertNotEqual(result.returncode, 0)
                            self.assertFalse((self.owner / "tool-calls").exists())
                            self.assertFalse((self.root / "artifacts").exists())
                            self.assertFalse(list(self.private.iterdir()))
                            self.assertEqual(
                                (self.root / ".git/index").read_bytes(), self.original_index
                            )

    def test_duration_admission_preserves_standard_unicode_whitespace(self) -> None:
        whitespace = " \t\n\r\v\f\u0085\u00a0\u1680\u2028\u2029\u202f\u205f\u3000"
        whitespace += "".join(chr(value) for value in range(0x2000, 0x200B))
        for separator in whitespace:
            with self.subTest(separator=separator):
                result = self.invoke(
                    "config",
                    "--",
                    "--url",
                    "https://example.invalid",
                    "--workers",
                    "1",
                    "--run-time",
                    separator + "1s" + separator,
                    "--warmup",
                    separator + "0" + separator,
                    "--rps",
                    "1",
                    "--scenario",
                    "smoke",
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertFalse((self.root / "artifacts").exists())
                self.assertFalse(list(self.private.iterdir()))
                self.assertEqual((self.root / ".git/index").read_bytes(), self.original_index)

    def test_runner_explicit_cargo_target_overrides_build_environment_and_config(self) -> None:
        attempted = self.owner / "unadmitted-build-target"
        config = self.write(
            ".cargo/config.toml",
            ("[build]\ntarget-dir = " + json.dumps(str(attempted)) + "\n").encode(),
        )
        self.git(self.root, "add", str(config))
        for configured in (False, True):
            for setting in ("environment", "config"):
                with self.subTest(configured=configured, setting=setting):
                    suffix = f"{configured}-{setting}"
                    selected = (
                        self.owner / ("selected-" + suffix) if configured else self.root / "target"
                    )
                    overrides = {
                        "CARGO_TARGET_DIR": str(selected) if configured else None,
                        "CARGO_BUILD_TARGET_DIR": str(attempted)
                        if setting == "environment"
                        else None,
                    }
                    calls = self.owner / "tool-calls"
                    previous_builds = (
                        calls.read_text().splitlines().count("cargo") if calls.exists() else 0
                    )
                    result = self.runner(
                        managed=True,
                        artifact="artifacts/perf/target-" + suffix,
                        overrides=overrides,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    observed = json.loads((self.owner / "cargo-target.json").read_bytes())
                    self.assertEqual(observed["target"], str(selected))
                    arguments = observed["argv"]
                    self.assertEqual(arguments.count("--target-dir"), 1)
                    self.assertEqual(arguments[arguments.index("--target-dir") + 1], str(selected))
                    self.assertTrue((selected / "release/aegaeon-server").is_file())
                    self.assertFalse(attempted.exists())
                    self.assertEqual(
                        calls.read_text().splitlines().count("cargo"), previous_builds + 1
                    )

    def test_default_cargo_target_links_and_files_reject_early(self) -> None:
        target = self.root / "target"
        outside = self.owner / "outside-target"
        outside.mkdir()
        marker = outside / "preserved"
        marker.write_bytes(b"preserved outside Cargo output")
        for kind in ("symlink", "file"):
            with self.subTest(kind=kind):
                if kind == "symlink":
                    target.symlink_to(outside)
                else:
                    target.write_bytes(b"preserved default Cargo file")
                artifact = self.owner / ("prior-" + kind)
                artifact.mkdir()
                status = artifact / "source-status.json"
                status.write_bytes(b"prior complete")
                result = self.runner(managed=True, artifact=str(artifact))
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(status.read_bytes(), b"prior complete")
                self.assertFalse((self.owner / "tool-calls").exists())
                self.assertFalse(list(self.private.iterdir()))
                self.assertFalse((artifact / "source").exists())
                self.assertEqual(marker.read_bytes(), b"preserved outside Cargo output")
                if kind == "symlink":
                    self.assertTrue(target.is_symlink())
                    self.assertEqual(target.readlink(), outside)
                else:
                    self.assertEqual(target.read_bytes(), b"preserved default Cargo file")
                self.assertEqual((self.root / ".git/index").read_bytes(), self.original_index)
                target.unlink()

    def test_default_cargo_target_nonowned_directory_is_preserved(self) -> None:
        target = self.root / "target"
        target.mkdir()
        with (
            mock.patch.dict(os.environ, {"CARGO_TARGET_DIR": ""}),
            mock.patch.object(os, "geteuid", return_value=target.stat().st_uid + 1),
            self.assertRaisesRegex(PRODUCER.SourceError, "Cargo output is not an owned"),
        ):
            PRODUCER.cargo_outputs(self.root)
        self.assertTrue(target.is_dir())

    def test_effective_config_accepts_ascii_decimal_and_exponent_rates(self) -> None:
        for rate in ("1", "+1", "1.", ".5", "1e2", "1E+2", "1e-2"):
            with self.subTest(rate=rate):
                result = self.invoke(
                    "config",
                    "--",
                    "--url",
                    "https://example.invalid",
                    "--workers",
                    "1",
                    "--run-time",
                    " 1s ",
                    "--warmup",
                    "0",
                    "--rps",
                    rate,
                    "--scenario",
                    "smoke",
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertFalse((self.root / "artifacts").exists())
                self.assertFalse(list(self.private.iterdir()))

    def test_cargo_target_roles_protect_complete_trees_and_allow_nested_artifacts(self):
        runtime = PRODUCER.select()
        for configured in (False, True):
            for leaf in ("target", "cache", "report", "evidence", "status", "program.d"):
                target = self.owner / "cargo" / leaf if configured else self.root / "target"
                env = {"CARGO_TARGET_DIR": str(target)} if configured else {}
                with mock.patch.dict(os.environ, env):
                    for role in ("file", "directory", "evidence", "status"):
                        for path in (target, target / "nested", target.parent):
                            with self.subTest(
                                configured=configured, leaf=leaf, role=role, path=path
                            ):
                                evidence = path if role == "evidence" else self.evidence
                                status = path if role == "status" else None
                                outputs = (
                                    [(str(path), role == "directory")]
                                    if role in {"file", "directory"}
                                    else []
                                )
                                with self.assertRaises(PRODUCER.SourceError):
                                    PRODUCER.output_roles(
                                        self.root, evidence, outputs, status, runtime=runtime
                                    )
                    PRODUCER.output_roles(
                        self.root,
                        self.evidence,
                        [
                            (str(self.evidence.parent), True),
                            (str(self.evidence.parent / "report.json"), False),
                        ],
                        runtime=runtime,
                    )
        self.assertFalse(self.evidence.exists())
        self.assertFalse(list(self.private.iterdir()))

    def test_runner_and_direct_status_cargo_overlap_preserve_prior_bytes(self):
        for role in ("REPORT_PATH", "SERVER_LOG", "LOADTEST_LOG", "artifact", "evidence", "status"):
            with self.subTest(role=role):
                artifact = self.owner / ("external-" + role)
                artifact.mkdir()
                status = artifact / "source-status.json"
                status.write_bytes(b"prior complete")
                target = artifact / {
                    "artifact": "cargo",
                    "evidence": "source",
                    "status": "source-status.json",
                }.get(role, "cache/program.d")
                overrides = {"CARGO_TARGET_DIR": str(target)}
                if role in {"REPORT_PATH", "SERVER_LOG", "LOADTEST_LOG"}:
                    overrides[role] = str(target / "nested")
                result = self.runner(artifact=str(artifact), overrides=overrides)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(status.read_bytes(), b"prior complete")
                self.assertFalse((self.owner / "tool-calls").exists())
                self.assertFalse(list(self.private.iterdir()))
                self.assertFalse((artifact / "source").exists())
                result = self.invoke(
                    "status",
                    "--artifact-directory",
                    str(artifact),
                    "--stage",
                    "complete",
                    env=self.environment | {"CARGO_TARGET_DIR": str(target)},
                    immutable=True,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(status.read_bytes(), b"prior complete")

    def test_config_pacing_uses_supplier_representability_without_local_approximation(self) -> None:
        workload = self.write("target/release/aegaeon-loadtest", b"inert workload\n", 0o755)
        prepare_supplier(
            SOURCE, self.root, self.owner, PRODUCER, workload, runtime_path=self.environment["PATH"]
        )
        supplier = supplier_module(SOURCE)
        helper = supplier.source_module(self.owner / "supplier/source")
        context_path = self.owner / "supplier/context.json"
        context = supplier.SupplierContext(
            helper,
            str(context_path),
            supplier.sha256(context_path.read_bytes()),
            str(shutil.which("git")),
        )
        runtime = PRODUCER.select(supplier=context)
        config = {
            "target_url": "https://issuer.example.test",
            "discovery_expected_issuer": None,
            "workers": 1,
            "duration": {"secs": 1, "nanos": 0},
            "target_rps": 1e9,
            "warmup_duration": {"secs": 0, "nanos": 0},
            "scenario": "Smoke",
            "debug": False,
        }
        # Exact Duration representability remains the selected Rust executable's decision.
        self.assertEqual(PRODUCER.validate_config(config, runtime=runtime), config)
        for target_rps in (1e308, 1e12, 5e-324, 1e-5):
            with self.subTest(target_rps=target_rps), self.assertRaises(ValueError):
                PRODUCER.validate_config({**config, "target_rps": target_rps}, runtime=runtime)
        self.assertFalse(self.evidence.exists())
        self.assertFalse(list(self.private.iterdir()))

    def test_public_helpers_keep_positional_inputs_and_reject_unknown_dependency_options(self):
        runtime = PRODUCER.select()
        domain = PRODUCER.git_domain(self.root, runtime=runtime)
        files, contents = PRODUCER.read_source(self.root, domain)
        with self.assertRaises(TypeError):
            PRODUCER.private_tree(self.root, domain, files, contents, [], unrelated=runtime)
        with self.assertRaises(TypeError):
            PRODUCER.bind(
                self.root, self.evidence, "digest", None, "aegaeon-server", unrelated=runtime
            )
        with (
            mock.patch.object(
                PRODUCER, "select", side_effect=RuntimeError("ambient tool selection")
            ),
            mock.patch.object(PRODUCER, "verify"),
            self.assertRaises(PRODUCER.SourceError),
        ):
            PRODUCER.bind(
                self.root, self.evidence, "digest", None, "aegaeon-server", runtime=runtime
            )
        self.assertFalse(self.evidence.exists())
        self.assertFalse(list(self.private.iterdir()))


if __name__ == "__main__":
    unittest.main()
