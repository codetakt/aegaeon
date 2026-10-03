"""Exercise the real sanitizer wrapper with controlled Cargo and libtest tools."""

from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WRAPPER = ROOT / "scripts/sanitizers/run_sanitizers.sh"
TARGETS = (
    "ffi",
    "aead_buffer_boundary_test",
    "dpop_header_test",
    "dpop_proof_test",
    "dpop_uri_test",
    "equivalence_pkce_test",
    "jose_header_runtime_test",
    "oidc_hash_runtime_test",
    "pkce_verifier_test",
)

# One fixture dispatches by executable identity. It emits realistic Cargo and
# libtest records; no compiler execution or synthetic Git commits are involved.
FIXTURE = r"""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

root = Path(os.environ["SANITIZER_FIXTURE"])
mode = os.environ.get("SANITIZER_FIXTURE_MODE", "success")
tool = Path(sys.argv[0]).name
args = sys.argv[1:]
with (root / "calls.jsonl").open("a") as output:
    output.write(
        json.dumps(
            {
                "tool": tool,
                "args": args,
                "flags": os.environ.get("RUSTFLAGS"),
                "encoded_flags": os.environ.get("CARGO_ENCODED_RUSTFLAGS"),
            }
        )
        + "\n"
    )


def stall(closed=False):
    child = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(60)",
        ],
        stdout=subprocess.DEVNULL if closed else None,
        stderr=subprocess.DEVNULL if closed else None,
    )
    (root / "child.pid").write_text(str(child.pid))
    if closed and not mode.endswith("descendant"):
        os.close(1)
        os.close(2)
    if mode.endswith("descendant"):
        return
    time.sleep(60)


if tool == "rustc":
    if mode == "bad-host":
        print("rustc unknown")
    elif "-vV" in args:
        print("host: x86_64-unknown-linux-gnu")
    else:
        print("rustc nightly fixture")
elif tool == "clang":
    print(root / "runtime")
elif tool == "nm":
    print("__asan_init __asan_report_load8 ___asan_gen_" if mode != "uninstrumented" else "main")
elif tool == "readelf":
    print("NEEDED libc.so.6")
elif tool == "cargo":
    metadata = json.loads((root / "metadata.json").read_text())
    if "metadata" in args:
        if mode == "metadata-missing":
            metadata["packages"][0]["targets"].pop()
        if mode == "metadata-duplicate":
            metadata["packages"][0]["targets"].append(metadata["packages"][0]["targets"][0])
        if mode == "metadata-wrong-root":
            metadata["workspace_root"] = "/different-workspace"
        print(json.dumps(metadata))
        sys.exit(0)
    if mode.startswith("build-") and mode in {
        "build-timeout",
        "build-closed-timeout",
        "build-descendant",
        "build-closed-descendant",
        "build-failure-descendant",
    }:
        stall(mode in {"build-closed-timeout", "build-closed-descendant"})
    if mode in {"build-failure", "build-failure-descendant"}:
        print("deliberate compiler error", file=sys.stderr)
        sys.exit(7)
    if mode == "build-signal":
        os.kill(os.getpid(), signal.SIGTERM)
    target_dir = Path(os.environ["CARGO_TARGET_DIR"]) / "x86_64-unknown-linux-gnu/debug/deps"
    target_dir.mkdir(parents=True, exist_ok=True)
    targets = metadata["packages"][0]["targets"]
    for index, target in enumerate(targets):
        binary = target_dir / f"nonstandard-name-{index}"
        binary.write_text((root / "fixture").read_text())
        binary.chmod(0o755)
        record = {
            "reason": "compiler-artifact",
            "package_id": "ffi-identity",
            "target": target,
            "profile": {"test": True},
            "fresh": mode == "fresh-cache",
            "features": ["lowstar_hash"] if mode == "oidc-feature-enabled" else [],
            "executable": str(binary),
            "filenames": [str(binary)],
        }
        if index == 0:
            if mode == "artifact-missing":
                continue
            if mode == "artifact-wrong-package":
                record["package_id"] = "different"
            if mode == "artifact-wrong-source":
                record["target"] = {**target, "src_path": str(root / "wrong.rs")}
            if mode == "artifact-outside-root":
                record["executable"] = str(root / "fixture")
                record["filenames"] = [record["executable"]]
            if mode == "artifact-missing-binary":
                binary.unlink()
            if mode == "artifact-no-executable":
                record["executable"] = None
            if mode == "artifact-no-filename":
                record["filenames"] = []
            if mode == "artifact-bad-features":
                record["features"] = "lowstar_hash"
            if mode == "artifact-bad-profile":
                record["profile"]["test"] = "true"
            if mode == "artifact-bad-fresh":
                record["fresh"] = "true"
            if mode == "artifact-malformed":
                print("{broken")
                continue
        if mode == "artifact-zero":
            continue
        print(json.dumps(record))
        if index == 0 and mode == "artifact-duplicate":
            print(json.dumps(record))
    if mode == "artifact-unknown-reason":
        print(json.dumps({"reason": "unknown"}))
    if mode != "missing-build-finished":
        print(json.dumps({"reason": "build-finished", "success": mode != "false-build-finished"}))
else:
    index = int(tool.rsplit("-", 1)[1])
    targets = json.loads((root / "metadata.json").read_text())["packages"][0]["targets"]
    name = targets[index]["name"]
    zero = name == "oidc_hash_runtime_test" or mode == "empty-tests"
    names = [] if zero else [name + "::required"]
    ignored = [name + "::ignored"] if mode == "ignored-policy" and not zero else []
    if "--list" in args:
        if mode == "list-failure":
            sys.exit(8)
        if mode == "list-malformed":
            print("unrecognised list output")
        else:
            for item in ignored if "--ignored" in args else names + ignored:
                print(item + ": test")
        sys.exit(0)
    if index == 0 and mode in {
        "run-timeout",
        "run-closed-timeout",
        "run-descendant",
        "run-closed-descendant",
    }:
        stall(mode in {"run-closed-timeout", "run-closed-descendant"})
    if mode == "run-failure":
        sys.exit(9)
    if mode == "run-signal":
        os.kill(os.getpid(), signal.SIGABRT)
    if mode == "run-malformed":
        print("not JSON")
        sys.exit(0)
    if mode == "run-empty":
        sys.exit(0)
    print(json.dumps({"type": "suite", "event": "started", "test_count": len(names + ignored)}))
    for item in names:
        if mode != "run-no-start":
            print(json.dumps({"type": "test", "event": "started", "name": item}))
        if mode != "run-missing-completion":
            print(json.dumps({"type": "test", "event": "ok", "name": item}))
        if mode == "run-duplicate":
            print(json.dumps({"type": "test", "event": "ok", "name": item}))
    for item in ignored:
        print(json.dumps({"type": "test", "event": "ignored", "name": item}))
    print(
        json.dumps(
            {
                "type": "suite",
                "event": "ok",
                "passed": len(names),
                "ignored": len(ignored),
                "failed": 0,
                "filtered_out": 0,
            }
        )
    )
"""


class SanitizerTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.bin = self.root / "bin"
        self.bin.mkdir()
        runtime = self.root / "runtime"
        runtime.mkdir()
        (runtime / "libclang_rt.asan-x86_64.so").touch()
        (runtime / "libclang_rt.asan-preinit-x86_64.a").touch()
        self.fixture = self.root / "fixture"
        self.fixture.write_text(f"#!{sys.executable}\n{FIXTURE}")
        self.fixture.chmod(0o755)
        for tool in ("rustc", "cargo", "clang", "nm", "readelf"):
            (self.bin / tool).symlink_to(self.fixture)
        for tool in ("python3", "awk", "dirname", "find"):
            (self.bin / tool).symlink_to(shutil.which(tool))
        targets = []
        for name in TARGETS:
            source = self.root / f"{name}.rs"
            source.write_text("// controlled source identity\n")
            targets.append(
                {
                    "name": name,
                    "kind": ["lib" if name == "ffi" else "test"],
                    "test": True,
                    "src_path": str(source),
                }
            )
        (self.root / "metadata.json").write_text(
            json.dumps(
                {
                    "workspace_root": str(self.root),
                    "packages": [{"name": "ffi", "id": "ffi-identity", "targets": targets}],
                }
            )
        )
        self.environment = {
            **os.environ,
            "PATH": str(self.bin),
            "SANITIZER_FIXTURE": str(self.root),
            "SANITIZER_RUNTIME_DIR": str(runtime),
            "LIBASAN_PATH": str(runtime / "libclang_rt.asan-x86_64.so"),
            "LIBCXXABI_PATH": str(runtime / "libclang_rt.asan-x86_64.so"),
            "SANITIZER_ARTIFACT_DIR": str(self.root / "evidence"),
            "SANITIZER_TARGET_DIR": str(self.root / "target"),
            "SANITIZER_TIMEOUT": "10",
            "SANITIZER_TIMEOUT_KILL": "0.05",
        }
        for variable in (
            "RUSTC",
            "CARGO",
            "LD_PRELOAD",
            "SANITIZER_RUSTFLAGS",
            "SANITIZER_CARGO_FLAGS",
            "SANITIZER_BUILD_EXTRA_ARGS",
            "SANITIZERS",
            "SANITIZER_TARGETS",
            "SANITIZER_BUILD_TIMEOUT",
            "SANITIZER_RUN_TIMEOUT",
        ):
            self.environment.pop(variable, None)

    def run_wrapper(self, mode="success", **overrides):
        return subprocess.run(  # noqa: S603
            [shutil.which("bash"), str(WRAPPER)],
            cwd=self.root,
            env={**self.environment, "SANITIZER_FIXTURE_MODE": mode, **overrides},
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )

    def summary(self):
        return json.loads((self.root / "evidence/run-summary.json").read_text())

    def test_nonstandard_names_and_cache_bound_to_all_required_targets(self):
        for mode in ("success", "fresh-cache", "ignored-policy"):
            with self.subTest(mode=mode):
                result = self.run_wrapper(mode)
                assert result.returncode == 0, result.stderr
                summary = self.summary()
                assert summary["status"] == "completed"
                targets = summary["units"][0]["targets"]
                assert {target["name"] for target in targets} == set(TARGETS)
                assert all(target["status"] == "completed" for target in targets)
                assert sum(len(target["completed"]) for target in targets) == 8
                oidc = next(
                    target for target in targets if target["name"] == "oidc_hash_runtime_test"
                )
                assert oidc["completed"] == []
                assert oidc["applicability"] == "lowstar_hash feature disabled"
                build = next(
                    command
                    for command in summary["commands"]
                    if command["phase"].startswith("build-")
                )
                assert build["args"][-3:-1] == ["--target", "x86_64-unknown-linux-gnu"]
                assert "--lib" in build["args"]
                assert "--tests" in build["args"]
                assert 'curve25519_dalek_backend="serial"' in summary["units"][0]["rustflags"]

    def test_metadata_additions_are_required_and_flags_are_owned(self):
        metadata_path = self.root / "metadata.json"
        metadata = json.loads(metadata_path.read_text())
        source = self.root / "additional_test.rs"
        source.write_text("// additional test target\n")
        metadata["packages"][0]["targets"].append(
            {
                "name": "additional_test",
                "kind": ["test"],
                "test": True,
                "src_path": str(source),
            }
        )
        metadata_path.write_text(json.dumps(metadata))
        result = self.run_wrapper(CARGO_ENCODED_RUSTFLAGS="-Copt-level=3")
        assert result.returncode == 0, result.stderr
        targets = self.summary()["units"][0]["targets"]
        assert len(targets) == 10
        assert targets[-1]["completed"] == ["additional_test::required"]
        calls = [json.loads(line) for line in (self.root / "calls.jsonl").read_text().splitlines()]
        builds = [call for call in calls if call["tool"] == "cargo" and "test" in call["args"]]
        assert builds[0]["encoded_flags"] is None

    def test_artifact_inventory_and_record_failures(self):
        modes = (
            "artifact-zero",
            "artifact-missing",
            "artifact-wrong-package",
            "artifact-wrong-source",
            "artifact-outside-root",
            "artifact-missing-binary",
            "artifact-no-executable",
            "artifact-no-filename",
            "artifact-bad-features",
            "artifact-bad-profile",
            "artifact-bad-fresh",
            "artifact-malformed",
            "artifact-duplicate",
            "artifact-unknown-reason",
            "missing-build-finished",
            "false-build-finished",
            "metadata-missing",
            "metadata-duplicate",
            "metadata-wrong-root",
        )
        for mode in modes:
            with self.subTest(mode=mode):
                result = self.run_wrapper(mode)
                assert result.returncode != 0, (mode, result.stdout)
                assert self.summary()["status"] == "failed"

    def test_stale_outputs_cannot_mask_compile_failure(self):
        assert self.run_wrapper().returncode == 0
        result = self.run_wrapper("build-failure")
        assert result.returncode == 7, result.stderr
        assert self.summary()["units"][0]["status"] == "not-run"
        assert (
            "deliberate compiler error"
            in next((self.root / "evidence").glob("*-build-*.stderr.log")).read_text()
        )

    def test_list_named_execution_and_instrumentation_failures(self):
        for mode in (
            "uninstrumented",
            "list-failure",
            "list-malformed",
            "empty-tests",
            "run-malformed",
            "run-empty",
            "run-no-start",
            "run-missing-completion",
            "run-duplicate",
            "oidc-feature-enabled",
        ):
            with self.subTest(mode=mode):
                result = self.run_wrapper(mode)
                assert result.returncode != 0, (mode, result.stdout)
                assert self.summary()["status"] == "failed"

    def test_original_exits_and_crash_signals_propagate(self):
        for mode, expected in (("build-signal", 143), ("run-failure", 9), ("run-signal", 134)):
            with self.subTest(mode=mode):
                result = self.run_wrapper(mode)
                assert result.returncode == expected, result.stderr

    def assert_child_stopped(self):
        child = int((self.root / "child.pid").read_text())
        stat = Path(f"/proc/{child}/stat")
        assert not stat.exists() or stat.read_text().rsplit(")", 1)[1].split()[0] in {"Z", "X"}

    def test_build_run_watchdogs_and_closed_output_kill_descendants(self):
        for mode in ("build-timeout", "build-closed-timeout", "run-timeout", "run-closed-timeout"):
            with self.subTest(mode=mode):
                result = self.run_wrapper(
                    mode, SANITIZER_BUILD_TIMEOUT="0.5", SANITIZER_RUN_TIMEOUT="0.5"
                )
                assert result.returncode == 124, result.stderr
                assert any(command["timed_out"] for command in self.summary()["commands"])
                self.assert_child_stopped()

    def test_normal_leader_exit_with_running_descendants_fails(self):
        for mode in (
            "build-descendant",
            "run-descendant",
            "build-closed-descendant",
            "run-closed-descendant",
            "build-failure-descendant",
        ):
            with self.subTest(mode=mode):
                result = self.run_wrapper(mode)
                assert result.returncode == (7 if mode == "build-failure-descendant" else 1), (
                    result.stderr
                )
                assert any(
                    command["lingering_descendants"] for command in self.summary()["commands"]
                )
                self.assert_child_stopped()

    def test_wrapper_interrupt_cleans_descendants(self):
        process = subprocess.Popen(  # noqa: S603
            [shutil.which("bash"), str(WRAPPER)],
            cwd=self.root,
            env={**self.environment, "SANITIZER_FIXTURE_MODE": "build-timeout"},
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            deadline = time.monotonic() + 5
            while not (self.root / "child.pid").exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            assert (self.root / "child.pid").exists()
            process.send_signal(signal.SIGTERM)
            _, stderr = process.communicate(timeout=10)
            assert process.returncode == 143, stderr
            self.assert_child_stopped()
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate()

    def test_invalid_selections_deadlines_and_cargo_overrides_fail(self):
        for key, value in (
            ("SANITIZERS", "address,address"),
            ("SANITIZERS", "thread"),
            ("SANITIZERS", " "),
            ("SANITIZER_TARGETS", "unknown"),
            ("SANITIZER_TARGETS", "ffi,ffi"),
            ("SANITIZER_BUILD_TIMEOUT", "0"),
            ("SANITIZER_RUN_TIMEOUT", "NaN"),
            ("SANITIZER_TIMEOUT_KILL", "-1"),
            ("SANITIZER_CARGO_FLAGS", "--target=other"),
            ("SANITIZER_CARGO_FLAGS", "-pffi"),
            ("SANITIZER_CARGO_FLAGS", "--release"),
        ):
            with self.subTest(key=key, value=value):
                assert self.run_wrapper(**{key: value}).returncode != 0

    def test_missing_required_tools_runtime_and_host_fail(self):
        for tool in ("rustc", "cargo", "clang", "python3", "nm", "readelf"):
            link = self.bin / tool
            original = link.readlink()
            link.unlink()
            try:
                with self.subTest(tool=tool):
                    assert self.run_wrapper().returncode != 0
            finally:
                link.symlink_to(original)
        assert self.run_wrapper(SANITIZER_RUNTIME_DIR=str(self.root / "missing")).returncode != 0
        assert self.run_wrapper("bad-host").returncode != 0
        (self.root / "runtime/libclang_rt.asan-x86_64.so").unlink()
        assert self.run_wrapper().returncode != 0

    def test_output_failure_cannot_report_success(self):
        (self.root / "blocked").write_text("not a directory")
        assert (
            self.run_wrapper(SANITIZER_ARTIFACT_DIR=str(self.root / "blocked/evidence")).returncode
            != 0
        )
        evidence = self.root / "evidence"
        evidence.mkdir()
        (evidence / "002-build-address-ffi.stdout.log").mkdir()
        result = self.run_wrapper()
        assert result.returncode != 0
        assert self.summary()["status"] == "failed"
        (evidence / "002-build-address-ffi.stdout.log").rmdir()
        (evidence / "run-summary.json").unlink()
        (evidence / "run-summary.json").mkdir()
        assert self.run_wrapper().returncode != 0


if __name__ == "__main__":
    unittest.main()
