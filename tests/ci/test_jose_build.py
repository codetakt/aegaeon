"""Check dependency preparation against the executed JOSE verification commands."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
PREPARE = ROOT / "scripts/flake/prepare_jose_dependencies.sh"
VERIFY = ROOT / "scripts/flake/verify_jose_check.sh"

FAKE_CARGO = """import json
import os
import sys
from pathlib import Path
path = Path(os.environ["CARGO_TRACE"])
with path.open("a") as stream:
    stream.write(json.dumps(sys.argv[1:]) + "\\n")
if len(path.read_text().splitlines()) == int(os.environ["FAIL_CARGO_AT"]):
    raise SystemExit(37)
print("fixture cargo output")
"""


def run_script(script: Path, fail_at: int = 0):
    bash = shutil.which("bash")
    assert bash, "JOSE build fixtures require Bash"
    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        binaries = directory / "bin"
        binaries.mkdir()
        cargo = binaries / "cargo"
        cargo.write_text(f"#!{sys.executable}\n{FAKE_CARGO}")
        cargo.chmod(0o755)
        # Only the Python conformance command is stubbed; execute the complete
        # checked-in shell, including its logging and error propagation.
        conformance = directory / "tests/conformance/jose_vector_test.py"
        conformance.parent.mkdir(parents=True)
        conformance.write_text("print('fixture conformance output')\n")
        trace = directory / "cargo.jsonl"
        environment = {
            **os.environ,
            "PATH": f"{binaries}{os.pathsep}{os.environ['PATH']}",
            "OUT_DIR": str(directory),
            "CARGO_TRACE": str(trace),
            "FAIL_CARGO_AT": str(fail_at),
        }
        for name in ("BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS"):
            environment.pop(name, None)
        result = subprocess.run(  # noqa: S603 - checked-in script with controlled fake Cargo
            [bash, "--noprofile", "--norc", str(script)],
            cwd=directory,
            env=environment,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        calls = [json.loads(line) for line in trace.read_text().splitlines()]
        return result, calls


def compilation_key(args):
    cargo_args = args[: args.index("--")] if "--" in args else args
    cargo_args = [
        part
        for arg in cargo_args
        for part in (arg.split("=", 1) if arg.startswith("--") and "=" in arg else [arg])
    ]
    known_options = {
        "-p",
        "--features",
        "--no-default-features",
        "--all-features",
        "--release",
        "--profile",
        "--target",
        "--target-dir",
        "--test",
        "--lib",
        "--no-run",
        "--locked",
    }
    assert all(not arg.startswith("-") or arg in known_options for arg in cargo_args), cargo_args
    package = cargo_args[cargo_args.index("-p") + 1]
    features = (
        frozenset(cargo_args[cargo_args.index("--features") + 1].split(","))
        if "--features" in cargo_args
        else frozenset()
    )
    profile = (
        cargo_args[cargo_args.index("--profile") + 1]
        if "--profile" in cargo_args
        else ("release" if "--release" in cargo_args else "test")
    )
    target = cargo_args[cargo_args.index("--target") + 1] if "--target" in cargo_args else None
    target_dir = (
        cargo_args[cargo_args.index("--target-dir") + 1] if "--target-dir" in cargo_args else None
    )
    return (
        package,
        features,
        "--no-default-features" in cargo_args,
        "--all-features" in cargo_args,
        profile,
        target,
        target_dir,
    )


class JoseBuildTests(unittest.TestCase):
    def test_changed_compilation_conditions_require_matching_preparation(self):
        base = ["test", "-p", "aegaeon-jose"]
        for option in (
            ["--no-default-features"],
            ["--all-features"],
            ["--release"],
            ["--profile", "ci"],
            ["--target", "aarch64-unknown-linux-gnu"],
            ["--target-dir", "target/other"],
            ["--profile=ci"],
            ["--features=verified-claim"],
        ):
            with self.subTest(option=option):
                assert compilation_key(base + option) != compilation_key(base)
        with pytest.raises(AssertionError):
            compilation_key([*base, "--config", "profile.test.opt-level=3"])

    def test_preparation_covers_each_executed_package_and_feature_combination(self):
        prepared, compile_calls = run_script(PREPARE)
        verified, test_calls = run_script(VERIFY)
        assert prepared.returncode == 0, prepared.stderr
        assert verified.returncode == 0, verified.stderr
        assert {compilation_key(call) for call in compile_calls} == {
            compilation_key(call) for call in test_calls
        }
        # Different features are not merged into an all-features preparation.
        assert len(compile_calls) == len({compilation_key(c) for c in compile_calls})
        for call in compile_calls:
            assert call[0] == "test"
            assert "--no-run" in call
            assert "--locked" in call
            assert "--release" not in call
            assert "--all-features" not in call
            assert "--" not in call
            assert call.count("-p") == 1

    def test_preparation_failure_stops_before_later_feature_combinations(self):
        success, expected = run_script(PREPARE)
        assert success.returncode == 0, success.stderr
        for position in (1, len(expected) // 2, len(expected)):
            with self.subTest(position=position):
                result, calls = run_script(PREPARE, fail_at=position)
                assert result.returncode == 37, result.stderr
                assert calls == expected[:position]


if __name__ == "__main__":
    unittest.main()
