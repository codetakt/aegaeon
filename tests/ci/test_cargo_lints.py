"""Keep command failures and the textual inventory blocking after Nix wrapping."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class CargoLintTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.scripts = self.root / "scripts/flake"
        self.scripts.mkdir(parents=True)
        source = self.root / "crates/server/src"
        source.mkdir(parents=True)
        self.source = source / "lib.rs"
        self.source.write_text("pub fn value() {}\n")
        (self.scripts / "server_unwrap_or_default_inventory.allowlist").write_text("")
        for name in (
            "lint_server_clippy_inventory.sh",
            "lint_supplemental_clippy.sh",
            "lint_server_unwrap_or_default_inventory.sh",
        ):
            shutil.copyfile(ROOT / "scripts/flake" / name, self.scripts / name)
        self.install_cargo()

    def install_cargo(self):
        cargo = self.root / "cargo"
        cargo.write_text(
            f"#!{sys.executable}\n"
            """
import json
import os
import pathlib
import sys
pathlib.Path(os.environ['CARGO_LINT_ARGS']).write_text(json.dumps(sys.argv[1:]))
sys.exit(int(os.environ.get('CARGO_LINT_EXIT', '0')))
"""
        )
        cargo.chmod(0o755)

    def run_lint(self, script, **extra_env):
        environment = {
            **os.environ,
            "PATH": f"{self.root}:{os.environ['PATH']}",
            "CARGO_LINT_ARGS": str(self.root / "args.json"),
        }
        environment.pop("CARGO_PROFILE", None)
        environment.update(extra_env)
        return subprocess.run(  # noqa: S603 - fixed repository script and fixture environment
            ["bash", str(self.scripts / script)],  # noqa: S607 - pinned shell
            cwd=self.root,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_server_inventory_fails_even_when_clippy_succeeds(self):
        script = "lint_server_clippy_inventory.sh"
        assert self.run_lint(script).returncode == 0
        self.source.write_text("pub fn value() { let _ = Some(1).unwrap_or_default(); }\n")
        result = self.run_lint(script)
        assert result.returncode != 0
        assert "Unexpected aegaeon-server unwrap_or_default inventory drift" in result.stderr

    def test_compiler_failure_is_not_hidden_by_inventory_success(self):
        result = self.run_lint("lint_server_clippy_inventory.sh", CARGO_LINT_EXIT="9")
        assert result.returncode == 9

    def test_inventory_supports_both_existing_profiles(self):
        for profile in ("dev", "release"):
            result = self.run_lint("lint_server_clippy_inventory.sh", CARGO_PROFILE=profile)
            assert result.returncode == 0
            args = json.loads((self.root / "args.json").read_text())
            assert args[args.index("--profile") + 1] == profile
            assert "--no-deps" in args
            assert "--locked" in args

    def test_supplemental_keeps_all_targets_and_propagates_failure(self):
        result = self.run_lint("lint_supplemental_clippy.sh", CARGO_LINT_EXIT="7")
        assert result.returncode == 7
        args = json.loads((self.root / "args.json").read_text())
        assert "--workspace" in args
        assert "--all-targets" in args
        assert args[args.index("--profile") + 1] == "dev"


if __name__ == "__main__":
    unittest.main()
