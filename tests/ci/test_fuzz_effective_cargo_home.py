# ruff: noqa: PT009 - directed unittest controls also execute with Python -O
"""Effective Cargo home source exclusion through owned tools and fixture HOME."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_security_fuzz import CARGO, TARGETS, SecurityFuzzFixture


class EffectiveCargoHomeTests(SecurityFuzzFixture):
    def home_environment(self, kind):
        # Manufacture only this isolated child's input HOME; no live HOME reads.
        home = self.root / ("isolated-fixture-home-" + kind)
        home.mkdir(exist_ok=True)
        environment = {**self.env, "HOME": str(home), "FUZZ_TARGETS": TARGETS[0]}
        environment.pop("CARGO_HOME", None)
        cargo_home = home / ".cargo"
        if kind == "explicit":
            cargo_home = home / "explicit-cargo"
            environment["CARGO_HOME"] = str(cargo_home)
        elif kind == "relative":
            cargo_home = home / "relative-cargo"
            environment["CARGO_HOME"] = cargo_home.relative_to(self.root).as_posix()
        elif kind == "empty":
            environment["CARGO_HOME"] = ""
        return environment, cargo_home

    def helper(self, environment, *args):
        return subprocess.run(  # noqa: S603 - explicit owned fixture and environment
            [sys.executable, "-I", str(self.root / "scripts/fuzz/manage_fuzz_corpus.py"), *args],
            cwd=self.root,
            env=environment,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )

    def registry_write(self, cargo_home):
        registry_dir = cargo_home / "registry/cache/fixture-index"
        registry_dir.mkdir(parents=True, exist_ok=True)
        registry = registry_dir / f"fixture-package-{len(list(registry_dir.iterdir()))}.crate"
        registry.write_bytes(b"owned modeled registry download")
        (cargo_home / ".global-cache").write_bytes(b"owned modeled cache update")
        return registry

    def test_registry_updates_after_prepare_preserve_source_and_finish_collection(self):
        for kind in ("explicit", "relative", "unset", "empty"):
            with self.subTest(cargo_home=kind):
                environment, cargo_home = self.home_environment(kind)
                output = self.artifacts / kind / "fuzz"
                output.mkdir(parents=True)
                environment["FUZZ_RUN_ARTIFACT_DIR"] = str(output)
                prepare = self.helper(environment, "--prepare-run", str(output))
                self.assertEqual(prepare.returncode, 0, prepare.stdout + prepare.stderr)
                prepared = json.loads((output / "execution.json").read_text())
                prefix = cargo_home.relative_to(self.root).as_posix()
                self.assertFalse(
                    any(
                        name == prefix or name.startswith(prefix + "/")
                        for name in prepared["source"]["files"]
                    )
                )
                registry = self.registry_write(cargo_home)
                finish = self.helper(environment, "--finish-run", str(output), "1")
                # Deliberately unrun phases remain failed, but collection must complete.
                self.assertEqual(finish.returncode, 1, finish.stdout + finish.stderr)
                self.assertNotIn("source identity changed", finish.stderr)
                summary = json.loads((output / "run_summary.json").read_text())
                self.assertEqual(
                    summary["execution"]["source"]["files"], prepared["source"]["files"]
                )
                self.assertEqual(summary["status"], "failed")
                self.assertTrue((output / "collection.ok").is_file())
                self.assertEqual(registry.read_bytes(), b"owned modeled registry download")

    def test_outer_fuzz_wrapper_finishes_after_effective_registry_download(self):
        self.install(
            "cargo",
            "import os,pathlib,sys\n"
            "if sys.argv[1:3] == ['fuzz','build']:\n"
            " home=pathlib.Path(os.environ.get('CARGO_HOME') or pathlib.Path.home()/'.cargo')\n"
            " if not home.is_absolute(): home=pathlib.Path(os.environ['FIXTURE_ROOT'])/home\n"
            " registry_dir=home/'registry/cache/fixture-index'\n"
            " registry_dir.mkdir(parents=True,exist_ok=True)\n"
            " count=str(len(list(registry_dir.iterdir())))\n"
            " registry=registry_dir/('fixture-package-'+count+'.crate')\n"
            " registry.write_bytes(b'owned modeled registry download')\n"
            " (home/'.global-cache').write_bytes(b'owned modeled cache update')\n" + CARGO,
        )
        for kind in ("explicit", "relative", "unset", "empty"):
            with self.subTest(cargo_home=kind):
                environment, cargo_home = self.home_environment(kind)
                self.env = environment
                result = self.run_suite()
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                summary = self.summary()
                self.assertEqual(summary["status"], "passed")
                self.assertEqual(summary["execution"]["cleanup_exit_code"], 0)
                self.assertTrue((self.artifacts / "fuzz/collection.ok").is_file())
                self.assertEqual(
                    (cargo_home / ".global-cache").read_bytes(), b"owned modeled cache update"
                )
                self.assertFalse(Path(self.env["CARGO_TARGET_DIR"], "fuzz").exists())

    def test_non_cargo_source_change_still_blocks_finish_and_collection(self):
        environment, cargo_home = self.home_environment("empty")
        output = self.artifacts / "fuzz"
        output.mkdir(parents=True)
        environment["FUZZ_RUN_ARTIFACT_DIR"] = str(output)
        prepare = self.helper(environment, "--prepare-run", str(output))
        self.assertEqual(prepare.returncode, 0, prepare.stdout + prepare.stderr)
        before = (output / "execution.json").read_bytes()
        self.registry_write(cargo_home)
        (self.root / "crates/server/src/lib.rs").write_text("// modified actual source\n")
        finish = self.helper(environment, "--finish-run", str(output), "1")
        self.assertEqual(finish.returncode, 2, finish.stdout + finish.stderr)
        self.assertIn("source identity changed", finish.stderr)
        self.assertEqual((output / "execution.json").read_bytes(), before)
        self.assertFalse((output / "collection.ok").exists())

    def test_effective_home_protected_source_and_cache_overlap_remain_rejected(self):
        for kind in ("explicit", "unset", "empty"):
            with self.subTest(cargo_home=kind):
                environment, _ = self.home_environment(kind)
                output = self.artifacts / kind / "fuzz"
                output.mkdir(parents=True)
                if kind == "explicit":
                    environment["CARGO_HOME"] = str(self.root / "crates/server/cargo-home")
                else:
                    environment["HOME"] = str(self.root / "crates/server")
                result = self.helper(environment, "--prepare-run", str(output))
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertIn("overlaps", result.stderr)
                self.assertFalse((output / "execution.json").exists())
                if kind == "explicit":
                    environment["CARGO_HOME"] = str(Path(environment["CARGO_TARGET_DIR"]) / "fuzz")
                else:
                    environment["HOME"] = str(Path(environment["CARGO_TARGET_DIR"]) / "fuzz")
                overlap = self.helper(environment, "--validate-preflight", str(output))
                self.assertEqual(overlap.returncode, 2, overlap.stdout + overlap.stderr)
                self.assertIn("overlaps", overlap.stderr)
                self.assertFalse((output / "execution.json").exists())


if __name__ == "__main__":
    import unittest

    unittest.main()
