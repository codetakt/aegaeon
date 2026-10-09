"""Exercise extraction admission with controlled tools and isolated outputs."""

# ruff: noqa: PT009 - stdlib unittest assertions remain active under Python -O

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ENTRIES = (
    "scripts/extraction/run_verified_core_lowstar.sh",
    "scripts/extraction/run_jose_lowstar.sh",
    "scripts/extraction/package_verified_core.sh",
    "scripts/extraction/run_everparse_batch.sh",
    "scripts/flake/verify_lowstar.sh",
    "ci/karamel.sh",
)


class ExtractionPreflightTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.bash = shutil.which("bash")
        self.git = shutil.which("git")
        self.assertIsNotNone(self.bash)
        self.assertIsNotNone(self.git)
        subprocess.run([self.git, "init", "-q", str(self.root)], check=True)  # noqa: S603 - owned fixture
        self.seed_sources()
        self.tools = self.root / "tools"
        self.env = dict(os.environ)
        for name in ("fstar", "karamel", "everparse", "hacl", "evercrypt"):
            (self.tools / name).mkdir(parents=True)
        routes = {
            "FSTAR_HOME": "fstar",
            "KARAMEL_HOME": "karamel",
            "EVERPARSE_PREFIX": "everparse",
            "EVERPARSE_SOURCE_ROOT": "everparse",
            "HACL_PREFIX": "hacl",
            "EVERCRYPT_PREFIX": "evercrypt",
            "HACL_FSTAR_PATH": "hacl/share/hacl-star/fstar",
            "EVERCRYPT_SRC_DIR": "evercrypt/share/evercrypt",
        }
        for name, route in routes.items():
            self.env[name] = str(self.tools / route)
            (self.tools / route).mkdir(parents=True, exist_ok=True)
        for directory in (
            "fstar/lib/fstar/ulib",
            "karamel/lib/krml",
            "everparse/share/everparse/prelude",
            "everparse/src/3d/prelude",
            "everparse/src/lowparse",
            "everparse/lib/lowparse",
            "everparse/krmllib/obj",
            "evercrypt/share/evercrypt/providers/fst",
            "evercrypt/share/evercrypt/specs",
            "evercrypt/share/evercrypt/code",
        ):
            (self.tools / directory).mkdir(parents=True, exist_ok=True)
        self.calls = self.root / "tool-calls.jsonl"
        self.env["CONTROLLED_CALLS"] = str(self.calls)
        for name, relative in (
            ("FSTAR", "fstar/bin/fstar.exe"),
            ("KAMEL", "karamel/bin/krml"),
            ("EVERPARSE", "everparse/bin/everparse"),
        ):
            tool = self.tools / relative
            tool.parent.mkdir(parents=True, exist_ok=True)
            tool.write_text(
                f"#!{sys.executable}\n"
                """import json, os, pathlib, sys
with open(os.environ["CONTROLLED_CALLS"], "a") as stream:
    stream.write(json.dumps({"tool": pathlib.Path(sys.argv[0]).name,
                            "args": sys.argv[1:],
                            "krml_home": os.environ.get("KRML_HOME")}) + "\\n")
sys.exit(71 if pathlib.Path(sys.argv[0]).name == "fstar.exe" else 0)
"""
            )
            tool.chmod(0o755)
            self.env[name] = str(tool)
        fake_bin = self.root / "bin"
        fake_bin.mkdir()
        nix = fake_bin / "nix"
        nix.write_text(
            f"#!{sys.executable}\n"
            f"""import os, sys
if sys.argv[1:4] != ["develop", ".#verification", "--command"]:
    sys.exit(99)
os.execv({self.bash!r}, ["bash", *sys.argv[5:]])
"""
        )
        nix.chmod(0o755)
        self.env["PATH"] = str(fake_bin) + os.pathsep + os.environ["PATH"]
        for name in (
            "WITH_WASM_BUILD",
            "LOWPARSE_LOCAL_ROOT",
            "AEG_USE_LOWPARSE_LOCAL",
            "AEG_USE_EVERPARSE_LOCAL",
            "WASI_CLANG",
            "WASI_SYSROOT",
        ):
            self.env.pop(name, None)

    def seed_sources(self):
        for relative in (
            *ENTRIES,
            "scripts/extraction/lib/toolchain_preflight.sh",
            "scripts/extraction/lib/everparse_postprocess.sh",
        ):
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, target)
        for source in (ROOT / "fstar/lowparse").glob("*.3d"):
            target = self.root / source.relative_to(ROOT)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
        for directory in ("fstar/pkce", "fstar/dpop", "fstar/verifiedcore/api"):
            (self.root / directory).mkdir(parents=True, exist_ok=True)
        (self.root / "fstar/pkce/Pkce.Fixture.fst").write_text("module Pkce.Fixture\n")

    def invoke(self, script=None, env=None):
        command = (
            [self.bash, str(self.root / script)]
            if script
            else [
                self.bash,
                "-euc",
                "source scripts/extraction/lib/toolchain_preflight.sh; extraction_preflight",
            ]
        )
        return subprocess.run(  # noqa: S603 - owned scripts and controlled fixture environment
            command,
            cwd=self.root,
            env=env or self.env,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )

    def test_every_consumer_rejects_missing_pins_before_output_or_tool_effects(self):
        for script in ENTRIES:
            with self.subTest(script=script):
                env = dict(self.env)
                env.pop("FSTAR")
                result = self.invoke(script, env)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("FSTAR must name an explicit absolute executable", result.stderr)
                self.assertFalse(self.calls.exists())
                self.assertFalse((self.root / "generated").exists())
                self.assertFalse((self.root / "artifacts").exists())

    def test_each_required_pin_must_be_explicit(self):
        for name in (
            "FSTAR",
            "KAMEL",
            "EVERPARSE",
            "FSTAR_HOME",
            "KARAMEL_HOME",
            "EVERPARSE_PREFIX",
            "EVERPARSE_SOURCE_ROOT",
            "HACL_PREFIX",
            "EVERCRYPT_PREFIX",
            "HACL_FSTAR_PATH",
            "EVERCRYPT_SRC_DIR",
        ):
            with self.subTest(pin=name):
                env = dict(self.env)
                env.pop(name)
                result = self.invoke(env=env)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(name, result.stderr)
                self.assertFalse(self.calls.exists())

    def test_legacy_archive_enters_pinned_shell_and_retains_archive_and_log(self):
        script = self.root / "scripts/extraction/run_jose_lowstar.sh"
        script.write_text(
            "set -euo pipefail\n"
            "source scripts/extraction/lib/toolchain_preflight.sh\n"
            "extraction_preflight\n"
            "mkdir -p generated/lowstar/jose\n"
            "printf 'controlled C output\\n' > generated/lowstar/jose/fixture.c\n"
            "echo controlled extraction\n"
        )
        result = self.invoke("ci/karamel.sh")
        self.assertEqual(result.returncode, 0, result.stderr)
        with tarfile.open(self.root / "artifacts/karamel/jose-lowstar.tar.gz") as archive:
            member = archive.extractfile("jose/fixture.c")
            self.assertIsNotNone(member)
            self.assertEqual(member.read(), b"controlled C output\n")
        log = (self.root / "artifacts/karamel.log").read_text()
        self.assertIn("controlled extraction", log)
        self.assertIn("extraction completed", log)
        self.assertFalse((self.root / "generated/lowstar/jose").exists())

    def test_legacy_archive_propagates_extraction_failure_without_archiving(self):
        script = self.root / "scripts/extraction/run_jose_lowstar.sh"
        script.write_text("echo controlled failure >&2\nexit 73\n")
        result = self.invoke("ci/karamel.sh")
        self.assertEqual(result.returncode, 73, result.stderr)
        self.assertIn("controlled failure", result.stdout)
        self.assertNotIn("extraction completed", result.stdout)
        self.assertFalse((self.root / "artifacts/karamel/jose-lowstar.tar.gz").exists())

    def test_legacy_archive_rejects_shell_activation_failure_before_writes(self):
        (self.root / "bin/nix").write_text(f"#!{self.bash}\nexit 67\n")
        result = self.invoke("ci/karamel.sh")
        self.assertEqual(result.returncode, 67, result.stderr)
        self.assertFalse((self.root / "artifacts").exists())
        self.assertFalse((self.root / "generated").exists())

    def test_invalid_executable_routes_do_not_fall_back_to_path(self):
        for value in ("fstar.exe", str(self.root / "absent"), str(self.tools / "fstar")):
            with self.subTest(value=value):
                env = dict(self.env, FSTAR=value)
                self.assertNotEqual(self.invoke(env=env).returncode, 0)
                self.assertFalse(self.calls.exists())
        tool = Path(self.env["FSTAR"])
        tool.chmod(0o644)
        self.assertNotEqual(self.invoke().returncode, 0)
        self.assertFalse(self.calls.exists())

    def test_executable_and_sources_must_match_their_supplier_routes(self):
        for name, value in (
            ("FSTAR", self.env["KAMEL"]),
            ("KAMEL", self.env["EVERPARSE"]),
            ("EVERPARSE", self.env["FSTAR"]),
            ("EVERPARSE_SOURCE_ROOT", str(self.tools / "hacl")),
            ("HACL_FSTAR_PATH", str(self.tools / "evercrypt")),
            ("EVERCRYPT_SRC_DIR", str(self.tools / "hacl")),
        ):
            with self.subTest(pin=name):
                result = self.invoke(env=dict(self.env, **{name: value}))
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("pinned supplier route", result.stderr)
                self.assertFalse(self.calls.exists())

    def test_missing_provider_layout_is_rejected_before_local_copy_cleanup(self):
        local = self.root / "local-copy"
        local.mkdir()
        marker = local / "keep"
        marker.write_bytes(b"previous evidence\n")
        env = dict(self.env, AEG_USE_LOWPARSE_LOCAL="1", LOWPARSE_LOCAL_ROOT=str(local))
        for relative in (
            "everparse/src/lowparse",
            "everparse/krmllib/obj",
            "evercrypt/share/evercrypt/providers/fst",
            "fstar/lib/fstar/ulib",
        ):
            with self.subTest(layout=relative):
                directory = self.tools / relative
                held = directory.with_name(directory.name + "-held")
                directory.rename(held)
                try:
                    result = self.invoke("scripts/extraction/run_jose_lowstar.sh", env)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(marker.read_bytes(), b"previous evidence\n")
                    self.assertFalse(self.calls.exists())
                    self.assertFalse((self.root / "generated").exists())
                finally:
                    held.rename(directory)

    def test_wasm_pins_are_admitted_before_extraction_outputs(self):
        for script in (ENTRIES[0], ENTRIES[2]):
            with self.subTest(script=script):
                result = self.invoke(script, dict(self.env, WITH_WASM_BUILD="1"))
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("WASI_CLANG", result.stderr)
                self.assertFalse(self.calls.exists())
                self.assertFalse((self.root / "generated").exists())
                self.assertFalse((self.root / "artifacts").exists())

    def test_wasi_requires_include_and_lib_before_accepting_the_explicit_route(self):
        sysroot = self.root / "wasi-sysroot"
        sysroot.mkdir()
        env = dict(
            self.env, WITH_WASM_BUILD="1", WASI_CLANG=self.env["FSTAR"], WASI_SYSROOT=str(sysroot)
        )
        for directory in ("include", "lib"):
            result = self.invoke(ENTRIES[0], env)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("WASI_SYSROOT must contain include and lib", result.stderr)
            self.assertFalse(self.calls.exists())
            self.assertFalse((self.root / "generated").exists())
            (sysroot / directory).mkdir()
        result = self.invoke(ENTRIES[0], env)
        self.assertEqual(result.returncode, 71, result.stderr)
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()]
        self.assertEqual([call["tool"] for call in calls], ["fstar.exe"])

    def test_verified_core_accepts_consistent_pins_and_preserves_fstar_arguments(self):
        result = self.invoke(ENTRIES[0])
        self.assertEqual(result.returncode, 71, result.stderr)
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()]
        self.assertEqual(len(calls), 1)
        args = calls[0]["args"]
        self.assertEqual(args[:2], ["--codegen", "krml"])
        self.assertIn("--cache_checked_modules", args)
        self.assertEqual(args[args.index("--warn_error") + 1], "-274")
        include = [args[index + 1] for index, arg in enumerate(args) if arg == "--include"]
        self.assertEqual(
            include[:2], [str(self.root / "fstar"), str(self.root / "fstar/verifiedcore/api")]
        )
        self.assertIn(str(self.tools / "hacl/share/hacl-star/fstar"), include)
        self.assertEqual(args[-1], "fstar/pkce/Pkce.Fixture.fst")

    def test_batch_uses_explicit_tools_and_retains_schema_order(self):
        result = self.invoke(ENTRIES[3])
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()]
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["tool"], "everparse")
        self.assertEqual(
            calls[0]["args"],
            [
                "--odir",
                "generated/everparse",
                "--batch",
                "--skip_c_makefiles",
                "--no_clang_format",
                "fstar/lowparse/JoseHeader.3d",
                "fstar/lowparse/DCR.3d",
                "fstar/lowparse/DcrRegistration.3d",
                "fstar/lowparse/IdTokenSchema.3d",
                "fstar/lowparse/LogoutTokenSchema.3d",
                "fstar/lowparse/RequestObjectSchema.3d",
                "fstar/lowparse/Dpop.3d",
            ],
        )
        self.assertFalse(Path(calls[0]["krml_home"]).exists())


if __name__ == "__main__":
    unittest.main()
