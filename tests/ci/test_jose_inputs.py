"""Check JOSE input identity with actual Nix sources and mutation fixtures."""

from __future__ import annotations

# ruff: noqa: PT009 - retain unittest discovery and assertions under -O.
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import ClassVar, TypedDict, cast

ROOT = Path(__file__).resolve().parents[2]
EXCLUDED = ("docs/automation", "scripts/ci", "tests/ci")
RETAINED = (
    "Cargo.toml",
    "Cargo.lock",
    "rust-toolchain.toml",
    ".cargo/config.toml",
    "crates/server/src/lib.rs",
    "crates/server/tests/process_local_runtime_state_guard_test.rs",
    "crates/jose/src/jws.rs",
    "crates/jose/tests/rfc7520_vectors.rs",
    "crates/ffi/build.rs",
    "crates/ffi/cbindgen.toml",
    "c/crypto_bridge.c",
    "include/jwe.h",
    "generated/everparse/DCR.c",
    "generated/lowstar/jose/runtime.c",
    "artifacts/karamel/runtime.c",
    "tests/fixtures/verified-core/manifest.json",
    "tests/fixtures/verified-core/verified_core.wasm",
    "tests/vectors/jws.json",
    "tests/conformance/jose_vector_test.py",
    "tests/constant_time/run_contract.py",
    "scripts/flake/prepare_jose_dependencies.sh",
    "scripts/flake/verify_jose_check.sh",
    "scripts/extraction/run_everparse_batch.sh",
    "db/migrations/input.sql",
    "nix/jose-check.nix",
    "nix/jose-source.nix",
    "flake.nix",
    "flake.lock",
    ".github/workflows/verification.yml",
    "ci/check-ownership.json",
    "docs/verification/claims.md",
    "README.md",
)


class SourceResult(TypedDict):
    fixtures: dict[str, str]
    actual: str


def nix_string(value: str | Path) -> str:
    return json.dumps(str(value)).replace("${", r"\${")


def evaluate(expression: str) -> SourceResult:
    nix = shutil.which("nix")
    if nix is None:
        message = "Nix is required to check the Jose source boundary"
        raise RuntimeError(message)
    result = subprocess.run(  # noqa: S603 - pinned local Nix expression and owned fixtures
        [nix, "eval", "--impure", "--json", "--expr", expression],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
        timeout=120,
    )
    return cast("SourceResult", json.loads(result.stdout))


class JoseInputTests(unittest.TestCase):
    temporary: ClassVar[tempfile.TemporaryDirectory[str]]
    sources: ClassVar[dict[str, str]]
    actual_source: ClassVar[Path]
    additions: ClassVar[tuple[str, ...]]

    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary = tempfile.TemporaryDirectory(prefix="jose-inputs-")
        cls.addClassCleanup(cls.temporary.cleanup)
        root = Path(cls.temporary.name)
        fixtures: dict[str, str] = {}

        def fixture(name: str, changes: dict[str, bytes | None]) -> None:
            directory = root / name
            files: dict[str, bytes | None] = dict.fromkeys(RETAINED, b"retained baseline\n")
            files.update({prefix + "/entry": b"CI baseline\n" for prefix in EXCLUDED})
            files["upstream-omitted/entry"] = b"filtered by the parent\n"
            files.update(changes)
            for relative, value in files.items():
                if value is not None:
                    path = directory / relative
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(value)
            fixtures[name] = str(directory)

        fixture("baseline", {})
        for index, prefix in enumerate(EXCLUDED):
            fixture(f"excluded-change-{index}", {prefix + "/entry": b"changed\n"})
            fixture(f"excluded-add-{index}", {prefix + "/new/nested": b"new\n"})
            fixture(f"excluded-delete-{index}", {prefix + "/entry": None})
        for index, path in enumerate(RETAINED):
            fixture(f"retained-change-{index}", {path: b"changed\n"})
            fixture(f"retained-delete-{index}", {path: None})
        cls.additions = (
            "new-input/data",
            "docs/automation-extra/input",
            "scripts/circuit/input",
            "docs/new/input",
            "tests/circuit/input",
            "crates/new/src/lib.rs",
            "generated/openapi/new.json",
            ".cargo/extra-config.toml",
        )
        for index, path in enumerate(cls.additions):
            fixture(f"retained-add-{index}", {path: b"new\n"})
        fixture("parent-change", {"upstream-omitted/entry": b"new\n"})
        expression = f"""
          let
            flake = builtins.getFlake {nix_string("git+file://" + str(ROOT))};
            lib = flake.inputs.nixpkgs.lib;
            fixtures = builtins.fromJSON {nix_string(json.dumps(fixtures))};
            sourceFor = path: import {nix_string(ROOT / "nix/jose-source.nix")} {{
              inherit lib;
              source = lib.cleanSourceWith {{
                src = builtins.toPath path;
                filter = candidate: _type:
                  let relative = lib.removePrefix (path + "/") (toString candidate);
                  in relative != "upstream-omitted" &&
                    !(lib.hasPrefix "upstream-omitted/" relative);
              }};
            }};
          in {{
            fixtures = builtins.mapAttrs (_: path: toString (sourceFor path)) fixtures;
            actual = toString flake.packages.${{builtins.currentSystem}}.verifyJose.src;
          }}
        """
        result = evaluate(expression)
        cls.sources = result["fixtures"]
        cls.actual_source = Path(result["actual"])

    def test_actual_package_uses_the_boundary_and_retains_required_sources(self) -> None:
        for path in EXCLUDED:
            with self.subTest(path=path):
                self.assertFalse((self.actual_source / path).exists())
        required = (
            "Cargo.toml",
            "Cargo.lock",
            "rust-toolchain.toml",
            ".cargo/config.toml",
            "crates/server/src/lib.rs",
            "crates/server/tests/process_local_runtime_state_guard_test.rs",
            "crates/jose/src/jws.rs",
            "crates/jose/tests/rfc7520_vectors.rs",
            "crates/ffi/build.rs",
            "crates/ffi/cbindgen.toml",
            "c/crypto_bridge.c",
            "include/jwe.h",
            "generated/everparse/DCR.c",
            "tests/fixtures/verified-core/manifest.json",
            "tests/fixtures/verified-core/verified_core.wasm",
            "tests/conformance/jose_vector_test.py",
            "tests/constant_time/run_contract.py",
            "scripts/flake/prepare_jose_dependencies.sh",
            "scripts/flake/verify_jose_check.sh",
            "scripts/extraction/run_everparse_batch.sh",
            "nix/jose-check.nix",
            "nix/jose-source.nix",
            "flake.nix",
            "flake.lock",
            ".github/workflows/verification.yml",
            "README.md",
        )
        for path in required:
            with self.subTest(path=path):
                self.assertEqual(
                    (self.actual_source / path).read_bytes(), (ROOT / path).read_bytes()
                )
        # Retain complete package trees, including guard tests and build scripts.
        for path in (ROOT / "crates").rglob("*"):
            if path.is_file() and "target" not in path.relative_to(ROOT).parts:
                relative = path.relative_to(ROOT)
                with self.subTest(path=relative):
                    self.assertEqual(
                        (self.actual_source / relative).read_bytes(), path.read_bytes()
                    )

    def test_ci_changes_additions_and_deletions_preserve_source_identity(self) -> None:
        for index, prefix in enumerate(EXCLUDED):
            for operation in ("change", "add", "delete"):
                with self.subTest(prefix=prefix, operation=operation):
                    self.assertEqual(
                        self.sources[f"excluded-{operation}-{index}"], self.sources["baseline"]
                    )

    def test_build_and_runtime_input_changes_and_deletions_invalidate(self) -> None:
        for index, path in enumerate(RETAINED):
            for operation in ("change", "delete"):
                with self.subTest(path=path, operation=operation):
                    self.assertNotEqual(
                        self.sources[f"retained-{operation}-{index}"], self.sources["baseline"]
                    )

    def test_unknown_and_near_prefix_additions_are_retained(self) -> None:
        for index, path in enumerate(self.additions):
            with self.subTest(path=path):
                self.assertNotEqual(self.sources[f"retained-add-{index}"], self.sources["baseline"])
                self.assertEqual(
                    (Path(self.sources[f"retained-add-{index}"]) / path).read_bytes(), b"new\n"
                )

    def test_composition_preserves_parent_filter_and_retained_bytes(self) -> None:
        baseline = Path(self.sources["baseline"])
        self.assertEqual(self.sources["parent-change"], self.sources["baseline"])
        for path in RETAINED:
            with self.subTest(path=path):
                self.assertEqual((baseline / path).read_bytes(), b"retained baseline\n")
        for path in (*EXCLUDED, "upstream-omitted"):
            with self.subTest(path=path):
                self.assertFalse((baseline / path).exists())


if __name__ == "__main__":
    unittest.main()
