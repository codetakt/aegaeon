"""Check the Clippy source boundary without dropping compile-time or guard inputs."""

from __future__ import annotations

# ruff: noqa: PT009 - keep unittest assertions under optimized discovery.
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import ClassVar

ROOT = Path(__file__).resolve().parents[2]
EXCLUDED = (
    "docs/automation/example.md",
    "scripts/ci/example.py",
    "tests/ci/test_example.py",
)
RETAINED = (
    "Cargo.toml",
    "Cargo.lock",
    "flake.nix",
    "flake.lock",
    "nix/cargo-lint-source.nix",
    "nix/cargo-lint-checks.nix",
    "crates/server/src/main.rs",
    "crates/server/Cargo.toml",
    "crates/jose/build.rs",
    "crates/jose/tests/rfc7520_vectors.rs",
    "c/jwe.c",
    "generated/fixture.c",
    "tests/fixtures/input.json",
    "docs/verification/contract.md",
    ".github/workflows/ci.yml",
    "scripts/flake/lint_supplemental_clippy.sh",
    "scripts/flake/lint_server_clippy_inventory.sh",
    "scripts/flake/lint_server_unwrap_or_default_inventory.sh",
)


def nix_string(value: object) -> str:
    return json.dumps(str(value)).replace("${", r"\${")


class CargoLintInputTests(unittest.TestCase):
    sources: ClassVar[dict[str, str]]
    actual: ClassVar[Path]
    additions: ClassVar[tuple[str, ...]]

    @classmethod
    def setUpClass(cls) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="cargo-lint-inputs-")
        cls.addClassCleanup(temporary.cleanup)
        root = Path(temporary.name)
        fixtures = {}

        def fixture(name: str, changes: dict[str, bytes | None]) -> None:
            directory = root / name
            files: dict[str, bytes | None] = dict.fromkeys((*RETAINED, *EXCLUDED), b"baseline\n")
            files.update(changes)
            for relative, data in files.items():
                if data is not None:
                    path = directory / relative
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(data)
            fixtures[name] = str(directory)

        fixture("baseline", {})
        for index, path in enumerate(EXCLUDED):
            fixture(f"excluded-change-{index}", {path: b"changed\n"})
            fixture(f"excluded-delete-{index}", {path: None})
        for index, path in enumerate(RETAINED):
            fixture(f"retained-change-{index}", {path: b"changed\n"})
            fixture(f"retained-delete-{index}", {path: None})
        cls.additions = (
            "tests/ci-extra/input",
            "scripts/ci-extra/input",
            "docs/automation-extra/input",
            "new-compile-input/input",
            "crates/new/build.rs",
            "tests/fixtures/new.json",
        )
        for index, path in enumerate(cls.additions):
            fixture(f"addition-{index}", {path: b"new\n"})
        fixture("unrelated-addition", {"tests/ci/test_new_unrelated.py": b"new\n"})
        expression = f"""
          let
            flake = builtins.getFlake {nix_string("git+file://" + str(ROOT))};
            lib = flake.inputs.nixpkgs.lib;
            fixtures = builtins.fromJSON {nix_string(json.dumps(fixtures))};
            sourceFor = path: import {nix_string(ROOT / "nix/cargo-lint-source.nix")} {{
              inherit lib; source = builtins.toPath path;
            }};
          in {{
            fixtures = builtins.mapAttrs (_: path: toString (sourceFor path)) fixtures;
            actual = toString
              flake.packages.${{builtins.currentSystem}}.lint-supplemental-clippy.src;
          }}
        """
        nix = shutil.which("nix")
        if nix is None:
            message = "Nix is required to check Clippy inputs"
            raise RuntimeError(message)
        result = subprocess.run(  # noqa: S603 - local expression and owned fixture sources
            [nix, "eval", "--impure", "--json", "--expr", expression],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
            timeout=120,
        )
        data = json.loads(result.stdout)
        cls.sources = data["fixtures"]
        cls.actual = Path(data["actual"])

    def test_actual_source_retains_all_rust_native_fixtures_and_lint_inputs(self) -> None:
        for directory in ("docs/automation", "scripts/ci", "tests/ci"):
            self.assertFalse((self.actual / directory).exists())
        for path in RETAINED:
            if (ROOT / path).is_file():
                self.assertEqual((self.actual / path).read_bytes(), (ROOT / path).read_bytes())
        git = shutil.which("git")
        if git is None:
            message = "Git is required to check the tracked Clippy input inventory"
            raise RuntimeError(message)
        tracked = subprocess.check_output(  # noqa: S603 - resolved Git, fixed inventory arguments
            [
                git,
                "ls-files",
                "-z",
                "--",
                "crates",
                "c",
                "generated",
                "tests/fixtures",
                "scripts/flake",
                ".github",
            ],
            cwd=ROOT,
        ).split(b"\0")
        self.assertTrue(any(tracked))
        for relative in tracked:
            if relative:
                path = Path(relative.decode("utf-8"))
                self.assertEqual((self.actual / path).read_bytes(), (ROOT / path).read_bytes())

    def test_orchestration_changes_do_not_invalidate_lint_source(self) -> None:
        for index, _ in enumerate(EXCLUDED):
            for operation in ("change", "delete"):
                self.assertEqual(
                    self.sources[f"excluded-{operation}-{index}"], self.sources["baseline"]
                )
        self.assertEqual(self.sources["unrelated-addition"], self.sources["baseline"])

    def test_every_declared_dependency_change_or_removal_invalidates(self) -> None:
        for index, path in enumerate(RETAINED):
            for operation in ("change", "delete"):
                with self.subTest(path=path, operation=operation):
                    self.assertNotEqual(
                        self.sources[f"retained-{operation}-{index}"], self.sources["baseline"]
                    )

    def test_unknown_inputs_and_near_prefixes_are_retained(self) -> None:
        for index, path in enumerate(self.additions):
            self.assertNotEqual(self.sources[f"addition-{index}"], self.sources["baseline"])
            self.assertEqual(
                (Path(self.sources[f"addition-{index}"]) / path).read_bytes(), b"new\n"
            )


if __name__ == "__main__":
    unittest.main()
