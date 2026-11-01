"""Check the F* source boundary without dropping proof or control inputs."""

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
    "tests/constant_time/example.py",
    "tests/ci/test_security_fuzz.py",
    "tests/ci/test_database_test_package.py",
)
RETAINED = (
    "fstar/jose/Jose.Federation.Policy.Types.fst",
    "tests/fstar/property/TestAuthCodeRedisGrant.fst",
    "tests/fixtures/authcode-redis-grant.json",
    "tests/fixtures/fstar_admission/example.json",
    "generated/everparse/Example.fst",
    "proofs/tamarin/AuthCode.spthy",
    "ci/tamarin_proofs.sh",
    "spec/assumption-register.json",
    "spec/compliance-matrix.yaml",
    "spec/assumption-graph.schema.json",
    "scripts/flake/verify_fstar.sh",
    "scripts/validation/assumption_graph.py",
    "crates/server/src/authcode/store/redis_backend/scripts.rs",
    "tests/ci/test_fstar_admission.py",
    "tests/ci/test_fstar_runner.py",
    "tests/ci/test_fstar_solver_pin.py",
    "tests/ci/test_fstar_source_lexing.py",
    "tests/ci/test_nix_fstar_inputs.py",
    "tests/ci/shared_helper.py",
    "docs/verification/fstar/assumption-graph.md",
    "flake.nix",
    "flake.lock",
    "nix/fstar-source.nix",
)


def nix_string(value: object) -> str:
    return json.dumps(str(value)).replace("${", r"\${")


class FstarInputTests(unittest.TestCase):
    sources: ClassVar[dict[str, str]]
    actual: ClassVar[Path]
    additions: ClassVar[tuple[str, ...]]

    @classmethod
    def setUpClass(cls) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="fstar-inputs-")
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
            "tests/ci/test_fstar_new.py",
            "tests/ci/new_helper.py",
            "tests/ci/package/test_extra.py",
            "tests/ci/test_misc.fixture",
            "tests/constant_time_extra/input",
            "docs/automation-extra/input",
            "new-proof-input/input",
            "fstar/New.fst",
        )
        for index, path in enumerate(cls.additions):
            fixture(f"addition-{index}", {path: b"new\n"})
        fixture("unrelated-addition", {"tests/ci/test_new_unrelated.py": b"new\n"})
        expression = f"""
          let
            flake = builtins.getFlake {nix_string("git+file://" + str(ROOT))};
            lib = flake.inputs.nixpkgs.lib;
            fixtures = builtins.fromJSON {nix_string(json.dumps(fixtures))};
            sourceFor = path: import {nix_string(ROOT / "nix/fstar-source.nix")} {{
              inherit lib; source = builtins.toPath path;
            }};
          in {{
            fixtures = builtins.mapAttrs (_: path: toString (sourceFor path)) fixtures;
            actual = toString flake.packages.${{builtins.currentSystem}}.verify-fstar.src;
          }}
        """
        nix = shutil.which("nix")
        if nix is None:
            message = "Nix is required to check F* inputs"
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

    def test_actual_source_preserves_proofs_controls_and_all_fstar_helpers(self) -> None:
        for path in EXCLUDED:
            self.assertFalse((self.actual / path).exists())
        fixture_only = {
            "tests/fixtures/fstar_admission/example.json",
            "generated/everparse/Example.fst",
            "proofs/tamarin/AuthCode.spthy",
            "tests/ci/shared_helper.py",
        }
        for path in RETAINED:
            if path not in fixture_only:
                self.assertEqual((self.actual / path).read_bytes(), (ROOT / path).read_bytes())
        git = shutil.which("git")
        if git is None:
            message = "Git is required to check the tracked F* input inventory"
            raise RuntimeError(message)
        tracked = subprocess.check_output(  # noqa: S603 - resolved Git, fixed inventory arguments
            [
                git,
                "ls-files",
                "-z",
                "--",
                "fstar",
                "tests/fstar",
                "tests/fixtures",
                "scripts/validation",
                "proofs/tamarin",
            ],
            cwd=ROOT,
        ).split(b"\0")
        self.assertTrue(any(tracked))
        for relative in tracked:
            if relative:
                path = Path(relative.decode("utf-8"))
                self.assertEqual((self.actual / path).read_bytes(), (ROOT / path).read_bytes())

    def test_unrelated_ci_and_timing_changes_do_not_invalidate_proof_source(self) -> None:
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

    def test_new_helpers_proofs_unknown_inputs_and_near_prefixes_are_retained(self) -> None:
        for index, path in enumerate(self.additions):
            self.assertNotEqual(self.sources[f"addition-{index}"], self.sources["baseline"])
            self.assertEqual(
                (Path(self.sources[f"addition-{index}"]) / path).read_bytes(), b"new\n"
            )


if __name__ == "__main__":
    unittest.main()
