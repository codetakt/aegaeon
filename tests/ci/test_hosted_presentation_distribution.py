"""Compile hosted page assets from the inputs that distributions actually ship."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CRATE = Path("crates/server")
# Modules whose compile-time includes render the hosted end-user pages.
MODULES = (
    CRATE / "src/web/presentation.rs",
    CRATE / "src/web/hosted_page.rs",
)
INCLUDE = re.compile(r'include_(?:str|bytes)!\("([^"]+)"\)')
# Set by the hosted-presentation-distribution Nix check, which supplies the
# pinned toolchain and vendored dependencies from an empty CARGO_HOME. There a
# missing tool is a failure. `cargo package` resolves the locked dependency
# graph, so other runners without prepared dependencies leave it to that check.
REQUIRED = os.environ.get("AEGAEON_REQUIRE_DISTRIBUTION_TOOLS") == "1"


def docker_inputs() -> list[Path]:
    """Return the build-context sources copied into the Dockerfile builder stage."""
    sources: list[Path] = []
    stage = None
    for line in (ROOT / "Dockerfile").read_text().splitlines():
        words = line.split()
        if words[:1] == ["FROM"]:
            stage = words[-1] if "AS" in words else None
        elif stage == "builder" and words[:1] == ["COPY"] and "--from" not in line:
            sources.extend(Path(word) for word in words[1:-1])
    assert sources, "Dockerfile builder copies no sources"
    return sources


def includes(module: Path) -> list[Path]:
    text = (ROOT / module).read_text()
    return [
        (ROOT / module.parent / target).resolve().relative_to(ROOT)
        for target in INCLUDE.findall(text)
    ]


def shipped(path: Path, inputs: list[Path]) -> bool:
    return any(path == source or path.is_relative_to(source) for source in inputs)


class HostedPresentationDistributionTests(unittest.TestCase):
    def tool(self, name: str) -> str:
        path = shutil.which(name)
        if path is None:
            assert not REQUIRED, f"{name} is required by the distribution check"
            self.skipTest(f"{name} is required")
        return path

    def test_includes_are_inside_the_package_and_docker_context(self) -> None:
        inputs = docker_inputs()
        for module in MODULES:
            targets = includes(module)
            assert targets, module
            for target in targets:
                with self.subTest(target=str(target)):
                    assert (ROOT / target).is_file()
                    assert not (ROOT / target).is_symlink()
                    assert target.is_relative_to(CRATE), "Cargo packages only the crate"
                    assert shipped(target, inputs), "Docker copies only its listed inputs"

    def test_embedded_mark_is_the_canonical_brand_asset(self) -> None:
        embedded = ROOT / CRATE / "src/web/presentation/aegaeon-mark.svg"
        canonical = ROOT / "assets/brand/aegaeon-mark.svg"
        assert embedded.read_bytes() == canonical.read_bytes()

    def test_cargo_package_lists_every_include(self) -> None:
        if not REQUIRED:
            self.skipTest("owned by the hosted-presentation-distribution Nix check")
        cargo = self.tool("cargo")
        listing = subprocess.run(  # noqa: S603 - fixed local toolchain argv
            [cargo, "package", "--list", "-p", "aegaeon-server", "--allow-dirty", "--offline"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
            timeout=300,
        ).stdout.splitlines()
        for module in MODULES:
            for target in includes(module):
                with self.subTest(target=str(target)):
                    assert str(target.relative_to(CRATE)) in listing

    def test_presentation_compiles_from_docker_inputs_alone(self) -> None:
        rustc = self.tool("rustc")
        inputs = docker_inputs()
        module = MODULES[0]
        with tempfile.TemporaryDirectory() as temporary:
            context = Path(temporary) / "context"
            # Stage only files the Docker builder would receive.
            for path in [module, *includes(module)]:
                if shipped(path, inputs):
                    staged = context / path
                    staged.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(ROOT / path, staged)
            source = context / CRATE / "src"
            (source / "lib.rs").write_text(
                "#![allow(dead_code)]\nmod web {\n    mod presentation;\n}\n"
            )
            result = subprocess.run(  # noqa: S603 - fixed local toolchain argv
                [
                    rustc,
                    "--edition=2021",
                    "--crate-type=lib",
                    "--crate-name=hosted_presentation",
                    "--emit=metadata",
                    "--out-dir",
                    str(Path(temporary) / "out"),
                    str(source / "lib.rs"),
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=300,
            )
            assert result.returncode == 0, result.stderr


if __name__ == "__main__":
    unittest.main()
