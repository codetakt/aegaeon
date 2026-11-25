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


def ignore_patterns() -> list[str]:
    """Return the build-context exclusions from the repository .dockerignore."""
    lines = (ROOT / ".dockerignore").read_text().splitlines()
    return [line.strip() for line in lines if line.strip() and not line.startswith("#")]


def pattern_regex(pattern: str) -> re.Pattern[str]:
    """Translate one Docker ignore pattern (Go filepath.Match plus `**`)."""
    parts = []
    index = 0
    pattern = pattern.strip("/")
    while index < len(pattern):
        if pattern.startswith("**/", index):
            parts.append("(?:.*/)?")
            index += 3
        elif pattern.startswith("**", index):
            parts.append(".*")
            index += 2
        elif pattern[index] == "*":
            parts.append("[^/]*")
            index += 1
        elif pattern[index] == "?":
            parts.append("[^/]")
            index += 1
        else:
            parts.append(re.escape(pattern[index]))
            index += 1
    return re.compile("".join(parts))


def docker_ignored(path: Path, patterns: list[str]) -> bool:
    """Apply patterns in order; the last match wins and `!` re-includes.

    A pattern matching a directory excludes everything below it.
    """
    candidates = [path, *path.parents][:-1]
    ignored = False
    for pattern in patterns:
        negated = pattern.startswith("!")
        regex = pattern_regex(pattern.removeprefix("!"))
        if any(regex.fullmatch(candidate.as_posix()) for candidate in candidates):
            ignored = not negated
    return ignored


def shipped(path: Path, inputs: list[Path], patterns: list[str]) -> bool:
    """Whether the Docker builder receives `path` from the build context."""
    copied = any(path == source or path.is_relative_to(source) for source in inputs)
    return copied and not docker_ignored(path, patterns)


def compile_from_docker_inputs(patterns: list[str]) -> subprocess.CompletedProcess[str]:
    """Compile the shared page shell from the files the Docker builder receives."""
    rustc = shutil.which("rustc")
    assert rustc is not None
    inputs = docker_inputs()
    module = MODULES[0]
    with tempfile.TemporaryDirectory() as temporary:
        context = Path(temporary) / "context"
        for path in [module, *includes(module)]:
            if shipped(path, inputs, patterns):
                staged = context / path
                staged.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / path, staged)
        source = context / CRATE / "src"
        source.mkdir(parents=True, exist_ok=True)
        (source / "lib.rs").write_text(
            "#![allow(dead_code)]\nmod web {\n    mod presentation;\n}\n"
        )
        return subprocess.run(  # noqa: S603 - fixed local toolchain argv
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


class HostedPresentationDistributionTests(unittest.TestCase):
    def tool(self, name: str) -> str:
        path = shutil.which(name)
        if path is None:
            assert not REQUIRED, f"{name} is required by the distribution check"
            self.skipTest(f"{name} is required")
        return path

    def test_includes_are_inside_the_package_and_docker_context(self) -> None:
        inputs = docker_inputs()
        patterns = ignore_patterns()
        for module in MODULES:
            targets = includes(module)
            assert targets, module
            for target in targets:
                with self.subTest(target=str(target)):
                    assert (ROOT / target).is_file()
                    assert not (ROOT / target).is_symlink()
                    assert target.is_relative_to(CRATE), "Cargo packages only the crate"
                    assert shipped(target, inputs, patterns), "Docker build context omits it"

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
        self.tool("rustc")
        result = compile_from_docker_inputs(ignore_patterns())
        assert result.returncode == 0, result.stderr

    def test_excluding_the_embedded_mark_fails_the_check(self) -> None:
        self.tool("rustc")
        mark = CRATE / "src/web/presentation/aegaeon-mark.svg"
        for rule in ("crates/server/src/web/presentation/aegaeon-mark.svg", "**/*.svg"):
            patterns = [*ignore_patterns(), rule]
            with self.subTest(rule=rule):
                assert not shipped(mark, docker_inputs(), patterns)
                result = compile_from_docker_inputs(patterns)
                assert result.returncode != 0
                assert "aegaeon-mark.svg" in result.stderr
        # A later exception restores it, as in Docker.
        patterns = [*ignore_patterns(), "**/*.svg", f"!{mark}"]
        assert shipped(mark, docker_inputs(), patterns)

    def test_docker_ignore_semantics(self) -> None:
        cases = [
            (["tests"], "tests/organizations/a.sql", True),
            (["**/target"], "crates/server/target/x", True),
            (["artifacts"], "crates/server/artifacts/x", False),
            (["**/artifacts"], "crates/server/artifacts/x", True),
            (["*.svg"], "crates/server/a.svg", False),
            (["**/*.svg"], "crates/server/a.svg", True),
            (["crates/*/src"], "crates/server/src/lib.rs", True),
            (["**/*.log", "!keep.log"], "keep.log", False),
            (["/crates/"], "crates/server/Cargo.toml", True),
        ]
        for patterns, path, expected in cases:
            with self.subTest(patterns=patterns, path=path):
                assert docker_ignored(Path(path), patterns) is expected


if __name__ == "__main__":
    unittest.main()
