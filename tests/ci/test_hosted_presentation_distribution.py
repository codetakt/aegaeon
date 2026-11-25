"""Compile hosted page assets from the inputs that distributions actually ship."""

from __future__ import annotations

import os
import posixpath
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


def ignore_file(root: Path = ROOT) -> Path:
    """BuildKit prefers `<Dockerfile>.dockerignore` beside the Dockerfile."""
    specific = root / "Dockerfile.dockerignore"
    return specific if specific.is_file() else root / ".dockerignore"


def read_ignore(text: str) -> list[str]:
    """Parse ignore lines as moby/patternmatcher/ignorefile.ReadAll does."""
    patterns = []
    for line in text.removeprefix("\ufeff").splitlines():
        # Comments are recognized before whitespace is trimmed.
        if line.startswith("#"):
            continue
        pattern = line.strip()
        if not pattern:
            continue
        invert = pattern.startswith("!")
        if invert:
            pattern = pattern[1:].strip()
        if pattern:
            # Go filepath.Clean, then strip one leading slash.
            pattern = posixpath.normpath(re.sub("/+", "/", pattern))
            if len(pattern) > 1 and pattern.startswith("/"):
                pattern = pattern[1:]
        patterns.append("!" + pattern if invert else pattern)
    return patterns


def ignore_patterns() -> list[str]:
    path = ignore_file()
    return read_ignore(path.read_text()) if path.is_file() else []


PIECE = re.compile(r"\*\*/?|\*|\?|\\.?|.", re.DOTALL)
WILDCARDS = {"*": "[^/]*", "?": "[^/]"}
# Regex metacharacters without filepath.Match meaning; [ and ] keep theirs.
ESCAPED = frozenset(".+()|{}$")


def regex_piece(piece: str, *, last: bool) -> str:
    if piece.startswith("**"):
        # Treat **/ as **. At the end it accepts everything below.
        translated = ".*" if last else "(.*/)?"
    elif piece.startswith("\\"):
        # Escape the next character; a trailing backslash stays literal.
        translated = "\\" + piece[1] if len(piece) == 2 else "\\\\"
    else:
        translated = WILDCARDS.get(piece, "\\" + piece if piece in ESCAPED else piece)
    return translated


def pattern_regex(pattern: str) -> re.Pattern[str]:
    """Translate a cleaned pattern as moby/patternmatcher Pattern.compile does."""
    pieces = PIECE.finditer(pattern)
    parts = [regex_piece(piece.group(), last=piece.end() == len(pattern)) for piece in pieces]
    return re.compile("^" + "".join(parts) + "$")


def docker_ignored(path: Path, patterns: list[str]) -> bool:
    """Apply patterns in order as MatchesOrParentMatches does.

    The last matching pattern wins, `!` re-includes, and a pattern matching a
    parent directory excludes everything below it.
    """
    candidates = [path, *path.parents][:-1]
    ignored = False
    for pattern in patterns:
        negated = pattern.startswith("!")
        regex = pattern_regex(pattern.removeprefix("!"))
        if any(regex.match(candidate.as_posix()) for candidate in candidates):
            ignored = not negated
    return ignored


def shipped(path: Path, inputs: list[Path], patterns: list[str]) -> bool:
    """Whether the Docker builder receives `path` from the build context."""
    copied = any(path == source or path.is_relative_to(source) for source in inputs)
    return copied and not docker_ignored(path, patterns)


def omitted(patterns: list[str]) -> list[Path]:
    """Hosted page modules and their includes that the Docker builder lacks."""
    inputs = docker_inputs()
    required = [path for module in MODULES for path in (module, *includes(module))]
    return [path for path in required if not shipped(path, inputs, patterns)]


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

    def test_modules_and_includes_are_inside_the_package_and_docker_context(self) -> None:
        for module in MODULES:
            targets = includes(module)
            assert targets, module
            for target in (module, *targets):
                with self.subTest(target=str(target)):
                    assert (ROOT / target).is_file()
                    assert not (ROOT / target).is_symlink()
                    assert target.is_relative_to(CRATE), "Cargo packages only the crate"
        assert omitted(ignore_patterns()) == [], "Docker build context omits it"

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

    def test_excluding_a_hosted_page_input_fails_the_check(self) -> None:
        self.tool("rustc")
        web = "crates/server/src/web"
        cases = [
            (f"{web}/presentation/aegaeon-mark.svg", True),
            (f"./{web}/presentation/aegaeon-mark.svg", True),
            ("**/*.svg", True),
            ("**/*.[s]vg", True),
            (f"{web}/presentation.rs", True),
            (f"/{web}//presentation/../presentation/page.css", True),
            (f"{web}/hosted_page.rs", False),
            (f"{web}/hosted_page/*.js", False),
        ]
        for line, compiles_presentation in cases:
            patterns = [*ignore_patterns(), *read_ignore(line)]
            with self.subTest(line=line):
                assert omitted(patterns), "the context check must fail"
                if compiles_presentation:
                    assert compile_from_docker_inputs(patterns).returncode != 0
        # A later exception restores the file, as in Docker.
        patterns = [*ignore_patterns(), *read_ignore(f"**/*.svg\n!{web}/**/aegaeon-mark.svg")]
        assert omitted(patterns) == []

    def test_dockerfile_specific_ignore_file_takes_precedence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / ".dockerignore").write_text("tests\n")
            assert ignore_file(root) == root / ".dockerignore"
            (root / "Dockerfile.dockerignore").write_text("**/*.svg\n")
            assert ignore_file(root) == root / "Dockerfile.dockerignore"

    def test_docker_ignore_semantics(self) -> None:
        # Each case was compared with BuildKit (buildx v0.31.1, Docker 29.9.3)
        # using a minimal `FROM scratch` build that copies the context.
        cases = [
            ("tests", "tests/organizations/a.sql", True),
            ("**/target", "crates/server/target/x", True),
            ("artifacts", "crates/server/artifacts/x", False),
            ("**/artifacts", "crates/server/artifacts/x", True),
            ("*.svg", "crates/server/a.svg", False),
            ("**/*.svg", "crates/server/a.svg", True),
            ("**/*.[s]vg", "crates/server/a.svg", True),
            ("crates/*/src", "crates/server/src/lib.rs", True),
            ("crates/*/a?.svg", "crates/server/ab.svg", True),
            ("crates/[a-r]*", "crates/a.svg", True),
            ("crates/[^a]*", "crates/a.svg", False),
            ("crates/a\\+b.svg", "crates/a+b.svg", True),
            ("crates/a+b.svg", "crates/a+b.svg", True),
            ("./crates/a.svg", "crates/a.svg", True),
            ("/crates//x/../a.svg", "crates/a.svg", True),
            ("crates/**", "crates/server/a.svg", True),
            ("**/*.log\n!keep.log", "keep.log", False),
            ("crates/**\n!crates/a.svg", "crates/a.svg", False),
            (" !crates/a.svg\ncrates/a.svg", "crates/a.svg", True),
            ("  # not a comment\n# comment\ncrates/a.svg", "crates/a.svg", True),
        ]
        for text, path, expected in cases:
            with self.subTest(text=text, path=path):
                assert docker_ignored(Path(path), read_ignore(text)) is expected


if __name__ == "__main__":
    unittest.main()
