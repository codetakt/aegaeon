"""Compile hosted page assets from the inputs that distributions actually ship."""

from __future__ import annotations

import os
import posixpath
import re
import shutil
import subprocess
import tempfile
import tomllib
import unittest
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

ROOT = Path(__file__).resolve().parents[2]
CRATE = Path("crates/server")
# Modules whose compile-time includes render the hosted end-user pages.
MODULES = (
    CRATE / "src/web/presentation.rs",
    CRATE / "src/web/hosted_page.rs",
)
INCLUDE = re.compile(r'include_(?:str|bytes)!\("([^"]+)"\)')
SUBMODULE = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+(\w+);", re.MULTILINE)
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


def submodules(module: Path) -> list[Path]:
    """Files of the out-of-line `mod name;` declarations of a module file."""
    directory = module.parent / module.stem
    found = []
    for name in SUBMODULE.findall((ROOT / module).read_text()):
        candidate = directory / f"{name}.rs"
        found.append(candidate if (ROOT / candidate).exists() else directory / name / "mod.rs")
    return found


def files(module: Path) -> list[Path]:
    """A module, its submodules recursively, and every file they include."""
    sources = [module]
    for source in sources:
        sources.extend(submodules(source))
    return [*sources, *(target for source in sources for target in includes(source))]


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
# Regex fragment for a piece, and whether it makes the pattern a regex match.
# Metacharacters without filepath.Match meaning are escaped; [ and ] keep
# their character-class meaning; a trailing backslash stays literal.
FRAGMENTS = {
    "*": ("[^/]*", True),
    "?": ("[^/]", True),
    "[": ("[", True),
    "]": ("]", True),
    "\\": ("\\\\", False),
    **{character: ("\\" + character, False) for character in ".+()|{}$"},
}


def translate(pattern: str) -> tuple[str, str]:
    """Return the match kind and regex as moby/patternmatcher v0.6.0 compiles.

    A pattern starting with ** and otherwise literal matches a path suffix, a
    literal pattern ending in ** matches a prefix, and a literal pattern
    matches exactly; only other patterns use the regex.
    """
    kind, regex = "exact", "^"
    for index, match in enumerate(PIECE.finditer(pattern)):
        piece = match.group()
        if piece.startswith("**"):
            if match.end() == len(pattern) and kind == "exact":
                kind = "prefix"
            else:
                # **/ is treated as **; at the end it accepts everything below.
                regex += ".*" if match.end() == len(pattern) else "(.*/)?"
                kind = "regex"
            if index == 0:
                kind = "suffix"
            continue
        # A two-character piece starting with a backslash escapes the next one.
        fragment, wildcard = (
            ("\\" + piece[1], True) if len(piece) == 2 else FRAGMENTS.get(piece, (piece, False))
        )
        regex += fragment
        if wildcard:
            kind = "regex"
    return kind, regex + "$"


def compile_pattern(pattern: str) -> Callable[[str], bool]:
    kind, regex = translate(pattern)
    suffix = pattern[2:]
    matchers: dict[str, Callable[[str], bool]] = {
        "exact": lambda path: path == pattern,
        "prefix": lambda path: path.startswith(pattern[:-2]),
        # **/foo also matches "foo".
        "suffix": lambda path: (
            path.endswith(suffix) or (suffix.startswith("/") and path == suffix[1:])
        ),
        "regex": lambda path: re.match(regex, path) is not None,
    }
    return matchers[kind]


def docker_ignored(path: Path, patterns: list[str]) -> bool:
    """Apply patterns in order as MatchesOrParentMatches does.

    The last matching pattern wins, `!` re-includes, and a pattern matching a
    parent directory excludes everything below it.
    """
    candidates = [candidate.as_posix() for candidate in [path, *path.parents][:-1]]
    ignored = False
    for pattern in patterns:
        negated = pattern.startswith("!")
        matches = compile_pattern(pattern.removeprefix("!"))
        if any(matches(candidate) for candidate in candidates):
            ignored = not negated
    return ignored


def shipped(path: Path, inputs: list[Path], patterns: list[str]) -> bool:
    """Whether the Docker builder receives `path` from the build context."""
    copied = any(path == source or path.is_relative_to(source) for source in inputs)
    return copied and not docker_ignored(path, patterns)


def omitted(patterns: list[str]) -> list[Path]:
    """Hosted page modules and their includes that the Docker builder lacks."""
    inputs = docker_inputs()
    required = [path for module in MODULES for path in files(module)]
    return [path for path in required if not shipped(path, inputs, patterns)]


def compile_from_docker_inputs(
    patterns: list[str], target: Path
) -> subprocess.CompletedProcess[str]:
    """Compile the shipped shell and its shared text validator with the project's locked crates."""
    cargo = shutil.which("cargo")
    assert cargo is not None
    inputs = docker_inputs()
    validator = CRATE / "src/util/visible_text.rs"
    with tempfile.TemporaryDirectory() as temporary:
        context = Path(temporary)
        for path in [*files(MODULES[0]), validator]:
            if shipped(path, inputs, patterns):
                staged = context / path.relative_to(CRATE)
                staged.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / path, staged)
        (context / "src/lib.rs").write_text(
            "#![allow(dead_code)]\nmod web { mod presentation; }\n"
            "mod util { mod visible_text; pub(crate) use visible_text::is_visible_nfc_text; }\n"
        )
        # The producer lock supplies both direct and transitive versions. Cargo can prune the
        # workspace-only packages in this disposable copy. The positive check requires compilation.
        shutil.copyfile(ROOT / "Cargo.lock", context / "Cargo.lock")
        packages = tomllib.loads((context / "Cargo.lock").read_text())["package"]
        manifest = [
            "[package]",
            'name="hosted-presentation-check"',
            'version="0.0.0"',
            'edition="2021"',
            "[dependencies]",
        ]
        for name in ("axum", "icu_properties", "unicode-normalization"):
            (version,) = [pkg["version"] for pkg in packages if pkg["name"] == name]
            manifest.append(f'{name}="={version}"')
        (context / "Cargo.toml").write_text("\n".join(manifest) + "\n")
        return subprocess.run(  # noqa: S603 - fixed local toolchain argv
            [
                cargo,
                "check",
                "--offline",
                "--quiet",
                "--manifest-path",
                str(context / "Cargo.toml"),
                "--target-dir",
                str(target),
            ],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            timeout=300,
        )


class HostedPresentationDistributionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cache = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cache.cleanup)
        cls.cargo_target = Path(cache.name)

    def tool(self, name: str) -> str:
        path = shutil.which(name)
        if path is None:
            assert not REQUIRED, f"{name} is required by the distribution check"
            self.skipTest(f"{name} is required")
        return path

    def test_modules_and_includes_are_inside_the_package_and_docker_context(self) -> None:
        for module in MODULES:
            assert includes(module), module
            for target in files(module):
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
            for target in files(module):
                with self.subTest(target=str(target)):
                    assert str(target.relative_to(CRATE)) in listing

    def test_presentation_compiles_from_docker_inputs_alone(self) -> None:
        self.tool("cargo")
        result = compile_from_docker_inputs(ignore_patterns(), self.cargo_target)
        assert result.returncode == 0, result.stderr

    def test_excluding_a_hosted_page_input_fails_the_check(self) -> None:
        self.tool("cargo")
        web = "crates/server/src/web"
        cases = [
            (f"{web}/presentation/aegaeon-mark.svg", True),
            (f"./{web}/presentation/aegaeon-mark.svg", True),
            ("**/*.svg", True),
            ("**/*.[s]vg", True),
            ("**.svg", True),
            ("**mark.svg", True),
            (f"{web}/presentation.rs", True),
            (f"{web}/presentation/messages/ja.rs", True),
            (f"{web}/presentation/*.rs", True),
            (f"/{web}//presentation/../presentation/page.css", True),
            (f"{web}/hosted_page.rs", False),
            (f"{web}/hosted_page/*.js", False),
        ]
        for line, compiles_presentation in cases:
            patterns = [*ignore_patterns(), *read_ignore(line)]
            with self.subTest(line=line):
                assert omitted(patterns), "the context check must fail"
                if compiles_presentation:
                    assert compile_from_docker_inputs(patterns, self.cargo_target).returncode != 0
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
            ("**.svg", "crates/server/a.svg", True),
            ("**mark.svg", "crates/server/aegaeon-mark.svg", True),
            ("**/a.svg", "a.svg", True),
            ("**/a.svg", "xa.svg", False),
            ("**a.svg", "xa.svg", True),
            ("crates/serv**", "crates/server/a.svg", True),
            ("crates/s*/**", "crates/server/a.svg", True),
            ("**/server/**", "crates/server/a.svg", True),
            ("**", "crates/a.svg", True),
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
