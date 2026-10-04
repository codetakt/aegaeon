"""Required fuzz sources, supported compiler configuration and preflight."""

from __future__ import annotations

import hashlib
import os
import platform
import re
import shutil
import stat
import sys
from pathlib import Path
from typing import Any, NoReturn

try:  # Python 3.11+
    import tomllib  # type: ignore[attr-defined]
except ModuleNotFoundError:  # pragma: no cover - older Python fallback
    import tomli as tomllib  # type: ignore[import-not-found]

from fuzz_support.filesystem import (
    CACHE_SOURCE_ROOTS,
    FUZZ_DIR,
    GIT_IDENTITY_OVERRIDES,
    KANI_OUTPUT_MODE,
    KANI_OUTPUT_POINTER,
    KANI_OUTPUT_TARGET,
    RECOVERY_RAW_NAMES,
    REQUIRED_TARGETS,
    ROOT,
    RUN_ARTIFACT_DIR,
    effective_cargo_home,
    evidence_digest,
    evidence_snapshot,
    evidence_text,
    invalid,
    lexical_directory,
    overlaps,
    repository_path,
    validate_cargo_home_paths,
    validate_collection_history,
    validate_collection_roots,
    validate_regular_destination,
)


def load_targets() -> list[str]:
    cargo_toml = FUZZ_DIR / "Cargo.toml"
    if not cargo_toml.exists():
        print("fuzz/Cargo.toml not found; run from repository root", file=sys.stderr)
        raise SystemExit(1)

    data = tomllib.loads(evidence_text(cargo_toml))
    bins = data.get("bin", [])
    names = [b["name"] for b in bins]
    if (
        not names
        or len(names) != len(set(names))
        or any(
            not isinstance(name, str) or not re.fullmatch(r"fuzz_[a-z0-9_]+", name)
            for name in names
        )
    ):
        invalid("fuzz manifest must contain distinct, nonempty fuzz target names")
    return sorted(names)


def selected_targets() -> list[str]:
    selected = os.environ.get("FUZZ_TARGETS", " ".join(REQUIRED_TARGETS)).split()
    if not selected or len(selected) != len(set(selected)):
        invalid("FUZZ_TARGETS must be nonempty and contain no duplicates")
    if set(load_targets()) != set(REQUIRED_TARGETS):
        invalid("fuzz manifest differs from the required seven-target inventory")
    if any(name not in REQUIRED_TARGETS for name in selected):
        invalid("FUZZ_TARGETS contains an unknown target")
    if os.environ.get("CI") == "true" and set(selected) != set(REQUIRED_TARGETS):
        invalid("CI requires the full seven-target fuzz inventory")
    return selected


def required_source(path: Path) -> Path:
    if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(ROOT):
        invalid(f"required fuzz input is missing or not a repository regular file: {path}")
    return path


def selected_sources(selected: list[str]) -> list[Path]:
    manifest = tomllib.loads(evidence_text(FUZZ_DIR / "Cargo.toml"))
    binaries = {entry["name"]: entry for entry in manifest["bin"]}
    paths = []
    for name in selected:
        value = binaries[name].get("path")
        if not isinstance(value, str) or not value:
            invalid(f"fuzz target {name} has no declared source path")
        relative = Path(value)
        if relative.is_absolute() or ".." in relative.parts or relative.suffix != ".rs":
            invalid(f"fuzz target {name} has an unsafe source path")
        paths.append(required_source(FUZZ_DIR / relative))
    return paths


def validate_compiler_environment() -> None:
    # Cargo can bypass the PATH compiler or RUSTFLAGS through these inputs.
    # Presence, including an empty value, is unsupported; never disclose values.
    for name in (
        "RUSTC",
        "RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER",
        "CARGO_ENCODED_RUSTFLAGS",
        "CARGO_BUILD_RUSTC",
        "CARGO_BUILD_RUSTC_WRAPPER",
        "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
        "CARGO_ALIAS_FUZZ",
    ):
        if name in os.environ:
            invalid(f"inherited {name} override is not supported for fuzz execution or cleanup")


def validate_git_environment() -> None:
    # Do not sanitize an override after using it to discover ROOT or record HEAD.
    if any(name in os.environ for name in GIT_IDENTITY_OVERRIDES) or any(
        name.startswith(("GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_")) for name in os.environ
    ):
        invalid("inherited Git identity overrides are not supported for fuzz execution or cleanup")


def source_exclusions() -> set[Path]:
    # Identified runtime/build outputs only. Everything else, including ignored
    # and untracked files, is an input until its ownership is explicitly known.
    excluded = {
        ROOT / ".git",
        ROOT / "target",
        FUZZ_DIR / "target",
        *(FUZZ_DIR / name for name in (*RECOVERY_RAW_NAMES, "corpus_meta")),
        ROOT / "artifacts/security",
        ROOT / "artifacts/security-upload",
        ROOT / "artifacts/sbom",
        ROOT / "security-artifacts/security_status.jsonl",
        ROOT / "result",
        ROOT / "result-server",
    }
    for name, default in (
        ("CARGO_TARGET_DIR", "target/security-suite"),
        ("CARGO_HOME", ""),
        ("SECURITY_ARTIFACT_DIR", "artifacts/security/latest"),
        ("SECURITY_HISTORY_DIR", "artifacts/security/history"),
        ("FUZZ_RUN_ARTIFACT_DIR", ""),
        ("FUZZ_HISTORY_DIR", ""),
    ):
        value = (
            str(effective_cargo_home()) if name == "CARGO_HOME" else os.environ.get(name, default)
        )
        if not value:
            continue
        path = repository_path(Path(value))
        if not path.is_relative_to(ROOT):
            continue
        if (
            path == ROOT
            or any(
                overlaps(path, ROOT / source)
                for source in CACHE_SOURCE_ROOTS
                if source not in {".git", "artifacts"}
            )
            or overlaps(path, FUZZ_DIR / "fuzz_targets")
            or any(
                overlaps(path, ROOT / relative)
                for relative in (
                    "artifacts/karamel",
                    "artifacts/ct",
                    "fuzz/Cargo.toml",
                    "fuzz/Cargo.lock",
                )
            )
        ):
            invalid("fuzz runtime output overlaps local source inputs")
        excluded.add(path)
    if "CARGO_TARGET_DIR" in os.environ:
        directory = (
            RUN_ARTIFACT_DIR
            or repository_path(
                Path(os.environ.get("SECURITY_ARTIFACT_DIR") or "artifacts/security/latest")
            )
            / "fuzz"
        )
        # A supported cache alias may point elsewhere inside the checkout. Only
        # the protected-path-validated canonical destination is an output.
        excluded.add(configured_cache(directory))
    return excluded


def local_fuzz_manifests(inventory: dict[str, dict[str, Any]], excluded: set[Path]) -> set[Path]:
    pending = [FUZZ_DIR / "Cargo.toml"]
    visited = set()
    while pending:
        manifest = pending.pop()
        if manifest in visited:
            continue
        visited.add(manifest)
        document = tomllib.loads(evidence_text(manifest))
        for route in cargo_path_values(document):
            check_local_cargo_path(manifest, route, inventory, excluded)
            target = (manifest.parent / route).resolve()
            if target.is_relative_to(ROOT / "crates/kani-harness"):
                invalid("Kani output pointer became relevant to the fuzz dependency closure")
            if target.is_dir():
                pending.append(target / "Cargo.toml")
    return visited


def kani_output_pointer() -> dict[str, Any] | None:
    # If the retired workspace-excluded launcher is present, retain its exact
    # literal bytes/mode without traversing its tool output. Absence is valid.
    manifest = tomllib.loads(evidence_text(ROOT / "Cargo.toml"))
    if "crates/kani-harness" not in manifest.get("workspace", {}).get("exclude", []):
        invalid("Kani output pointer is no longer workspace-excluded")
    path = ROOT / KANI_OUTPUT_POINTER
    if not path.exists() and not path.is_symlink():
        return None
    if (
        not path.is_symlink()
        or os.fsencode(os.readlink(path)) != os.fsencode(KANI_OUTPUT_TARGET)  # noqa: PTH115
        or stat.S_IMODE(path.lstat().st_mode) != KANI_OUTPUT_MODE
    ):
        invalid("root-reviewed Kani output pointer is missing or changed")
    return {
        "type": "unrelated-tool-output-pointer",
        "mode": KANI_OUTPUT_MODE,
        "git_mode": "120000",
        "target": KANI_OUTPUT_TARGET,
        "sha256": hashlib.sha256(os.fsencode(os.readlink(path))).hexdigest(),  # noqa: PTH115
    }


def validate_kani_output_relevance(
    inventory: dict[str, dict[str, Any]], excluded: set[Path]
) -> None:
    packages = {manifest.parent for manifest in local_fuzz_manifests(inventory, excluded)}
    for relative, record in inventory.items():
        if record["type"] != "file":
            continue
        candidate = ROOT / relative
        if candidate.is_relative_to(ROOT / ".cargo"):
            if b"kani-harness" in evidence_snapshot(candidate):
                invalid("Cargo configuration references the Kani output pointer")
        elif (
            any(candidate.is_relative_to(package) for package in packages)
            and candidate.suffix in {".rs", ".toml", ".c", ".h", ".sh", ".py"}
            and b"kani-harness" in evidence_snapshot(candidate)
        ):
            invalid("local fuzz source/build input references the Kani output pointer")
    if any("kani-harness" in value for value in os.environ.values()):
        invalid("build environment references the Kani output pointer")


def source_hashes(selected: list[str]) -> dict[str, dict[str, Any]]:
    validate_git_environment()
    required = [
        ROOT / path
        for path in (
            "Cargo.toml",
            "Cargo.lock",
            "fuzz/Cargo.toml",
            "fuzz/Cargo.lock",
            "flake.lock",
            "rust-toolchain.toml",
            "scripts/security/run_security_suite.sh",
            "scripts/fuzz/manage_fuzz_corpus.py",
        )
    ]
    required.extend(
        ROOT / "scripts/fuzz/fuzz_support" / name
        for name in (
            "__init__.py",
            "directories.py",
            "filesystem.py",
            "source.py",
            "archives.py",
            "collection.py",
            "execution.py",
            "recovery.py",
            "cli.py",
        )
    )
    required.extend(selected_sources(selected))
    excluded = source_exclusions()
    for path in required:
        required_source(path)
        if any(path.is_relative_to(output) for output in excluded):
            invalid("required fuzz source is excluded by a runtime output")
    pointer = kani_output_pointer()
    inventory = local_source_inventory(excluded, pointer)
    validate_local_cargo_paths(inventory, excluded)
    validate_kani_output_relevance(inventory, excluded)
    return dict(sorted(inventory.items()))


def local_source_inventory(
    excluded: set[Path], pointer: dict[str, Any] | None
) -> dict[str, dict[str, Any]]:
    inventory: dict[str, dict[str, Any]] = {}

    # os.walk does not silently follow symlink directories or discard their
    # identity. Errors are fatal, and directory records detect empty additions.
    def traversal_error(error: OSError) -> NoReturn:
        raise error

    for base, directories, files in os.walk(ROOT, followlinks=False, onerror=traversal_error):
        directory = Path(base)
        directories[:] = [name for name in directories if directory / name not in excluded]
        for name in sorted([*directories, *files]):
            path = directory / name
            if path in excluded:
                continue
            relative = path.relative_to(ROOT).as_posix()
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                if relative != KANI_OUTPUT_POINTER or pointer is None:
                    invalid(f"symlink or external local source input is not supported: {relative}")
                inventory[relative] = pointer
                continue
            mode = stat.S_IMODE(info.st_mode)
            if stat.S_ISDIR(info.st_mode):
                inventory[relative] = {"type": "directory", "mode": mode}
            elif stat.S_ISREG(info.st_mode):
                inventory[relative] = {
                    "type": "file",
                    "mode": mode,
                    "sha256": evidence_digest(path, info),
                }
            else:
                invalid(f"special local source input is not supported: {relative}")
    return inventory


def inherited_cargo_dependencies(document: dict[str, Any]) -> list[Any]:
    inherited_values = []
    for table in ("dependencies", "dev-dependencies", "build-dependencies"):
        for name, dependency in document.get(table, {}).items():
            if not isinstance(dependency, dict) or dependency.get("workspace") is not True:
                continue
            workspace = tomllib.loads(evidence_text(ROOT / "Cargo.toml"))
            inherited = workspace.get("workspace", {}).get("dependencies", {}).get(name)
            if inherited is None or (isinstance(inherited, dict) and inherited.get("workspace")):
                invalid("unresolved inherited local Cargo dependency")
            if isinstance(inherited, dict) and "path" in inherited:
                inherited = {**inherited, "path": str(ROOT / inherited["path"])}
            inherited_values.append(inherited)
    return inherited_values


def cargo_path_values(document: dict[str, Any]) -> list[str]:
    paths = []
    pending: list[Any] = [document]
    while pending:
        value = pending.pop()
        if isinstance(value, dict):
            pending.extend(value.values())
            pending.extend(inherited_cargo_dependencies(value))
            if "path" in value:
                route = value["path"]
                if not isinstance(route, str) or not route:
                    invalid("malformed local Cargo source path")
                paths.append(route)
        elif isinstance(value, list):
            pending.extend(value)
    return paths


def check_local_cargo_path(
    manifest: Path, route: str, inventory: dict[str, dict[str, Any]], excluded: set[Path]
) -> None:
    target = manifest.parent / route
    resolved = target.resolve()
    if (
        not resolved.is_relative_to(ROOT)
        or not target.exists()
        or any(resolved.is_relative_to(output) for output in excluded)
        or (target.is_dir() and not (target / "Cargo.toml").is_file())
    ):
        invalid("external, missing or excluded local Cargo source path")
    if resolved.relative_to(ROOT).as_posix() not in inventory:
        invalid("local Cargo source path is absent from the input inventory")


def validate_local_cargo_paths(inventory: dict[str, dict[str, Any]], excluded: set[Path]) -> None:
    # Reject external/missing local Cargo paths; manifests cannot introduce an
    # excluded output or another repository as unrecorded implementation.
    for relative, record in inventory.items():
        if record["type"] != "file" or Path(relative).name != "Cargo.toml":
            continue
        manifest = ROOT / relative
        document = tomllib.loads(evidence_text(manifest))
        for route in cargo_path_values(document):
            check_local_cargo_path(manifest, route, inventory, excluded)


def git_metadata_paths() -> list[Path]:  # noqa: PLR0912 - validate Git metadata pointers
    validate_git_environment()
    git_entry = ROOT / ".git"
    if not git_entry.exists():
        if git_entry.is_symlink():
            invalid("fuzz cache cannot resolve Git metadata pointer")
        return []
    if git_entry.is_file():
        record = evidence_text(git_entry).removesuffix("\n")
        if (
            not record.startswith("gitdir: ")
            or not record[len("gitdir: ") :]
            or record.endswith("\r")
        ):
            invalid("fuzz cache cannot resolve Git metadata pointer")
        git_dir = Path(record[len("gitdir: ") :])
        git_dir = (git_dir if git_dir.is_absolute() else ROOT / git_dir).resolve()
    elif git_entry.is_dir():
        git_dir = git_entry.resolve()
    else:
        invalid("fuzz cache cannot resolve Git metadata entry")
    if not git_dir.is_dir():
        invalid("fuzz cache Git metadata pointer does not name a directory")
    paths = [git_dir]
    common_file = git_dir / "commondir"
    if common_file.exists() or common_file.is_symlink():
        record = evidence_text(common_file).removesuffix("\n")
        if not record or record.endswith("\r"):
            invalid("fuzz cache cannot resolve shared Git metadata pointer")
        common_dir = Path(record)
        common_dir = (common_dir if common_dir.is_absolute() else git_dir / common_dir).resolve()
        if not common_dir.is_dir():
            invalid("fuzz cache shared Git metadata pointer does not name a directory")
        paths.append(common_dir)
    return paths


def cache_protected_paths(directory: Path) -> list[Path]:
    evidence_root = repository_path(directory).parent
    paths = [ROOT / name for name in CACHE_SOURCE_ROOTS]
    paths.extend(git_metadata_paths())
    paths.extend(path for path in ROOT.iterdir() if path.is_file())
    paths.extend(FUZZ_DIR / name for name in (*RECOVERY_RAW_NAMES, "corpus_meta", "fuzz_targets"))
    paths.extend(selected_sources(selected_targets()))
    paths.extend([FUZZ_DIR / "Cargo.toml", FUZZ_DIR / "Cargo.lock", evidence_root])
    paths.append(effective_cargo_home())
    paths.append(
        repository_path(Path(os.environ.get("SECURITY_HISTORY_DIR", "artifacts/security/history")))
    )
    return [path.resolve() for path in paths]


def configured_cache(directory: Path) -> Path:
    validate_compiler_environment()
    base = repository_path(Path(os.environ["CARGO_TARGET_DIR"]))
    cache = (base / "fuzz").resolve()
    # Descendant caches are allowed; the workspace and fuzz root themselves,
    # or any ancestor that can remove them, are never cleanup destinations.
    if any(root.is_relative_to(path) for root in (ROOT, FUZZ_DIR) for path in (base, cache)):
        invalid("fuzz cache cannot be a workspace root or ancestor")
    if any(
        overlaps(output, path)
        for output in (base, cache)
        for path in cache_protected_paths(directory)
    ):
        invalid("fuzz cache overlaps protected source, raw, evidence or Cargo home paths")
    if cache.exists() and not cache.is_dir():
        invalid("fuzz cache is not a directory")
    return cache


def validate_evidence_route(directory: Path) -> Path:
    path = lexical_directory(directory)
    protected = [ROOT, FUZZ_DIR, *git_metadata_paths()]
    # ROOT/FUZZ_DIR ancestors are forbidden; their supported output descendants
    # must also be disjoint from source, Git metadata and every raw root.
    if any(root.is_relative_to(path) for root in protected):
        invalid("fuzz evidence route overlaps repository or metadata")
    sources = [ROOT / name for name in CACHE_SOURCE_ROOTS if name != "artifacts"]
    sources.extend(ROOT / name for name in ("artifacts/ct", "artifacts/karamel"))
    sources.extend(FUZZ_DIR / name for name in (*RECOVERY_RAW_NAMES, "corpus_meta", "fuzz_targets"))
    sources.extend([FUZZ_DIR / "Cargo.toml", FUZZ_DIR / "Cargo.lock", *git_metadata_paths()])
    sources.extend(entry for entry in ROOT.iterdir() if entry.is_file())
    if any(overlaps(path, source) for source in sources):
        invalid("fuzz evidence route overlaps source, raw or metadata paths")
    return path


def validate_fuzz_logs(directory: Path) -> None:
    directory = directory if directory.is_absolute() else ROOT / directory
    for name in ("run.log", "cargo-fuzz-help.log"):
        validate_regular_destination(directory / name)
    for target in selected_targets():
        for name in ("build.log", "run.log"):
            validate_regular_destination(directory / target / name)


def validate_preflight(directory: Path) -> Path:
    validate_compiler_environment()
    validate_git_environment()
    validate_collection_roots()
    routes = [directory]
    for name, default in (
        ("SECURITY_ARTIFACT_DIR", "artifacts/security/latest"),
        ("SECURITY_HISTORY_DIR", "artifacts/security/history"),
        ("FUZZ_RUN_ARTIFACT_DIR", ""),
        ("FUZZ_HISTORY_DIR", ""),
    ):
        if value := os.environ.get(name, default):
            routes.append(Path(value))
    validate_cargo_home_paths([lexical_directory(route) for route in routes], "collection")
    for target in selected_targets():
        for root in ("corpus", "artifacts"):
            lexical_directory(FUZZ_DIR / root / target)
    for route in routes:
        validate_evidence_route(route)
    validate_collection_history(directory)
    artifact = Path(os.environ.get("SECURITY_ARTIFACT_DIR", "artifacts/security/latest"))
    artifact = artifact if artifact.is_absolute() else ROOT / artifact
    validate_evidence_route(artifact / "summary")
    validate_regular_destination(artifact / "summary/security.log")
    validate_fuzz_logs(directory)
    for name in ("collection.ok", "execution.json", "run_summary.json", "collection-summary.json"):
        validate_regular_destination(lexical_directory(directory) / name)
    for name, default in (
        ("FUZZ_HISTORY_DIR", ""),
        ("SECURITY_HISTORY_DIR", "artifacts/security/history"),
    ):
        if value := os.environ.get(name, default):
            path = Path(value)
            path = path if path.is_absolute() else ROOT / path
            validate_regular_destination(path / "fuzz_runs.jsonl")
    validate_evidence_route(effective_cargo_home())
    cache = configured_cache(directory)
    lexical_directory(Path(os.environ["CARGO_TARGET_DIR"]))
    lexical_directory(cache)
    effective_native_commands()
    source_hashes(selected_targets())
    return cache


def validate_native_configuration() -> dict[str, str]:
    # Cargo merges configuration from the invocation directory, ancestors and
    # Cargo home. Only the tracked repository config is modeled here.
    extra = [FUZZ_DIR / ".cargo/config", FUZZ_DIR / ".cargo/config.toml", ROOT / ".cargo/config"]
    for parent in ROOT.parents:
        extra.extend(parent / ".cargo" / name for name in ("config", "config.toml"))
    cargo_home = effective_cargo_home()
    extra.extend(cargo_home / name for name in ("config", "config.toml"))
    if any(path.exists() or path.is_symlink() for path in extra):
        invalid("unmodeled external or nested Cargo compiler configuration")
    config_path = ROOT / ".cargo/config.toml"
    config = (
        tomllib.loads(evidence_text(required_source(config_path))) if config_path.exists() else {}
    )
    # Manifest inventory does not resolve dependency overrides or included config.
    # Empty valid containers add no source input; malformed containers fail closed.
    empty_source_settings = {"paths": [], "patch": {}, "source": {}, "replace": {}, "include": []}
    registry = config.get("registry", {})
    registries = config.get("registries", {})
    if (
        any(
            name in config and config[name] != empty
            for name, empty in empty_source_settings.items()
        )
        or not isinstance(registry, dict)
        or not isinstance(registries, dict)
        or "index" in registry
        or any(not isinstance(value, dict) or "index" in value for value in registries.values())
    ):
        invalid("unmodeled Cargo dependency source configuration")
    if "fuzz" in config.get("alias", {}):
        invalid("Cargo fuzz alias is not supported for fuzz execution or cleanup")
    forced = {
        "CC_x86_64_unknown_linux_gnu": "cc",
        "CXX_x86_64_unknown_linux_gnu": "c++",
        "AR_x86_64_unknown_linux_gnu": "ar",
        "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER": "cc",
        "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_AR": "ar",
    }
    if config.get("build") or any(
        name not in forced or value != {"value": forced[name], "force": True}
        for name, value in config.get("env", {}).items()
    ):
        invalid("unmodeled Cargo compiler configuration")
    supported_target = {"linker": "cc", "rustflags": ["-Clink-self-contained=no"]}
    if any(
        name != "x86_64-unknown-linux-gnu" or value != supported_target
        for name, value in config.get("target", {}).items()
    ):
        invalid("unmodeled Cargo target compiler configuration")
    return forced


def validate_native_overrides(expected: dict[str, str]) -> None:
    for name, value in os.environ.items():
        if name == "CARGO_REGISTRY_INDEX" or (
            name.startswith("CARGO_REGISTRIES_") and name.endswith("_INDEX")
        ):
            invalid("unmodeled Cargo dependency source environment override")
        if (
            name.startswith(
                (
                    "CC_",
                    "CXX_",
                    "AR_",
                    "CARGO_TARGET_",
                    "TARGET_CC",
                    "TARGET_CXX",
                    "TARGET_AR",
                    "HOST_CC",
                    "HOST_CXX",
                    "HOST_AR",
                )
            )
            and name not in expected
            and name != "CARGO_TARGET_DIR"
        ):
            invalid("unmodeled native compiler environment override")
        if name in expected:
            actual = shutil.which(value) if value else None
            selected = shutil.which(expected[name])
            if (
                actual is None
                or selected is None
                or Path(actual).resolve() != Path(selected).resolve()
            ):
                invalid("native compiler override differs from effective supported tool")


def effective_native_commands(target: str | None = None) -> dict[str, str]:
    machine = platform.machine()
    expected_target = {
        "x86_64": "x86_64-unknown-linux-gnu",
        "aarch64": "aarch64-unknown-linux-gnu",
    }.get(machine)
    if sys.platform != "linux" or expected_target is None or target not in (None, expected_target):
        invalid("unmodeled native fuzz compiler target")
    forced = validate_native_configuration()
    expected = {
        "CC": "cc",
        "CXX": "c++",
        "AR": "ar",
        "CC_FOR_BUILD": "cc",
        "CXX_FOR_BUILD": "c++",
        "AR_FOR_BUILD": "ar",
        **forced,
    }
    if expected_target == "aarch64-unknown-linux-gnu":
        expected.update(
            {
                "CC_aarch64_unknown_linux_gnu": "cc",
                "CXX_aarch64_unknown_linux_gnu": "c++",
                "AR_aarch64_unknown_linux_gnu": "ar",
                "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER": "cc",
                "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_AR": "ar",
            }
        )
    validate_native_overrides(expected)
    return {"cc": "cc", "cxx": "c++", "linker": "cc", "ar": "ar"}


def prepared_source_inputs(cache: Path, selected: list[str]) -> dict[str, dict[str, Any]]:
    # Include newly created cache ancestors in both full source snapshots.
    cache.mkdir(parents=True, exist_ok=True)
    return source_hashes(selected)
