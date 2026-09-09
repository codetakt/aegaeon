"""Admit Kani results per requested harness (contract ``kani-0.66.0-text-v1``, registry v2).

The runner executes the selection in ``spec/kani-evidence.json`` under a controlled build
environment, binds every result to the request that produced it (package, lib target,
source file, harness, configuration, compiled metadata) and writes a gate certificate only
when the whole required set is admitted in one run. Diagnostic requests are executed and
recorded but never counted; excluded sites are listed and never executed. ``--verify-records``
re-decides a retained run without the tool. Nothing here asserts implementation refinement.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import platform
import posixpath
import re
import resource
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parents[2]
REGISTRY = pathlib.Path("spec/kani-evidence.json")
SCHEMA = pathlib.Path("spec/kani-evidence.schema.json")
CONTRACT = "kani-0.66.0-text-v1"
RECORD_VERSION = 3
POLICY_RUSTFLAGS = "-C panic=abort -Z panic-abort-tests --cfg kani"
# Inherited variables that would change the effective compiler, flags or target.
FORBIDDEN_ENVIRONMENT = (
    "RUSTC",
    "RUSTDOC",
    "RUSTC_WRAPPER",
    "RUSTC_WORKSPACE_WRAPPER",
    "CARGO_BUILD_RUSTC",
    "CARGO_BUILD_RUSTC_WRAPPER",
    "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
    "CARGO_BUILD_RUSTFLAGS",
    "CARGO_BUILD_RUSTDOCFLAGS",
    "CARGO_BUILD_TARGET",
    "CARGO_ENCODED_RUSTFLAGS",
    "CARGO_UNSTABLE_BUILD_STD",
    "RUSTC_BOOTSTRAP",
    "__CARGO_TEST_CHANNEL_OVERRIDE_DO_NOT_USE_THIS",
)
FORBIDDEN_ENVIRONMENT_PREFIXES = ("CARGO_TARGET_",)
# Nix-provided target linker/archiver variables are recorded and allowed (they name store paths).
ALLOWED_TARGET_ENVIRONMENT = re.compile(r"^CARGO_TARGET_[A-Z0-9_]+_(LINKER|AR)$")
ALLOWED_ENVIRONMENT = (
    "PATH",
    "HOME",
    "TMPDIR",
    "TMP",
    "TEMP",
    "USER",
    "LOGNAME",
    "SHELL",
    "TERM",
    "LANG",
    "LC_ALL",
    "SOURCE_DATE_EPOCH",
    "CARGO_HOME",
    "CARGO_NET_OFFLINE",
    "RUSTUP_HOME",
    "NIX_BUILD_TOP",
    "NIX_STORE",
    "SSL_CERT_FILE",
    "NIX_SSL_CERT_FILE",
    "CC",
    "CXX",
    "AR",
    "LD",
    "NIX_CC",
    "NIX_CFLAGS_COMPILE",
    "NIX_LDFLAGS",
    "NIX_BINTOOLS",
    "NIX_HARDENING_ENABLE",
    "NIX_ENFORCE_NO_NATIVE",
    "LD_LIBRARY_PATH",
    "LIBRARY_PATH",
    "PKG_CONFIG_PATH",
    "XDG_CACHE_HOME",
    "XDG_STATE_HOME",
)
FORBIDDEN_CARGO_CONFIG = (
    "build.rustc",
    "build.rustc-wrapper",
    "build.rustc-workspace-wrapper",
    "build.rustdoc",
    "build.target",
    "build.rustflags",
    "build.rustdocflags",
    "unstable.build-std",
)
KANI_BANNER = re.compile(r"^Kani Rust Verifier (\S+) \(cargo plugin\)$", re.MULTILINE)
CHECKING = re.compile(r"^Checking harness (.+)\.\.\.$", re.MULTILINE)
PROPERTY = re.compile(
    r"Check (\d+): ([^\n]+)\n"
    r"\t - Status: ([A-Z]+)\n"
    r"\t - Description: \"([^\n]*(?:\n[ ]+[^\n]*)*)\"\n"
    r"(?:\t - Location: [^\n]+\n)?"
)
SUMMARY_LINE = re.compile(
    r"^ \*\* (\d+) of (\d+) failed(?: \((\d+) (unreachable|undetermined)\))?$"
)
COMPLETION = re.compile(
    r"\n\nVERIFICATION:- SUCCESSFUL\nVerification Time: [0-9.]+s\n"
    r"\nManual Harness Summary:\n"
    r"Complete - 1 successfully verified harnesses, 0 failures, 1 total\.\n?\Z"
)
SOURCE_SITE = re.compile(r"#\[(?:kani::)?proof\b|cfg_attr\(kani,\s*kani::proof")


class AdmissionError(Exception):
    """A rule of the contract was violated; the message names the rule."""


# ----------------------------------------------------------------------------- helpers


def digest_file(path: pathlib.Path) -> str:
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def digest_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_json(path: pathlib.Path) -> Any:
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError) as error:
        raise AdmissionError(f"cannot read {path}: {error}") from error


def write_json_new(path: pathlib.Path, value: Any) -> None:
    if path.exists():
        raise AdmissionError(f"refusing to overwrite existing record {path}")
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def short_name(qualified: str) -> str:
    return qualified.rsplit("::", 1)[-1]


def now() -> str:
    return datetime.now(UTC).isoformat()


# ----------------------------------------------------------------------------- registry


def validate_schema(registry: Any, schema: Any) -> None:
    try:
        import jsonschema
    except ImportError as error:  # pragma: no cover - the pinned shells provide it
        raise AdmissionError("jsonschema is required to validate the registry") from error
    validator = jsonschema.Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(registry), key=lambda e: list(e.absolute_path))
    if errors:
        first = errors[0]
        where = "/".join(str(p) for p in first.absolute_path) or "<root>"
        raise AdmissionError(f"registry violates schema at {where}: {first.message}")


def executable_groups(registry: dict[str, Any]) -> list[dict[str, Any]]:
    return [g for g in registry["groups"] if g["class"] in ("required", "diagnostic")]


def excluded_sites(registry: dict[str, Any]) -> list[dict[str, Any]]:
    return [s for g in registry["groups"] if g["class"] == "excluded" for s in g["sites"]]


def source_sites(root: pathlib.Path) -> list[dict[str, Any]]:
    """Every ``#[kani::proof]``/``#[proof]`` site under crates/, with its function name."""
    sites: list[dict[str, Any]] = []
    for path in sorted((root / "crates").rglob("*.rs")):
        if "target" in path.parts:
            continue
        lines = path.read_text(errors="replace").splitlines()
        for index, line in enumerate(lines):
            if not SOURCE_SITE.search(line):
                continue
            name = None
            for candidate in lines[index + 1 : index + 8]:
                match = re.search(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)", candidate)
                if match:
                    name = match[1]
                    break
            sites.append({"file": str(path.relative_to(root)), "line": index + 1, "function": name})
    return sites


def check_registry(registry: dict[str, Any], root: pathlib.Path) -> None:
    """Structural rules beyond the schema: uniqueness, existence, complete site coverage."""
    ids = [g["id"] for g in registry["groups"]]
    if len(ids) != len(set(ids)):
        raise AdmissionError("duplicate group id")
    per_package: set[tuple[str, str]] = set()
    per_file_short: dict[tuple[str, str], str] = {}
    for group in executable_groups(registry):
        for harness in group["harnesses"]:
            key = (group["package"]["name"], harness["name"])
            if key in per_package:
                raise AdmissionError(f"duplicate harness {harness['name']} in {key[0]}")
            per_package.add(key)
            fs = (harness["file"], short_name(harness["name"]))
            if fs in per_file_short:
                raise AdmissionError(f"ambiguous short name {fs[1]} in {fs[0]}")
            per_file_short[fs] = harness["name"]
            if not (root / harness["file"]).is_file():
                raise AdmissionError(f"harness source {harness['file']} does not exist")
        if not (root / group["package"]["manifest"]).is_file():
            raise AdmissionError(f"manifest {group['package']['manifest']} does not exist")
    for site in excluded_sites(registry):
        if not (root / site["file"]).is_file():
            raise AdmissionError(f"excluded site file {site['file']} does not exist")
    for entry in registry["cargo_config"]["registered_files"]:
        path = root / entry["path"]
        if not path.is_file() or digest_file(path) != entry["sha256"]:
            raise AdmissionError(f"registered cargo config {entry['path']} is missing or changed")
    covered = set(per_file_short)
    covered.update((s["file"], short_name(s["name"])) for s in excluded_sites(registry))
    missing = [
        s
        for s in source_sites(root)
        if s["function"] is None or (s["file"], s["function"]) not in covered
    ]
    if missing:
        first = missing[0]
        raise AdmissionError(
            f"{len(missing)} proof site(s) are neither selected nor excluded, e.g. "
            f"{first['file']}:{first['line']} {first['function']}"
        )


def load_registry(
    root: pathlib.Path, registry_path: pathlib.Path, schema_path: pathlib.Path
) -> dict[str, Any]:
    registry: dict[str, Any] = load_json(registry_path)
    validate_schema(registry, load_json(schema_path))
    if registry["contract"] != CONTRACT:
        raise AdmissionError(f"registry contract {registry['contract']!r} is not {CONTRACT}")
    check_registry(registry, root)
    return registry


# ----------------------------------------------------------------------------- environment


def controlled_environment(inherited: dict[str, str]) -> tuple[dict[str, str], dict[str, Any]]:
    """Build the child environment from an allowlist; reject compiler/flag overrides."""
    forbidden = sorted(
        name
        for name in inherited
        if name in FORBIDDEN_ENVIRONMENT
        or (
            name.startswith(FORBIDDEN_ENVIRONMENT_PREFIXES)
            and not ALLOWED_TARGET_ENVIRONMENT.match(name)
        )
    )
    if inherited.get("RUSTFLAGS", POLICY_RUSTFLAGS) != POLICY_RUSTFLAGS:
        forbidden.append("RUSTFLAGS")
    if forbidden:
        raise AdmissionError(
            "inherited build environment overrides the compiler or flags: " + ", ".join(forbidden)
        )
    child: dict[str, str] = {}
    kept: list[str] = []
    dropped: list[str] = []
    for name, value in inherited.items():
        if name in ALLOWED_ENVIRONMENT or ALLOWED_TARGET_ENVIRONMENT.match(name):
            child[name] = value
            kept.append(name)
        else:
            dropped.append(name)
    child["RUSTFLAGS"] = POLICY_RUSTFLAGS
    child["CARGO_TERM_COLOR"] = "never"
    child["CARGO_INCREMENTAL"] = "0"
    return child, {
        "kept": sorted(kept),
        "dropped": sorted(dropped),
        "target_variables": {k: v for k, v in child.items() if ALLOWED_TARGET_ENVIRONMENT.match(k)},
    }


def cargo_config_files(cwd: pathlib.Path, env: dict[str, str]) -> list[pathlib.Path]:
    """Every configuration file Cargo would read for ``cwd`` (ancestor .cargo dirs, CARGO_HOME)."""
    files: list[pathlib.Path] = []
    for directory in [cwd, *cwd.parents]:
        for name in ("config.toml", "config"):
            candidate = directory / ".cargo" / name
            if candidate.is_file():
                files.append(candidate)
    home = pathlib.Path(env.get("CARGO_HOME") or (pathlib.Path(env.get("HOME", "/")) / ".cargo"))
    for name in ("config.toml", "config"):
        candidate = home / name
        if candidate.is_file() and candidate not in files:
            files.append(candidate)
    return files


def flatten(value: Any, prefix: str = "") -> dict[str, Any]:
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, inner in value.items():
            out.update(flatten(inner, f"{prefix}.{key}" if prefix else str(key)))
        return out
    return {prefix: value}


def check_cargo_config(
    cargo: str,
    cwd: pathlib.Path,
    env: dict[str, str],
    registry: dict[str, Any],
    root: pathlib.Path,
) -> dict[str, Any]:
    """Effective Cargo configuration must not redirect the compiler, flags or target."""
    completed = subprocess.run(
        [cargo, "config", "get", "-Z", "unstable-options", "--format", "json"],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise AdmissionError(f"cargo config get failed: {completed.stderr.strip()[:400]}")
    effective = json.loads(completed.stdout or "{}")
    flat = flatten(effective)
    violations = [key for key in flat if key in FORBIDDEN_CARGO_CONFIG]
    registered = {
        root / e["path"]: e["sha256"] for e in registry["cargo_config"]["registered_files"]
    }
    files = []
    for path in cargo_config_files(cwd, env):
        entry = {"path": str(path), "sha256": digest_file(path), "registered": path in registered}
        if not entry["registered"]:
            content = flatten(_load_toml(path))
            foreign = [
                key
                for key in content
                if not key.startswith(("source.", "net.", "registries.", "registry."))
            ]
            if foreign:
                violations.extend(f"{path}:{key}" for key in foreign)
        files.append(entry)
    for key in flat:
        if key.startswith("target.") and key.endswith((".rustflags", ".linker")):
            if not any(f["registered"] for f in files):
                violations.append(key)
    if violations:
        raise AdmissionError("cargo configuration overrides the build: " + ", ".join(violations))
    return {"effective": effective, "files": files}


def _load_toml(path: pathlib.Path) -> dict[str, Any]:
    import tomllib

    with path.open("rb") as handle:
        loaded: dict[str, Any] = tomllib.load(handle)
    return loaded


# ----------------------------------------------------------------------------- tools

REQUIRED_COMPONENTS = (
    "bin/kani-driver",
    "bin/kani-compiler",
    "toolchain/bin/rustc",
    "toolchain/bin/cargo",
    "cbmc",
)
SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")


def is_sha256(value: Any) -> bool:
    return isinstance(value, str) and SHA256_HEX.match(value) is not None


def validate_tools(tools: Any, registry: dict[str, Any]) -> dict[str, Any]:
    """Typed, policy-consistent tool identity: the retained paths and digests are
    provenance of what ran, not a requirement that the binaries exist at replay time."""
    if not isinstance(tools, dict):
        raise AdmissionError("tool identity record is not an object")
    store = tools.get("store_path")
    wrapper = tools.get("cargo_kani")
    if not isinstance(store, str) or not store or not isinstance(wrapper, dict):
        raise AdmissionError("tool identity record lacks the Kani store path or wrapper")
    if wrapper.get("path") != f"{store}/bin/cargo-kani" or not is_sha256(wrapper.get("sha256")):
        raise AdmissionError("tool identity record does not name the store's cargo-kani wrapper")
    if tools.get("reported_version") != f"cargo-kani {registry['kani_version']}":
        raise AdmissionError(
            f"tool identity record reports {tools.get('reported_version')!r}, "
            f"policy requires cargo-kani {registry['kani_version']}"
        )
    components = tools.get("components")
    if not isinstance(components, dict):
        raise AdmissionError("tool identity record lacks components")
    for name in REQUIRED_COMPONENTS:
        entry = components.get(name)
        if (
            not isinstance(entry, dict)
            or not isinstance(entry.get("path"), str)
            or not is_sha256(entry.get("sha256"))
        ):
            raise AdmissionError(f"tool identity record lacks component {name}")
        # kani-driver/kani-compiler are files of the Kani store; the bundled toolchain
        # resolves through symlinks into its own derivation, so only absoluteness is
        # required there (the digest is the identity).
        if name.startswith("bin/") and not entry["path"].startswith(f"{store}/"):
            raise AdmissionError(f"tool component {name} lies outside the Kani store")
        if not entry["path"].startswith("/"):
            raise AdmissionError(f"tool component {name} is not an absolute path")
    solver = components.get(registry["solver"])
    if isinstance(solver, dict) and solver.get("builtin") == "cbmc":
        if solver.get("cbmc_sha256") != components["cbmc"]["sha256"]:
            raise AdmissionError("tool identity record's built-in solver does not bind cbmc")
    elif not (
        isinstance(solver, dict)
        and isinstance(solver.get("path"), str)
        and is_sha256(solver.get("sha256"))
    ):
        raise AdmissionError(f"tool identity record lacks solver {registry['solver']}")
    if not isinstance(tools.get("cbmc_version"), str) or not tools["cbmc_version"]:
        raise AdmissionError("tool identity record lacks the cbmc version")
    rustc_v = tools.get("rustc_vV")
    if not isinstance(rustc_v, str) or not re.search(
        rf"^host: {re.escape(registry['target'])}$", rustc_v, re.MULTILINE
    ):
        raise AdmissionError(f"tool identity record's rustc host is not {registry['target']}")
    if tools.get("cargo") != components["toolchain/bin/cargo"]["path"]:
        raise AdmissionError("tool identity record's cargo is not the bundled toolchain cargo")
    return tools


def validate_environment(
    environment: Any, cargo_config: Any, registry: dict[str, Any], root: str
) -> None:
    """The recorded build environment must itself satisfy the controlled-build policy."""
    if not isinstance(environment, dict) or not isinstance(cargo_config, dict):
        raise AdmissionError("environment record is not an object")
    kept = environment.get("kept")
    targets = environment.get("target_variables")
    if not isinstance(kept, list) or not isinstance(targets, dict):
        raise AdmissionError("environment record lacks kept variables")
    for name in kept:
        if not isinstance(name, str) or not (
            name in ALLOWED_ENVIRONMENT or ALLOWED_TARGET_ENVIRONMENT.match(name)
        ):
            raise AdmissionError(
                f"environment record keeps a variable outside the allowlist: {name}"
            )
    for name in targets:
        if not ALLOWED_TARGET_ENVIRONMENT.match(str(name)):
            raise AdmissionError(f"environment record carries a forbidden target variable: {name}")
    effective = cargo_config.get("effective")
    files = cargo_config.get("files")
    if not isinstance(effective, dict) or not isinstance(files, list):
        raise AdmissionError("environment record lacks the effective cargo configuration")
    violations = [key for key in flatten(effective) if key in FORBIDDEN_CARGO_CONFIG]
    if violations:
        raise AdmissionError(
            "environment record's cargo configuration overrides the build: " + ", ".join(violations)
        )
    registered = {
        posixpath.join(root, e["path"]): e["sha256"]
        for e in registry["cargo_config"]["registered_files"]
    }
    for entry in files:
        if (
            not isinstance(entry, dict)
            or not isinstance(entry.get("path"), str)
            or not is_sha256(entry.get("sha256"))
            or not isinstance(entry.get("registered"), bool)
        ):
            raise AdmissionError("environment record's cargo config file entry is malformed")
        if entry["registered"] and registered.get(entry["path"]) != entry["sha256"]:
            raise AdmissionError(
                f"environment record's registered cargo config {entry['path']} "
                "differs from the registry"
            )


def expected_invocation(
    tools: dict[str, Any],
    registry: dict[str, Any],
    group: dict[str, Any],
    harness: dict[str, Any] | None,
    root: str,
) -> list[str]:
    """The exact command the runner issues for a request (harness) or a discovery (None)."""
    manifest = pathlib.PurePosixPath(root) / group["package"]["manifest"]
    budget = registry["budgets"]["list_timeout_seconds" if harness is None else "timeout_seconds"]
    command = kani_command(
        tools["cargo_kani"]["path"],
        group,
        pathlib.Path(manifest),
        registry,
        harness,
        harness is None,
    )
    return ["timeout", "--kill-after=10", str(budget), *command]


def validate_invocation(
    invocation: Any,
    expected_argv: list[str],
    registry: dict[str, Any],
    root: str,
    harness: dict[str, Any] | None,
) -> dict[str, Any]:
    """A recorded invocation must be the approved command, run from the recorded root,
    under the policy budgets; absent, extra, duplicated or weakened options reject."""
    if not isinstance(invocation, dict):
        raise AdmissionError("execution record is not an object")
    if invocation.get("argv") != expected_argv:
        raise AdmissionError("execution record's command differs from the approved command")
    if invocation.get("cwd") != root:
        raise AdmissionError("execution record did not run from the recorded checkout root")
    budget = registry["budgets"]["list_timeout_seconds" if harness is None else "timeout_seconds"]
    if (
        invocation.get("budget_seconds") != budget
        or invocation.get("memory_limit_bytes") != registry["budgets"]["memory_limit_bytes"]
    ):
        raise AdmissionError("execution record's budgets differ from the policy budgets")
    if not is_int(invocation.get("exit_code")) or not is_sha256(invocation.get("log_sha256")):
        raise AdmissionError("execution record lacks a typed exit code or log digest")
    if harness is not None:
        if invocation.get("harness") != harness["name"]:
            raise AdmissionError("execution record names another harness")
        if not is_int(invocation.get("new_metadata_files")) or invocation["new_metadata_files"] < 0:
            raise AdmissionError("execution record lacks the compiled metadata count")
    return invocation


def effective_settings(
    argv: list[str], attributes: dict[str, Any], harness: dict[str, Any]
) -> dict[str, Any]:
    """Effective solver/unwind from the validated invocation reconciled with the compiled
    attributes, following kani-driver: CLI --unwind, else the attribute, else --default-unwind."""
    solver = argv[argv.index("--solver") + 1]
    default_unwind = int(argv[argv.index("--default-unwind") + 1])
    if "--unwind" in argv:
        unwind = int(argv[argv.index("--unwind") + 1])
        if harness.get("unwind") != unwind:
            raise AdmissionError("execution record's unwind override differs from the registry")
    elif attributes["unwind_value"] is not None:
        unwind = attributes["unwind_value"]
    else:
        unwind = default_unwind
    return {"unwind": unwind, "solver": solver}


def resolve_tools(env: dict[str, str], registry: dict[str, Any]) -> dict[str, Any]:
    kani = shutil.which("cargo-kani", path=env.get("PATH"))
    if kani is None:
        raise AdmissionError("cargo-kani is required; compile-only substitutes are not evidence")
    kani_path = pathlib.Path(kani).resolve()
    version = subprocess.run(
        [str(kani_path), "kani", "--version"], env=env, capture_output=True, text=True, check=False
    )
    reported = version.stdout.strip()
    if version.returncode != 0 or reported != f"cargo-kani {registry['kani_version']}":
        raise AdmissionError(f"unsupported Kani: {reported!r} (exit {version.returncode})")
    store = kani_path.parent.parent
    tools: dict[str, Any] = {
        "cargo_kani": {"path": str(kani_path), "sha256": digest_file(kani_path)},
        "reported_version": reported,
        "store_path": str(store),
        "components": {},
    }
    sysroot = store / f"kani-{registry['kani_version']}"
    for name in (
        "bin/kani-driver",
        "bin/kani-compiler",
        "toolchain/bin/rustc",
        "toolchain/bin/cargo",
    ):
        candidate = sysroot / name
        if candidate.exists():
            resolved = candidate.resolve()
            tools["components"][name] = {"path": str(resolved), "sha256": digest_file(resolved)}
    for required in ("bin/kani-driver", "bin/kani-compiler", "toolchain/bin/rustc"):
        if required not in tools["components"]:
            raise AdmissionError(f"Kani component {required} not found under {sysroot}")
    rustc = tools["components"]["toolchain/bin/rustc"]["path"]
    rustc_v = subprocess.run([rustc, "-vV"], env=env, capture_output=True, text=True, check=False)
    tools["rustc_vV"] = rustc_v.stdout.strip()
    host = re.search(r"^host: (\S+)$", tools["rustc_vV"], re.MULTILINE)
    if host is None or host[1] != registry["target"]:
        raise AdmissionError(
            f"rustc host {host[1] if host else None!r} is not {registry['target']}"
        )
    wrapper_text = kani_path.read_text(errors="replace")
    for tool in ("cbmc", "cadical", "kissat", "minisat", "z3", "cvc5"):
        located = re.search(rf"(/[^'\":\s]+-{tool}-[^'\":\s/]+/bin)", wrapper_text)
        if located:
            binary = pathlib.Path(located[1]) / tool
            if binary.exists():
                tools["components"][tool] = {"path": str(binary), "sha256": digest_file(binary)}
    if "cbmc" in tools["components"]:
        out = subprocess.run(
            [tools["components"]["cbmc"]["path"], "--version"],
            capture_output=True,
            text=True,
            check=False,
        )
        tools["cbmc_version"] = out.stdout.strip()
    if registry["solver"] not in tools["components"]:
        # cadical is CBMC's built-in SAT backend (no separate binary); its identity is the
        # cbmc component. Every other solver must resolve to a binary on the wrapper PATH.
        if registry["solver"] != "cadical" or "cbmc" not in tools["components"]:
            raise AdmissionError(
                f"solver {registry['solver']} not resolvable from the Kani wrapper"
            )
        tools["components"]["cadical"] = {
            "builtin": "cbmc",
            "cbmc_sha256": tools["components"]["cbmc"]["sha256"],
        }
    cargo = tools["components"].get("toolchain/bin/cargo", {}).get("path") or shutil.which(
        "cargo", path=env.get("PATH")
    )
    if cargo is None:
        raise AdmissionError("cargo is required for metadata")
    tools["cargo"] = cargo
    return validate_tools(tools, registry)


# ----------------------------------------------------------------------------- cargo metadata


def source_path(original_file: str, source_base: str) -> str:
    """Map Kani's workspace-root-relative original_file onto a repository-relative path."""
    if not original_file or pathlib.PurePosixPath(original_file).is_absolute():
        raise AdmissionError(f"compiled source {original_file!r} is not workspace-relative")
    joined = posixpath.normpath(posixpath.join(source_base, original_file))
    if joined == ".." or joined.startswith("../"):
        raise AdmissionError(f"compiled source {original_file!r} escapes the repository")
    return joined


def cargo_metadata(
    cargo: str,
    manifest: pathlib.Path,
    group: dict[str, Any],
    env: dict[str, str],
    target: str,
    root: pathlib.Path,
) -> dict[str, Any]:
    command = [
        cargo,
        "metadata",
        "--format-version",
        "1",
        "--manifest-path",
        str(manifest),
        "--filter-platform",
        target,
    ]
    if group["features"]:
        command += ["--features", ",".join(group["features"])]
    if group["no_default_features"]:
        command.append("--no-default-features")
    completed = subprocess.run(command, env=env, capture_output=True, text=True, check=False)
    if completed.returncode != 0:
        raise AdmissionError(f"cargo metadata failed: {completed.stderr.strip()[:400]}")
    data = json.loads(completed.stdout)
    packages = {p["id"]: p for p in data["packages"]}
    selected = [p for p in data["packages"] if p["name"] == group["package"]["name"]]
    if len(selected) != 1:
        raise AdmissionError(
            f"package {group['package']['name']} resolves to {len(selected)} packages"
        )
    package = selected[0]
    libs = [t for t in package["targets"] if "lib" in t["kind"]]
    if len(libs) != 1 or libs[0]["name"] != group["crate"]:
        found = [t["name"] for t in libs]
        raise AdmissionError(
            f"package {package['name']} lib target {found} is not {group['crate']}"
        )
    node = next(n for n in data["resolve"]["nodes"] if n["id"] == package["id"])
    # Workspace path dependencies (transitively) are part of the verified input.
    path_dependencies: list[str] = []
    pending = list(node["dependencies"])
    seen: set[str] = set()
    while pending:
        dep_id = pending.pop()
        if dep_id in seen:
            continue
        seen.add(dep_id)
        dep = packages[dep_id]
        if dep.get("source") is None:
            dep_dir = pathlib.Path(dep["manifest_path"]).parent.resolve()
            try:
                path_dependencies.append(dep_dir.relative_to(root.resolve()).as_posix())
            except ValueError as error:
                raise AdmissionError(
                    f"path dependency {dep_dir} lies outside the repository"
                ) from error
            dep_node = next(n for n in data["resolve"]["nodes"] if n["id"] == dep_id)
            pending.extend(dep_node["dependencies"])
    workspace_root = pathlib.Path(data["workspace_root"]).resolve()
    try:
        source_base = workspace_root.relative_to(root.resolve()).as_posix()
    except ValueError as error:
        raise AdmissionError(
            f"workspace root {workspace_root} lies outside the repository"
        ) from error
    return {
        "command": command,
        "workspace_root": str(workspace_root),
        "source_base": source_base,
        "package_id": package["id"],
        "version": package["version"],
        "manifest_path": package["manifest_path"],
        "lib_target": libs[0]["name"],
        "resolved_features": node.get("features", []),
        "path_dependencies": sorted(path_dependencies),
        "sha256": digest_bytes(completed.stdout.encode()),
    }


# ----------------------------------------------------------------------------- execution


def kani_command(
    kani: str,
    group: dict[str, Any],
    manifest: pathlib.Path,
    registry: dict[str, Any],
    harness: dict[str, Any] | None,
    only_codegen: bool,
) -> list[str]:
    command = [
        kani,
        "kani",
        "--manifest-path",
        str(manifest),
        "-p",
        group["package"]["name"],
        "--lib",
    ]
    if group["features"]:
        command += ["--features", ",".join(group["features"])]
    if group["no_default_features"]:
        command.append("--no-default-features")
    if only_codegen:
        command.append("--only-codegen")
    else:
        assert harness is not None
        command += [
            "--exact",
            "--harness",
            harness["name"],
            "--solver",
            registry["solver"],
            "--default-unwind",
            str(group["default_unwind"]),
        ]
        if "unwind" in harness:
            command += ["--unwind", str(harness["unwind"])]
    return command


def run_process(
    command: list[str],
    cwd: pathlib.Path,
    env: dict[str, str],
    log_path: pathlib.Path,
    budget_seconds: int,
    memory_limit: int,
) -> dict[str, Any]:
    def limits() -> None:
        resource.setrlimit(resource.RLIMIT_AS, (memory_limit, memory_limit))

    wrapped = ["timeout", "--kill-after=10", str(budget_seconds), *command]
    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    started = time.monotonic()
    with log_path.open("w") as log:
        process = subprocess.run(
            wrapped,
            cwd=cwd,
            env=env,
            stdout=log,
            stderr=subprocess.STDOUT,
            preexec_fn=limits,
            check=False,
        )
    after = resource.getrusage(resource.RUSAGE_CHILDREN)
    return {
        "argv": wrapped,
        "cwd": str(cwd),
        "exit_code": process.returncode,
        "wall_seconds": round(time.monotonic() - started, 3),
        "cpu_seconds": round(
            (after.ru_utime + after.ru_stime) - (before.ru_utime + before.ru_stime), 3
        ),
        "budget_seconds": budget_seconds,
        "memory_limit_bytes": memory_limit,
        "log_sha256": digest_file(log_path),
    }


def metadata_files(target: pathlib.Path) -> set[pathlib.Path]:
    return set(target.rglob("*.kani-metadata.json")) if target.exists() else set()


def discover(
    group: dict[str, Any],
    manifest: pathlib.Path,
    kani: str,
    registry: dict[str, Any],
    env: dict[str, str],
    group_dir: pathlib.Path,
    target: pathlib.Path,
    root: pathlib.Path,
    source_base: str,
) -> dict[str, Any]:
    """Compile once with the group's exact configuration and read every harness identity."""
    command = kani_command(kani, group, manifest, registry, None, only_codegen=True)
    env = {**env, "CARGO_TARGET_DIR": str(target)}
    record = run_process(
        command,
        root,
        env,
        group_dir / "discovery.log",
        registry["budgets"]["list_timeout_seconds"],
        registry["budgets"]["memory_limit_bytes"],
    )
    if record["exit_code"] != 0:
        raise AdmissionError(f"discovery compilation failed with exit {record['exit_code']}")
    files = []
    for candidate in metadata_files(target):
        document = read_metadata(candidate)
        if document is not None and document.get("crate_name") == group["crate"]:
            files.append(candidate)
    if len(files) != 1:
        raise AdmissionError(
            f"discovery produced {len(files)} metadata files for crate {group['crate']}"
        )
    shutil.copy2(files[0], group_dir / "discovery.kani-metadata.json")
    record["metadata_sha256"] = digest_file(files[0])
    record["source_base"] = source_base
    record["harnesses"] = derive_discovery(read_metadata(files[0]), group, source_base)
    return record


def derive_discovery(
    metadata: Any, group: dict[str, Any], source_base: str
) -> dict[str, dict[str, Any]]:
    """Harness identities of a group from its raw discovery metadata (live and on replay).
    Kani writes original_file relative to the compiled crate's workspace root, which is the
    repository for workspace members and the crate directory for excluded crates."""
    document = validate_metadata(metadata)
    if document["crate_name"] != group["crate"]:
        raise AdmissionError(
            f"discovery metadata is for crate {document['crate_name']!r}, not {group['crate']!r}"
        )
    names = [p["pretty_name"] for p in document["proof_harnesses"]]
    if len(names) != len(set(names)):
        raise AdmissionError("discovery metadata lists a harness twice")
    return {
        p["pretty_name"]: {
            "file": source_path(p["original_file"], source_base),
            "original_file": p["original_file"],
            "attributes": p["attributes"],
        }
        for p in document["proof_harnesses"]
    }


def classify_exit(exit_code: int, log: str, budget_seconds: int) -> str:
    if exit_code == 0:
        return "exit 0"
    if exit_code == 124:
        return f"wall-clock budget of {budget_seconds}s exceeded (timeout exit 124)"
    if exit_code < 0:
        return f"terminated by signal {-exit_code}"
    if exit_code > 128:
        return f"terminated by signal {exit_code - 128} (exit {exit_code})"
    if exit_code == 101 and "panicked at" in log:
        return "process panic (exit 101)"
    if exit_code == 101:
        return "exit 101 without a panic marker (unknown nonzero)"
    return f"unknown nonzero exit {exit_code}"


def accept_report(
    log: str,
    harness: str,
    exit_code: int,
    unreachable_assertions: dict[str, str] | None = None,
    kani_version: str | None = None,
    budget_seconds: int = 0,
) -> dict[str, Any]:
    """Accept one completed exact harness structurally; return properties and callee notes."""
    if exit_code != 0:
        raise AdmissionError(classify_exit(exit_code, log, budget_seconds))
    banner = KANI_BANNER.findall(log)
    if kani_version is not None and banner != [kani_version]:
        raise AdmissionError(f"Kani banner {banner!r} does not name version {kani_version}")
    selected = CHECKING.findall(log)
    if selected != [harness]:
        raise AdmissionError(f"unexpected harness selection: {selected!r}")
    sections = log.split("\nRESULTS:\n")
    if len(sections) != 2:
        raise AdmissionError("expected exactly one property report")
    body, separator, summary = sections[1].partition("\nSUMMARY:\n")
    if not separator:
        raise AdmissionError("missing result summary")
    checks = list(PROPERTY.finditer(body))
    if not checks or PROPERTY.sub("", body).strip():
        raise AdmissionError("missing or unrecognized property records")
    properties: list[dict[str, str]] = []
    for number, match in enumerate(checks, 1):
        if int(match[1]) != number:
            raise AdmissionError("nonconsecutive property records")
        if match[3] not in {"SUCCESS", "UNREACHABLE"}:
            raise AdmissionError(f"unaccepted property {match[2]}: {match[3]}")
        properties.append({"id": match[2], "status": match[3], "description": match[4]})
    if len({p["id"] for p in properties}) != len(properties):
        raise AdmissionError("duplicate property identity")
    own = [p for p in properties if p["id"].startswith(harness + ".")]
    if not any(p["status"] == "SUCCESS" for p in own):
        raise AdmissionError("no reachable successful harness property")
    own_unreachable = {
        p["id"]: p["description"]
        for p in own
        if p["status"] == "UNREACHABLE" and ".assertion." in p["id"]
    }
    if own_unreachable != (unreachable_assertions or {}):
        raise AdmissionError("unreviewed unreachable harness assertion or changed guard")
    unreachable = sum(p["status"] == "UNREACHABLE" for p in properties)
    first = summary.splitlines()[0] if summary else ""
    summary_match = SUMMARY_LINE.match(first)
    if (
        summary_match is None
        or int(summary_match[1]) != 0
        or int(summary_match[2]) != len(properties)
        or (
            unreachable
            and (
                summary_match[3] is None
                or int(summary_match[3]) != unreachable
                or summary_match[4] != "unreachable"
            )
        )
        or (not unreachable and summary_match[3] is not None)
    ):
        raise AdmissionError("property count/status does not match summary")
    if COMPLETION.search(summary[len(first) :]) is None:
        raise AdmissionError("missing or unrecognized completion record")
    return {
        "properties": properties,
        "callee_unreachable": [
            {"id": p["id"], "description": p["description"]}
            for p in properties
            if p["status"] == "UNREACHABLE" and not p["id"].startswith(harness + ".")
        ],
    }


METADATA_ATTRIBUTES = ("kind", "should_panic", "solver", "unwind_value", "stubs", "verified_stubs")
HARNESS_KINDS = ("Proof", "Test")  # plus {"ProofForContract": {"target_fn": ...}}
SOLVER_VARIANTS = ("Bitwuzla", "Cadical", "Cvc5", "Kissat", "Minisat", "Z3")  # plus {"Binary": ...}
U32_MAX = 0xFFFFFFFF


def is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def valid_kind(kind: Any) -> bool:
    if isinstance(kind, str):
        return kind in HARNESS_KINDS
    return (
        isinstance(kind, dict)
        and set(kind) == {"ProofForContract"}
        and isinstance(kind["ProofForContract"], dict)
        and isinstance(kind["ProofForContract"].get("target_fn"), str)
    )


def valid_solver(solver: Any) -> bool:
    if solver is None:
        return True
    if isinstance(solver, str):
        return solver in SOLVER_VARIANTS
    return (
        isinstance(solver, dict)
        and set(solver) == {"Binary"}
        and isinstance(solver["Binary"], str)
        and bool(solver["Binary"])
    )


def validate_attributes(attributes: dict[str, Any]) -> None:
    for key in METADATA_ATTRIBUTES:
        if key not in attributes:
            raise AdmissionError(f"compiled metadata attributes lack {key}")
    if not valid_kind(attributes["kind"]):
        raise AdmissionError(f"compiled metadata kind {attributes['kind']!r} is not a HarnessKind")
    if not isinstance(attributes["should_panic"], bool):
        raise AdmissionError("compiled metadata should_panic is not a bool")
    if not valid_solver(attributes["solver"]):
        raise AdmissionError(
            f"compiled metadata solver {attributes['solver']!r} is not a CbmcSolver"
        )
    unwind = attributes["unwind_value"]
    if unwind is not None and not (is_int(unwind) and 0 <= unwind <= U32_MAX):
        raise AdmissionError(f"compiled metadata unwind_value {unwind!r} is not a u32")
    stubs = attributes["stubs"]
    if not isinstance(stubs, list) or not all(
        isinstance(stub, dict)
        and isinstance(stub.get("original"), str)
        and isinstance(stub.get("replacement"), str)
        for stub in stubs
    ):
        raise AdmissionError("compiled metadata stubs are not Stub records")
    verified = attributes["verified_stubs"]
    if not isinstance(verified, list) or not all(isinstance(v, str) for v in verified):
        raise AdmissionError("compiled metadata verified_stubs are not strings")


def validate_metadata(metadata: Any) -> dict[str, Any]:
    """Structural and typed check of a kani-metadata document against the 0.66.0 shapes;
    nothing is presumed for a missing key."""
    if not isinstance(metadata, dict):
        raise AdmissionError("compiled metadata missing, unreadable or not a JSON object")
    if not isinstance(metadata.get("crate_name"), str) or not isinstance(
        metadata.get("proof_harnesses"), list
    ):
        raise AdmissionError("compiled metadata lacks crate_name or proof_harnesses")
    for proof in metadata["proof_harnesses"]:
        if not isinstance(proof, dict):
            raise AdmissionError("compiled metadata proof entry is not an object")
        for key in ("pretty_name", "mangled_name", "original_file"):
            if not isinstance(proof.get(key), str) or not proof[key]:
                raise AdmissionError(f"compiled metadata proof entry lacks {key}")
        start, end = proof.get("original_start_line"), proof.get("original_end_line")
        if (
            not isinstance(start, int)
            or not isinstance(end, int)
            or isinstance(start, bool)
            or isinstance(end, bool)
            or not 1 <= start <= end
        ):
            raise AdmissionError("compiled metadata proof entry has invalid source lines")
        if not isinstance(proof.get("attributes"), dict):
            raise AdmissionError("compiled metadata proof entry lacks attributes")
        validate_attributes(proof["attributes"])
    return metadata


def read_metadata(path: pathlib.Path) -> dict[str, Any] | None:
    """Read a retained metadata file; anything that is not a JSON object is None."""
    try:
        document = json.loads(path.read_text())
    except (OSError, ValueError):
        return None
    return document if isinstance(document, dict) else None


def bind_metadata(
    metadata: dict[str, Any],
    group: dict[str, Any],
    harness: dict[str, Any],
    registry: dict[str, Any],
    source_base: str,
    argv: list[str] | None = None,
) -> dict[str, Any]:
    validate_metadata(metadata)
    if metadata.get("crate_name") != group["crate"]:
        raise AdmissionError(
            f"compiled crate {metadata.get('crate_name')!r} is not {group['crate']!r}"
        )
    proofs = metadata["proof_harnesses"]
    if [p.get("pretty_name") for p in proofs] != [harness["name"]]:
        raise AdmissionError("compiled metadata does not list exactly the requested harness")
    proof = proofs[0]
    compiled_file = source_path(str(proof.get("original_file") or ""), source_base)
    if compiled_file != harness["file"]:
        raise AdmissionError(f"compiled source {compiled_file!r} is not {harness['file']!r}")
    attributes = proof["attributes"]
    if attributes["kind"] != "Proof":
        raise AdmissionError(f"selected harness kind {attributes['kind']!r} is not Proof")
    if attributes["should_panic"] or attributes["stubs"] or attributes["verified_stubs"]:
        raise AdmissionError("unexpected panic expectation or proof substitution")
    # Kani resolves unwind as CLI, else attribute, else default, keeping an explicit 0.
    if argv is not None:
        effective = effective_settings(argv, attributes, harness)
    else:
        if "unwind" in harness:
            effective_unwind = harness["unwind"]
        elif attributes["unwind_value"] is not None:
            effective_unwind = attributes["unwind_value"]
        else:
            effective_unwind = group["default_unwind"]
        effective = {"unwind": effective_unwind, "solver": registry["solver"]}
    return {
        "mangled_name": proof.get("mangled_name"),
        "lines": [proof.get("original_start_line"), proof.get("original_end_line")],
        "attributes": attributes,
        "source": {
            "original_file": proof.get("original_file"),
            "source_base": source_base,
            "file": compiled_file,
        },
        "effective": effective,
        "proven_by": {
            "crate_name/pretty_name/original_file/attributes": "compiled metadata",
            "file": "original_file joined onto the cargo metadata workspace root",
            "features/no_default_features/package/lib": "argv and cargo metadata",
            "target": "rustc -vV host and metadata path",
            "solver": "validated argv (the registry solver on the command line)",
            "unwind": "validated argv --unwind, else compiled attribute, "
            "else validated argv --default-unwind",
        },
    }


def decide_request(
    request: dict[str, Any],
    group: dict[str, Any],
    registry: dict[str, Any],
    log_text: str,
    invocation: dict[str, Any],
    metadata: dict[str, Any] | None,
    metadata_count: int,
    discovery_entry: dict[str, Any] | None,
    source_base: str,
    expected_argv: list[str] | None = None,
    root: str | None = None,
) -> dict[str, Any]:
    reasons: list[str] = []
    argv: list[str] | None = None
    if expected_argv is not None and root is not None:
        try:
            validate_invocation(invocation, expected_argv, registry, root, request)
            argv = expected_argv
        except AdmissionError as error:
            reasons.append(str(error))
    result: dict[str, Any] = {
        "record_version": RECORD_VERSION,
        "contract": CONTRACT,
        "group": group["id"],
        "class": group["class"],
        "gating": group.get("gating"),
        "harness": request,
        "status": "rejected",
    }
    if discovery_entry is None:
        reasons.append("harness missing from compiled discovery")
    elif discovery_entry["file"] != request["file"]:
        reasons.append("discovery file differs from the registry")
    try:
        report = accept_report(
            log_text,
            request["name"],
            invocation["exit_code"],
            request.get("unreachable_assertions"),
            registry["kani_version"],
            invocation["budget_seconds"],
        )
        result.update(report)
    except AdmissionError as error:
        reasons.append(str(error))
    if metadata_count != 1:
        reasons.append(f"expected exactly one new compiled metadata file, found {metadata_count}")
    else:
        try:
            result["compiled"] = bind_metadata(
                validate_metadata(metadata), group, request, registry, source_base, argv
            )
        except AdmissionError as error:
            reasons.append(str(error))
    result["reasons"] = reasons
    if not reasons:
        result["status"] = "accepted"
    return result


def evidence_line(result: dict[str, Any], invocation: dict[str, Any]) -> str:
    payload = {
        "harness": result["harness"]["name"],
        "group": result["group"],
        "class": result["class"],
        "gating": result.get("gating"),
        "status": result["status"],
        "exit_code": invocation.get("exit_code"),
        "wall_seconds": invocation.get("wall_seconds"),
        "cpu_seconds": invocation.get("cpu_seconds"),
        "budget_seconds": invocation.get("budget_seconds"),
        "log_sha256": invocation.get("log_sha256"),
        "reasons": result["reasons"],
    }
    return "KANI-EVIDENCE " + json.dumps(payload, separators=(",", ":"), sort_keys=True)


def log_tail(path: pathlib.Path, max_lines: int = 60, max_bytes: int = 8192) -> str:
    data = path.read_bytes()[-max_bytes:]
    return "\n".join(data.decode("utf-8", errors="replace").splitlines()[-max_lines:])


FIXED_INPUTS = (
    str(REGISTRY),
    str(SCHEMA),
    "scripts/validation/run_kani_evidence.py",
    "scripts/validation/check_kani_citations.py",
    "spec/compliance-matrix.yaml",
    "Cargo.toml",
    "Cargo.lock",
    "rust-toolchain.toml",
    "flake.lock",
    ".cargo/config.toml",
)


def input_digests(
    root: pathlib.Path, groups: list[dict[str, Any]], path_dependencies: list[str]
) -> dict[str, str]:
    """Digest the source snapshot the selection depends on (registry-derived set plus the
    workspace path dependencies that cargo metadata reported, all root-relative)."""
    inputs: dict[str, str] = {}
    for relative in FIXED_INPUTS:
        path = root / relative
        if path.is_file():
            inputs[relative] = digest_file(path)
    inputs["adapter"] = digest_file(pathlib.Path(__file__).resolve())
    directories: set[pathlib.Path] = {root / "nix" / "kani"}
    for group in groups:
        directories.add((root / group["package"]["manifest"]).parent)
    for dep in path_dependencies:
        directories.add(root / dep)
    for directory in sorted(directories):
        for source in sorted(directory.rglob("*")):
            if source.is_file() and "target" not in source.relative_to(root).parts:
                inputs[source.relative_to(root).as_posix()] = digest_file(source)
    return inputs


def input_differences(recorded: dict[str, str], current: dict[str, str]) -> str:
    changed = sorted(k for k in recorded if k in current and recorded[k] != current[k])
    missing = sorted(k for k in recorded if k not in current)
    extra = sorted(k for k in current if k not in recorded)
    if not (changed or missing or extra):
        return ""
    first = (changed + missing + extra)[0]
    return f"changed {len(changed)}, missing {len(missing)}, extra {len(extra)}; first: {first}"


def fault_result(group: dict[str, Any], harness: dict[str, Any], reason: str) -> dict[str, Any]:
    return {
        "record_version": RECORD_VERSION,
        "contract": CONTRACT,
        "group": group["id"],
        "class": group["class"],
        "gating": group.get("gating"),
        "harness": harness,
        "status": "fault",
        "reasons": [reason],
    }


def run_records(run_dir: pathlib.Path) -> dict[str, str]:
    """Digest every retained file of a run except the evaluation record itself."""
    return {
        path.relative_to(run_dir).as_posix(): digest_file(path)
        for path in sorted(run_dir.rglob("*"))
        if path.is_file() and path.relative_to(run_dir).as_posix() != "evaluation.json"
    }


def derive_outcome(
    scope: str, results: list[dict[str, Any]], run_faults: list[str], expected: int
) -> tuple[dict[str, int], bool, str]:
    counts = {
        "required_accepted": 0,
        "required_rejected": 0,
        "diagnostic_accepted": 0,
        "diagnostic_rejected": 0,
        "faults": len(run_faults),
    }
    for result in results:
        if result["status"] == "fault":
            counts["faults"] += 1
        else:
            counts[f"{result['class']}_{result['status']}"] += 1
    gate_ok = (
        scope == "full"
        and counts["faults"] == 0
        and expected > 0
        and len(results) == expected
        and counts["required_rejected"] == 0
        and counts["required_accepted"] > 0
    )
    if counts["faults"]:
        status = "fault"
    elif gate_ok:
        status = "accepted"
    else:
        status = "recorded" if scope != "full" else "rejected"
    return counts, gate_ok, status


def baseline_context_differs(
    baseline: dict[str, Any], old: dict[str, Any], result: dict[str, Any], group: dict[str, Any]
) -> bool:
    tools_differ = any(
        baseline.get("tools", {}).get(k) != result.get("_tools", {}).get(k)
        for k in ("reported_version", "cbmc_version")
    )
    effective_differ = old.get("compiled", {}).get("effective") != result.get("compiled", {}).get(
        "effective"
    )
    domain_differ = old.get("harness", {}).get("domain") != result["harness"].get("domain")
    old_group = baseline.get("group_context", {}).get(group["id"], {})
    group_differ = any(old_group.get(k) != group.get(k) for k in ("cfg", "features"))
    return tools_differ or effective_differ or domain_differ or group_differ


def baseline_comparison(
    baseline: dict[str, Any] | None,
    baseline_sha256: str | None,
    record: dict[str, Any],
    registry: dict[str, Any],
) -> dict[str, Any]:
    """Report-only property-set comparison against an earlier evaluation (design D4)."""
    if baseline is None:
        return {"baseline": "none", "requests": []}
    groups = {g["id"]: g for g in executable_groups(registry)}
    previous = {(r["group"], r["harness"]["name"]): r for r in baseline.get("results", [])}
    entries = []
    for result in record["results"]:
        key = (result["group"], result["harness"]["name"])
        old = previous.get(key)
        entry: dict[str, Any] = {"group": key[0], "harness": key[1], "changes": []}
        if old is None:
            entry["context"] = "no baseline entry"
        elif baseline_context_differs(
            baseline, old, {**result, "_tools": record["tools"]}, groups[key[0]]
        ):
            entry["context"] = "new context"
        else:
            entry["context"] = "same"
            before = {p["id"]: p for p in old.get("properties", [])}
            after = {p["id"]: p for p in result.get("properties", [])}
            for pid in sorted(set(before) - set(after)):
                entry["changes"].append({"kind": "removed", "id": pid})
            for pid in sorted(set(after) - set(before)):
                entry["changes"].append({"kind": "added", "id": pid})
            for pid in sorted(set(before) & set(after)):
                if before[pid]["status"] != after[pid]["status"]:
                    entry["changes"].append(
                        {
                            "kind": "status",
                            "id": pid,
                            "before": before[pid]["status"],
                            "after": after[pid]["status"],
                        }
                    )
                if before[pid].get("description") != after[pid].get("description"):
                    entry["changes"].append({"kind": "description", "id": pid})
        entries.append(entry)
    return {"baseline_sha256": baseline_sha256, "requests": entries}


# ----------------------------------------------------------------------------- run


def selected_groups(
    registry: dict[str, Any], scope: str, wanted: list[str] | None
) -> list[dict[str, Any]]:
    groups = executable_groups(registry)
    if scope == "full":
        return groups
    if scope == "diagnostic":
        return [g for g in groups if g["class"] == "diagnostic"]
    chosen = [g for g in groups if g["id"] in (wanted or [])]
    if not wanted or len(chosen) != len(set(wanted)):
        raise AdmissionError("partial scope requires existing group ids")
    return chosen


def run(args: argparse.Namespace) -> int:
    root = args.root.resolve()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    gate = output / "gate.json"
    gate.unlink(missing_ok=True)
    registry_path = (root / REGISTRY) if args.registry is None else args.registry.resolve()
    schema_path = root / SCHEMA
    registry = load_registry(root, registry_path, schema_path)
    if (platform.system(), platform.machine()) != ("Linux", "x86_64"):
        raise AdmissionError("the admitted selection requires x86_64 Linux")
    env, environment_record = controlled_environment(dict(os.environ))
    tools = resolve_tools(env, registry)
    groups = selected_groups(registry, args.scope, args.groups)
    run_dir = pathlib.Path(tempfile.mkdtemp(prefix="run-", dir=output))
    shutil.copy2(registry_path, run_dir / "policy.json")
    shutil.copy2(schema_path, run_dir / "schema.json")
    write_json_new(run_dir / "tools.json", tools)
    config_record = check_cargo_config(tools["cargo"], root, env, registry, root)
    validate_environment(environment_record, config_record, registry, str(root))
    write_json_new(
        run_dir / "environment.json", {**environment_record, "cargo_config": config_record}
    )
    baseline: dict[str, Any] | None = None
    baseline_sha256: str | None = None
    if args.baseline is not None:
        baseline = load_json(args.baseline)
        baseline_sha256 = digest_file(args.baseline)
    build = tempfile.TemporaryDirectory(prefix="aegaeon-kani-evidence-")
    build_root = pathlib.Path(build.name)
    record: dict[str, Any] = {
        "record_version": RECORD_VERSION,
        "contract": CONTRACT,
        "scope": args.scope,
        "groups_selected": [g["id"] for g in groups],
        "started_at": now(),
        "registry_sha256": digest_file(registry_path),
        "schema_sha256": digest_file(schema_path),
        "root": str(root),
        "tools": tools,
        "environment": environment_record,
        "group_context": {g["id"]: {k: g.get(k) for k in ("cfg", "features")} for g in groups},
        "baseline": "none"
        if baseline is None
        else {"path": str(args.baseline), "sha256": baseline_sha256},
        "results": [],
        "faults": [],
        "status": "incomplete",
    }
    # Preflight: cargo metadata for every selected group, then the input snapshot the whole
    # run is bound to (re-taken after the last request).
    metadata_by_group: dict[str, dict[str, Any]] = {}
    group_faults: dict[str, str] = {}
    for group in groups:
        group_dir = run_dir / "groups" / group["id"]
        group_dir.mkdir(parents=True)
        manifest = root / group["package"]["manifest"]
        try:
            meta = cargo_metadata(tools["cargo"], manifest, group, env, registry["target"], root)
            write_json_new(group_dir / "cargo-metadata.json", meta)
            metadata_by_group[group["id"]] = meta
        except AdmissionError as error:
            group_faults[group["id"]] = str(error)
    path_dependencies = sorted(
        {dep for meta in metadata_by_group.values() for dep in meta["path_dependencies"]}
    )
    record["inputs"] = input_digests(root, groups, path_dependencies)
    index = 0
    for group in groups:
        group_dir = run_dir / "groups" / group["id"]
        manifest = root / group["package"]["manifest"]
        try:
            if group["id"] in group_faults:
                raise AdmissionError(group_faults[group["id"]])
            meta = metadata_by_group[group["id"]]
            discovery = discover(
                group,
                manifest,
                tools["cargo_kani"]["path"],
                registry,
                env,
                group_dir,
                build_root / f"discovery-{group['id']}",
                root,
                meta["source_base"],
            )
            write_json_new(group_dir / "discovery.json", discovery)
        except AdmissionError as error:
            # A runner/preflight fault is typed: it blocks every scope and never counts as
            # a mathematical rejection of the group's requests.
            write_json_new(group_dir / "fault.json", {"kind": "preflight", "reason": str(error)})
            for harness in group["harnesses"]:
                index += 1
                result = fault_result(group, harness, f"group preflight failed: {error}")
                request_dir = run_dir / "requests" / f"{index:02d}"
                request_dir.mkdir(parents=True)
                write_json_new(request_dir / "result.json", result)
                record["results"].append(
                    {**result, "request_dir": str(request_dir.relative_to(run_dir))}
                )
                print(f"{harness['name']}: fault", flush=True)
                print(evidence_line(result, {}), flush=True)
            continue
        target = build_root / f"group-{group['id']}"
        for harness in group["harnesses"]:
            index += 1
            request_dir = run_dir / "requests" / f"{index:02d}"
            request_dir.mkdir(parents=True)
            before = metadata_files(target)
            approved = expected_invocation(tools, registry, group, harness, str(root))
            command = approved[3:]  # run_process adds the timeout prefix back
            invocation = run_process(
                command,
                root,
                {**env, "CARGO_TARGET_DIR": str(target)},
                request_dir / "output.log",
                registry["budgets"]["timeout_seconds"],
                registry["budgets"]["memory_limit_bytes"],
            )
            new_files = sorted(metadata_files(target) - before)
            metadata = None
            if len(new_files) == 1:
                shutil.copy2(new_files[0], request_dir / "kani-metadata.json")
                metadata = read_metadata(request_dir / "kani-metadata.json")
            invocation["harness"] = harness["name"]
            invocation["new_metadata_files"] = len(new_files)
            write_json_new(request_dir / "command.json", invocation)
            result = decide_request(
                harness,
                group,
                registry,
                (request_dir / "output.log").read_text(errors="replace"),
                invocation,
                metadata,
                len(new_files),
                discovery["harnesses"].get(harness["name"]),
                meta["source_base"],
                approved,
                str(root),
            )
            result["command_sha256"] = digest_file(request_dir / "command.json")
            result["log_sha256"] = invocation["log_sha256"]
            if (request_dir / "kani-metadata.json").is_file():
                result["metadata_sha256"] = digest_file(request_dir / "kani-metadata.json")
            write_json_new(request_dir / "result.json", result)
            record["results"].append(
                {**result, "request_dir": str(request_dir.relative_to(run_dir))}
            )
            print(f"{harness['name']}: {result['status']}", flush=True)
            print(evidence_line(result, invocation), flush=True)
            if result["status"] != "accepted":
                print(f"--- last lines of {request_dir.name}/output.log ---", flush=True)
                print(log_tail(request_dir / "output.log"), flush=True)
                print("--- end ---", flush=True)
            (run_dir / "evaluation.json").write_text(
                json.dumps(record, indent=2, sort_keys=True) + "\n"
            )
    inputs_after = input_digests(root, groups, path_dependencies)
    difference = input_differences(record["inputs"], inputs_after)
    if difference:
        record["inputs_after"] = inputs_after
        record["faults"].append(f"inputs changed during the run: {difference}")
    expected = sum(len(g["harnesses"]) for g in groups)
    counts, gate_ok, status = derive_outcome(
        args.scope, record["results"], record["faults"], expected
    )
    record["counts"] = counts
    record["status"] = status
    write_json_new(
        run_dir / "unreachable_diff.json",
        baseline_comparison(baseline, baseline_sha256, record, registry),
    )
    record["records"] = run_records(run_dir)
    record["completed_at"] = now()
    (run_dir / "evaluation.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    for fault in record["faults"]:
        print(f"KANI-ADMISSION {json.dumps({'event': 'fault', 'reason': fault})}", flush=True)
    if not record["faults"]:
        # Self-check: the gate is written only if the retained records reconstruct to the
        # same outcome through the replay path (a faulted run never writes a gate).
        reconstruction = reconstruct_run(run_dir, registry, registry_path, schema_path, root)
        if reconstruction["gate_ok"] != gate_ok or reconstruction["status"] != status:
            raise AdmissionError("self-check: the retained records do not reconstruct this outcome")
    if gate_ok:
        gate.write_text(
            json.dumps(
                {
                    "record_version": RECORD_VERSION,
                    "contract": CONTRACT,
                    "run": run_dir.name,
                    "evaluation": str((run_dir / "evaluation.json").relative_to(output)),
                    "evaluation_sha256": digest_file(run_dir / "evaluation.json"),
                    "registry_sha256": record["registry_sha256"],
                },
                indent=2,
            )
            + "\n"
        )
    print(
        "KANI-ADMISSION "
        + json.dumps(
            {
                "event": "summary",
                "scope": args.scope,
                "counts": counts,
                "gate": gate_ok,
                "status": record["status"],
            },
            separators=(",", ":"),
            sort_keys=True,
        ),
        flush=True,
    )
    print(f"Evaluation: {run_dir / 'evaluation.json'}")
    build.cleanup()
    if status == "fault":
        return 1
    if args.scope == "full":
        return 0 if gate_ok else 1
    return 0


# ----------------------------------------------------------------------------- replay


GROUP_RECORDS = (
    "cargo-metadata.json",
    "discovery.json",
    "discovery.kani-metadata.json",
    "discovery.log",
)


def first_difference(stored: dict[str, Any], expected: dict[str, Any]) -> str:
    for key in sorted(set(stored) | set(expected)):
        if stored.get(key) != expected.get(key):
            return key
    return "?"


def check_anchors(
    run_dir: pathlib.Path,
    evaluation: dict[str, Any],
    registry_path: pathlib.Path,
    schema_path: pathlib.Path,
) -> None:
    if evaluation.get("contract") != CONTRACT or evaluation.get("record_version") != RECORD_VERSION:
        raise AdmissionError("evaluation record is not of this contract")
    for name in ("policy.json", "schema.json"):
        if not (run_dir / name).is_file():
            raise AdmissionError(f"record {name} missing")
    registry_sha256 = digest_file(registry_path)
    if evaluation.get("registry_sha256") != registry_sha256:
        raise AdmissionError("evaluation was made under a different registry")
    if digest_file(run_dir / "policy.json") != registry_sha256:
        raise AdmissionError("retained policy copy differs from the caller's registry")
    schema_sha256 = digest_file(schema_path)
    if evaluation.get("schema_sha256") != schema_sha256:
        raise AdmissionError("evaluation was made under a different schema")
    if digest_file(run_dir / "schema.json") != schema_sha256:
        raise AdmissionError("retained schema copy differs from the caller's schema")
    inputs = evaluation.get("inputs") or {}
    if inputs.get("adapter") != digest_file(pathlib.Path(__file__).resolve()):
        raise AdmissionError(
            "evaluation was made by a different adapter (runner) than the caller's"
        )
    if not isinstance(evaluation.get("root"), str) or not evaluation["root"]:
        raise AdmissionError("evaluation does not record the checkout root")


def check_execution_records(
    run_dir: pathlib.Path, evaluation: dict[str, Any], registry: dict[str, Any]
) -> dict[str, Any]:
    """Tool identity and environment records must be typed, policy-consistent and equal to
    their summary copies; they are provenance of what ran, not proof of installed binaries."""
    tools = validate_tools(load_json(run_dir / "tools.json"), registry)
    if evaluation.get("tools") != tools:
        raise AdmissionError("tool identity summary differs from the retained tools.json")
    environment = load_json(run_dir / "environment.json")
    if not isinstance(environment, dict):
        raise AdmissionError("environment record is not an object")
    summary = evaluation.get("environment")
    if summary != {k: environment.get(k) for k in ("kept", "dropped", "target_variables")}:
        raise AdmissionError("environment summary differs from the retained environment.json")
    validate_environment(environment, environment.get("cargo_config"), registry, evaluation["root"])
    return tools


def check_records(run_dir: pathlib.Path, evaluation: dict[str, Any]) -> dict[str, str]:
    recorded = evaluation.get("records") or {}
    present = run_records(run_dir)
    for relative, sha in recorded.items():
        if present.get(relative) != sha:
            raise AdmissionError(f"record {relative} missing or changed")
    for relative in present:
        if relative not in recorded:
            raise AdmissionError(f"unexpected record {relative} in the run")
    for name in ("policy.json", "schema.json", "tools.json", "environment.json"):
        if name not in recorded:
            raise AdmissionError(f"record {name} missing")
    return recorded


def reconstruct_discovery(
    run_dir: pathlib.Path,
    group: dict[str, Any],
    recorded: dict[str, str],
    registry: dict[str, Any],
    tools: dict[str, Any],
    root: str,
) -> tuple[dict[str, dict[str, Any]], str]:
    """Re-derive a group's discovery from its raw metadata and check the stored summary."""
    group_dir = run_dir / "groups" / group["id"]
    label = f"groups/{group['id']}"
    cargo_meta = load_json(group_dir / "cargo-metadata.json")
    discovery = load_json(group_dir / "discovery.json")
    try:
        validate_invocation(
            discovery, expected_invocation(tools, registry, group, None, root), registry, root, None
        )
    except AdmissionError as error:
        raise AdmissionError(f"{label}: discovery {error}") from error
    if discovery.get("exit_code") != 0:
        raise AdmissionError(
            f"{label}: discovery exit code {discovery.get('exit_code')!r} is not success"
        )
    raw = f"{label}/discovery.kani-metadata.json"
    if discovery.get("metadata_sha256") != recorded.get(raw):
        raise AdmissionError(f"{label}: discovery summary does not bind the raw metadata")
    source_base = cargo_meta.get("source_base")
    if not isinstance(source_base, str) or discovery.get("source_base") != source_base:
        raise AdmissionError(f"{label}: discovery summary does not name the cargo workspace base")
    try:
        derived = derive_discovery(read_metadata(run_dir / raw), group, source_base)
    except AdmissionError as error:
        raise AdmissionError(f"{label}: discovery reconstruction failed: {error}") from error
    if discovery.get("harnesses") != derived:
        raise AdmissionError(f"{label}: discovery summary disagrees with the reconstruction")
    return derived, source_base


def reconstruct_request(
    run_dir: pathlib.Path,
    index: int,
    group: dict[str, Any],
    harness: dict[str, Any],
    registry: dict[str, Any],
    recorded: dict[str, str],
    discovery: tuple[dict[str, dict[str, Any]], str] | None,
    registry_tools: dict[str, Any],
    root: str,
) -> dict[str, Any]:
    request = f"requests/{index:02d}"
    request_dir = run_dir / request
    group_dir = run_dir / "groups" / group["id"]
    if (group_dir / "fault.json").is_file():
        fault = load_json(group_dir / "fault.json")
        if (request_dir / "command.json").exists():
            raise AdmissionError(f"{request}: execution record present for a faulted group")
        return fault_result(group, harness, f"group preflight failed: {fault['reason']}")
    for name in ("command.json", "output.log"):
        if f"{request}/{name}" not in recorded:
            raise AdmissionError(f"record {request}/{name} missing")
    invocation = load_json(request_dir / "command.json")
    if not isinstance(invocation, dict):
        raise AdmissionError(f"{request}: execution record is not an object")
    if invocation.get("log_sha256") != recorded[f"{request}/output.log"]:
        raise AdmissionError(f"{request}: execution record does not bind its log")
    metadata_path = request_dir / "kani-metadata.json"
    if (
        invocation.get("new_metadata_files") == 1
        and f"{request}/kani-metadata.json" not in recorded
    ):
        raise AdmissionError(f"record {request}/kani-metadata.json missing")
    metadata = read_metadata(metadata_path) if metadata_path.is_file() else None
    if discovery is None:
        raise AdmissionError(f"{request}: no reconstructed discovery for the group")
    harnesses, source_base = discovery
    return decide_request(
        harness,
        group,
        registry,
        (request_dir / "output.log").read_text(errors="replace"),
        invocation,
        metadata,
        int(invocation.get("new_metadata_files", -1)),
        harnesses.get(harness["name"]),
        source_base,
        expected_invocation(registry_tools, registry, group, harness, root),
        root,
    )


def reconstruct_run(
    run_dir: pathlib.Path,
    registry: dict[str, Any],
    registry_path: pathlib.Path,
    schema_path: pathlib.Path,
    root: pathlib.Path,
) -> dict[str, Any]:
    """Re-derive every decision of a retained run from its raw records under the caller's
    registry, schema, adapter and source tree. Any disagreement with the stored summary,
    any missing, extra, changed or malformed record and any fault reject."""
    try:
        return reconstruct_run_records(run_dir, registry, registry_path, schema_path, root)
    except (KeyError, TypeError, ValueError, OSError) as error:
        raise AdmissionError(f"malformed run records: {error!r}") from error


def reconstruct_run_records(
    run_dir: pathlib.Path,
    registry: dict[str, Any],
    registry_path: pathlib.Path,
    schema_path: pathlib.Path,
    root: pathlib.Path,
) -> dict[str, Any]:
    evaluation = load_json(run_dir / "evaluation.json")
    check_anchors(run_dir, evaluation, registry_path, schema_path)
    recorded = check_records(run_dir, evaluation)
    tools = check_execution_records(run_dir, evaluation, registry)
    root_recorded = str(evaluation["root"])
    scope = evaluation.get("scope")
    groups = selected_groups(registry, scope, evaluation.get("groups_selected"))
    if [g["id"] for g in groups] != list(evaluation.get("groups_selected") or []):
        raise AdmissionError("selected groups do not match the caller's registry")
    path_dependencies: set[str] = set()
    for group in groups:
        faulted = f"groups/{group['id']}/fault.json" in recorded
        for name in GROUP_RECORDS:
            if f"groups/{group['id']}/{name}" not in recorded and not faulted:
                raise AdmissionError(f"record groups/{group['id']}/{name} missing")
        meta_path = run_dir / "groups" / group["id"] / "cargo-metadata.json"
        if meta_path.is_file():
            path_dependencies.update(load_json(meta_path)["path_dependencies"])
    inputs = evaluation.get("inputs") or {}
    difference = input_differences(inputs, input_digests(root, groups, sorted(path_dependencies)))
    if difference:
        raise AdmissionError(f"source inputs differ from the recorded snapshot ({difference})")
    run_faults = list(evaluation.get("faults") or [])
    if "inputs_after" in evaluation and not run_faults:
        raise AdmissionError("post-run input snapshot recorded without a fault")
    summaries = evaluation.get("results") or []
    expected_requests = [(g, h) for g in groups for h in g["harnesses"]]
    if len(summaries) != len(expected_requests):
        raise AdmissionError("result set does not equal the selected groups' harnesses")
    discoveries: dict[str, tuple[dict[str, dict[str, Any]], str]] = {}
    for group in groups:
        if f"groups/{group['id']}/fault.json" not in recorded:
            discoveries[group["id"]] = reconstruct_discovery(
                run_dir, group, recorded, registry, tools, root_recorded
            )
    derived_results: list[dict[str, Any]] = []
    statuses: dict[tuple[str, str], str] = {}
    for index, (group, harness) in enumerate(expected_requests, 1):
        request = f"requests/{index:02d}"
        if f"{request}/result.json" not in recorded:
            raise AdmissionError(f"record {request}/result.json missing")
        stored = load_json(run_dir / request / "result.json")
        derived = reconstruct_request(
            run_dir,
            index,
            group,
            harness,
            registry,
            recorded,
            discoveries.get(group["id"]),
            tools,
            root_recorded,
        )
        expected = dict(derived)
        if derived["status"] != "fault":
            expected["command_sha256"] = recorded[f"{request}/command.json"]
            expected["log_sha256"] = recorded[f"{request}/output.log"]
            if f"{request}/kani-metadata.json" in recorded:
                expected["metadata_sha256"] = recorded[f"{request}/kani-metadata.json"]
        if stored != expected:
            key = first_difference(stored, expected)
            raise AdmissionError(
                f"{request}: stored result disagrees with the reconstruction on {key} "
                f"(stored {stored.get(key)!r}, reconstructed {expected.get(key)!r})"
            )
        if summaries[index - 1] != {**expected, "request_dir": request}:
            key = first_difference(summaries[index - 1], {**expected, "request_dir": request})
            raise AdmissionError(f"{request}: summary disagrees with the reconstruction on {key}")
        derived_results.append(derived)
        statuses[(group["id"], harness["name"])] = derived["status"]
    counts, gate_ok, status = derive_outcome(
        scope, derived_results, run_faults, len(expected_requests)
    )
    if evaluation.get("counts") != counts or evaluation.get("status") != status:
        raise AdmissionError("summary counts/status disagree with the reconstruction")
    return {
        "scope": scope,
        "gate_ok": gate_ok,
        "status": status,
        "counts": counts,
        "faults": run_faults,
        "results": statuses,
        "inputs": inputs,
        "registry_sha256": evaluation["registry_sha256"],
        "evaluation_sha256": digest_file(run_dir / "evaluation.json"),
    }


def check_gate(run_dir: pathlib.Path, reconstruction: dict[str, Any]) -> None:
    gate = run_dir.parent / "gate.json"
    if reconstruction["gate_ok"]:
        if not gate.is_file():
            raise AdmissionError("gate.json missing for an accepted full-scope run")
        gate_record = load_json(gate)
        if (
            gate_record.get("run") != run_dir.name
            or gate_record.get("evaluation_sha256") != reconstruction["evaluation_sha256"]
            or gate_record.get("registry_sha256") != reconstruction["registry_sha256"]
        ):
            raise AdmissionError("gate.json does not bind this evaluation")
    elif gate.is_file() and load_json(gate).get("run") == run_dir.name:
        raise AdmissionError("gate.json exists although the run reconstructs to no gate")


def verify_records(
    run_dir: pathlib.Path,
    registry_path: pathlib.Path,
    schema_path: pathlib.Path,
    root: pathlib.Path = ROOT,
) -> int:
    registry = load_registry(root, registry_path, schema_path)
    reconstruction = reconstruct_run(run_dir, registry, registry_path, schema_path, root)
    check_gate(run_dir, reconstruction)
    if reconstruction["status"] == "fault":
        details = "; ".join(reconstruction["faults"] or ["group preflight"])
        raise AdmissionError(f"run has {reconstruction['counts']['faults']} fault(s): {details}")
    if reconstruction["scope"] == "full" and not reconstruction["gate_ok"]:
        raise AdmissionError("full-scope run reconstructs to no admitted gate (status rejected)")
    print(
        f"[OK] {len(reconstruction['results'])} Kani requests replay "
        f"({reconstruction['scope']} scope, status {reconstruction['status']})"
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=pathlib.Path, default=ROOT, help="repository root")
    parser.add_argument("--output", type=pathlib.Path, default=None)
    parser.add_argument("--registry", type=pathlib.Path, default=None)
    parser.add_argument("--scope", choices=("full", "diagnostic", "partial"), default="full")
    parser.add_argument("--groups", nargs="*", default=None, help="group ids for --scope partial")
    parser.add_argument("--verify-records", type=pathlib.Path, default=None, metavar="RUN_DIR")
    parser.add_argument(
        "--baseline",
        type=pathlib.Path,
        default=None,
        metavar="EVALUATION_JSON",
        help="earlier evaluation.json to compare property sets against (report-only)",
    )
    args = parser.parse_args()
    root = args.root.resolve()
    if args.output is None:
        args.output = root / "artifacts/kani-evidence"
    try:
        if args.verify_records is not None:
            registry_path = (root / REGISTRY) if args.registry is None else args.registry.resolve()
            return verify_records(args.verify_records.resolve(), registry_path, root / SCHEMA, root)
        return run(args)
    except AdmissionError as error:
        print(f"KANI-ADMISSION {json.dumps({'event': 'fault', 'reason': str(error)})}", flush=True)
        print(f"[FAIL] Kani admission: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
