#!/usr/bin/env python3
"""Check root npm development dependencies in a disposable source snapshot."""

from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
from pathlib import Path, PurePosixPath
from typing import Any

TIMEOUT = 300
NPM_VERSION = "10.9.7"
NPM_URL = "https://registry.npmjs.org/npm/-/npm-10.9.7.tgz"
NPM_INTEGRITY = (
    "17u9+Ssv6as3iua2l6abTv1H4TtQDhle/Qn+XJ4TjKR4SzIjk1Ox3SZXRVBUW48KojLttHNQUk/U00m7sh1OGw=="
)
MAX_ARCHIVE_BYTES = 16 * 1024 * 1024
MAX_UNPACKED_BYTES = 64 * 1024 * 1024
MAX_MEMBERS = 5000
REVIEWED_POSTINSTALL = "c458e147d052603e5b1649fdae671b54201e47c5bf91b1d452bcb0483c9f6c75"
INSTALL_HOOKS = {"preinstall", "install", "postinstall"}
TESTS = (
    "tests/verified_core_wasm/root_strict_types_policy_test.ts",
    "tests/verified_core_wasm/strict_types_policy_test.ts",
    "tests/verified_core_wasm/workflow_inventory_policy_test.ts",
)
CONSUMERS = (
    "scripts/check-strict-types.ts",
    "scripts/check-workflow-inventory.ts",
    "scripts/sdk/check_sdk_strict_types.ts",
    "scripts/sdk/tools-src/check-strict-types.ts",
    *TESTS,
)
EXPECTED_SCRIPTS = {
    "lint:ts": "eslint --max-warnings 0 " + " ".join(CONSUMERS),
    "typecheck:ts": "tsc --project tsconfig.json --pretty false --noEmit",
    "audit:strict-types": "node --experimental-strip-types scripts/check-strict-types.ts",
}
INCLUDE = ["--include=dev", "--include=optional", "--include=peer"]


def require(condition: bool, message: str) -> None:  # noqa: FBT001 - predicate guard
    if not condition:
        raise ValueError(message)


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def verify_archive(raw: bytes) -> None:
    require(len(raw) <= MAX_ARCHIVE_BYTES, "npm archive exceeds size bound")
    actual = base64.b64encode(hashlib.sha512(raw).digest()).decode()
    require(actual == NPM_INTEGRITY, "npm archive integrity mismatch")


def extract_archive(raw: bytes, destination: Path) -> int:
    seen: set[str] = set()
    total = 0
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
        for member in archive:
            path = PurePosixPath(member.name)
            require(bool(path.parts) and path.parts[0] == "package", "Unexpected npm archive root")
            require(
                str(path) == member.name.rstrip("/") and ".." not in path.parts,
                "Noncanonical npm archive path",
            )
            require(not any(ord(c) < 32 for c in member.name), "Control character in archive path")
            require(member.isfile() or member.isdir(), "Archive links/devices are not permitted")
            require(
                str(path) not in seen and len(seen) < MAX_MEMBERS,
                "Duplicate or excessive archive members",
            )
            seen.add(str(path))
            require(member.size >= 0, "Negative archive member size")
            total += member.size
            require(0 <= total <= MAX_UNPACKED_BYTES, "Archive unpacked size exceeds bound")
            target = destination / str(path)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                write_member(archive, member, target)
    require(bool(seen), "Empty npm archive")
    return len(seen)


def write_member(archive: tarfile.TarFile, member: tarfile.TarInfo, target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    stream = archive.extractfile(member)
    require(stream is not None, "Missing npm archive member contents")
    if stream is None:
        raise ValueError("Missing archive stream")
    with stream:
        raw = stream.read(MAX_UNPACKED_BYTES + 1)
    require(len(raw) == member.size, "Truncated archive member")
    with target.open("xb") as destination:
        destination.write(raw)
    target.chmod(member.mode & 0o777)


def bootstrap_npm(work: Path, output: Path) -> tuple[Path, dict[str, Any]]:
    with urllib.request.urlopen(NPM_URL, timeout=30) as response:
        raw = response.read(MAX_ARCHIVE_BYTES + 1)
    (output / "npm-10.9.7.tgz").write_bytes(raw)
    verify_archive(raw)
    directory = work / "npm-tool"
    directory.mkdir()
    count = extract_archive(raw, directory)
    package_file = directory / "package/package.json"
    package = mapping(json.loads(package_file.read_text()), "npm bootstrap package")
    require(package.get("version") == NPM_VERSION, "Wrong bootstrapped npm version")
    require(
        package.get("engines") == {"node": "^18.17.0 || >=20.5.0"},
        "Unreviewed npm engine requirements",
    )
    return directory / "package/bin/npm-cli.js", {
        "url": NPM_URL,
        "version": NPM_VERSION,
        "integrity": "sha512-" + NPM_INTEGRITY,
        "archive_sha256": sha(raw),
        "member_count": count,
        "package_sha256": sha(package_file.read_bytes()),
        "engines": package["engines"],
    }


def raw_link(path: Path) -> str:
    # Path.readlink() normalizes aliases that must remain distinct source inputs.
    return os.readlink(path)  # noqa: PTH115 - preserve exact target text


def identity(path: Path) -> dict[str, str | int]:
    mode = path.lstat().st_mode
    raw = os.fsencode(raw_link(path)) if path.is_symlink() else path.read_bytes()
    return {"sha256": sha(raw), "mode": mode, "kind": "symlink" if path.is_symlink() else "file"}


def tracked_inputs(root: Path) -> list[str]:
    actual = subprocess.check_output(
        ["git", "-C", str(root), "rev-parse", "--show-toplevel"], text=True
    ).strip()
    require(Path(actual).resolve() == root.resolve(), "Source must be a repository worktree root")
    raw = subprocess.check_output(["git", "-C", str(root), "ls-files", "--cached", "-z"])
    paths = raw.decode().removesuffix("\0").split("\0")
    require(bool(paths) and len(paths) == len(set(paths)), "Empty or duplicated tracked input list")
    for value in paths:
        path = PurePosixPath(value)
        require(
            str(path) == value and not path.is_absolute() and ".." not in path.parts,
            "Invalid tracked path",
        )
        require(
            "node_modules" not in path.parts, "Tracked dependency installation is not supported"
        )
    return paths


def snapshot(root: Path, destination: Path) -> dict[str, dict[str, str | int]]:
    inputs = {}
    for relative in tracked_inputs(root):
        source = root / relative
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        inputs[relative] = identity(source)
        if source.is_symlink():
            # This existing Kani launcher is outside the npm consumer profile.
            require(
                relative == "crates/kani-harness/kani"
                and raw_link(source) == "result/bin/cargo-kani",
                f"Unreviewed source symlink: {relative}",
            )
            target.symlink_to(raw_link(source))
        else:
            require(source.is_file(), f"Unsupported source input: {relative}")
            shutil.copy2(source, target)
        require(identity(target) == inputs[relative], f"Snapshot changed input: {relative}")
    return inputs


def unchanged(root: Path, inputs: dict[str, dict[str, str | int]]) -> None:
    require(
        all(identity(root / path) == value for path, value in inputs.items()),
        "Source or lock changed during validation",
    )


def package_contract(source: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    require(not (source / ".npmrc").exists(), "Project npm configuration requires explicit review")
    package = mapping(json.loads((source / "package.json").read_text()), "package manifest")
    lock = mapping(json.loads((source / "package-lock.json").read_text()), "lock manifest")
    scripts = mapping(package.get("scripts"), "package scripts")
    require(package.get("private") is True, "Root development package must remain private")
    for name, command in EXPECTED_SCRIPTS.items():
        require(
            scripts.get(name) == command,
            f"Unreviewed or empty consumer script: {name}",
        )
    lifecycle_contract(package)
    require(
        not package.get("dependencies"),
        "Production dependencies require a reviewed consumer profile",
    )
    require(
        bool(mapping(package.get("devDependencies"), "development dependencies")),
        "Development dependency set is empty",
    )
    require(
        lock.get("lockfileVersion") == 3 and isinstance(lock.get("packages"), dict),
        "Unsupported lockfile format",
    )
    packages = lock["packages"]
    require("" in packages and len(packages) > 1, "Empty locked dependency graph")
    for path, entry in packages.items():
        if path:
            locked_entry(path, mapping(entry, "locked package"))
    return package, lock


def lifecycle_contract(package: dict[str, Any]) -> None:
    scripts = mapping(package.get("scripts"), "package scripts")
    require(all(isinstance(value, str) for value in scripts.values()), "Malformed script command")
    lifecycle = {
        name
        for name in scripts
        if name.startswith(("pre", "post")) or name in {"install", "prepare", "dependencies"}
    }
    require(lifecycle == {"postinstall"}, "Unreviewed root lifecycle hooks")
    require(
        sha(scripts["postinstall"].encode()) == REVIEWED_POSTINSTALL,
        "Root postinstall differs from reviewed informational message",
    )


def locked_entry(path: str, entry: dict[str, Any]) -> None:
    parts = PurePosixPath(path).parts
    require(
        path.startswith("node_modules/") and ".." not in parts and str(PurePosixPath(path)) == path,
        f"Unsupported locked path: {path}",
    )
    require(not entry.get("link"), "Linked dependencies require explicit review")
    require(
        not entry.get("hasInstallScript"), "Dependency lifecycle scripts require explicit review"
    )
    require(isinstance(entry.get("version"), str), f"Missing locked version: {path}")
    require(
        str(entry.get("resolved", "")).startswith("https://registry.npmjs.org/"),
        "Unreviewed package registry",
    )
    require(
        bool(re.fullmatch(r"sha(?:512|256|1)-[A-Za-z0-9+/=]+", str(entry.get("integrity", "")))),
        "Missing or unknown package integrity",
    )


def environment(work: Path, node: str) -> dict[str, str]:
    env = {
        key: os.environ[key]
        for key in ("HOME", "PATH", "LANG", "LC_ALL", "SSL_CERT_FILE", "NIX_SSL_CERT_FILE")
        if key in os.environ
    }
    env["PATH"] = str(Path(node).parent) + os.pathsep + env.get("PATH", "")
    for name in ("user", "global"):
        (work / f"{name}.npmrc").write_text("")
    (work / "tmp").mkdir()
    env.update(
        {
            "CI": "true",
            "NODE_ENV": "development",
            "TMPDIR": str(work / "tmp"),
            "NPM_CONFIG_CACHE": str(work / "npm-cache"),
            "NPM_CONFIG_USERCONFIG": str(work / "user.npmrc"),
            "NPM_CONFIG_GLOBALCONFIG": str(work / "global.npmrc"),
            "NPM_CONFIG_REGISTRY": "https://registry.npmjs.org/",
            "NPM_CONFIG_UPDATE_NOTIFIER": "false",
        }
    )
    return env


class Commands:
    def __init__(self, output: Path, env: dict[str, str]) -> None:
        self.output = output
        self.env = env
        self.records: list[dict[str, Any]] = []

    def run(self, name: str, argv: list[str], cwd: Path) -> str:
        record: dict[str, Any] = {
            "name": name,
            "argv": argv,
            "stdout": name + ".stdout",
            "stderr": name + ".stderr",
        }
        self.records.append(record)
        started = time.monotonic()
        try:
            result = subprocess.run(
                argv, cwd=cwd, env=self.env, capture_output=True, timeout=TIMEOUT, check=False
            )
            record.update(exit=result.returncode, seconds=time.monotonic() - started)
            (self.output / record["stdout"]).write_bytes(result.stdout)
            (self.output / record["stderr"]).write_bytes(result.stderr)
            require(result.returncode == 0, f"{name} failed with exit {result.returncode}")
        except (OSError, subprocess.TimeoutExpired) as error:
            record.update(error=str(error), seconds=time.monotonic() - started)
            if isinstance(error, subprocess.TimeoutExpired):
                (self.output / record["stdout"]).write_bytes(error.stdout or b"")
                (self.output / record["stderr"]).write_bytes(error.stderr or b"")
            raise
        else:
            return result.stdout.decode()
        finally:
            (self.output / "commands.json").write_text(json.dumps(self.records, indent=2) + "\n")


def tool_identity(
    commands: Commands, source: Path, tools: dict[str, str], package: dict[str, Any]
) -> dict[str, Any]:
    node = commands.run("node-version", [tools["node"], "--version"], source).strip()
    npm = commands.run("npm-version", [tools["node"], tools["npm"], "--version"], source).strip()
    require(node.startswith("v24."), f"Expected pinned Node 24, got {node}")
    require(
        package.get("packageManager") == f"npm@{npm}",
        "packageManager and actual npm version differ",
    )
    paths = {**tools, "python": sys.executable}
    stores = set()
    for name, executable in paths.items():
        if name == "npm":
            continue  # npm is the integrity-verified archive; Node supplies its runtime closure.
        resolved = Path(executable).resolve()
        require(resolved.parts[1:3] == ("nix", "store"), f"Unpinned tool: {resolved}")
        stores.add(str(Path(*resolved.parts[:4])))
    closure = json.loads(
        commands.run(
            "nix-closure",
            [tools["nix"], "path-info", "--json", "--recursive", *sorted(stores)],
            source,
        )
    )
    return {
        "node": node,
        "npm": npm,
        "executables": paths,
        "hashes": {name: sha(Path(path).resolve().read_bytes()) for name, path in paths.items()},
        "nix_closure": closure,
    }


def installed_graph(source: Path, lock: dict[str, Any]) -> dict[str, dict[str, Any]]:
    result = {}
    for path, entry in lock["packages"].items():
        if path:
            manifest = source / path / "package.json"
            require(
                manifest.is_file() and not manifest.is_symlink(),
                f"Missing installed package: {path}",
            )
            raw = manifest.read_bytes()
            actual = mapping(json.loads(raw), "installed manifest")
            require(
                not (set(mapping(actual.get("scripts", {}), "installed scripts")) & INSTALL_HOOKS),
                f"Installed package requires lifecycle execution: {path}",
            )
            require(
                actual.get("version") == entry["version"],
                f"Installed version differs from lock: {path}",
            )
            result[path] = {
                "name": actual["name"],
                "version": actual["version"],
                "manifest_sha256": sha(raw),
                "locked_integrity": entry["integrity"],
                "optional_peers": {
                    name: actual["peerDependencies"][name]
                    for name, value in mapping(
                        actual.get("peerDependenciesMeta", {}), "peer metadata"
                    ).items()
                    if mapping(value, "peer metadata entry").get("optional") is True
                    and name in mapping(actual.get("peerDependencies", {}), "peer dependencies")
                },
            }
    hidden = mapping(
        json.loads((source / "node_modules/.package-lock.json").read_text()), "installed lock"
    )
    require(
        set(hidden.get("packages", {})) == set(result),
        "Installed graph omits or adds locked packages",
    )
    return result


def mapping(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"Malformed {label}")  # noqa: TRY004 - invalid external JSON value
    return dict(value)


def graph_contract(
    graph: object, package: dict[str, Any], installed: dict[str, dict[str, Any]]
) -> list[dict[str, str]]:
    graph = mapping(graph, "installed graph")
    require(graph.get("name") == package["name"], "Installed graph root differs")
    expected = set(package.get("dependencies", {})) | set(package["devDependencies"])
    require(
        set(mapping(graph.get("dependencies", {}), "root graph dependencies")) == expected,
        "Installed root graph is incomplete",
    )
    pending = [(str(package["name"]), graph)]
    optional_omissions = []
    while pending:
        name, node = pending.pop()
        require(
            isinstance(node, dict) and isinstance(node.get("version"), str), "Unknown graph node"
        )
        require(
            not any(
                node.get(key) for key in ("problems", "missing", "invalid", "extraneous", "error")
            ),
            "Installed graph contains dependency problems",
        )
        children = node.get("dependencies", {})
        require(isinstance(children, dict), "Malformed dependency graph children")
        for child_name, child in children.items():
            if child == {}:
                parents = [
                    entry
                    for entry in installed.values()
                    if entry["name"] == name and entry["version"] == node["version"]
                ]
                require(
                    bool(parents)
                    and all(child_name in entry["optional_peers"] for entry in parents),
                    "Empty graph node is not a declared optional peer",
                )
                ranges = {entry["optional_peers"][child_name] for entry in parents}
                require(
                    len(ranges) == 1 and all(isinstance(value, str) for value in ranges),
                    "Ambiguous optional peer range",
                )
                optional_omissions.append(
                    {
                        "parent": name,
                        "parent_version": node["version"],
                        "peer": child_name,
                        "declared_range": ranges.pop(),
                    }
                )
            else:
                pending.append((child_name, child))
    return sorted(optional_omissions, key=lambda entry: (entry["parent"], entry["peer"]))


def audit_contract(audit: object, lock: dict[str, Any]) -> None:
    audit = mapping(audit, "audit report")
    require(
        isinstance(audit, dict)
        and set(audit) == {"auditReportVersion", "vulnerabilities", "metadata"},
        "Unknown or incomplete audit report",
    )
    require(audit["auditReportVersion"] == 2, "Unknown npm audit report version")
    require(audit["vulnerabilities"] == {}, "Dependency vulnerabilities reported")
    metadata = audit["metadata"]
    require(
        isinstance(metadata, dict) and set(metadata) == {"vulnerabilities", "dependencies"},
        "Missing audit metadata",
    )
    severity = metadata["vulnerabilities"]
    require(
        isinstance(severity, dict)
        and set(severity) == {"info", "low", "moderate", "high", "critical", "total"},
        "Unknown vulnerability summary",
    )
    require(
        all(type(value) is int and value == 0 for value in severity.values()),
        "Audit has vulnerabilities or unknown counts",
    )
    counts = metadata["dependencies"]
    require(
        isinstance(counts, dict)
        and set(counts) == {"prod", "dev", "optional", "peer", "peerOptional", "total"},
        "Unknown audited dependency counts",
    )
    require(
        all(type(value) is int and value >= 0 for value in counts.values()),
        "Invalid audited dependency count",
    )
    entries = [entry for path, entry in lock["packages"].items() if path]
    require(counts["total"] == len(entries), "Audit does not cover the complete locked graph")
    require(
        counts["dev"] == sum(entry.get("dev") is True for entry in entries),
        "Audit omits development dependencies",
    )


def consumer_entrypoints(
    source: Path, installed: dict[str, dict[str, Any]]
) -> dict[str, dict[str, str | int]]:
    result = {}
    for package, command, relative in (
        ("eslint", "eslint", "bin/eslint.js"),
        ("typescript", "tsc", "bin/tsc"),
    ):
        package_path = "node_modules/" + package
        entrypoint = source / package_path / relative
        manifest = source / package_path / "package.json"
        for target in (manifest, entrypoint):
            path = source
            for part in target.relative_to(source).parts:
                path = path / part
                require(not path.is_symlink(), f"Symlink in consumer package path: {path}")
            require(target.is_file(), f"Missing regular consumer package file: {target}")
        raw = manifest.read_bytes()
        observed = installed.get(package_path, {})
        require(
            observed.get("name") == package and observed.get("manifest_sha256") == sha(raw),
            f"Consumer package differs from validated graph: {package}",
        )
        actual = mapping(json.loads(raw), "consumer package")
        bins = mapping(actual.get("bin"), "consumer package bins")
        require(
            bins.get(command) in (relative, "./" + relative),
            f"Unreviewed consumer package entrypoint: {command}",
        )
        result[command] = {"path": str(entrypoint), **identity(entrypoint)}
    return result


def consumers(
    commands: Commands,
    source: Path,
    tools: dict[str, str],
    entrypoints: dict[str, dict[str, str | int]],
) -> None:
    # Keep these arguments aligned with the exact EXPECTED_SCRIPTS contract.
    # npm run would prepend untrusted dependency-provided .bin names to PATH.
    commands.run(
        "lint-ts",
        [tools["node"], str(entrypoints["eslint"]["path"]), "--max-warnings", "0", *CONSUMERS],
        source,
    )
    commands.run(
        "typecheck-ts",
        [
            tools["node"],
            str(entrypoints["tsc"]["path"]),
            "--project",
            "tsconfig.json",
            "--pretty",
            "false",
            "--noEmit",
        ],
        source,
    )
    commands.run(
        "audit-strict-types",
        [tools["node"], "--experimental-strip-types", "scripts/check-strict-types.ts"],
        source,
    )
    for index, test in enumerate(TESTS):
        commands.run(
            f"consumer-{index}", [tools["node"], "--experimental-strip-types", test], source
        )


def execute(root: Path, output: Path, tools: dict[str, str]) -> dict[str, Any]:
    report: dict[str, Any] = {
        "status": "failed",
        "scope": "Root development tools; no Cargo, proof or deployment execution",
    }
    started = time.monotonic()
    try:
        with tempfile.TemporaryDirectory(prefix="aegaeon-development-tools-") as temporary:
            work = Path(temporary)
            source = work / "source"
            report["inputs"] = snapshot(root, source)
            package, lock = package_contract(source)
            npm_cli, report["npm_bootstrap"] = bootstrap_npm(work, output)
            tools = {**tools, "npm": str(npm_cli)}
            commands = Commands(output, environment(work, tools["node"]))
            report["commands"] = commands.records
            report["tools"] = tool_identity(commands, source, tools, package)
            npm = [tools["node"], tools["npm"]]
            commands.run(
                "npm-ci",
                [*npm, "ci", "--ignore-scripts", "--audit=false", "--fund=false", *INCLUDE],
                source,
            )
            unchanged(source, report["inputs"])
            report["installed_graph"] = installed_graph(source, lock)
            graph = json.loads(
                commands.run("npm-ls", [*npm, "ls", "--all", "--json", *INCLUDE], source)
            )
            report["uninstalled_optional_peers"] = graph_contract(
                graph, package, report["installed_graph"]
            )
            report["npm_graph"] = graph
            report["audit"] = json.loads(
                commands.run(
                    "npm-audit", [*npm, "audit", "--json", "--audit-level=info", *INCLUDE], source
                )
            )
            audit_contract(report["audit"], lock)
            report["consumer_entrypoints"] = consumer_entrypoints(source, report["installed_graph"])
            consumers(commands, source, tools, report["consumer_entrypoints"])
            unchanged(source, report["inputs"])
            unchanged(root, report["inputs"])
            report["status"] = "passed"
    except (OSError, ValueError, tarfile.TarError, subprocess.SubprocessError) as error:
        report["error"] = str(error)
    report["seconds"] = time.monotonic() - started
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument(
        "--output", type=Path, default=Path("artifacts/development-tools-validation")
    )
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    report: dict[str, Any] = {"status": "failed"}
    try:
        found = {name: shutil.which(name) for name in ("node", "nix")}
        require(all(found.values()), "Node and Nix tools must be available")
        tools = {name: str(path) for name, path in found.items()}
        report = execute(args.root.resolve(), args.output.resolve(), tools)
    except (OSError, ValueError) as error:
        report["error"] = str(error)
    report["runner_sha256"] = sha(Path(__file__).read_bytes())
    (args.output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"Development tools validation: {report['status']}; evidence: {args.output}")
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
