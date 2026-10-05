"""Produce and admit the two binaries for the immutable performance application."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import pathlib
import shutil
import stat
import subprocess
import sys
from typing import TYPE_CHECKING, Any, Never, cast

if TYPE_CHECKING:
    from types import ModuleType

BINARIES = ("aegaeon-loadtest", "aegaeon-loadtest-url-check")
FILE_FIELDS = {"path", "git_mode", "bytes", "git_blob", "sha256", "symlink"}


def invalid(message: str) -> Never:
    raise ValueError(message)


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def checked_bytes(path: pathlib.Path) -> bytes:
    def identity(info: os.stat_result) -> tuple[int, ...]:
        return (
            info.st_dev,
            info.st_ino,
            info.st_size,
            info.st_mtime_ns,
            info.st_ctime_ns,
            info.st_mode,
            info.st_nlink,
        )

    before = path.lstat()
    if not stat.S_ISREG(before.st_mode):
        invalid("supplier input is not a regular file")
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), "rb") as stream:
        opened = os.fstat(stream.fileno())
        raw = stream.read()
        after = os.fstat(stream.fileno())
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
        opened.st_dev,
        opened.st_ino,
        opened.st_size,
        opened.st_mtime_ns,
    ) or (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns) != (
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    ):
        invalid("supplier input changed during read")
    if identity(path.lstat()) != identity(before):
        invalid("supplier input changed after read")
    return raw


def record(path: pathlib.Path, expected: str | None = None) -> tuple[bytes, dict[str, Any]]:
    raw = checked_bytes(path)
    if expected is not None and sha256(raw) != expected:
        invalid("immutable supplier identity mismatch")

    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                invalid("duplicate supplier field")
            value[key] = item
        return value

    value = json.loads(raw, object_pairs_hook=unique)
    if not isinstance(value, dict):
        invalid("supplier record is not an object")
    return raw, value


def file_projection(files: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {"path": name, **{key: entry[key] for key in FILE_FIELDS - {"path"}}}
        for name, entry in sorted(files.items())
    ]


def source_module(source: pathlib.Path) -> ModuleType:
    path = source / "scripts/perf/source_manifest.py"
    spec = importlib.util.spec_from_file_location("aegaeon_perf_source", path)
    if spec is None or spec.loader is None:
        invalid("immutable source module is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def nar_hash(source: pathlib.Path, nix_store: str) -> str:
    result = subprocess.run(  # noqa: S603 - fixed store tool, readonly NAR projection
        [nix_store, "--dump", str(source)], capture_output=True, check=True
    )
    return sha256(result.stdout)


def inventory(source: pathlib.Path, nix_store: str, output: pathlib.Path) -> None:
    helper = source_module(source)
    files: dict[str, Any] = {}
    for directory, dirs, names in os.walk(source, followlinks=False):
        for name in list(dirs):
            if (pathlib.Path(directory) / name).is_symlink():
                dirs.remove(name)
                names.append(name)
        for name in names:
            path = pathlib.Path(directory) / name
            relative = path.relative_to(source).as_posix()
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                link = os.readlink(path)  # noqa: PTH115 - preserve exact Git link bytes
                raw, mode = link.encode(), "120000"
            elif stat.S_ISREG(info.st_mode):
                link = None
                raw = checked_bytes(path)
                mode = "100755" if info.st_mode & 0o111 else "100644"
            else:
                invalid("unsupported supplier source member")
            files[relative] = {
                "git_mode": mode,
                "bytes": len(raw),
                "git_blob": hashlib.sha1(
                    b"blob " + str(len(raw)).encode() + b"\0" + raw, usedforsecurity=False
                ).hexdigest(),
                "sha256": sha256(raw),
                "symlink": link,
            }
    if not files.keys() >= helper.MANDATORY:
        invalid("mandatory supplier source input missing")
    helper.validate_source_links(files)
    output.write_bytes(
        canonical(
            {
                "schema_version": 1,
                "projection": "git-worktree-content-v1",
                "source_path": str(source),
                "source_nar_sha256": nar_hash(source, nix_store),
                "files": file_projection(files),
            }
        )
    )


def install_pair(  # noqa: PLR0915 - keep actual selection and installation one observation
    output: pathlib.Path, build_argv: list[str], toolchain: dict[str, str]
) -> None:
    log = pathlib.Path("loadtest-build.jsonl")
    graph = pathlib.Path("loadtest-graph.json")
    observations = [json.loads(line) for line in log.read_bytes().splitlines()]
    if [row.get("success") for row in observations if row.get("reason") == "build-finished"] != [
        True
    ]:
        invalid("supplier Cargo build did not finish successfully exactly once")
    _, metadata = record(graph)
    packages = [row for row in metadata["packages"] if row["name"] == "aegaeon-loadtest"]
    if len(packages) != 1:
        invalid("supplier graph lacks exact workload package")
    package_id = packages[0]["id"]
    bin_dir = output / "bin"
    bin_dir.mkdir(parents=True)
    executables = {}
    for name in BINARIES:
        matches = [
            row
            for row in observations
            if row.get("reason") == "compiler-artifact"
            and row.get("package_id") == package_id
            and row.get("target", {}).get("name") == name
            and "bin" in row.get("target", {}).get("kind", [])
            and row.get("executable")
        ]
        if len(matches) != 1:
            invalid("supplier build did not select exactly one executable")
        original = pathlib.Path(matches[0]["executable"])
        raw = checked_bytes(original)
        if not original.stat().st_mode & 0o111:
            invalid("selected supplier artifact is not executable")
        destination = bin_dir / name
        destination.write_bytes(raw)
        destination.chmod(0o755)
        if checked_bytes(destination) != raw:
            invalid("installed supplier artifact differs from Cargo selection")
        executables[name] = {
            "path": str(destination),
            "bytes": len(raw),
            "sha256": sha256(raw),
            "package_id": package_id,
            "target": name,
            "original_build_path": str(original),
            "original_sha256": sha256(raw),
        }
    evidence = output / "share/aegaeon-perf"
    evidence.mkdir(parents=True)
    shutil.copyfile(log, evidence / log.name)
    shutil.copyfile(graph, evidence / graph.name)
    (evidence / "build.json").write_bytes(
        canonical(
            {
                "argv": build_argv,
                "toolchain": toolchain,
                "features": "default",
                "cargo_lock_sha256": sha256(checked_bytes(pathlib.Path("Cargo.lock"))),
                "cargo_log": {
                    "path": str(evidence / log.name),
                    "sha256": sha256(checked_bytes(log)),
                },
                "resolved_graph": {
                    "path": str(evidence / graph.name),
                    "sha256": sha256(checked_bytes(graph)),
                },
                "executables": executables,
            }
        )
    )


def bind_pair(
    manifest: pathlib.Path,
    build_source: pathlib.Path,
    package: pathlib.Path,
    nix_store: str,
    output: pathlib.Path,
) -> None:
    manifest_raw, projection = record(manifest)
    _, build = record(package / "share/aegaeon-perf/build.json")
    for binary in build["executables"].values():
        raw = checked_bytes(pathlib.Path(binary["path"]))
        if sha256(raw) != binary["sha256"] or len(raw) != binary["bytes"]:
            invalid("supplier artifact changed after installation")
    output.write_bytes(
        canonical(
            {
                "schema_version": 1,
                "source_inventory": {
                    "path": str(manifest),
                    "sha256": sha256(manifest_raw),
                    "source_path": projection["source_path"],
                    "source_nar_sha256": projection["source_nar_sha256"],
                },
                "build_source": {
                    "path": str(build_source),
                    "nar_sha256": nar_hash(build_source, nix_store),
                    "filter_sha256": sha256(
                        checked_bytes(
                            pathlib.Path(projection["source_path"]) / "nix/build-source.nix"
                        )
                    ),
                },
                "build": {
                    "package": str(package),
                    **{key: value for key, value in build.items() if key != "executables"},
                },
                "executables": build["executables"],
            }
        )
    )


class SupplierContext:
    """Constants supplied by the generated store launcher, never by the user CLI."""

    def __init__(
        self,
        helper: ModuleType,
        binding: str,
        expected: str,
        git: str,
        *,
        fixed_inputs: tuple[str, ...] = (),
    ):
        self.helper = helper
        self.path = pathlib.Path(binding)
        self.expected = expected
        self.git = git
        self.fixed_inputs = tuple(pathlib.Path(value) for value in fixed_inputs)

    def input_paths(self) -> tuple[pathlib.Path, ...]:
        _, binding, _ = self.validate()
        # Runtime tool names may link to separate executable input leaves.
        runtime = (pathlib.Path(self.git), *self.fixed_inputs)
        return (
            self.path,
            *runtime,
            *(path.resolve(strict=True) for path in runtime),
            pathlib.Path(binding["source_inventory"]["path"]),
            pathlib.Path(binding["source_inventory"]["source_path"]),
            pathlib.Path(binding["build_source"]["path"]),
            pathlib.Path(binding["build"]["package"]),
            pathlib.Path(binding["build"]["cargo_log"]["path"]),
            pathlib.Path(binding["build"]["resolved_graph"]["path"]),
        )

    def validate(self) -> tuple[bytes, dict[str, Any], dict[str, Any]]:
        raw, binding = record(self.path, self.expected)
        if (
            binding.keys()
            != {"schema_version", "source_inventory", "build_source", "build", "executables"}
            or type(binding["schema_version"]) is not int
            or binding["schema_version"] != 1
        ):
            invalid("unknown supplier schema")
        manifest = self.source_projection(binding)
        self.selected_executables(binding)
        for name in ("cargo_log", "resolved_graph"):
            entry = binding["build"][name]
            if entry.keys() != {"path", "sha256"} or (
                sha256(checked_bytes(pathlib.Path(entry["path"]))) != entry["sha256"]
            ):
                invalid("supplier build evidence identity mismatch")
        return raw, binding, manifest

    def source_projection(self, binding: dict[str, Any]) -> dict[str, Any]:
        source = binding["source_inventory"]
        if source.keys() != {"path", "sha256", "source_path", "source_nar_sha256"}:
            invalid("unknown supplier source binding fields")
        if binding["build_source"].keys() != {"path", "nar_sha256", "filter_sha256"}:
            invalid("unknown supplier build-source fields")
        if binding["build"].keys() != {
            "package",
            "argv",
            "toolchain",
            "features",
            "cargo_lock_sha256",
            "cargo_log",
            "resolved_graph",
        } or binding["build"]["toolchain"].keys() != {"cargo", "rustc", "target"}:
            invalid("unknown supplier build fields")
        _, manifest = record(pathlib.Path(source["path"]), source["sha256"])
        if (
            manifest.keys()
            != {"schema_version", "projection", "source_path", "source_nar_sha256", "files"}
            or type(manifest["schema_version"]) is not int
            or manifest["schema_version"] != 1
        ):
            invalid("unknown source projection schema")
        if manifest["projection"] != "git-worktree-content-v1" or (
            manifest["source_path"],
            manifest["source_nar_sha256"],
        ) != (source["source_path"], source["source_nar_sha256"]):
            invalid("supplier source projection mismatch")
        helper_path = self.helper.__file__
        if helper_path is None or pathlib.Path(helper_path) != (
            pathlib.Path(source["source_path"]) / "scripts/perf/source_manifest.py"
        ):
            invalid("immutable helper differs from supplier source")
        names = [entry["path"] for entry in manifest["files"]]
        if names != sorted(set(names)) or any(
            entry.keys() != FILE_FIELDS for entry in manifest["files"]
        ):
            invalid("invalid complete source projection")
        members = {entry["path"]: entry for entry in manifest["files"]}
        if members["Cargo.lock"]["sha256"] != binding["build"]["cargo_lock_sha256"] or (
            members["nix/build-source.nix"]["sha256"] != binding["build_source"]["filter_sha256"]
        ):
            invalid("supplier build inputs differ from complete source")
        return manifest

    def selected_executables(self, binding: dict[str, Any]) -> None:
        if set(binding["executables"]) != set(BINARIES):
            invalid("supplier binary inventory mismatch")
        package_ids = set()
        for name, executable in binding["executables"].items():
            if (
                executable.keys()
                != {
                    "path",
                    "bytes",
                    "sha256",
                    "package_id",
                    "target",
                    "original_build_path",
                    "original_sha256",
                }
                or executable["target"] != name
                or type(executable["bytes"]) is not int
            ):
                invalid("unknown supplier executable fields")
            package_ids.add(executable["package_id"])
            path = pathlib.Path(executable["path"])
            if path != pathlib.Path(binding["build"]["package"]) / "bin" / name:
                invalid("supplier executable not in admitted package")
            if (
                self.helper.executable(path) != executable["sha256"]
                or (executable["sha256"] != executable["original_sha256"])
                or path.stat().st_size != executable["bytes"]
            ):
                invalid("supplier executable identity mismatch")
        if len(package_ids) != 1:
            invalid("URL utility and workload differ in selected package")

    def check_files(self, files: dict[str, Any]) -> None:
        _, _, manifest = self.validate()
        if file_projection(files) != manifest["files"]:
            invalid("complete worktree differs from immutable supplier source")

    def admit(self, root: pathlib.Path) -> None:
        self.validate()
        domain = self.helper.git_domain(root, runtime=self.helper.select(git=self.git))
        self.helper.unexpected_paths(root, domain)
        files, _ = self.helper.read_source(root, domain)
        self.check_files(files)
        self.helper.unexpected_paths(root, domain)
        if (
            self.helper.git_domain(root, runtime=self.helper.select(git=self.git)) != domain
            or self.helper.read_source(root, domain)[0] != files
        ):
            invalid("source changed during immutable admission")

    def validate_urls(self, target: str, issuer: str | None) -> None:
        _, binding, _ = self.validate()
        utility = binding["executables"]["aegaeon-loadtest-url-check"]["path"]
        argv = [utility, "--url=" + target]
        if issuer is not None:
            argv.append("--discovery-expected-issuer=" + issuer)
        result = subprocess.run(  # noqa: S603 - immutable admitted utility, no shell
            argv, env={}, capture_output=True, check=False
        )
        if result.returncode != 0 or result.stdout or result.stderr:
            invalid("URL validation failed")

    def bind_workload(self, evidence: pathlib.Path, source_sha256: str) -> str:
        raw, producer, _ = self.validate()
        selected = producer["executables"]["aegaeon-loadtest"]
        self.helper.publish(evidence / "LOADTEST-SUPPLIER.json", raw)
        for name, filename in (
            ("cargo_log", "LOADTEST-SUPPLIER-BUILD.jsonl"),
            ("resolved_graph", "LOADTEST-SUPPLIER-GRAPH.json"),
        ):
            self.helper.publish(
                evidence / filename, checked_bytes(pathlib.Path(producer["build"][name]["path"]))
            )
        self.helper.publish(
            evidence / "aegaeon-loadtest.json",
            self.helper.canonical(
                {
                    "schema_version": 2,
                    "supplier_binding_sha256": self.expected,
                    "source_manifest_sha256": source_sha256,
                    "artifact_sha256": selected["sha256"],
                    "executable": selected["path"],
                    "build_success": True,
                    "build_command": producer["build"]["argv"],
                }
            ),
        )
        return cast("str", selected["path"])

    def verify_workload(
        self, evidence: pathlib.Path, source_sha256: str, binding: dict[str, Any]
    ) -> pathlib.Path:
        raw, producer, _ = self.validate()
        selected = producer["executables"]["aegaeon-loadtest"]
        expected = {
            "schema_version": 2,
            "supplier_binding_sha256": self.expected,
            "source_manifest_sha256": source_sha256,
            "artifact_sha256": selected["sha256"],
            "executable": selected["path"],
            "build_success": True,
            "build_command": producer["build"]["argv"],
        }
        if (
            binding != expected
            or type(binding.get("schema_version")) is not int
            or (type(binding.get("build_success")) is not bool)
            or (checked_bytes(evidence / "LOADTEST-SUPPLIER.json") != raw)
        ):
            invalid("workload consumer binding differs from immutable producer")
        for name, filename in (
            ("cargo_log", "LOADTEST-SUPPLIER-BUILD.jsonl"),
            ("resolved_graph", "LOADTEST-SUPPLIER-GRAPH.json"),
        ):
            if sha256(checked_bytes(evidence / filename)) != producer["build"][name]["sha256"]:
                invalid("retained supplier build observations differ from producer")
        return pathlib.Path(selected["path"])


def generated_launchers(
    source: pathlib.Path, binding: pathlib.Path, output: pathlib.Path, tools: dict[str, str]
) -> None:
    raw, _ = record(binding)
    output.mkdir(parents=True, exist_ok=True)
    factory = (
        "import sys\nsys.dont_write_bytecode=True\n"
        "import importlib.util, pathlib\n"
        f"source = pathlib.Path({str(source)!r})\n"
        "def load(name, filename):\n"
        " spec=importlib.util.spec_from_file_location(name, source/'scripts/perf'/filename)\n"
        " module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)\n"
        " return module\n"
        "helper=load('aegaeon_perf_source','source_manifest.py')\n"
        "supplier=load('aegaeon_perf_supplier','loadtest_supplier.py')\n"
        f"context=supplier.SupplierContext(helper,{str(binding)!r},{sha256(raw)!r},{tools['git']!r},"
        f"fixed_inputs={(str(output), tools['python'], tools['bash'], tools['git'])!r})\n"
    )
    internal = output / "source-helper"
    internal.write_text(
        f"#!{tools['python']} -I\n" + factory + "raise SystemExit(helper.main(context))\n"
    )
    internal.chmod(0o755)
    runner = (source / "scripts/perf/run_load_tests.sh").read_text()
    runner = runner.replace("@PERF_SOURCE_HELPER@", str(internal)).replace(
        "@PERF_PYTHON@", tools["python"]
    )
    immutable_runner = output / "runner.sh"
    immutable_runner.write_text(runner)
    controller = output / "aegaeon-perf-load"
    controller.write_text(
        f"#!{tools['python']} -I\n"
        "import os\n"
        + factory
        + "if 'AEG_LOADTEST_SOURCE_SHA256' in os.environ or any(\n"
        + " key.startswith('AEG_LOADTEST_SUPPLIER_') for key in os.environ):\n"
        + " sys.stderr.write('[perf] caller source/supplier identity is not accepted\\n')\n"
        + " sys.exit(2)\n"
        + "if any(key.startswith('BASH_FUNC_') for key in os.environ):\n"
        + " sys.stderr.write('[perf] inherited shell functions are not supported\\n');sys.exit(2)\n"
        + "environment={key:value for key,value in os.environ.items()\n"
        + " if key not in {'BASH_ENV','ENV','SHELLOPTS','BASHOPTS','PYTHONPATH','PYTHONHOME'}\n"
        + " and not key.startswith('BASH_FUNC_')}\n"
        + f"environment['PATH']={tools['runtime_path']!r}\n"
        + f"os.execve({tools['bash']!r},[{tools['bash']!r},'--noprofile','--norc',"
        + f"{str(immutable_runner)!r},*sys.argv[1:]],environment)\n"
    )
    controller.chmod(0o755)


def main() -> None:
    action, *args = sys.argv[1:]
    if action == "inventory":
        source, nix_store, output = args
        inventory(pathlib.Path(source), nix_store, pathlib.Path(output))
    elif action == "install":
        output, argv, toolchain = args
        install_pair(pathlib.Path(output), json.loads(argv), json.loads(toolchain))
    elif action == "bind":
        manifest, build_source, package, nix_store, output = args
        bind_pair(
            pathlib.Path(manifest),
            pathlib.Path(build_source),
            pathlib.Path(package),
            nix_store,
            pathlib.Path(output),
        )
    elif action == "launchers":
        source, binding, output, tools = args
        generated_launchers(
            pathlib.Path(source), pathlib.Path(binding), pathlib.Path(output), json.loads(tools)
        )
    else:
        invalid("unknown supplier production action")


if __name__ == "__main__":
    main()
