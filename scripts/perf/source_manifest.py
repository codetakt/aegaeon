"""CLI and compatible source-record API backed by fixed helper modules."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import pathlib
import sys
import uuid
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable
    from types import ModuleType
    from typing import TypedDict, Unpack


def load_helpers() -> dict[str, ModuleType]:
    directory = pathlib.Path(__file__).resolve().parent / "perf_source"
    namespace = (
        "_aegaeon_perf_source_"
        + hashlib.sha256(str(directory).encode()).hexdigest()
        + "_"
        + uuid.uuid4().hex
    )
    spec = importlib.util.spec_from_file_location(
        namespace, directory / "__init__.py", submodule_search_locations=[str(directory)]
    )
    if spec is None or spec.loader is None:
        message = "fixed performance source package is unavailable"
        raise ImportError(message)
    package = importlib.util.module_from_spec(spec)
    sys.modules[namespace] = package
    spec.loader.exec_module(package)
    return {
        name: importlib.import_module("." + name, namespace)
        for name in ("io", "dependencies", "boundaries", "git_source", "invocation", "status")
    }


_helpers = load_helpers()

if TYPE_CHECKING:
    from perf_source import (
        boundaries as _boundaries,
        dependencies as _dependencies,
        git_source as _git_source,
        invocation as _invocation,
        io as _io,
        status as _status,
    )
    from perf_source.dependencies import Dependencies, Supplier

    class RuntimeOptions(TypedDict, total=False):
        runtime: Dependencies | None
else:
    _io = _helpers["io"]
    _dependencies = _helpers["dependencies"]
    _git_source = _helpers["git_source"]
    _boundaries = _helpers["boundaries"]
    _invocation = _helpers["invocation"]
    _status = _helpers["status"]
    Dependencies = _dependencies.Dependencies
    Supplier = _dependencies.Supplier

select = _dependencies.select
environment = _dependencies.environment
SourceError = _io.SourceError
MODES = _io.MODES
MANDATORY = _io.MANDATORY
MODULE_FILES = _io.MODULE_FILES
SHA256_LENGTH = _io.SHA256_LENGTH
MAX_RUN_SECONDS = _io.MAX_RUN_SECONDS
NANOS_PER_SECOND = _io.NANOS_PER_SECOND
UUID_VERSION = _io.UUID_VERSION
LEGACY = _io.LEGACY
SCENARIOS = _invocation.SCENARIOS
CONFIG_FIELDS = _invocation.CONFIG_FIELDS
IDENTITY_FIELDS = _invocation.IDENTITY_FIELDS
load_json = _io.load_json
required = _io.required
stamp = _io.stamp
strict_json = _io.strict_json
executable = _io.executable
canonical = _io.canonical
digest = _io.digest
fail = _io.fail
ancestors = _io.ancestors
publish = _io.publish
unexpected_paths = _git_source.unexpected_paths
validate_source_links = _git_source.validate_source_links
retain_preimages = _git_source.retain_preimages
read_source = _git_source.read_source
source_link_target = _git_source.source_link_target
require_fresh_outputs = _boundaries.require_fresh_outputs
checked_output = _boundaries.checked_output
output_path = _boundaries.output_path
write_status = _status.write_status


def selected_runtime(options: RuntimeOptions) -> Dependencies:
    if options.keys() - {"runtime"}:
        message = "unknown source dependency option"
        raise TypeError(message)
    return options.get("runtime") or select()


def private_tree(
    root: pathlib.Path,
    domain: dict[str, Any],
    files: dict[str, Any],
    contents: dict[str, bytes],
    forbidden: list[pathlib.Path],
    **options: Unpack[RuntimeOptions],
) -> tuple[str, bytes, pathlib.Path]:
    snapshot = _git_source.Snapshot(root, domain, files, contents)
    return _git_source.private_tree(snapshot, forbidden, runtime=selected_runtime(options))


def root_path(value: str, *, runtime: Dependencies | None = None) -> pathlib.Path:
    return _git_source.root_path(value, runtime=runtime or select())


def git_domain(root: pathlib.Path, *, runtime: Dependencies | None = None) -> dict[str, Any]:
    return _git_source.git_domain(root, runtime=runtime or select())


def output_boundaries(
    root: pathlib.Path,
    domain: dict[str, Any],
    evidence: pathlib.Path,
    outputs: list[tuple[str, bool]],
    *,
    runtime: Dependencies | None = None,
) -> None:
    _boundaries.output_boundaries(root, domain, evidence, outputs, runtime=runtime or select())


def output_roles(
    root: pathlib.Path,
    evidence: pathlib.Path,
    outputs: list[tuple[str, bool]],
    status: pathlib.Path | None = None,
    *,
    runtime: Dependencies | None = None,
) -> None:
    _boundaries.output_roles(root, evidence, outputs, status, runtime=runtime or select())


def cargo_outputs(root: pathlib.Path, *, runtime: Dependencies | None = None) -> list[pathlib.Path]:
    return _boundaries.cargo_outputs(root, runtime=runtime or select())


def reject_supplier_overlap(
    root: pathlib.Path, paths: list[pathlib.Path], *, runtime: Dependencies | None = None
) -> None:
    _boundaries.reject_supplier_overlap(root, paths, runtime=runtime or select())


def private_root(
    root: pathlib.Path, forbidden: list[pathlib.Path], *, runtime: Dependencies | None = None
) -> pathlib.Path:
    return _boundaries.private_root(root, forbidden, runtime=runtime or select())


def declared_outputs(
    root: pathlib.Path, args: argparse.Namespace, *, runtime: Dependencies | None = None
) -> list[tuple[str, bool]]:
    return _boundaries.declared_outputs(root, args, runtime=runtime or select())


def reject_source_overlap(
    root: pathlib.Path,
    domain: dict[str, Any],
    paths: list[pathlib.Path],
    *,
    runtime: Dependencies | None = None,
) -> None:
    _boundaries.reject_source_overlap(root, domain, paths, runtime=runtime or select())


def validate_config(value: object, *, runtime: Dependencies | None = None) -> dict[str, Any]:
    return _invocation.validate_config(value, runtime=runtime or select())


def validate_url_pair(
    target: str, issuer: str | None, *, runtime: Dependencies | None = None
) -> None:
    _invocation.validate_url_pair(target, issuer, runtime=runtime or select())


def invocation_config(
    argv: list[str], *, runtime: Dependencies | None = None
) -> tuple[dict[str, Any], str, str]:
    return _invocation.invocation_config(argv, runtime=runtime or select())


def status_geometry(
    root: pathlib.Path,
    outputs: list[tuple[str, bool]],
    evidence: pathlib.Path,
    *,
    runtime: Dependencies | None = None,
) -> None:
    _status.status_geometry(root, outputs, evidence, runtime=runtime or select())


def status_boundary(
    root: pathlib.Path, artifact: str, *, runtime: Dependencies | None = None
) -> pathlib.Path:
    return _status.status_boundary(root, artifact, runtime=runtime or select())


def initialize_status(
    root: pathlib.Path,
    artifact: str,
    outputs: list[tuple[str, bool]],
    evidence: pathlib.Path,
    *,
    runtime: Dependencies | None = None,
) -> None:
    _status.initialize_status(root, artifact, outputs, evidence, runtime=runtime or select())


def retain_status(
    root: pathlib.Path,
    path: pathlib.Path,
    outputs: list[tuple[str, bool]],
    evidence: pathlib.Path,
    *,
    runtime: Dependencies | None = None,
) -> None:
    _status.retain_status(root, path, outputs, evidence, runtime=runtime or select())


def command(
    root: pathlib.Path,
    *args: str,
    env: dict[str, str] | None = None,
    data: bytes | None = None,
    runtime: Dependencies | None = None,
) -> bytes:
    return (runtime or select()).command(root, *args, env=env, data=data)


class SourceBindings:
    __slots__ = ("runtime",)

    def __init__(self, runtime: Dependencies) -> None:
        self.runtime = runtime

    def verify_binary(
        self, root: pathlib.Path, evidence: pathlib.Path, expected: str, name: str
    ) -> str:
        return verify_binary(root, evidence, expected, name, runtime=self.runtime)


def freeze_invocation(
    root: pathlib.Path,
    evidence: pathlib.Path,
    expected: str,
    argv: list[str],
    *,
    runtime: Dependencies | None = None,
) -> None:
    runtime = runtime or select()
    _invocation.freeze_invocation(root, evidence, expected, argv, bindings=SourceBindings(runtime))


def verify_report(
    root: pathlib.Path,
    evidence: pathlib.Path,
    expected: str,
    report: pathlib.Path,
    *,
    runtime: Dependencies | None = None,
) -> None:
    runtime = runtime or select()
    _invocation.verify_report(root, evidence, expected, report, bindings=SourceBindings(runtime))


def freeze(
    root: pathlib.Path,
    evidence: pathlib.Path,
    outputs: list[tuple[str, bool]],
    *,
    runtime: Dependencies | None = None,
) -> str:
    runtime = runtime or select()
    domain = git_domain(root, runtime=runtime)
    output_boundaries(root, domain, evidence, outputs, runtime=runtime)
    evidence.mkdir(parents=True, exist_ok=False)
    unexpected_paths(root, domain)
    files, contents = read_source(root, domain)
    if runtime.supplier is not None:
        runtime.supplier.check_files(files)
    forbidden = [evidence.parent] + [
        checked_output(root, path, directory=True) for path, is_dir in outputs if is_dir
    ]
    snapshot = _git_source.Snapshot(root, domain, files, contents)
    tree, patch, private = _git_source.private_tree(snapshot, forbidden, runtime=runtime)
    unexpected_paths(root, domain)
    if git_domain(root, runtime=runtime) != domain or read_source(root, domain)[0] != files:
        fail("source changed during freeze")
    publish(evidence / "TRACKED-PATHS.json", canonical(domain))
    publish(evidence / "OUTPUTS.json", canonical(outputs))
    manifest = {
        "candidate_tree": tree,
        "files": files,
        "patch_sha256": digest(patch),
        "source_base_commit": domain["head"],
    }
    raw = canonical(manifest)
    publish(evidence / "SOURCE-MANIFEST.json", raw)
    origin = {
        "source_manifest_sha256": digest(raw),
        "source_archive_sha256": digest((private / "source.tar").read_bytes()),
        "patch_sha256": digest(patch),
        "tracked_domain_sha256": digest((evidence / "TRACKED-PATHS.json").read_bytes()),
        "outputs_sha256": digest((evidence / "OUTPUTS.json").read_bytes()),
    }
    publish(evidence / "ORIGIN.json", canonical(origin))
    (private / "LOCATION.json").write_bytes(
        canonical({"evidence": str(evidence), "origin": origin})
    )
    (private / "LOCATION.json").chmod(0o600)
    verify(root, evidence, digest(raw), runtime=runtime)
    return digest(raw)


def verify(
    root: pathlib.Path,
    evidence: pathlib.Path,
    expected: str,
    *,
    runtime: Dependencies | None = None,
) -> dict[str, Any]:
    runtime = runtime or select()
    raw, manifest = load_json(evidence / "SOURCE-MANIFEST.json")
    if (
        not isinstance(manifest, dict)
        or digest(raw) != expected
        or set(manifest)
        != {
            "candidate_tree",
            "files",
            "patch_sha256",
            "source_base_commit",
        }
    ):
        fail("raw source manifest binding failed")
    domain_raw, domain = load_json(evidence / "TRACKED-PATHS.json")
    outputs_raw, outputs = load_json(evidence / "OUTPUTS.json")
    _, origin = load_json(evidence / "ORIGIN.json")
    if (
        origin["source_manifest_sha256"] != expected
        or origin["tracked_domain_sha256"] != digest(domain_raw)
        or origin["outputs_sha256"] != digest(outputs_raw)
        or (origin["patch_sha256"] != manifest["patch_sha256"])
    ):
        fail("independent source evidence binding failed")
    if (
        git_domain(root, runtime=runtime) != domain
        or domain["head"] != manifest["source_base_commit"]
    ):
        fail("Git source domain changed")
    output_boundaries(root, domain, evidence, outputs, runtime=runtime)
    unexpected_paths(root, domain)
    files, _ = read_source(root, domain)
    if runtime.supplier is not None:
        runtime.supplier.check_files(files)
    if files != manifest["files"] or set(files) != set(domain["index"]):
        fail("complete source bytes, modes or links changed")
    return manifest


def admitted_executable(root: pathlib.Path, evidence: pathlib.Path, value: str) -> pathlib.Path:
    path = output_path(root, value)
    if path.is_relative_to(root) and (not path.is_relative_to(root / "target")):
        fail("build executable overlaps source")
    _, outputs = load_json(evidence / "OUTPUTS.json")
    leaves = {output_path(root, destination) for destination, directory in outputs if not directory}
    leaves.update(output_path(root, name) for name in LEGACY)
    leaves.add(evidence.parent / "source-status.json")
    if path in leaves or path.is_relative_to(evidence):
        fail("build executable overlaps an output or source evidence")
    return path


def bind(
    root: pathlib.Path,
    evidence: pathlib.Path,
    expected: str,
    build_log: pathlib.Path | None,
    name: str,
    **options: Unpack[RuntimeOptions],
) -> str:
    runtime = selected_runtime(options)
    verify(root, evidence, expected, runtime=runtime)
    if name == "aegaeon-loadtest":
        if runtime.supplier is None:
            fail("immutable loadtest supplier is required")
        return runtime.supplier.bind_workload(evidence, expected)
    if build_log is None:
        fail("actual server build log is required")
    matches: list[str] = []
    finished = []
    for line in build_log.read_text().splitlines():
        record = json.loads(line)
        target = record.get("target", {})
        if record.get("reason") == "build-finished":
            finished.append(record.get("success"))
        if (
            record.get("reason") == "compiler-artifact"
            and target.get("name") == name
            and ("bin" in target.get("kind", []))
            and record.get("executable")
        ):
            matches.append(record["executable"])
    if len(matches) != 1 or finished != [True]:
        fail("build did not identify exactly one selected executable")
    path = admitted_executable(root, evidence, matches[0])
    sha = executable(path)
    publish(
        evidence / (name + ".json"),
        canonical(
            {
                "source_manifest_sha256": expected,
                "artifact_sha256": sha,
                "executable": str(path),
                "build_success": True,
                "build_command": (
                    ["cargo", "build", "--release", "--locked", "--bin", name]
                    if name == "aegaeon-server"
                    else ["cargo", "build", "--release", "-p", "aegaeon-loadtest", "--bin", name]
                )
                + ["--message-format=json-render-diagnostics"],
            }
        ),
    )
    return str(path)


def verify_binary(
    root: pathlib.Path,
    evidence: pathlib.Path,
    expected: str,
    name: str,
    *,
    runtime: Dependencies | None = None,
) -> str:
    runtime = runtime or select()
    verify(root, evidence, expected, runtime=runtime)
    _, binding = load_json(evidence / (name + ".json"))
    if binding["source_manifest_sha256"] != expected:
        fail("executable source binding failed")
    if name == "aegaeon-loadtest":
        if runtime.supplier is None:
            fail("immutable loadtest supplier is required")
        path = runtime.supplier.verify_workload(evidence, expected, binding)
    else:
        path = admitted_executable(root, evidence, binding["executable"])
    if executable(path) != binding["artifact_sha256"]:
        fail("built executable changed before launch")
    return str(path)


def admit_helper(root: pathlib.Path, action: str, *, runtime: Dependencies | None = None) -> None:
    runtime = runtime or select()
    if runtime.supplier is not None:
        if action == "status":
            runtime.supplier.validate()
        else:
            runtime.supplier.admit(root)
    elif pathlib.Path(__file__).resolve() != root / "scripts/perf/source_manifest.py":
        fail("producer must be the tracked repository entrypoint")


def dispatch(args: argparse.Namespace, *, runtime: Dependencies | None = None) -> None:
    runtime = runtime or select()
    root = root_path(args.root, runtime=runtime)
    admit_helper(root, args.action, runtime=runtime)
    evidence = checked_output(root, args.evidence, directory=True)
    if args.action == "paths":
        outputs = declared_outputs(root, args, runtime=runtime)
        if args.artifact_directory:
            initialize_status(root, args.artifact_directory, outputs, evidence, runtime=runtime)
        output_boundaries(
            root, git_domain(root, runtime=runtime), evidence, outputs, runtime=runtime
        )
        require_fresh_outputs(root, args.fresh_output_file)
    elif args.action == "status":
        write_status(
            status_boundary(root, required(args.artifact_directory), runtime=runtime),
            required(args.stage),
            args.exit_status,
        )
    elif args.action == "freeze":
        if "AEG_LOADTEST_SOURCE_SHA256" in os.environ:
            fail("caller source digest is not accepted")
        outputs = declared_outputs(root, args, runtime=runtime)
        output_boundaries(
            root, git_domain(root, runtime=runtime), evidence, outputs, runtime=runtime
        )
        require_fresh_outputs(root, args.fresh_output_file)
        print(freeze(root, evidence, outputs, runtime=runtime))
    else:
        expected = required(args.sha256)
        if len(expected) != SHA256_LENGTH or any(c not in "0123456789abcdef" for c in expected):
            fail("producer source digest is required")
        actions: dict[str, Callable[[], object]] = {
            "verify": lambda: verify(root, evidence, expected, runtime=runtime),
            "bind": lambda: print(
                bind(
                    root,
                    evidence,
                    expected,
                    pathlib.Path(args.build_log) if args.build_log is not None else None,
                    required(args.name),
                    runtime=runtime,
                )
            ),
            "binary": lambda: print(
                verify_binary(root, evidence, expected, required(args.name), runtime=runtime)
            ),
            "invocation": lambda: freeze_invocation(
                root, evidence, expected, args.child_args, runtime=runtime
            ),
            "report": lambda: verify_report(
                root, evidence, expected, pathlib.Path(required(args.report)), runtime=runtime
            ),
        }
        actions[args.action]()


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "action",
        choices=[
            "urls",
            "paths",
            "freeze",
            "verify",
            "bind",
            "binary",
            "invocation",
            "report",
            "status",
        ],
    )
    parser.add_argument("--root", required=True)
    parser.add_argument("--evidence", required=True)
    parser.add_argument("--sha256")
    parser.add_argument("--artifact-directory")
    parser.add_argument("--stage")
    parser.add_argument("--exit-status", type=int, default=1)
    parser.add_argument("--output-file", action="append", default=[])
    parser.add_argument("--report-file")
    parser.add_argument("--legacy-report-file")
    parser.add_argument("--fresh-output-file", action="append", default=[])
    parser.add_argument("--output-directory", action="append", default=[])
    parser.add_argument("--build-log")
    parser.add_argument("--name", choices=["aegaeon-server", "aegaeon-loadtest"])
    parser.add_argument("--report")
    parser.add_argument("--url")
    parser.add_argument("--discovery-expected-issuer")
    producer_args = sys.argv[1:]
    child_args: list[str] = []
    if "--" in producer_args:
        position = producer_args.index("--")
        child_args = producer_args[position + 1 :]
        producer_args = producer_args[:position]
    args = parser.parse_args(producer_args)
    args.child_args = child_args
    if child_args and args.action != "invocation":
        parser.error("child arguments are only accepted by invocation")
    return args


def validate_requested_urls(
    args: argparse.Namespace, *, runtime: Dependencies | None = None
) -> None:
    runtime = runtime or select()
    if runtime.supplier is None:
        fail("immutable URL supplier is required")
    runtime.supplier.admit(root_path(args.root, runtime=runtime))
    validate_url_pair(required(args.url), args.discovery_expected_issuer, runtime=runtime)


def main(supplier_context: Supplier | None = None) -> int:
    args = parse_arguments()
    try:
        runtime = select(supplier=supplier_context)
        if args.action == "urls":
            validate_requested_urls(args, runtime=runtime)
        else:
            dispatch(args, runtime=runtime)
    except (OSError, ValueError, KeyError, TypeError, OverflowError, UnicodeError, SourceError):
        print("[perf] source or executable evidence validation failed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
