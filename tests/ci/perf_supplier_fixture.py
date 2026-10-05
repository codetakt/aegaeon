"""Inert supplier records for source controls; never production build evidence."""

from __future__ import annotations

import importlib.util
import json
import shutil
import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import pathlib
    from types import ModuleType


def module(source: pathlib.Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "perf_supplier_controls", source / "scripts/perf/loadtest_supplier.py"
    )
    if spec is None or spec.loader is None:
        message = "supplier control module unavailable"
        raise RuntimeError(message)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


# Deliberately finite scripted cases exercise delegation, not a second URL parser.
# Rust's existing URL-only tests establish the parser contract separately.
REJECTED_URLS = (
    "",
    "not-a-url",
    "https://[invalid.fixture-secret",
    "https://issuer.example.test:not-a-port",
    "https://issuer.example.test:65536",
    "https://user:fixture-secret@issuer.example.test",
    "https://user%3Afixture-secret@issuer.example.test",
    "https://issuer.example.test?fixture-secret",
    "https://issuer.example.test?",
    "https://issuer.example.test#fixture-secret",
    "https://issuer.example.test#",
    "ftp://issuer.example.test/fixture-secret",
    "https:///fixture-secret",
    "http://user:fixture-secret@127.0.0.1:8080",
    *(
        "https://issuer.example.test/" + char + "fixture-secret"
        for char in ("\n", "\u0085", "\u009f", "\u00a0", "\u2028")
    ),
)
REJECTED_ISSUERS = (
    "http://issuer.example.test",
    "https://issuer.example.test/",
    "https://issuer.example.test:443",
    "https://issuer.example.test:",
    "HTTPS://issuer.example.test",
    "https://ISSUER.example.test",
    "https://issuer.example.test/caf\u00e9",
    "http://issuer.example.test/fixture-secret",
    "https://issuer.example.test/fixture-secret/",
)


def prepare(  # noqa: PLR0913, PLR0915 - one owned inert closure and its source/observations
    source: pathlib.Path,
    root: pathlib.Path,
    owner: pathlib.Path,
    helper: ModuleType,
    workload: pathlib.Path,
    *,
    runtime_path: str,
) -> pathlib.Path:
    """Freeze fixture bytes and synthesize explicit inert Cargo observations once."""
    supplier = module(source)
    base = owner / "supplier"
    context_path = base / "context.json"
    if context_path.exists():
        return base / "controller/aegaeon-perf-load"
    domain = helper.git_domain(root)
    files, contents = helper.read_source(root, domain)
    snapshot = base / "source"
    snapshot.mkdir(parents=True)
    for name, entry in files.items():
        path = snapshot / name
        path.parent.mkdir(parents=True, exist_ok=True)
        if entry["symlink"] is not None:
            path.symlink_to(entry["symlink"])
        else:
            path.write_bytes(contents[name])
            path.chmod(0o755 if entry["git_mode"] == "100755" else 0o644)
    manifest = base / "source.json"
    manifest.write_bytes(
        supplier.canonical(
            {
                "schema_version": 1,
                "projection": "git-worktree-content-v1",
                "source_path": str(snapshot),
                "source_nar_sha256": "inert-fixture-nar",
                "files": supplier.file_projection(files),
            }
        )
    )
    package = base / "package"
    (package / "bin").mkdir(parents=True, exist_ok=True)
    selected = package / "bin/aegaeon-loadtest"
    if selected != workload:
        selected.write_bytes(workload.read_bytes())
        selected.chmod(0o755)
    utility = package / "bin/aegaeon-loadtest-url-check"
    utility.write_text(
        f"#!{sys.executable}\nimport json,sys\n"
        f"rejected={REJECTED_URLS!r}\nissuers={REJECTED_ISSUERS!r}\n"
        'if sys.argv[1:]==["--config-stdin"]:\n'
        " config=json.load(sys.stdin)\n"
        " # Scripted control cases only; this inert utility is not Rust equivalence.\n"
        ' bad=config["target_rps"] in (1e308,1e12,5e-324,1e-5)\n'
        ' bad=bad or config["target_url"] in rejected\n'
        ' issuer=config["discovery_expected_issuer"]\n'
        " bad=bad or issuer in rejected or issuer in issuers\n"
        " raise SystemExit(2 if bad else 0)\n"
        "values=dict(value.split('=',1) for value in sys.argv[1:])\n"
        "bad=values.get('--url') in rejected or values.get('--url') is None\n"
        "issuer=values.get('--discovery-expected-issuer')\n"
        "bad=bad or issuer in rejected or issuer in issuers\n"
        "raise SystemExit(2 if bad else 0)\n"
    )
    utility.chmod(0o755)
    graph = base / "graph.json"
    graph.write_text('{"packages":[{"name":"aegaeon-loadtest","id":"inert-workload"}]}\n')
    build_log = base / "build.jsonl"
    observations = [
        {
            "reason": "compiler-artifact",
            "package_id": "inert-workload",
            "target": {"name": name, "kind": ["bin"]},
            "executable": str(package / "bin" / name),
        }
        for name in supplier.BINARIES
    ]
    build_log.write_text(
        "\n".join(json.dumps(row) for row in observations)
        + '\n{"reason":"build-finished","success":true}\n'
    )
    binding = {
        "schema_version": 1,
        "source_inventory": {
            "path": str(manifest),
            "sha256": supplier.sha256(manifest.read_bytes()),
            "source_path": str(snapshot),
            "source_nar_sha256": "inert-fixture-nar",
        },
        "build_source": {
            "path": str(snapshot),
            "nar_sha256": "inert-fixture-build-nar",
            "filter_sha256": supplier.sha256(contents["nix/build-source.nix"]),
        },
        "build": {
            "package": str(package),
            "argv": ["inert-fixture-cargo", "build", "both-bins"],
            "toolchain": {
                "cargo": "inert-fixture-cargo",
                "rustc": "inert-fixture-rustc",
                "target": "inert-fixture-target",
            },
            "features": "default",
            "cargo_lock_sha256": supplier.sha256(contents["Cargo.lock"]),
            "cargo_log": {
                "path": str(build_log),
                "sha256": supplier.sha256(build_log.read_bytes()),
            },
            "resolved_graph": {"path": str(graph), "sha256": supplier.sha256(graph.read_bytes())},
        },
        "executables": {},
    }
    for name in supplier.BINARIES:
        path = package / "bin" / name
        raw = path.read_bytes()
        binding["executables"][name] = {
            "path": str(path),
            "bytes": len(raw),
            "sha256": supplier.sha256(raw),
            "package_id": "inert-workload",
            "target": name,
            "original_build_path": str(path),
            "original_sha256": supplier.sha256(raw),
        }
    context_path.write_bytes(supplier.canonical(binding))
    supplier.generated_launchers(
        snapshot,
        context_path,
        base / "controller",
        {
            "python": sys.executable,
            "git": str(shutil.which("git")),
            "bash": str(shutil.which("bash")),
            "runtime_path": runtime_path,
        },
    )
    return base / "controller/aegaeon-perf-load"
