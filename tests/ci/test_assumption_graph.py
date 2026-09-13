"""Effective-assumption graph: reconstruction, register reconciliation and negative controls.

Every test here is a contract test of the new ``scripts/validation/assumption_graph.py``
function. The original contract cases are supplemented by regressions for review-reproduced
false qualification and reconstruction acceptance.
"""

from __future__ import annotations

import copy
import gzip
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/validation/assumption_graph.py"
sys.path.insert(0, str(SCRIPT.parent))
import assumption_graph as ag  # noqa: E402 - path set above

FIXTURES = ROOT / "tests/fixtures/assumption_graph"
BASELINE = FIXTURES / "baseline-2b"
Z3PROC_LINE = 'Creating new z3proc (cmd=[("z3-4.13.3", ["-smt2", "-in"])], version=["4.13.3"])\n'
RECORDED_ROOT = "/build/source"
CWD = f"{RECORDED_ROOT}/fstar"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_fixture(relative: str) -> str:
    path = FIXTURES / relative
    if path.is_file():
        return path.read_text(errors="replace")
    # Recordings above the repository's added-file limit are stored gzip-compressed
    # (gzip -n, byte-exact after decompression; both digests are in MANIFEST.json).
    return gzip.decompress(path.with_name(path.name + ".gz").read_bytes()).decode(errors="replace")


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


class Fixture:
    """A small source tree, provider trees, tool wrapper and pass records."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.src = root / "src"
        self.evidence = root / "evidence"
        self.tool_dir = root / "tool"
        self.bundled_z3 = root / "bundled-z3" / "bin"
        self.outer_z3 = root / "outer-z3"
        self.providers = {
            "HACL_FSTAR_PATH": root / "providers/hacl",
            "KRMLLIB_PATH": root / "providers/krml",
            "STEEL_PATH": root / "providers/steel",
            "EVERPARSE_FSTAR_PATH": root / "providers/everparse",
            "EVERPARSE_PRELUDE_PATH": root / "providers/everparse/prelude",
            "EVERPARSE_LOWPARSER_PATH": root / "providers/everparse/lowparse",
        }
        self.sources: dict[str, str] = {
            "fstar/Alpha.fst": (
                "module Alpha\nopen Beta\n\n"
                "assume val alpha_axiom: x:nat -> Lemma (x >= 0)\n\n"
                "let alpha_prop (x:nat) : Lemma (x >= 0) = alpha_axiom x\n"
            ),
            "fstar/Beta.fsti": "module Beta\nval beta : nat\n",
            "fstar/Beta.fst": "module Beta\nlet beta = 1\n",
            "fstar/Gamma.fst": "module Gamma\nopen C.Loops\nlet gamma = 2\n",
        }
        self.provider_sources = {
            "providers/hacl/Spec.X.fst": "module Spec.X\nlet x = 1\n",
            "providers/hacl/Spec.X.fsti": "module Spec.X\nval x : nat\n",
            "providers/krml/C.Loops.fst": "module C.Loops\nlet while = ()\n",
            "providers/everparse/LowParse.Y.fst": "module LowParse.Y\nopen C.Loops\nlet y = 3\n",
        }
        self.dependencies: dict[str, dict[str, list[str]]] = {
            "1": {
                "Alpha.fst": ["Beta.fsti", "ulib:FStar.Pervasives.fsti"],
                "Beta.fsti": ["ulib:FStar.Pervasives.fsti"],
                "Beta.fst": ["Beta.fsti", "hacl:Spec.X.fsti", "ulib:FStar.Pervasives.fsti"],
                "hacl:Spec.X.fsti": ["ulib:FStar.Pervasives.fsti"],
                "ulib:FStar.Pervasives.fsti": [],
            },
            "2": {
                "Gamma.fst": ["krml:C.Loops.fst", "everparse:LowParse.Y.fst"],
                "krml:C.Loops.fst": [
                    "ulib:FStar.Classical.fsti",
                    "ulib:FStar.HyperStack.fst",
                    "ulib:FStar.HyperStack.ST.fsti",
                    "ulib:FStar.Pervasives.fsti",
                ],
                "everparse:LowParse.Y.fst": ["krml:C.Loops.fst"],
                "ulib:FStar.Classical.fsti": [],
                "ulib:FStar.HyperStack.fst": [],
                "ulib:FStar.HyperStack.ST.fsti": [],
                "ulib:FStar.Pervasives.fsti": [],
            },
        }
        self.requested = {
            "1": ["Alpha.fst", "Beta.fsti", "Beta.fst"],
            "2": ["Gamma.fst"],
        }
        self.solver_mismatch = False
        self.shadow_beta = False
        self.loads: dict[str, list[str]] = {}

    # -- layout --

    def recorded(self, spec: str) -> str:
        """Map a dependency spec to its recorded absolute path."""
        if ":" not in spec:
            return f"{CWD}/{spec}"
        origin, name = spec.split(":", 1)
        roots = {
            "ulib": self.tool_dir / "lib/fstar/ulib",
            "krml": self.providers["KRMLLIB_PATH"],
            "hacl": self.providers["HACL_FSTAR_PATH"],
            "everparse": self.providers["EVERPARSE_FSTAR_PATH"],
        }
        return str(roots[origin] / name)

    def checked_path(self, spec: str) -> str:
        if spec == "krml:C.Loops.fst" or spec.startswith(("hacl:", "everparse:", "krml:")):
            return self.recorded(spec) + ".checked"
        if spec.startswith("ulib:"):
            name = spec.split(":", 1)[1]
            return str(self.tool_dir / "lib/fstar/ulib.checked" / (name + ".checked"))
        return self.recorded(spec) + ".checked"

    def install(self) -> None:
        for relative, text in {**self.sources, **self.provider_sources}.items():
            base = self.src if relative.startswith("fstar/") else self.root
            path = base / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        for path in self.providers.values():
            path.mkdir(parents=True, exist_ok=True)
        if self.shadow_beta:
            (self.providers["HACL_FSTAR_PATH"] / "Beta.fst").write_text(
                "module Beta\nlet beta = 9\n"
            )
        (self.tool_dir / "lib/fstar/ulib").mkdir(parents=True, exist_ok=True)
        (self.tool_dir / "lib/fstar/ulib.checked").mkdir(parents=True, exist_ok=True)
        for name in (
            "FStar.Pervasives.fsti",
            "FStar.Classical.fsti",
            "FStar.HyperStack.fst",
            "FStar.HyperStack.ST.fsti",
        ):
            module = name.rsplit(".", 1)[0]
            (self.tool_dir / "lib/fstar/ulib" / name).write_text(f"module {module}\n")
        self.write_external_cache_inputs()
        self.bundled_z3.mkdir(parents=True, exist_ok=True)
        (self.bundled_z3 / "z3-4.13.3").write_text("#!/bin/sh\necho bundled\n")
        (self.bundled_z3 / "z3-4.13.3").chmod(0o755)
        self.outer_z3.mkdir(parents=True, exist_ok=True)
        (self.outer_z3 / "z3").write_text("#!/bin/sh\necho outer\n")
        (self.outer_z3 / "z3").chmod(0o755)
        (self.tool_dir / "bin").mkdir(parents=True, exist_ok=True)
        wrapper = self.tool_dir / "bin/fstar.exe"
        wrapper.write_text(
            "#! /bin/bash -e\n"
            f"PATH='{self.bundled_z3}'$PATH\n"
            "export PATH\n"
            'exec "$0-wrapped" "$@"\n'
        )
        wrapper.chmod(0o755)
        shutil.copyfile(ROOT / "scripts/flake/verify_fstar.sh", self.driver_path())
        self.write_spec()
        for pass_id in self.requested:
            self.write_pass(pass_id)
        admission = {
            "admitter": {
                "path": f"{RECORDED_ROOT}/scripts/validation/admit_fstar_modules.py",
                "sha256": "0" * 64,
            },
            "contract": "fstar-2025.10.06-text-v1",
            "created_at": "2026-09-11T00:00:00+00:00",
            "passes": {},
            "status": "accepted",
        }
        for pass_id in self.requested:
            directory = self.evidence / "invocations" / pass_id
            admission["passes"][pass_id] = {
                "inputs_sha256": sha256((directory / "inputs.json").read_bytes()),
                "modules_sha256": sha256((directory / "modules.json").read_bytes()),
                "output_sha256": sha256((directory / "output.log").read_bytes()),
                "status": "accepted",
            }
        write_json(self.evidence / "admission.json", admission)
        write_json(self.src / "spec/assumption-register.json", self.register())

    def driver_path(self) -> Path:
        path = self.src / "scripts/flake/verify_fstar.sh"
        path.parent.mkdir(parents=True, exist_ok=True)
        return path

    def write_external_cache_inputs(self) -> None:
        # These bytes exercise retained-input integrity only, not F* cache semantics.
        for dependencies in self.dependencies.values():
            for spec in dependencies:
                if spec.startswith(("ulib:", "everparse:")):
                    Path(self.checked_path(spec)).write_bytes(b"synthetic checked input\n")

    def external_context(self) -> list[dict[str, str]]:
        external = {
            path
            for base in [self.root / "providers", self.tool_dir / "lib"]
            for path in base.rglob("*")
            if path.is_file()
        }
        return [
            {"path": str(path), "sha256": sha256(path.read_bytes())} for path in sorted(external)
        ]

    def loops_text(self) -> str:
        return ag.regenerate_loops(self.driver_path().read_text())

    def write_spec(self) -> None:
        (self.src / "spec").mkdir(parents=True, exist_ok=True)
        (self.src / "spec/compliance-matrix.yaml").write_text(
            "metadata:\n  version: 1\nrfc_x:\n"
            "- id: x-001\n  status: verified\n  proof:\n"
            "  - type: fstar\n    file: fstar/Alpha.fst\n    lemma: alpha_prop\n"
            "  - type: tamarin\n    file: proofs/tamarin/t/a.spthy\n    lemma: l1\n"
            "- id: x-002\n  status: verified\n  proof:\n"
            "  - type: fstar\n    file: fstar/Gamma.fst\n    computation: gamma\n"
        )
        write_json(
            self.src / "spec/server-assurance-contract.v1.json",
            {"matrix_groups": [{"matrix_key": "rfc_x", "guarantee_ids": ["G-01", "G-02"]}]},
        )
        write_json(
            self.src / "spec/kani-evidence.json",
            {
                "kani_version": "0.66.0",
                "solver": "cadical",
                "target": "x86_64-unknown-linux-gnu",
                "toolchain": {"rust_toolchain_toml_sha256": "1" * 64},
                "groups": [
                    {
                        "id": "g",
                        "class": "required",
                        "gating": "evidence",
                        "crate": "c",
                        "features": ["kani"],
                        "cfg": ["kani"],
                        "default_unwind": 3,
                        "harnesses": [
                            {"name": "h", "file": "f.rs", "rows": ["x-001"], "unwind": 2}
                        ],
                    }
                ],
            },
        )
        (self.src / "ci").mkdir(parents=True, exist_ok=True)
        (self.src / "ci/tamarin_proofs.sh").write_text('PROOFS=(\n\t"t/a.spthy:"\n\t"l1"\n)\n')
        theory = self.src / "proofs/tamarin/t/a.spthy"
        theory.parent.mkdir(parents=True, exist_ok=True)
        theory.write_text(
            "theory A\nbegin\nbuiltins: hashing, signing\nfunctions: mac/2\n"
            'equations: verify(mac(m, k), m, k) = true\n\nrestriction Eq:\n  "x"\n\n'
            'lemma l1:\n  "x"\nlemma l2 [use_induction]:\n  "y"\nend\n'
        )

    def argv(self, pass_id: str) -> list[str]:
        includes: list[str] = []
        for name in ("HACL_FSTAR_PATH", "KRMLLIB_PATH", "STEEL_PATH", "EVERPARSE_FSTAR_PATH"):
            includes += ["--include", str(self.providers[name])]
        return ["fstar.exe", "--use_hints", "--hint_dir", ".", *includes, *self.requested[pass_id]]

    def write_pass(self, pass_id: str) -> None:
        directory = self.evidence / "invocations" / pass_id
        directory.mkdir(parents=True, exist_ok=True)
        argv = self.argv(pass_id)
        tool = self.tool_dir / "bin/fstar.exe"
        solver_path = (
            self.outer_z3 / "z3" if self.solver_mismatch else self.bundled_z3 / "z3-4.13.3"
        )
        local_context = []
        for relative in sorted(self.sources):
            recorded = f"{RECORDED_ROOT}/{relative}"
            local_context.append(
                {"path": recorded, "sha256": sha256((self.src / relative).read_bytes())}
            )
        local_context.append(
            {"path": f"{CWD}/C.Loops.fst", "sha256": sha256(self.loops_text().encode())}
        )
        local_context.extend(self.external_context())
        local_context.sort(key=lambda item: item["path"])
        modules = [
            {"path": p, "sha256": sha256((self.src / "fstar" / p).read_bytes())}
            for p in self.requested[pass_id]
        ]
        inputs = {
            "argv": argv,
            "executed_argv": [str(tool), *argv[1:]],
            "cwd": CWD,
            "recorder": {
                "path": f"{RECORDED_ROOT}/scripts/validation/run_fstar_invocation.py",
                "sha256": "2" * 64,
            },
            "tool": {"path": str(tool), "sha256": sha256(tool.read_bytes())},
            "solver": {"path": str(solver_path), "sha256": sha256(solver_path.read_bytes())},
            "modules": modules,
            "include_paths": [
                a for i, a in enumerate(argv) if i > 0 and argv[i - 1] == "--include"
            ],
            "providers": {name: str(path) for name, path in self.providers.items()},
            "local_context": local_context,
            "loops_origin": "builder-generated-assumptions",
        }
        write_json(directory / "inputs.json", inputs)
        output = Z3PROC_LINE
        requested_records = []
        for path in self.requested[pass_id]:
            role = "interface" if path.endswith(".fsti") else "implementation"
            module = Path(path).name.rsplit(".", 1)[0]
            paired = role == "interface" and path[:-1] in self.requested[pass_id]
            if role == "implementation":
                output += f"Verified module: {module}\n"
            elif not paired:
                output += f"Verified i'face (or impl+i'face): {module}\n"
            requested_records.append(
                {
                    "disposition": "paired-interface"
                    if paired
                    else "interface-verified"
                    if role == "interface"
                    else "verified",
                    "line": None if paired else len(output.splitlines()),
                    "module": module,
                    "path": path,
                    "role": role,
                    "sha256": sha256((self.src / "fstar" / path).read_bytes()),
                }
            )
        output += "All verification conditions discharged successfully\n"
        (directory / "output.log").write_text(output)
        result = {
            "schema_version": 1,
            "pass_id": pass_id,
            "argv": argv,
            "cwd": CWD,
            "status": "succeeded",
            "returncode": 0,
            "inputs_sha256": sha256((directory / "inputs.json").read_bytes()),
            "output_sha256": sha256((directory / "output.log").read_bytes()),
        }
        write_json(directory / "result.json", result)
        write_json(
            directory / "modules.json",
            {
                "schema_version": 1,
                "contract": "fstar-2025.10.06-text-v1",
                "pass_id": pass_id,
                "status": "accepted",
                "requested": requested_records,
                "unrequested": [],
                "inputs_sha256": result["inputs_sha256"],
                "output_sha256": result["output_sha256"],
                "checked_scan": {"directories": [], "candidates": []},
            },
        )
        self.write_dependencies(pass_id, inputs)

    def write_dependencies(self, pass_id: str, inputs: dict) -> None:
        directory = self.evidence / "dependencies" / pass_id
        directory.mkdir(parents=True, exist_ok=True)
        lines = [
            f'# This .depend was generated by F* 2025.10.06~dev\n# Running in directory "{CWD}"\n'
        ]
        deps = self.dependencies[pass_id]
        for spec, targets in deps.items():
            target = self.checked_path(spec) if ":" in spec else spec + ".checked"
            source = self.recorded(spec) if ":" in spec else spec
            if spec == "krml:C.Loops.fst":
                source = (
                    "C.Loops.fst"  # the builder copy in the working directory shadows KaRaMeL's
                )
            if self.shadow_beta and spec == "Beta.fst":
                target = str(self.providers["HACL_FSTAR_PATH"] / "Beta.fst.checked")
            entry = [f"{target}: \\", f"\t{source} \\"]
            entry += [f"\t{self.checked_path(d)} \\" for d in targets]
            entry[-1] = entry[-1].removesuffix(" \\")
            lines.append("\n".join(entry) + "\n\n")
        lines.append("ALL_FST_FILES= \\\n\tAlpha.fst\n")
        (directory / "depend.txt").write_text("".join(lines))
        load = self.loads.get(pass_id) or self.default_load(pass_id)
        (directory / "load.log").write_text("".join(f"{line}\n" for line in load))
        record = {
            "schema_version": 1,
            "contract": ag.DEP_CONTRACT,
            "load_contract": ag.LOAD_CONTRACT,
            "pass_id": pass_id,
            "cwd": CWD,
            "tool": inputs["tool"],
            "verifier_argv": inputs["argv"],
            "dependency_argv": [
                inputs["tool"]["path"],
                "--dep",
                "full",
                *ag.strip_probe_options(inputs["argv"][1:]),
            ],
            "load_argv": [
                inputs["tool"]["path"],
                "--admit_smt_queries",
                "true",
                "--debug",
                "CheckedFiles",
                *ag.strip_probe_options(inputs["argv"][1:]),
            ],
            "dependency_returncode": 0,
            "load_returncode": 0,
            "dependency_sha256": sha256((directory / "depend.txt").read_bytes()),
            "load_sha256": sha256((directory / "load.log").read_bytes()),
            "status": "succeeded",
        }
        write_json(directory / "record.json", record)

    def default_load(self, pass_id: str) -> list[str]:
        lines: list[str] = []
        for spec in self.dependencies[pass_id]:
            checked = self.checked_path(spec) if ":" in spec else spec + ".checked"
            lines.append(f"Trying to load checked file result {checked}")
            module = Path(spec.split(":", 1)[-1]).name.rsplit(".", 1)[0]
            role = "interface" if spec.endswith(".fsti") else "implementation"
            if spec.startswith(("ulib:", "everparse:")):
                lines.append(f"Successfully loaded module from checked file {checked}")
            elif spec == "krml:C.Loops.fst":
                lines.append(
                    f"Checked file {checked} is stale since incorrect digest of C.Loops.fst"
                )
                lines.append(f"Now lax-checking {role} of {module}")
            elif ":" in spec:
                lines.append(f"Now lax-checking {role} of {module}")
            else:
                lines.append(f"Now verifying {role} of {module}")
        return lines

    def register(self) -> dict:
        parsed = ag.parse_fstar_source(self.sources["fstar/Alpha.fst"])
        alpha = next(p for p in parsed["premises"] if p["name"] == "alpha_axiom")
        loops = {
            f"premise:C.Loops#{p['name']}": ag.digest_text(p["statement"])
            for p in ag.parse_fstar_source(self.loops_text())["premises"]
        }
        entries = [
            {
                "id": "decl:alpha_axiom",
                "kind": "declaration",
                "title": "Alpha axiom",
                "status": "specified-not-attested",
                "statement": "test premise",
                "premise_ids": ["premise:Alpha#alpha_axiom"],
                "statements": {"premise:Alpha#alpha_axiom": ag.digest_text(alpha["statement"])},
            },
            {
                "id": "injected:C.Loops",
                "kind": "builder-injected",
                "title": "Injected loops",
                "status": "specified-not-attested",
                "statement": "test premise",
                "premise_ids": sorted(loops),
                "statements": loops,
            },
            {
                "id": "provider-lax-source:hacl",
                "kind": "provider-lax-source",
                "title": "HACL lax",
                "status": "specified-not-attested",
                "statement": "test premise",
                "covers": [{"kind": "lax-module", "origin": "provider:hacl"}],
            },
            {
                "id": "checked-import:ulib",
                "kind": "checked-import",
                "title": "ulib",
                "status": "specified-not-attested",
                "statement": "test premise",
                "covers": [{"kind": "checked-import", "origin": "ulib"}],
            },
            {
                "id": "checked-import:everparse",
                "kind": "checked-import",
                "title": "everparse",
                "status": "specified-not-attested",
                "statement": "test premise",
                "covers": [{"kind": "checked-import", "origin": "provider:everparse"}],
            },
            {
                "id": "tool:fstar",
                "kind": "tool",
                "title": "F*",
                "status": "specified-not-attested",
                "statement": "test premise",
                "premise_ids": ["premise:tool:fstar"],
                "tool_sha256": sha256((self.tool_dir / "bin/fstar.exe").read_bytes()),
            },
            {
                "id": "tool:solver",
                "kind": "tool",
                "title": "solver",
                "status": "specified-not-attested",
                "statement": "test premise",
                "premise_ids": ["premise:tool:solver"],
                "tool_sha256": sha256((self.bundled_z3 / "z3-4.13.3").read_bytes()),
            },
            {
                "id": "tamarin-symbolic-model",
                "kind": "tamarin-model",
                "title": "tamarin",
                "status": "specified-not-attested",
                "statement": "test premise",
                "covers": [
                    {"kind": k}
                    for k in (
                        "tamarin-model",
                        "tamarin-builtin",
                        "tamarin-function",
                        "tamarin-equation",
                        "tamarin-restriction",
                    )
                ],
            },
            {
                "id": "kani-bounded-model",
                "kind": "kani-model",
                "title": "kani",
                "status": "specified-not-attested",
                "statement": "test premise",
                "covers": [{"kind": "kani-model"}, {"kind": "kani-bound"}],
            },
        ]
        return {
            "schema_version": 1,
            "contract": "assumption-register-v1",
            "updated": "2026-09-11",
            "entries": entries,
        }

    # -- running the tool --

    def run(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # noqa: S603 - fixed script and fixture arguments
            [sys.executable, str(SCRIPT), *args],
            capture_output=True,
            text=True,
            check=False,
            env={**os.environ, "PATH": f"{self.outer_z3}:{os.environ['PATH']}"},
        )

    def common(self) -> list[str]:
        return ["--evidence", str(self.evidence), "--source-root", str(self.src)]

    def build(self, out: Path | None = None) -> tuple[subprocess.CompletedProcess[str], Path]:
        out = out or self.root / "graph.json"
        return self.run("build", *self.common(), "--out", str(out)), out

    def check(self, graph: Path, *extra: str) -> subprocess.CompletedProcess[str]:
        return self.run("check", *self.common(), "--graph", str(graph), *extra)

    def qualify(self, graph: Path) -> subprocess.CompletedProcess[str]:
        return self.run("qualify", *self.common(), "--graph", str(graph))


def summary(result: subprocess.CompletedProcess[str]) -> dict:
    line = next(line for line in result.stdout.splitlines() if line.startswith("ASSUMPTION-GRAPH "))
    return json.loads(line.removeprefix("ASSUMPTION-GRAPH "))


def rewrap(graph: Path, body: dict) -> None:
    stored = json.loads(graph.read_text())
    stored["body"] = body
    stored["body_sha256"] = ag.digest_text(ag.canonical(body))
    graph.write_text(ag.canonical(stored))


class SyntheticGraphTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.fixture = Fixture(self.root)

    def built(self) -> tuple[Path, dict]:
        self.fixture.install()
        result, graph = self.fixture.build()
        assert result.returncode == 0, result.stdout + result.stderr
        return graph, json.loads(graph.read_text())["body"]

    def test_build_check_and_qualify_on_a_consistent_tree(self):
        """Contract test: a consistent tree builds, checks and is reported incomplete."""
        graph, body = self.built()
        check = self.fixture.check(graph)
        assert check.returncode == 0, check.stdout
        assert summary(check)["status"] == "consistent"
        qualify = self.fixture.qualify(graph)
        assert qualify.returncode == 2
        reasons = summary(qualify)["reasons"]
        assert any("is not accepted" in r for r in reasons)
        assert "qualified" not in qualify.stdout.replace('"status": "incomplete"', "")
        # Structure: requested sources, the injected C.Loops and the shadow edge are present.
        assert (
            body["nodes"][f"source:{CWD}/Alpha.fst"]["load_modes"]["1"]["mode"]
            == "requested-verified"
        )
        loops = body["nodes"][f"source:{CWD}/C.Loops.fst"]
        assert loops["origin"] == "builder-generated"
        assert loops["load_modes"]["2"] == {
            "mode": "lax-source",
            "checked": "stale",
            "stale_reason": "incorrect digest of C.Loops.fst",
        }
        assert body["nodes"]["premise:C.Loops#while"]["premise_kind"] == "builder-injected"
        assert any(
            e["kind"] == "shadows" and e["from"] == f"source:{CWD}/C.Loops.fst"
            for e in body["edges"]
        )
        # Guarantee mapping and Tamarin/Kani premises are indexed.
        assert any(e["kind"] == "guarantees" and e["to"] == "guarantee:G-01" for e in body["edges"])
        assert "premise:tamarin:t/a.spthy#builtin:hashing" in body["nodes"]
        assert body["nodes"]["tamarin:t/a.spthy#l1"]["selected"] is True
        assert "tamarin:t/a.spthy#l2" not in body["nodes"]
        assert body["nodes"]["premise:kani:g#unwind@h"]["value"] == 2
        assert any(e["kind"] == "cites" and e["to"] == "kani:g#h" for e in body["edges"])
        assert body["findings"] == []

    def test_transitive_dependency_reaches_provider_premises(self):
        """Contract test: closure edges carry module-closure granularity, never exactness."""
        _graph, body = self.built()
        edges = {(e["from"], e["to"]): e for e in body["edges"] if e["kind"] == "depends-on"}
        prop = "property:Alpha#alpha_prop"
        assert (prop, "premise:Alpha#alpha_axiom") in edges
        assert edges[(prop, "premise:Alpha#alpha_axiom")]["explicit_call"] is True
        # Alpha never mentions Spec.X; the lax HACL interface is reached through Beta.
        lax = (prop, "premise:lax-module:Spec.X#interface")
        assert lax in edges
        assert edges[lax]["granularity"] == "module-closure"
        assert edges[lax]["exact"] is False
        assert edges[lax]["through"] == "interface-satisfaction"
        assert edges[(prop, "premise:Alpha#alpha_axiom")]["through"] == "import"
        assert "explicit_call" not in edges[lax]
        assert any(
            e["kind"] == "satisfied-by" and e["from"] == f"source:{CWD}/Beta.fsti"
            for e in body["edges"]
        )
        assert (prop, "premise:checked-import:ulib") in edges
        gamma = "property:Gamma#gamma"
        assert (gamma, "premise:C.Loops#while") in edges
        assert (gamma, "premise:lax-module:LowParse.Y#implementation") not in edges
        assert (gamma, "premise:checked-import:provider:everparse") in edges

    def test_qualifies_only_with_accepted_register_and_no_findings(self):
        """Contract test: qualification requires review status on every reachable premise."""
        graph, _body = self.built()
        register_path = self.fixture.src / "spec/assumption-register.json"
        register = json.loads(register_path.read_text())
        for entry in register["entries"]:
            entry["status"] = "accepted"
            entry["review"] = {
                "reviewer_role": "verification lead",
                "reviewer_id": "synthetic-test-reviewer",
                "subject_sha256": ag.review_subject_digest(entry),
                "date": "2026-09-11",
                "record": "r",
            }
        register_path.write_text(ag.canonical(register))
        # The register digest is part of the body: rebuild before checking.
        result, graph = self.fixture.build()
        assert result.returncode == 0
        qualify = self.fixture.qualify(graph)
        assert qualify.returncode == 0, qualify.stdout
        assert summary(qualify)["status"] == "qualified"
        assert summary(qualify)["reachable_premises"] > 0

    def test_same_named_module_in_include_directory_is_recorded_and_required(self):
        """Contract test: a shadowed provider module is an edge; dropping it is inconsistent."""
        self.fixture.shadow_beta = True
        graph, body = self.built()
        shadow = [
            e
            for e in body["edges"]
            if e["kind"] == "shadows" and e["from"] == f"source:{CWD}/Beta.fst"
        ]
        assert len(shadow) == 1
        assert sorted(shadow[0]["evidence"]) == [
            "checked target attributed to a different directory than the source",
            "same file name in a searched include directory",
        ]
        body["edges"] = [e for e in body["edges"] if e is not shadow[0]]
        rewrap(graph, body)
        check = self.fixture.check(graph)
        assert check.returncode == 1
        assert any("edge only in reconstruction: shadows" in r for r in summary(check)["reasons"])

    def test_interface_and_implementation_are_distinct_nodes(self):
        """Contract test: .fsti and .fst are separate sources with their own load modes."""
        graph, body = self.built()
        iface = body["nodes"][f"source:{CWD}/Beta.fsti"]
        impl = body["nodes"][f"source:{CWD}/Beta.fst"]
        assert (iface["role"], impl["role"]) == ("interface", "implementation")
        iface["role"], impl["role"] = "implementation", "interface"
        rewrap(graph, body)
        check = self.fixture.check(graph)
        assert check.returncode == 1
        assert any("node attributes differ" in r for r in summary(check)["reasons"])

    def test_injected_assumption_content_change_is_rejected(self):
        """Contract test: the generator output must equal the recorded injected source."""
        self.fixture.install()
        driver = self.fixture.driver_path()
        driver.write_text(
            driver.read_text().replace('"assume val total_while"', '"assume val total_whilst"')
        )
        result, _ = self.fixture.build()
        assert result.returncode == 3
        assert "differs from the generator output" in result.stdout

    def test_injected_statement_must_match_the_register(self):
        """Contract test: a re-declared register digest for an injected premise is rejected."""
        graph, _ = self.built()
        register_path = self.fixture.src / "spec/assumption-register.json"
        register = json.loads(register_path.read_text())
        entry = next(e for e in register["entries"] if e["id"] == "injected:C.Loops")
        entry["statements"]["premise:C.Loops#while"] = "9" * 64
        register_path.write_text(ag.canonical(register))
        result, graph = self.fixture.build()
        assert result.returncode == 0
        check = self.fixture.check(graph)
        assert check.returncode == 1
        assert any(
            "premise:C.Loops#while differs from the registered statement" in r
            for r in summary(check)["reasons"]
        )

    def test_unregistered_assume_val_is_rejected(self):
        """Contract test: a discovered declaration without a register entry is inconsistent."""
        graph, _ = self.built()
        register_path = self.fixture.src / "spec/assumption-register.json"
        register = json.loads(register_path.read_text())
        register["entries"] = [e for e in register["entries"] if e["id"] != "decl:alpha_axiom"]
        register_path.write_text(ag.canonical(register))
        result, graph = self.fixture.build()
        assert result.returncode == 0
        check = self.fixture.check(graph)
        assert check.returncode == 1
        assert (
            "unregistered premise premise:Alpha#alpha_axiom (assume-val)"
            in summary(check)["reasons"]
        )

    def test_uncovered_lax_provider_load_is_rejected(self):
        """Contract test: a lax-loaded provider module needs a covering register entry."""
        graph, _ = self.built()
        register_path = self.fixture.src / "spec/assumption-register.json"
        register = json.loads(register_path.read_text())
        register["entries"] = [
            e for e in register["entries"] if e["id"] != "provider-lax-source:hacl"
        ]
        register_path.write_text(ag.canonical(register))
        result, graph = self.fixture.build()
        assert result.returncode == 0
        check = self.fixture.check(graph)
        assert check.returncode == 1
        assert any(
            "uncovered lax-module premise premise:lax-module:Spec.X#interface" in r
            for r in summary(check)["reasons"]
        )

    def test_empty_missing_duplicate_and_unknown_ids_are_rejected(self):
        """Contract test: structural defects in the stored graph or register are rejected."""
        graph, body = self.built()
        empty = copy.deepcopy(body)
        empty["nodes"] = {}
        empty["edges"] = []
        rewrap(graph, empty)
        check = self.fixture.check(graph)
        assert check.returncode == 1
        assert "graph has no nodes" in summary(check)["reasons"]
        missing = copy.deepcopy(body)
        missing["nodes"].pop("premise:Alpha#alpha_axiom")
        missing["edges"] = [
            e for e in missing["edges"] if "premise:Alpha#alpha_axiom" not in (e["from"], e["to"])
        ]
        rewrap(graph, missing)
        check = self.fixture.check(graph)
        assert check.returncode == 1
        assert "node only in reconstruction: premise:Alpha#alpha_axiom" in summary(check)["reasons"]
        unknown = copy.deepcopy(body)
        unknown["edges"].append(
            {"kind": "imports", "from": "source:/nowhere", "to": "source:/else"}
        )
        rewrap(graph, unknown)
        check = self.fixture.check(graph)
        assert check.returncode == 1
        assert any("references an unknown node" in r for r in summary(check)["reasons"])

    def test_duplicate_keys_and_duplicate_register_ids_are_rejected(self):
        """Contract test: duplicate JSON keys and duplicate register ids are fatal."""
        graph, _body = self.built()
        text = graph.read_text().replace(
            '"schema_version": 1,', '"schema_version": 1,\n  "schema_version": 1,', 1
        )
        graph.write_text(text)
        check = self.fixture.check(graph)
        assert check.returncode == 1
        assert any("duplicate JSON key" in r for r in summary(check)["reasons"])
        register_path = self.fixture.src / "spec/assumption-register.json"
        register = json.loads(register_path.read_text())
        register["entries"].append(dict(register["entries"][0]))
        register_path.write_text(ag.canonical(register))
        result, _ = self.fixture.build()
        assert result.returncode == 3
        assert "duplicate register entry" in result.stdout

    def test_duplicate_yaml_keys_cannot_overwrite_claim_inputs(self):
        self.fixture.install()
        matrix = self.fixture.src / "spec/compliance-matrix.yaml"
        original = matrix.read_text()
        mutations = [
            original + "rfc_x: []\n",
            original.replace("  status: verified", "  status: verified\n  status: partial", 1),
            original.replace(
                "    lemma: alpha_prop", "    lemma: alpha_prop\n    lemma: missing", 1
            ),
            original
            + "defaults: &defaults\n  status: verified\nrow:\n  <<: *defaults\n  status: partial\n",
            original + "row:\n  <<: {file: X.fst}\n  <<: {lemma: good}\n",
            original + "row:\n  <<: {}\n  <<: {}\n",
            original + "row: {<<: {<<: {file: X.fst}, <<: {lemma: good}}}\n",
            original + "row: {<<: {<<: {}, <<: {}}}\n",
            original + "defaults: &defaults {<<: {}, <<: {}}\nrow: {<<: *defaults}\n",
            original + "row: {<<: {<<: {<<: {}, <<: {}}}}\n",
            original + "row: {<<: [{<<: {}, <<: {}}, {status: partial}]}\n",
        ]
        for index, mutated in enumerate(mutations):
            with self.subTest(index=index):
                matrix.write_text(mutated)
                result, output = self.fixture.build(self.root / f"rejected-{index}.json")
                assert result.returncode == 3, result.stdout + result.stderr
                assert "duplicate YAML key" in result.stdout
                assert not output.exists()

    def test_circular_justification_is_rejected(self):
        """Contract test: a premise justified by a property that depends on it is a cycle."""
        graph, _ = self.built()
        register_path = self.fixture.src / "spec/assumption-register.json"
        register = json.loads(register_path.read_text())
        entry = next(e for e in register["entries"] if e["id"] == "decl:alpha_axiom")
        entry["justified_by"] = ["property:Alpha#alpha_prop"]
        register_path.write_text(ag.canonical(register))
        result, graph = self.fixture.build()
        assert result.returncode == 0
        check = self.fixture.check(graph)
        assert check.returncode == 1
        assert any(r.startswith("circular justification:") for r in summary(check)["reasons"])

    def test_deleted_or_altered_elements_with_redeclared_digest_are_rejected(self):
        """Contract test: deleting or altering nodes/edges and re-signing the body is caught."""
        graph, body = self.built()
        cases = {
            "premise": lambda b: b["nodes"].pop("premise:Alpha#alpha_axiom"),
            "edge": lambda b: b["edges"].remove(
                next(
                    e
                    for e in b["edges"]
                    if e["kind"] == "imports" and e["from"] == f"source:{CWD}/Alpha.fst"
                )
            ),
            "provider": lambda b: b["nodes"]["pass:1"]["include_paths"].pop(),
            "tool": lambda b: b["nodes"]["tool:fstar"].update(sha256="a" * 64),
            "property": lambda b: b["nodes"].pop("property:Alpha#alpha_prop"),
            "same-count dependency": lambda b: next(
                e
                for e in b["edges"]
                if e["kind"] == "imports" and e["from"] == f"source:{CWD}/Alpha.fst"
            ).update(to=f"source:{CWD}/Gamma.fst"),
        }
        for name, mutate in cases.items():
            with self.subTest(case=name):
                mutated = copy.deepcopy(body)
                mutate(mutated)
                for edge in list(mutated["edges"]):
                    if edge["from"] not in mutated["nodes"] or edge["to"] not in mutated["nodes"]:
                        mutated["edges"].remove(edge)
                rewrap(graph, mutated)
                check = self.fixture.check(graph)
                assert check.returncode == 1, name
                assert summary(check)["reasons"], name

    def test_dependency_absent_from_tool_output_is_rejected(self):
        """Contract test: a declared open without a tool import edge is inconsistent."""
        self.fixture.dependencies["1"]["Alpha.fst"] = ["ulib:FStar.Pervasives.fsti"]
        graph, _ = self.built()
        check = self.fixture.check(graph)
        assert check.returncode == 1
        assert any(
            "declared dependency Beta (open, line 2) is absent" in r
            for r in summary(check)["reasons"]
        )

    def test_solver_identity_mismatch_is_a_blocking_finding(self):
        """Contract test: the effective solver is taken from the output, not the record."""
        self.fixture.solver_mismatch = True
        graph, body = self.built()
        solver = body["nodes"]["premise:tool:solver"]
        assert solver["effective"]["name"] == "z3-4.13.3"
        assert solver["effective"]["path"] == str(self.fixture.bundled_z3 / "z3-4.13.3")
        assert solver["effective"]["sha256"] != solver["recorded"]["sha256"]
        assert [f["code"] for f in body["findings"]] == ["solver-identity-mismatch"] * 2
        check = self.fixture.check(graph)
        assert check.returncode == 0
        qualify = self.fixture.qualify(graph)
        assert qualify.returncode == 2
        assert any("solver-identity-mismatch" in r for r in summary(qualify)["reasons"])

    def test_missing_load_evidence_and_missing_dependency_record_are_fatal(self):
        """Contract test: absent probe records never degrade to an empty dependency set."""
        self.fixture.install()
        shutil.move(self.fixture.evidence / "dependencies" / "2", self.root / "aside")
        result, _ = self.fixture.build()
        assert result.returncode == 3
        assert "dependency record missing for pass 2" in result.stdout
        shutil.move(self.root / "aside", self.fixture.evidence / "dependencies" / "2")
        load = self.fixture.evidence / "dependencies/1/load.log"
        load.write_text("Now verifying implementation of Alpha\n")
        record_path = self.fixture.evidence / "dependencies/1/record.json"
        record = json.loads(record_path.read_text())
        record["load_sha256"] = sha256(load.read_bytes())
        write_json(record_path, record)
        result, _ = self.fixture.build()
        assert result.returncode == 3
        assert "load-mode evidence missing" in result.stdout

    def test_unresolved_load_mode_is_reported(self):
        """Contract test: a stale artifact without a follow-up source check blocks qualification."""
        self.fixture.install()
        load = self.fixture.evidence / "dependencies/1/load.log"
        checked = self.fixture.checked_path("hacl:Spec.X.fsti")
        text = "\n".join(
            f"Checked file {checked} is stale since incorrect digest of Spec.X.fsti"
            if line == "Now lax-checking interface of Spec.X"
            else line
            for line in load.read_text().splitlines()
        )
        load.write_text(text + "\n")
        record_path = self.fixture.evidence / "dependencies/1/record.json"
        record = json.loads(record_path.read_text())
        record["load_sha256"] = sha256(load.read_bytes())
        write_json(record_path, record)
        result, graph = self.fixture.build()
        assert result.returncode == 0
        body = json.loads(graph.read_text())["body"]
        assert any(f["code"] == "load-mode-unresolved" for f in body["findings"])
        check = self.fixture.check(graph)
        assert check.returncode == 1
        assert any("unresolved load mode" in r for r in summary(check)["reasons"])

    def test_expectations_pin_selection_tool_and_receiver(self):
        """Contract test: trust anchors supplied separately from the graph are enforced."""
        graph, body = self.built()
        expect = self.root / "expect.json"
        write_json(
            expect,
            {
                "selection": {"1": ["Alpha.fst", "Beta.fsti", "Beta.fst"], "2": ["Gamma.fst"]},
                "tool_sha256": body["nodes"]["tool:fstar"]["sha256"],
                "receiver_sha256": sha256(SCRIPT.read_bytes()),
            },
        )
        assert self.fixture.check(graph, "--expect", str(expect)).returncode == 0
        write_json(
            expect, {"selection": {"1": ["Alpha.fst"]}, "tool_sha256": "b" * 64, "tree": "t"}
        )
        check = self.fixture.check(graph, "--expect", str(expect))
        assert check.returncode == 1
        reasons = summary(check)["reasons"]
        assert any("selection differs" in r for r in reasons)
        assert any("verifier identity differs" in r for r in reasons)
        assert any("source identity" in r for r in reasons)


class BaselineRecordTests(unittest.TestCase):
    """Parsers exercised on the retained baseline records of the production pass 2b."""

    def test_dependency_output_of_pass_2b(self):
        """Contract test: the real --dep full output yields the recorded closure shape."""
        entries, version = ag.parse_depend(read_fixture("baseline-2b/depend.txt"))
        assert version == "F* 2025.10.06~dev"
        checked = {k: v for k, v in entries.items() if k.endswith(".checked")}
        assert len(checked) == 501
        assert checked["HashComputation.fst.checked"][0] == "HashComputation.fst"
        loops = [k for k in checked if k.endswith("C.Loops.fst.checked")]
        assert loops == [
            "/nix/store/jzlin36arbymkbbxwxaypx0q2bk7jhi0-karamel-2025-10-08/lib/krml/C.Loops.fst.checked"
        ]
        assert checked[loops[0]][0] == "C.Loops.fst"
        dependents = {k for k, v in checked.items() if loops[0] in v}
        assert (
            "/nix/store/vxlik1l0njv6lxmb2fqhjx28g5164x9f-everparse-2025-10-06/lib/lowparse/LowParse.Low.Base.fst.checked"
            in dependents
        )

    def test_load_log_of_pass_2b(self):
        """Contract test: the real load probe shows the stale KaRaMeL C.Loops and lax HACL."""
        load = ag.parse_load_log(read_fixture("baseline-2b/load.log"))
        stale = [p for p in load["stale"] if p.endswith("C.Loops.fst.checked")]
        assert len(stale) == 1
        assert load["stale"][stale[0]].startswith("incorrect digest of C.Loops.fst")
        assert "Spec.Agile.HMAC#interface" in load["lax"]
        assert "LowParse.Low.Base#implementation" in load["lax"]
        assert "Jose.SdJwt#implementation" in load["verified"]
        assert not any(p.startswith("/nix/store/80anjgdr") for p in load["loaded"])

    def test_effective_solver_of_pass_2b(self):
        """Contract test: the pass output names z3-4.13.3 although the record names 4.15.4."""
        inputs = json.loads(read_fixture("baseline-2b/inputs.json"))
        assert inputs["solver"]["path"].endswith("z3-4.15.4/bin/z3")
        solver = ag.effective_solver(
            read_fixture("baseline-2b/output-head.log"), Path("/nonexistent/fstar.exe")
        )
        assert (solver["observed"], solver["name"], solver["version"]) == (
            True,
            "z3-4.13.3",
            "4.13.3",
        )

    def test_injected_loops_digest_matches_the_recorded_context(self):
        """Contract test: the generator block reproduces the recorded C.Loops.fst exactly."""
        inputs = json.loads(read_fixture("baseline-2b/inputs.json"))
        recorded = next(c for c in inputs["local_context"] if c["path"].endswith("/C.Loops.fst"))
        text = ag.regenerate_loops((ROOT / "scripts/flake/verify_fstar.sh").read_text())
        assert ag.digest_text(text) == recorded["sha256"]
        names = [p["name"] for p in ag.parse_fstar_source(text)["premises"]]
        assert names == ["while", "do_while", "total_while"]

    def test_fixture_manifest(self):
        """Contract test: fixture bytes match MANIFEST.json (gzip members by decompressed)."""
        manifest = json.loads((FIXTURES / "MANIFEST.json").read_text())
        for relative, digest in manifest["files"].items():
            path = FIXTURES / relative
            data = (
                gzip.decompress(path.read_bytes())
                if relative.endswith(".gz")
                else path.read_bytes()
            )
            assert sha256(data) == digest, relative


if __name__ == "__main__":
    unittest.main()
