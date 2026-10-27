# Preserve import/annotation behavior of the measured checkpoint.
# ruff: noqa: I001, I002
"""Separately identified full-provider diagnostic and injected-clock artifacts."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import runtime_dependencies

HERE = Path(__file__).resolve().parent


def sha(path):
    with Path(path).open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def generate(text, fixture):
    for old, new in [
        ("uint8_t do_one_computation(", "uint8_t base_computation("),
        ("void prepare_inputs(", "void original_prepare_inputs("),
        ("int main(", "int original_harness_main("),
    ]:
        if text.count(old) != 1:
            raise ValueError("Unrecognized provider source: " + old)
        text = text.replace(old, new)
    prefix = ""
    if fixture:
        prefix = (
            "#include <stdint.h>\n#include <x86intrin.h>\n#define SENSITIVITY_FIXTURE 1\n"
            "static uint64_t fixture_clock;\nstatic uint64_t injected_clock(void) { return fixture_clock; }\n"  # noqa: E501 -- fixed protocol text retained byte for byte
            "#define __rdtsc() injected_clock()\n"
        )
    return prefix + text + "\n" + (HERE / "compare_signal.inc").read_text()


def build(package, dest, fixture):
    dest.mkdir(parents=True, exist_ok=False)
    source = package / "sources"
    generated = dest / "provider.c"
    generated.write_text(
        generate((source / "tests/constant_time/compare_timing_test.c").read_text(), fixture)
    )
    base = json.loads((package / "native/compare/build-manifest.json").read_text())
    index = json.loads((package / "package.json").read_text())
    argv = base["argv_before_binding"].copy()
    argv[argv.index("tests/constant_time/compare_timing_test.c")] = str(generated)
    argv[argv.index("-o") + 1] = str(dest / "native")
    record = {
        "schema": "legacy-compare-sensitivity-native/1",
        "adopted": False,
        "kind": "injected_clock" if fixture else "physical_diagnostic",
        "base_package_sha256": sha(package / "package.json"),
        "base_build_manifest": base,
        "generated_source_sha256": sha(generated),
        "implementation": {
            n: sha(HERE / n)
            for n in ("build_compare.py", "compare_signal.inc", "runtime_dependencies.py")
        },
        "dependency_discovery": "elf-pt-interp-list/1",
        "argv_before_binding": argv,
        "environment": base["environment"],
        "ordinary_equivalence": False,
        "full_provider_order": False,
        "suite": "legacy",
        "case": "compare",
    }
    binding = {k: index[k] for k in ("contract_sha256", "numerical_sha256")}
    binding["build_sha256"] = hashlib.sha256(canonical(record)).hexdigest()
    command = argv + ["-DAEGAEON_DUDECT_CANDIDATE=1", '-DAEGAEON_DUDECT_SUITE="legacy"']  # noqa: RUF005 -- retain the measured sequence construction
    command += [f'-DAEGAEON_DUDECT_{k.upper()}="{v}"' for k, v in binding.items()]
    (dest / "build-manifest.json").write_bytes(canonical(record))
    env = (
        os.environ
        | base["environment"]
        | {"AEGAEON_SENSITIVITY_PROFILE": "zero", "AEGAEON_SENSITIVITY_TARGET": "compare"}
    )
    for name, cmd in [
        ("compile", command),
        ("signal-self-test", [str(dest / "native"), "--signal-self-test"]),
        ("self-test", [str(dest / "native"), "--self-test"]),
    ]:
        r = subprocess.run(cmd, cwd=source, env=env, capture_output=True, timeout=120)  # noqa: PLW1510, S603 -- return code is inspected and retained after capture; explicit argv; artifact validation precedes execution
        (dest / (name + ".stdout")).write_bytes(r.stdout)
        (dest / (name + ".stderr")).write_bytes(r.stderr)
        r.check_returncode()
    runtime = runtime_dependencies.inspect(dest / "native")
    (dest / "runtime-dependencies.json").write_bytes(canonical(runtime))
    libraries = runtime["dynamic_libraries"]
    for fn in (
        "base_computation",
        "do_one_computation",
        "signal_work",
        "prepare_inputs",
        "original_harness_main",
    ):
        (dest / (fn + ".asm")).write_bytes(
            subprocess.check_output(  # noqa: S603 -- explicit argv; artifact validation precedes execution
                ["objdump", "-drwC", "--disassemble=" + fn, str(dest / "native")]  # noqa: S607 -- fixed tool resolved from the bound toolchain PATH
            )
        )
    artifact = {
        "binary_sha256": sha(dest / "native"),
        "binding": binding,
        "build_manifest_sha256": sha(dest / "build-manifest.json"),
        "dynamic_libraries": libraries,
        "runtime_dependencies_sha256": sha(dest / "runtime-dependencies.json"),
        "kind": record["kind"],
        "base_package": str(package),
        "ordinary_equivalence": False,
    }
    (dest / "artifact.json").write_bytes(canonical(artifact))
    return artifact


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--package", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--fixture", action="store_true")
    a = p.parse_args()
    print(json.dumps(build(a.package, a.output, a.fixture)))
