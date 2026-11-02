# Preserve import/annotation behavior of the measured checkpoint.
# ruff: noqa: I001, I002
"""Explicit full-provider diagnostic build; ordinary packages stay immutable."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

HERE = Path(__file__).resolve().parent


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def generate(original):
    body = original
    for old, new in [
        ("void prepare_inputs(", "void original_prepare_inputs("),
        ("int main(", "int original_harness_main("),
    ]:
        assert body.count(old) == 1
        body = body.replace(old, new)
    start = body.index("    case TEST_HMAC_SHA256: {")
    end = body.index("        break;", start)
    body = body[:end] + "        diagnostic_measure(data);\n" + body[end:]
    hook = "/* ── dudect callbacks ── */"
    assert body.count(hook) == 1
    body = body.replace(hook, (HERE / "provider_signal.h").read_text() + "\n" + hook)
    return body + "\n" + (HERE / "provider_tail.h").read_text()


def main():  # noqa: PLR0915 -- ordered evidence checks retain each rejection boundary
    ap = argparse.ArgumentParser()
    ap.add_argument("--package", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    package = args.package
    dest = args.output
    dest.mkdir(parents=True, exist_ok=False)
    source = package / "sources"
    original = source / "c/dudect_harness.c"
    generated = dest / "provider.c"
    generated.write_text(generate(original.read_text()))
    base = json.loads((package / "native/dudect_harness/build-manifest.json").read_text())
    index = json.loads((package / "package.json").read_text())
    argv = base["argv_before_binding"].copy()
    argv[argv.index("c/dudect_harness.c")] = str(generated)
    argv[argv.index("-o") + 1] = str(dest / "native")
    record = {
        "schema": "full-provider-hmac-sensitivity/1",
        "adopted": False,
        "base_package_sha256": sha(package / "package.json"),
        "base_build_manifest": base,
        "original_source_sha256": sha(original),
        "generated_source_sha256": sha(generated),
        "implementation": {
            n: sha(HERE / n) for n in ["build_provider.py", "provider_signal.h", "provider_tail.h"]
        },
        "argv_before_binding": argv,
        "compiler_sha256": sha(argv[0]),
        "environment": base["environment"],
        "scope": "original full provider order, extra work in HMAC message only",
        "ordinary_binary_equivalence": False,
    }
    build = hashlib.sha256(canonical(record)).hexdigest()
    # Preserve the native measurement identities; overlay build gets its own ID.
    native = index
    binding = {
        "contract_sha256": native["contract_sha256"],
        "numerical_sha256": native["numerical_sha256"],
        "build_sha256": build,
    }
    command = argv + ["-DAEGAEON_DUDECT_CANDIDATE=1", '-DAEGAEON_DUDECT_SUITE="nix"']  # noqa: RUF005 -- retain the measured sequence construction
    command += [f'-DAEGAEON_DUDECT_{k.upper()}="{v}"' for k, v in binding.items()]
    (dest / "build-manifest.json").write_bytes(canonical(record))
    env = os.environ | base["environment"]
    result = subprocess.run(command, cwd=source, env=env, capture_output=True, timeout=120)  # noqa: PLW1510, S603 -- return code is inspected and retained after capture; explicit argv; artifact validation precedes execution
    (dest / "compile.stdout").write_bytes(result.stdout)
    (dest / "compile.stderr").write_bytes(result.stderr)
    result.check_returncode()
    for mode in ["--signal-self-test", "--self-test"]:
        result = subprocess.run(  # noqa: PLW1510, S603 -- return code is inspected and retained after capture; explicit argv; artifact validation precedes execution
            [str(dest / "native"), mode],
            env=env | {"AEGAEON_HMAC_SIGNAL_SCOPE": "zero"},
            capture_output=True,
            timeout=120,
        )
        (dest / (mode[2:] + ".stdout")).write_bytes(result.stdout)
        (dest / (mode[2:] + ".stderr")).write_bytes(result.stderr)
        result.check_returncode()
    libraries = {}
    linked = subprocess.check_output(["ldd", str(dest / "native")])  # noqa: S603, S607 -- explicit argv; artifact validation precedes execution; fixed tool resolved from the bound toolchain PATH
    (dest / "ldd.txt").write_bytes(linked)
    for line in linked.decode().splitlines():
        for p in line.split():
            if p.startswith("/"):
                libraries[p] = sha(p)
    for function in [
        "do_one_computation",
        "diagnostic_work",
        "original_prepare_inputs",
        "prepare_inputs",
        "original_harness_main",
    ]:
        (dest / (function + ".asm")).write_bytes(
            subprocess.check_output(  # noqa: S603 -- explicit argv; artifact validation precedes execution
                ["objdump", "-drwC", "--disassemble=" + function, str(dest / "native")]  # noqa: S607 -- fixed tool resolved from the bound toolchain PATH
            )
        )
    (dest / "artifact.json").write_bytes(
        canonical(
            {
                "binary_sha256": sha(dest / "native"),
                "binding": binding,
                "build_manifest_sha256": sha(dest / "build-manifest.json"),
                "dynamic_libraries": libraries,
                "base_package": str(package),
                "not_ordinary_artifact": True,
            }
        )
    )
    print(json.dumps({"output": str(dest), "binary_sha256": sha(dest / "native"), "self_tests": 2}))


if __name__ == "__main__":
    main()
