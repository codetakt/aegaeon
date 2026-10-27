"""Real callback and deterministic injected clock for packaging integration tests."""

from __future__ import annotations

from analysis_contract import assess, identity
from analysis_runtime import replay
from dudect_candidate import NUMERICAL_SHA256
from run import Adapter, Harness, discover_flags
from run_analysis import HERE, SOURCE, installed
from run_candidate import BuildInputs, build, check_contract, collect, current_sources


def capture(directory, mode=0):
    directory.mkdir()
    text = (SOURCE / "c/dudect_harness.c").read_text()
    for old, new in [
        ("uint8_t do_one_computation(", "uint8_t real_callback("),
        ("void prepare_inputs(", "void original_prepare_inputs("),
        ("int main(", "int original_harness_main("),
    ]:
        assert text.count(old) == 1
        text = text.replace(old, new)
    prefix = (
        "#include <stdint.h>\n#include <x86intrin.h>\n"
        "static uint64_t fixture_clock;\n"
        "static uint64_t injected_clock(void) { return fixture_clock; }\n"
        "#define __rdtsc() injected_clock()\n"
    )
    generated = directory / "fixture.c"
    generated.write_text(prefix + text + (HERE / "clock_fixture.inc").read_text())
    contract = check_contract(SOURCE)
    inputs = BuildInputs(
        SOURCE, current_sources(SOURCE), contract, discover_flags(SOURCE, directory), Adapter.SHELL
    )
    spec = Harness(
        "fixture", (str(generated), "c/crypto_init.c"), ("-lm", "-pthread", f"-DTEST_MODE={mode}")
    )
    binary, artifact = build(inputs, directory, spec, "nix")
    name = "hmac_sha256_key" if mode >= 7 else "hmac_sha256"
    binding = {
        "case_id": "nix/" + name,
        "profile": "pr",
        "contract_sha256": contract,
        "build_sha256": artifact["build_sha256"],
        "numerical_sha256": NUMERICAL_SHA256,
    }
    analysis = identity("distributed", "nix-package-fixture-v1", f"mode-{mode}")
    with installed(analysis):
        rows = collect(SOURCE, directory, binary, "pr", {name: binding})
    decisions = replay(directory, {name: binding}, rows, analysis)
    role = assess("nix/" + name, "protected_input_observation", decisions)
    return binding, analysis, rows[name], decisions, role
