# Preserve import/annotation behavior of the measured checkpoint.
# ruff: noqa: I001, I002
"""Actual child/collector/ACK regression using crypto callbacks and an injected clock."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys


def save(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():  # noqa: PLR0915 -- ordered evidence checks retain each rejection boundary
    ap = argparse.ArgumentParser()
    ap.add_argument("--analysis", type=Path, required=True)
    ap.add_argument("--package", type=Path, action="append", required=True)
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--ct-order", action="store_true")
    args = ap.parse_args()
    args.output.mkdir(exist_ok=False)
    sys.path.insert(0, str(args.analysis))
    from run_analysis import SOURCE  # noqa: F401, PLC0415 -- retain imported-module initialization in this measured checkpoint; retain initialization order of the measured analysis
    from analysis_contract import identity, assess  # noqa: PLC0415 -- retain initialization order of the measured analysis
    from analysis_runtime import replay  # noqa: PLC0415 -- retain initialization order of the measured analysis
    from dudect_affinity import placement  # noqa: PLC0415 -- retain initialization order of the measured analysis

    allowed = os.sched_getaffinity(0)
    p = placement(allowed)
    cpus = sorted([p["collector"][0], p["native"][0]])
    parent = {cpus[0]}
    os.sched_setaffinity(0, parent)
    checks = []
    try:
        for number, package in enumerate(args.package):
            root = args.output / str(number)
            root.mkdir()
            source = package / "sources"
            text = (source / "c/dudect_harness.c").read_text()
            for old, new in [
                ("uint8_t do_one_computation(", "uint8_t real_callback("),
                ("void prepare_inputs(", "void original_prepare_inputs("),
                ("int main(", "int original_harness_main("),
            ]:
                assert text.count(old) == 1
                text = text.replace(old, new)
            prefix = "#include <stdint.h>\n#include <x86intrin.h>\nstatic uint64_t fixture_clock;\nstatic uint64_t injected_clock(void){return fixture_clock;}\n#define __rdtsc() injected_clock()\n"  # noqa: E501 -- fixed protocol text retained byte for byte
            tail = (args.analysis / "clock_fixture.inc").read_text()
            names = ["hmac_sha256_key"]
            if args.ct_order:
                names = ["ct_eq_32", "ct_eq_64", "ct_eq_128"]
                tail = """
static uint64_t fixture_calls;
void prepare_inputs(dudect_config_t *c, uint8_t *data, uint8_t *classes) {
    original_prepare_inputs(c,data,classes);
}
uint8_t do_one_computation(uint8_t *data) {
    uint8_t result=real_callback(data); fixture_clock+=1000; ++fixture_calls; return result;
}
int main(int argc,char **argv) {
    aegaeon_crypto_init(); current_test=TEST_CT_EQ;
    const char *names[]={"ct_eq_32","ct_eq_64","ct_eq_128"};
    const size_t chunks[]={32,64,128};
    for (unsigned i=0;i<3;++i) {
        int status=dudect_run_case(names[i],chunks[i],argc,argv); if(status)return status;
    }
    fprintf(stderr,"FIXTURE_CALLBACKS %llu\\n",(unsigned long long)fixture_calls);
    dudect_require(fixture_calls==3u*17u*65536u,"all three real callback schedules");
    return 0;
}
"""
            generated = root / "fixture.c"
            generated.write_text(prefix + text + tail)
            base = json.loads((package / "native/dudect_harness/build-manifest.json").read_text())
            index = json.loads((package / "package.json").read_text())
            argv = base["argv_before_binding"].copy()
            argv[argv.index("c/dudect_harness.c")] = str(generated)
            binary = root / "native"
            argv[argv.index("-o") + 1] = str(binary)
            build = hashlib.sha256(
                json.dumps(
                    {"argv": argv, "generated": sha(generated), "mode": 7}, sort_keys=True
                ).encode()
            ).hexdigest()
            binding = {
                "contract_sha256": index["contract_sha256"],
                "numerical_sha256": index["numerical_sha256"],
                "build_sha256": build,
            }
            argv += [
                "-DTEST_MODE=7",
                "-DAEGAEON_DUDECT_CANDIDATE=1",
                '-DAEGAEON_DUDECT_SUITE="nix"',
            ]
            argv += [f'-DAEGAEON_DUDECT_{k.upper()}="{v}"' for k, v in binding.items()]
            result = subprocess.run(  # noqa: PLW1510, S603 -- return code is inspected and retained after capture; explicit argv; artifact validation precedes execution
                argv,
                cwd=source,
                env=os.environ | base["environment"],
                capture_output=True,
                timeout=120,
            )
            (root / "compile.stderr").write_bytes(result.stderr)
            result.check_returncode()
            save(
                root / "build.json",
                {"argv": argv, "base": base, "binary": sha(binary), "binding": binding},
            )
            binding |= {"case_id": "nix/hmac_sha256_key", "profile": "pr"}
            analysis = identity(
                "distributed", "sensitivity-launch-functional-v1", f"compiler-{number}"
            )
            bindings = {name: binding | {"case_id": "nix/" + name} for name in names}
            modes = [("one-core", cpus[:1]), ("two-core", cpus)]
            if args.ct_order:
                modes = [("wrong-order", cpus), ("duplicate-order", cpus)] + modes  # noqa: RUF005 -- retain the measured sequence construction
            for mode, mask in modes:
                dest = root / mode
                dest.mkdir()
                invocation = {
                    "analysis_path": str(args.analysis),
                    "analysis": analysis,
                    "binary": str(binary),
                    "binary_sha256": sha(binary),
                    "bindings": bindings,
                    "case_order": sorted(names)
                    if mode == "wrong-order"
                    else names + [names[0]]  # noqa: RUF005 -- retain the measured sequence construction
                    if mode == "duplicate-order"
                    else names,
                    "output": str(dest),
                    "cpus": mask,
                }
                path = dest / "invocation.json"
                save(path, invocation)
                with (dest / "stdout").open("wb") as stdout, (dest / "stderr").open("wb") as stderr:
                    result = subprocess.run(  # noqa: PLW1510, S603 -- return code is inspected and retained after capture; explicit argv; artifact validation precedes execution
                        [
                            sys.executable,
                            "-B",
                            str(Path(__file__).with_name("collect_one.py")),
                            str(path),
                            sha(path),
                        ],
                        stdout=stdout,
                        stderr=stderr,
                        timeout=180,
                    )
                assert os.sched_getaffinity(0) == parent
                if mode in ("one-core", "duplicate-order"):
                    assert result.returncode != 0 and not (dest / "native.timing").exists()  # noqa: PT018 -- fixed functional fixture retains its combined obligation
                    checks.append(
                        {
                            "compiler": number,
                            "test": "reject " + mode + " before native",
                            "passed": True,
                        }
                    )
                    continue
                if mode == "wrong-order":
                    process = json.loads((dest / "process.json").read_text())
                    assert result.returncode != 0 and not process["collection_complete"]  # noqa: PT018 -- fixed functional fixture retains its combined obligation
                    assert "Candidate identity mismatch" in (dest / "stderr").read_text()
                    checks.append(
                        {
                            "compiler": number,
                            "test": "reject sorted case order at native binding",
                            "passed": True,
                        }
                    )
                    continue
                assert result.returncode == 0, (dest / "stderr").read_text()
                process = json.loads((dest / "process.json").read_text())
                assert process["collection_complete"] and process["exit"] == 0  # noqa: PT018 -- fixed functional fixture retains its combined obligation
                assert process["cpu_placement"]["original"] == cpus
                assert process["cpu_placement"]["native"] == [cpus[-1]]
                assert process["cpu_placement"]["collector"] == [cpus[0]]
                rows = json.loads((dest / "observations.json").read_text())
                effective = replay(dest, bindings, rows, analysis)
                roles = [
                    assess(
                        "nix/" + name,
                        "measurement_negative_control"
                        if args.ct_order
                        else "protected_input_observation",
                        [r for r in effective if r["case"] == name],
                    )
                    for name in names
                ]
                assert len(effective) == 8 * len(names) and all(  # noqa: PT018 -- fixed functional fixture retains its combined obligation
                    role["requirement_satisfied"] for role in roles
                )
                assert (
                    f"FIXTURE_CALLBACKS {1114112 * len(names)}"
                    in (dest / "native.stderr").read_text()
                )
                save(dest / "effective.json", effective)
                checks.append(
                    {
                        "compiler": number,
                        "test": "actual child collector native ACK and replay",
                        "passed": True,
                        "looks": 8 * len(names),
                        "frames": 17 * len(names),
                        "callbacks": 1114112 * len(names),
                        "parent_cpu": sorted(parent),
                        "case_order": names,
                        "cpu_placement": process["cpu_placement"],
                        "roles": roles,
                    }
                )
    finally:
        os.sched_setaffinity(0, allowed)
    save(
        args.output / "result.json",
        {"passed": True, "injected_clock": True, "fresh_physical_timing": False, "checks": checks},
    )
    print(json.dumps({"passed": True, "checks": len(checks)}))


if __name__ == "__main__":
    main()
