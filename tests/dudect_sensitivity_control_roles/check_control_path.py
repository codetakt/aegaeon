# Preserve import/annotation behavior of the measured checkpoint.
# ruff: noqa: I001, I002
"""Actual original control callbacks + injected clocks, through live worker/ACK.
Never a fresh hardware-clock trial. Two compiler artifacts, fixed on/off modes.
"""

import argparse
import hashlib
import json
import os
import subprocess
import sys  # noqa: F401 -- retain measured import initialization
import time
from pathlib import Path
from contract import identity as qualification_identity
from live_runtime import identity, installed, replay
from analysis_contract import SOURCE
from dudect_candidate import canonical, digest
from dudect_package import checked_package
from dudect_diagnostics import validate_diagnostics
from dudect_affinity import placement
import run_candidate
import ordinary


def sha(p):
    with Path(p).open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def save(p, x):
    p.write_bytes(canonical(x))


NAMES = ("control_independent", "control_mean_shift", "control_variance_shift")


def main():  # noqa: PLR0915 -- ordered evidence checks retain each rejection boundary
    p = argparse.ArgumentParser()
    p.add_argument("--package", type=Path, action="append", required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    a.output.mkdir(exist_ok=False)
    assert len(a.package) == 2
    allowed = os.sched_getaffinity(0)
    place = placement(allowed)
    cpus = [place["collector"][0], place["native"][0]]
    start = time.monotonic()
    checks = []
    try:
        for i, package in enumerate(a.package):
            d = a.output / str(i)
            d.mkdir()
            index = checked_package(package, run_candidate.current_sources(SOURCE), "nix")
            base = json.loads((package / "native/dudect_controls/build-manifest.json").read_bytes())
            source = package / "sources"
            text = (source / "tests/constant_time/calibration_timing_test.c").read_text()
            assert text.count("uint8_t do_one_computation(") == 1 and text.count("int main(") == 1  # noqa: PT018 -- fixed functional fixture retains its combined obligation
            text = text.replace("uint8_t do_one_computation(", "uint8_t base_computation(").replace(
                "int main(", "int base_main("
            )
            prefix = "#include <stdint.h>\n#include <stdlib.h>\n#include <x86intrin.h>\nstatic uint64_t clock_ticks;\nstatic int remove_signal;\nstatic uint64_t injected_clock(void){return clock_ticks;}\n#define __rdtsc() injected_clock()\n"  # noqa: E501 -- fixed protocol text retained byte for byte
            suffix = """
uint8_t do_one_computation(uint8_t *data) {
 uint32_t n; memcpy(&n,data,sizeof n); uint8_t result=base_computation(data);
 clock_ticks += 1000u + (remove_signal ? (n & 31u) : n); return result;
}
int main(int argc,char **argv) {
 const char *mode=getenv("AEGAEON_CONTROL_FIXTURE_MODE");
 dudect_require(mode && (!strcmp(mode,"on") || !strcmp(mode,"off")),"fixed fixture mode");
 remove_signal=!strcmp(mode,"off"); return base_main(argc,argv);
}
"""
            generated = d / "controls.c"
            generated.write_text(prefix + text + suffix)
            native = d / "native"
            argv = base["argv_before_binding"].copy()
            argv[argv.index("tests/constant_time/calibration_timing_test.c")] = str(generated)
            argv[argv.index("-o") + 1] = str(native)
            manifest = {
                "schema": "original-control-injected-clock/1",
                "base": base,
                "generated_sha256": sha(generated),
                "argv_before_binding": argv,
                "qualification": qualification_identity(),
                "physical_clock": False,
            }
            binding = {k: index[k] for k in ("contract_sha256", "numerical_sha256")}
            binding["build_sha256"] = digest(canonical(manifest))
            command = (
                argv
                + ["-DAEGAEON_DUDECT_CANDIDATE=1", '-DAEGAEON_DUDECT_SUITE="nix"']
                + [f'-DAEGAEON_DUDECT_{k.upper()}="{v}"' for k, v in binding.items()]
            )
            r = subprocess.run(  # noqa: PLW1510, S603 -- return code is inspected and retained after capture; explicit argv; artifact validation precedes execution
                command,
                cwd=source,
                env=os.environ | base["environment"],
                capture_output=True,
                timeout=120,
            )
            (d / "compile.stdout").write_bytes(r.stdout)
            (d / "compile.stderr").write_bytes(r.stderr)
            r.check_returncode()
            save(d / "build.json", manifest | {"binary_sha256": sha(native), "binding": binding})
            bindings = {n: binding | {"case_id": "nix/" + n, "profile": "pr"} for n in NAMES}
            for mode in ("on", "off"):
                dest = d / mode
                dest.mkdir()
                analysis = identity("control-role-correction-functional", f"{i}-{mode}", "ordinary")
                save(
                    dest / "invocation.json",
                    {
                        "analysis": analysis,
                        "binary_sha256": sha(native),
                        "build_manifest_sha256": sha(d / "build.json"),
                        "mode": mode,
                        "physical_clock": False,
                    },
                )
                os.environ["AEGAEON_CONTROL_FIXTURE_MODE"] = mode
                os.sched_setaffinity(0, set(cpus))
                with installed(analysis):
                    run_candidate.collect(SOURCE, dest, native, "pr", bindings)
                proc = json.loads((dest / "process.json").read_bytes())
                assert proc["exit"] == 0 and proc["collection_complete"]  # noqa: PT018 -- fixed functional fixture retains its combined obligation
                validate_diagnostics(dest, proc, bindings, "pr")
                rows = json.loads((dest / "observations.json").read_bytes())
                replay(dest, bindings, rows, analysis)
                entries = [
                    json.loads(l)
                    for l in (dest / "analysis-prefixes.jsonl").read_bytes().splitlines()  # noqa: E741 -- historical look identifier retained in the measured evaluator
                ]
                assessment = ordinary.evaluate_proofs(
                    bindings, rows, entries, analysis, sha(generated)
                )
                save(
                    dest / "qualification.json",
                    {
                        "assessment": assessment,
                        "qualified": all(x["qualification_passed"] for x in assessment),
                        "injected_clock": True,
                    },
                )
                expected = [True, mode == "on", mode == "on"]
                assert [x["qualification_passed"] for x in assessment] == expected
                if mode == "on":
                    for x in assessment[1:]:
                        assert (  # noqa: PT018 -- fixed functional fixture retains its combined obligation
                            x["original_role_result"]["requirement_satisfied"]
                            and not x["all_final_statistics_eligible"]
                            and x["native_support_limitations"]
                        )
                else:
                    for x in assessment[1:]:
                        assert (  # noqa: PT018 -- fixed functional fixture retains its combined obligation
                            "original_role_failed" in x["failures"]
                            and not x["original_role_result"]["requirement_satisfied"]
                        )
                checks.append(
                    {
                        "compiler": i,
                        "mode": mode,
                        "cases": 3,
                        "expected": expected,
                        "actual": [x["qualification_passed"] for x in assessment],
                        "real_callback": True,
                        "collector_worker_ACK": True,
                        "replay": True,
                        "physical_timing": False,
                    }
                )
                save(a.output / "progress.json", {"checks": checks})
                print(json.dumps(checks[-1]), flush=True)
    finally:
        os.sched_setaffinity(0, allowed)
    save(
        a.output / "result.json",
        {
            "passed": True,
            "processes": 4,
            "cases": 12,
            "looks": 96,
            "checks": checks,
            "seconds": time.monotonic() - start,
            "physical_timing": False,
        },
    )


if __name__ == "__main__":
    main()
