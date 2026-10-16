"""Compile explicit research overlays from an unchanged native Nix package."""
# ruff: noqa: E402, S603 -- source-specific imports and verified compiler argv

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/ci"))
from verify_dudect_analysis_matrix import require, sha256, write_json

PROVIDER = [
    "ct_eq_32",
    "ct_eq_64",
    "ct_eq_128",
    "sha256",
    "hmac_sha256",
    "ed25519_verify",
    "hmac_sha256_key",
]
CONTROLS = ["control_independent", "control_mean_shift", "control_variance_shift"]

SELFTEST = r"""
static int ct_preparation_selftest(void) {
    const size_t strides[] = {32,64,128,32,32,128,32};
    const test_id_t ids[] = {TEST_CT_EQ,TEST_CT_EQ,TEST_CT_EQ,TEST_SHA256,
        TEST_HMAC_SHA256,TEST_ED25519_VERIFY,TEST_HMAC_SHA256_KEY};
    uint8_t original[256*128], changed[256*128], old_labels[256], new_labels[256];
    memset(key_test_message,0x5a,sizeof(key_test_message));
    size_t callbacks = 0;
    for (size_t k=0; k<7; k++) {
        current_test=ids[k];
        dudect_config_t c={strides[k],256};
        ct_fixture_reset();
        prepare_reference(&c,original,old_labels);
        uint64_t state=ct_fixture_state;
        size_t requests=ct_fixture_requests, bytes=ct_fixture_bytes;
        dudect_require(requests==257 && bytes==256*(strides[k]+1), "original draw schedule");
        ct_fixture_reset();
        prepare_inputs(&c,changed,new_labels);
        dudect_require(state==ct_fixture_state && requests==ct_fixture_requests &&
                       bytes==ct_fixture_bytes, "unchanged random draw schedule");
        dudect_require(!memcmp(original,changed,256*strides[k]) &&
                       !memcmp(old_labels,new_labels,256), "unchanged full inputs and labels");
        for(size_t i=0;i<256;i+=31) {
            uint8_t before=do_one_computation(original+i*strides[k]);
            uint8_t after=do_one_computation(changed+i*strides[k]);
            dudect_require(before==after,"unchanged actual callback result"); callbacks++;
        }
    }
    printf("{\"cases\":7,\"callbacks\":%zu,\"timing_executed\":false}\n",callbacks);
    return 0;
}
"""

SIGNAL = r"""
uint8_t do_one_computation(uint8_t *data) {
    uint8_t result = ct_original_callback(data);
    if (current_test == TEST_CT_EQ && ct_preparation_active && ct_signal && data[0]) {
        uint32_t value = data[0];
        for (uint32_t i=0; i<16; i++) {
            value += i+1;
            __asm__ __volatile__("" : "+r"(value) : : "memory");
        }
    }
    return result;
}
"""


def replace_once(text: str, before: str, after: str) -> str:
    require(text.count(before) == 1, "Source anchor changed")
    return text.replace(before, after)


def build(package: Path, output: Path, variant: str) -> dict[str, Any]:  # noqa: PLR0915 -- one overlay build transaction
    require(variant in {"normal", "selftest", "signal"}, "Unknown build variant")
    output.mkdir(parents=True, exist_ok=False)
    source = output / "source"
    shutil.copytree(package / "sources", source)
    for path in [source, *source.rglob("*")]:
        path.chmod(0o700 if path.is_dir() else 0o600)
    original = json.loads((package / "native/dudect_harness/build-manifest.json").read_text())
    for name, digest in original["sources"].items():
        require(sha256(source / name) == digest, "Original package source changed")
    file = source / "c/dudect_harness.c"
    text = file.read_text()
    start = text.index("void prepare_inputs(")
    end = text.index("\nint main(", start)
    reference = text[start:end].replace("void prepare_inputs(", "void prepare_reference(", 1)
    text = replace_once(
        text, "/* ── Test selector ── */", '#include "ct_preparation.h"\n/* ── Test selector ── */'
    )
    anchor = "void prepare_inputs(dudect_config_t *c, uint8_t *input_data, uint8_t *classes) {"
    text = replace_once(
        text, anchor, anchor + "\n    if(current_test==TEST_CT_EQ) ct_preparation_begin(c);"
    )
    text = replace_once(
        text,
        "\n}\n\nint main(",
        "\n    if(current_test==TEST_CT_EQ) ct_preparation_finish(c,input_data,classes);"
        "\n}\n\nint main(",
    )
    anchor = "    memset(hmac_key, 0x42, HMAC_KEY_LEN);"
    text = replace_once(text, anchor, anchor + "\n    ct_preparation_init();")
    shutil.copy2(ROOT / "scripts/diagnostics/ct_preparation.h", source / "c/ct_preparation.h")
    if variant == "selftest":
        shutil.copy2(
            ROOT / "scripts/diagnostics/ct_preparation_selftest.h",
            source / "c/ct_preparation_selftest.h",
        )
        text = replace_once(
            text,
            "void prepare_inputs(",
            '#include "ct_preparation_selftest.h"\n' + reference + "\nvoid prepare_inputs(",
        )
        text = replace_once(text, "\nint main(", "\n" + SELFTEST + "\nint main(")
        text = replace_once(
            text,
            "    ct_preparation_init();",
            "    ct_preparation_init();\n    return ct_preparation_selftest();",
        )
    if variant == "signal":
        text = replace_once(
            text,
            "uint8_t do_one_computation(",
            "static int ct_signal;\nuint8_t ct_original_callback(",
        )
        text = replace_once(text, "void prepare_inputs(", SIGNAL + "\nvoid prepare_inputs(")
        text = replace_once(
            text,
            "    ct_preparation_init();",
            """    ct_preparation_init();
    const char *signal_mode=getenv("AEGAEON_DUDECT_PREPARATION_SIGNAL");
    dudect_require(signal_mode && (!strcmp(signal_mode,"0") || !strcmp(signal_mode,"16")),
                   "fixed signal dose");
    ct_signal=!strcmp(signal_mode,"16");""",
        )
        text = replace_once(
            text,
            "        if (status) return status;",
            "        if (status) return status;\n"
            "        if(i==2) return 0; /* Explicit sensitivity prefix. */",
        )
    file.write_text(text)
    argv = original["argv_before_binding"][:]
    binary = output / "dudect_harness"
    argv[argv.index("-o") + 1] = str(binary)
    manifest = {
        "schema": "dudect-ct-preparation-build/1",
        "variant": variant,
        "original_manifest_sha256": sha256(package / "native/dudect_harness/build-manifest.json"),
        "sources": {
            str(p.relative_to(source)): sha256(p) for p in sorted(source.rglob("*")) if p.is_file()
        },
        "argv_before_binding": argv,
        "environment": original["environment"],
        "contract_sha256": original["contract_sha256"],
        "numerical_sha256": json.loads((package / "package.json").read_text())["numerical_sha256"],
        "ordinary_gate_admission": False,
    }
    import hashlib  # noqa: PLC0415 -- manifest encoding next to its binding

    build_hash = hashlib.sha256(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    argv = [
        *argv,
        "-DAEGAEON_DUDECT_CANDIDATE=1",
        '-DAEGAEON_DUDECT_SUITE="nix"',
        f'-DAEGAEON_DUDECT_CONTRACT_SHA256="{manifest["contract_sha256"]}"',
        f'-DAEGAEON_DUDECT_BUILD_SHA256="{build_hash}"',
        f'-DAEGAEON_DUDECT_NUMERICAL_SHA256="{manifest["numerical_sha256"]}"',
    ]
    env = {
        k: v
        for k, v in os.environ.items()
        if k not in {"PYTHONPATH", "PYTHONHOME", "LD_PRELOAD", "LD_LIBRARY_PATH"}
    }
    env.update(original["environment"])
    with (output / "compile.log").open("xb") as log:
        subprocess.run(
            argv, cwd=source, env=env, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=120
        )
    manifest.update(
        build_sha256=build_hash,
        binary=str(binary),
        binary_sha256=sha256(binary),
        source=str(source),
    )
    write_json(output / "build.json", manifest)
    return manifest
