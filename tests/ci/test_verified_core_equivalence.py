"""Exercise the actual native/WASM wrapper with controlled and real children."""

# Fixed argv fixtures use unittest assertions, including when run with Python -O.
# ruff: noqa: PT009, S603
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BASH = shutil.which("bash")
HELPERS = (
    "replay_store_result_boundary_test.mjs",
    "dpop_time_policy_boundary_test.mjs",
    "dpop_iat_numericdate_boundary_test.mjs",
    "pkce_alias_test.ts",
)


class VerifiedCoreEquivalenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        nix = shutil.which("nix")
        if nix is None:
            message = "Nix is required to resolve the declared pinned Node"
            raise RuntimeError(message)
        result = subprocess.run(
            [nix, "develop", f"{ROOT}#typescript", "--command", "node", "-p", "process.execPath"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=True,
            timeout=120,
        )
        cls.node = result.stdout.strip()
        if not Path(cls.node).is_file():
            message = "Declared TypeScript shell did not resolve an executable Node"
            raise RuntimeError(message)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        for tool in (
            "env",
            "python3",
            "sed",
            "head",
            "cat",
            "sha256sum",
            "grep",
            "mktemp",
            "rm",
            "find",
            "dirname",
        ):
            (self.bin / tool).symlink_to(shutil.which(tool))
        paths = [
            "tests/verified_core_wasm/test_equivalence.sh",
            "tests/verified_core_wasm/test_equivalence_wasm.ts",
            "tests/verified_core_wasm/vectors/pkce_s256.json",
            "tests/verified_core_wasm/vectors/pure_functions.json",
            "tests/fixtures/verified-core/verified_core.wasm",
            "scripts/sdk/runtime_node_reference.ts",
            "scripts/sdk/runtime_web_reference.ts",
            "crates/ffi/tests/equivalence_pkce_test.rs",
        ] + [f"tests/verified_core_wasm/{name}" for name in HELPERS]
        for relative in paths:
            destination = self.root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, destination)
        (self.root / "package.json").write_text('{"type":"module"}')
        self.wrapper = self.root / "tests/verified_core_wasm/test_equivalence.sh"
        self.wasm = self.root / "tests/fixtures/verified-core/verified_core.wasm"
        self.native = self.tool(
            "native-test",
            """
if [[ $1 == --list ]]; then
    if [[ ${ZERO_NATIVE:-0} != 1 ]]; then
        echo 'pkce_s256_generate_matches_vectors: test'
        [[ ${OMIT_VERIFY:-0} == 1 ]] || echo 'pkce_s256_verify_matches_vectors: test'
    fi
    exit 0
fi
echo "test $1 ... ok"
echo "NATIVE_PKCE_INPUT sha256=$PKCE_HASH"
for id in rfc7636-appendix-b alpha-43 max-length-128 unreserved-mix same-char-43; do
    route=verify
    [[ $1 != pkce_s256_generate_matches_vectors ]] || route=generate
    echo "NATIVE_PKCE_CASE $route/$id passed"
done
if [[ $1 == pkce_s256_verify_matches_vectors ]]; then
    for id in too-short too-long-129 invalid-char-space challenge-mismatch; do
        echo "NATIVE_PKCE_CASE error/$id passed (existing native assertions)"
    done
fi
if [[ ${ZERO_RUN:-0} == 1 ]]; then
    echo 'test result: ok. 0 passed; 0 failed; 0 ignored;'
else
    echo 'test result: ok. 1 passed; 0 failed; 0 ignored;'
fi
exit "${NATIVE_RC:-0}"
""",
        )
        self.tool(
            "cargo",
            """
if [[ ${CARGO_RC:-0} != 0 ]]; then
    echo 'success before build failure' >&2
    exit "$CARGO_RC"
fi
if [[ ${BAD_JSON:-0} == 1 ]]; then echo broken-json; exit 0; fi
[[ ${NO_ARTIFACT:-0} == 1 ]] || echo "$CARGO_ARTIFACT"
""",
        )
        self.tool(
            "rustc",
            """
if [[ $1 == -vV ]]; then echo 'host: test-host'; else echo "$TEST_SYSROOT"; fi
""",
        )
        self.tool(
            "node",
            """
if [[ $2 == *node-probe.ts ]]; then exit "${NODE_PROBE_RC:-0}"; fi
echo 'WASM child success text'
exit "${WASM_RC:-0}"
""",
        )
        self.env = os.environ.copy()
        self.env.update(
            {
                "PATH": str(self.bin),
                "AEGAEON_REQUIRE_NATIVE_EQUIV": "1",
                "AEGAEON_REQUIRE_WASM": "1",
                "TEST_SYSROOT": str(self.root / "sysroot"),
                "PKCE_HASH": hashlib.sha256(
                    (self.root / "tests/verified_core_wasm/vectors/pkce_s256.json").read_bytes()
                ).hexdigest(),
                "CARGO_ARTIFACT": json.dumps(
                    {
                        "reason": "compiler-artifact",
                        "package_id": "path+file:///fixture/crates/ffi#ffi@0.9.0-beta",
                        "manifest_path": str(self.root / "crates/ffi/Cargo.toml"),
                        "profile": {"test": True},
                        "target": {
                            "name": "equivalence_pkce_test",
                            "kind": ["test"],
                            "src_path": str(
                                self.root / "crates/ffi/tests/equivalence_pkce_test.rs"
                            ),
                        },
                        "executable": str(self.native),
                    }
                ),
            }
        )
        for variable in (
            "CARGO_RC",
            "NATIVE_RC",
            "WASM_RC",
            "NODE_PROBE_RC",
            "ZERO_NATIVE",
            "ZERO_RUN",
            "OMIT_VERIFY",
            "BAD_JSON",
            "NO_ARTIFACT",
        ):
            self.env.pop(variable, None)

    def tool(self, name, body):
        path = self.bin / name
        path.write_text(f"#!{BASH}\nset -eu\n" + body)
        path.chmod(0o755)
        return path

    def real_node(self):
        (self.bin / "node").unlink()
        (self.bin / "node").symlink_to(self.node)

    def run_wrapper(self, expected, path=None, **environment):
        env = self.env | environment
        result = subprocess.run(
            [BASH, str(self.wrapper), str(path or self.wasm)],
            cwd=self.root,
            env=env,
            text=True,
            capture_output=True,
            timeout=45,
            check=False,
        )
        self.assertEqual(result.returncode == 0, expected == 0, result.stdout + result.stderr)
        self.assertIn("=== Native PKCE and WASM regression execution ===", result.stdout)
        if expected:
            self.assertNotIn("REGRESSION EXECUTION COMPLETE", result.stdout)
        self.assertNotIn("EQUIVALENCE CONFIRMED", result.stdout)
        return result.stdout

    def test_success_requires_both_named_native_tests(self):
        output = self.run_wrapper(0)
        self.assertIn("NATIVE_RESULT=passed WASM_RESULT=passed", output)

    def test_requirement_flags_are_independent(self):
        for tool in ("cargo", "rustc"):
            with self.subTest(tool=tool):
                saved = (self.bin / tool).read_bytes()
                (self.bin / tool).unlink()
                self.run_wrapper(1, AEGAEON_REQUIRE_NATIVE_EQUIV="1", AEGAEON_REQUIRE_WASM="0")
                output = self.run_wrapper(
                    0, AEGAEON_REQUIRE_NATIVE_EQUIV="0", AEGAEON_REQUIRE_WASM="1"
                )
                self.assertIn("REGRESSION EXECUTION INCOMPLETE", output)
                (self.bin / tool).write_bytes(saved)
                (self.bin / tool).chmod(0o755)

    def test_required_missing_node_and_unsupported_types_do_not_use_fallback(self):
        self.tool("nix", "echo 'fallback must not execute' >&2; exit 99\n")
        self.run_wrapper(1, NODE_PROBE_RC="1", AEGAEON_REQUIRE_NATIVE_EQUIV="0")
        (self.bin / "node").unlink()
        self.run_wrapper(1, AEGAEON_REQUIRE_NATIVE_EQUIV="0")

    def test_optional_unsupported_node_with_unavailable_fallback_is_incomplete(self):
        self.tool("nix", "exit 127\n")
        output = self.run_wrapper(0, NODE_PROBE_RC="1", AEGAEON_REQUIRE_WASM="0")
        self.assertIn("NATIVE_RESULT=passed WASM_RESULT=skipped", output)
        self.assertIn("REGRESSION EXECUTION INCOMPLETE", output)

    def test_optional_missing_node_is_incomplete(self):
        (self.bin / "node").unlink()
        output = self.run_wrapper(0, AEGAEON_REQUIRE_WASM="0")
        self.assertIn("REGRESSION EXECUTION INCOMPLETE", output)

    def test_broken_linker_is_enforced_only_by_native_flag(self):
        wrapper = self.root / "sysroot/lib/rustlib/test-host/bin/gcc-ld/ld.lld"
        wrapper.parent.mkdir(parents=True)
        wrapper.write_text('"/missing/ld-wrapper.sh" "$@"\n')
        self.run_wrapper(1, AEGAEON_REQUIRE_NATIVE_EQUIV="1", AEGAEON_REQUIRE_WASM="0")
        output = self.run_wrapper(0, AEGAEON_REQUIRE_NATIVE_EQUIV="0", AEGAEON_REQUIRE_WASM="1")
        self.assertIn("NATIVE_RESULT=skipped WASM_RESULT=passed", output)

    def test_child_success_text_does_not_mask_failure(self):
        for variable in ("CARGO_RC", "NATIVE_RC", "WASM_RC"):
            with self.subTest(variable=variable):
                self.run_wrapper(1, **{variable: "19"})

    def test_missing_zero_or_malformed_native_artifacts_fail(self):
        for variable in ("NO_ARTIFACT", "BAD_JSON", "ZERO_NATIVE", "OMIT_VERIFY", "ZERO_RUN"):
            with self.subTest(variable=variable):
                self.run_wrapper(1, **{variable: "1"})

    def test_wrong_native_target_and_nonexistent_binary_fail(self):
        record = json.loads(self.env["CARGO_ARTIFACT"])
        record["target"]["name"] = "other"
        self.run_wrapper(1, CARGO_ARTIFACT=json.dumps(record))
        record["target"]["name"] = "equivalence_pkce_test"
        record["executable"] = str(self.root / "missing-binary")
        self.run_wrapper(1, CARGO_ARTIFACT=json.dumps(record))

    def test_native_vector_binding_and_case_completion_are_required(self):
        self.run_wrapper(1, PKCE_HASH="incorrect-digest")
        self.native.write_text(self.native.read_text().replace("same-char-43; do", "; do"))
        self.run_wrapper(1)

    def test_missing_and_ambiguous_wasm_fail_when_required(self):
        self.run_wrapper(1, path=self.root / "missing.wasm")
        output = self.run_wrapper(0, path=self.root / "missing.wasm", AEGAEON_REQUIRE_WASM="0")
        self.assertIn("REGRESSION EXECUTION INCOMPLETE", output)
        shutil.copy2(self.wasm, self.wasm.parent / "second.wasm")
        self.run_wrapper(1, path=self.wasm.parent)

    def test_empty_wasm_directory_and_single_output(self):
        empty = self.root / "empty-output"
        empty.mkdir()
        self.run_wrapper(1, path=empty)
        self.run_wrapper(0, path=self.wasm.parent)

    def test_wrapper_rejects_one_wasm_path_followed_by_scan_failure(self):
        (self.bin / "find").unlink()
        self.tool("find", 'printf "%s\\0" "$SELECTED_WASM"; exit 23\n')
        output = self.run_wrapper(1, path=self.wasm.parent, SELECTED_WASM=str(self.wasm))
        self.assertIn("WASM artifact scan failed", output)
        self.assertNotIn("WASM child success text", output)

    def test_workflow_rejects_one_wasm_path_followed_by_scan_failure(self):
        workflow = (ROOT / ".github/workflows/verification.yml").read_text()
        job = workflow.split("  verified-core-equivalence:", 1)[1].split("  # Dudect", 1)[0]
        command = textwrap.dedent(job.split("        run: |\n", 1)[1])
        (self.bin / "find").unlink()
        self.tool("find", 'printf "%s\\0" "$SELECTED_WASM"; exit 23\n')
        self.tool("nix", "echo 'unexpected lane execution'; exit 0\n")
        result = subprocess.run(
            [BASH, "-c", command],
            cwd=self.root,
            env=self.env | {"SELECTED_WASM": str(self.wasm)},
            text=True,
            capture_output=True,
            check=False,
            timeout=45,
        )
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("WASM build output scan failed", result.stdout)
        self.assertNotIn("unexpected lane execution", result.stdout)

    def test_pkce_inputs_missing_invalid_empty_or_substituted_fail(self):
        path = self.root / "tests/verified_core_wasm/vectors/pkce_s256.json"
        original = path.read_text()
        path.unlink()
        self.run_wrapper(1)
        path.write_text("not json")
        self.run_wrapper(1)
        for group in ("vectors", "error_vectors"):
            data = json.loads(original)
            data[group] = []
            path.write_text(json.dumps(data))
            self.run_wrapper(1)
            data = json.loads(original)
            data[group][0]["id"] = "replacement-same-count"
            path.write_text(json.dumps(data))
            self.run_wrapper(1)

    def test_actual_node_rejects_malformed_wasm_and_missing_exports(self):
        self.real_node()
        self.wasm.write_bytes(b"malformed")
        self.run_wrapper(1)
        self.wasm.write_bytes(b"\0asm\x01\0\0\0")
        self.run_wrapper(1)

    def test_actual_node_rejects_invalid_pure_vector_groups(self):
        self.real_node()
        path = self.root / "tests/verified_core_wasm/vectors/pure_functions.json"
        original = path.read_text()
        path.unlink()
        self.run_wrapper(1)
        path.write_text("invalid")
        self.run_wrapper(1)
        for group in ("status_to_u32", "iat_in_window", "not_expired", "is_active"):
            data = json.loads(original)
            data[group] = []
            path.write_text(json.dumps(data))
            self.run_wrapper(1)
        data = json.loads(original)
        data["iat_in_window"][0]["id"] = "replacement-same-count"
        path.write_text(json.dumps(data))
        self.run_wrapper(1)

    def test_actual_node_rejects_missing_helper_export_and_zero_or_missing_case_execution(self):
        self.real_node()
        path = self.root / "tests/verified_core_wasm/replay_store_result_boundary_test.mjs"
        original = path.read_text()
        path.unlink()
        self.run_wrapper(1)
        for replacement in (
            "export const unrelated = 1;",
            "export async function checkReplayStoreResults() { return 0; }",
            "export async function checkReplayStoreResults() { return 46; }",
            original.replace(
                "onCheck?.(`${kind}/result/${label}`);",
                'if (label !== "false") onCheck?.(`${kind}/result/${label}`);',
            ),
        ):
            path.write_text(replacement)
            self.run_wrapper(1)

    def test_actual_node_success_and_optional_native_skip(self):
        self.real_node()
        output = self.run_wrapper(0)
        digest = hashlib.sha256(self.wasm.read_bytes()).hexdigest()
        self.assertIn(f"WASM_ARTIFACT sha256={digest}", output)
        self.assertIn("WASM_HELPER_RESULT replay checks=46 completed=46", output)
        self.assertIn("WASM_HELPER_CASE alias/adapter/web passed", output)
        (self.bin / "cargo").unlink()
        output = self.run_wrapper(0, AEGAEON_REQUIRE_NATIVE_EQUIV="0")
        self.assertIn("REGRESSION EXECUTION INCOMPLETE", output)

    def test_actual_node_requires_the_reference_adapter_inputs(self):
        self.real_node()
        for adapter in ("node", "web"):
            with self.subTest(adapter=adapter):
                path = self.root / f"scripts/sdk/runtime_{adapter}_reference.ts"
                original = path.read_bytes()
                path.unlink()
                self.run_wrapper(1)
                path.write_bytes(original)

    def test_helper_callback_omission_and_failed_assertion_reporting(self):
        self.real_node()
        script = self.root / "helper-compatibility.ts"
        script.write_text("""
import assert from "node:assert/strict";
import { pathToFileURL } from "node:url";
const root = process.argv[2], wasm = process.argv[3];
for (const [file, name, alias] of [
 ["replay_store_result_boundary_test.mjs", "checkReplayStoreResults", false],
 ["dpop_time_policy_boundary_test.mjs", "checkDpopTimePolicyBounds", false],
 ["dpop_iat_numericdate_boundary_test.mjs", "checkDpopIatNumericDates", false],
 ["pkce_alias_test.ts", "checkPkceAliasing", true],
]) {
 const { [name]: run } = await import(pathToFileURL(`${root}/tests/verified_core_wasm/${file}`));
 const args = alias ? [wasm] : [root, wasm];
 const ordinary = await run(...args);
 const labels = [];
 const reported = await run(...args, id => labels.push(id));
 assert.equal(ordinary, reported, file);
 assert.ok(labels.length > 0, file);
}
""")
        result = subprocess.run(
            [self.node, "--experimental-strip-types", str(script), str(self.root), str(self.wasm)],
            cwd=self.root,
            text=True,
            capture_output=True,
            timeout=45,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        script.write_text("""
import assert from "node:assert/strict";
import { pathToFileURL } from "node:url";
const root = process.argv[2], wasm = process.argv[3];
const file = process.argv[4], name = process.argv[5];
const {[name]: run} = await import(pathToFileURL(`${root}/tests/verified_core_wasm/${file}`));
const args = name === "checkPkceAliasing" ? [wasm] : [root, wasm];
const completed = [];
await assert.rejects(run(...args, id => completed.push(id)), /injected assertion failure/);
assert.deepEqual(completed, []);
""")
        failures = (
            (
                HELPERS[0],
                "checkReplayStoreResults",
                "assert.deepEqual([...actualNamespace], [...namespace]);",
            ),
            (
                HELPERS[1],
                "checkDpopTimePolicyBounds",
                "assert.equal(read(route,ptr),route.bits===64 ? BigInt(value) : value);",
            ),
            (
                HELPERS[2],
                "checkDpopIatNumericDates",
                "assert.equal(returnCode, expectedStatus, `${context}: return status`);",
            ),
            (HELPERS[3], "checkPkceAliasing", "assert.equal(generated.code, 0);"),
        )
        for file, name, first_assertion in failures:
            with self.subTest(helper=file):
                helper = self.root / f"tests/verified_core_wasm/{file}"
                original = helper.read_text()
                self.assertIn(first_assertion, original)
                helper.write_text(
                    original.replace(
                        first_assertion, 'assert.fail("injected assertion failure");', 1
                    )
                )
                result = subprocess.run(
                    [
                        self.node,
                        "--experimental-strip-types",
                        str(script),
                        str(self.root),
                        str(self.wasm),
                        file,
                        name,
                    ],
                    cwd=self.root,
                    text=True,
                    capture_output=True,
                    timeout=45,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                helper.write_text(original)

    def test_workflow_requires_both_flags_and_declared_pinned_node(self):
        workflow = (ROOT / ".github/workflows/verification.yml").read_text()
        job = workflow.split("  verified-core-equivalence:", 1)[1].split("  # Dudect", 1)[0]
        self.assertIn("AEGAEON_REQUIRE_WASM=1 AEGAEON_REQUIRE_NATIVE_EQUIV=1", job)
        self.assertIn("nix develop .#typescript --command", job)
        self.assertIn('"${#wasm_files[@]}" -ne 1', job)
        self.assertIn("No .wasm file found", job)
        self.assertNotIn("nixpkgs#nodejs", job)


if __name__ == "__main__":
    unittest.main()
