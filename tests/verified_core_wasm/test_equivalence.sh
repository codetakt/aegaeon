#!/usr/bin/env bash
# Execute native PKCE and WASM vector/ABI/adapter regressions.
# Native invalid-length assertions intentionally have a distinct scope.
# Local unavailable lanes may be skipped. CI must require each lane explicitly.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
WASM="${1:-$ROOT/tests/fixtures/verified-core/verified_core.wasm}"
require_native="${AEGAEON_REQUIRE_NATIVE_EQUIV:-0}"
require_wasm="${AEGAEON_REQUIRE_WASM:-0}"
for flag in "$require_native" "$require_wasm"; do
	if [[ $flag != 0 && $flag != 1 ]]; then
		echo "[error] requirement flags must be 0 or 1"
		exit 1
	fi
done

scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT
native_state=skipped
wasm_state=skipped
rc=0
pkce_path="$ROOT/tests/verified_core_wasm/vectors/pkce_s256.json"
if [[ -f $pkce_path ]]; then
	sha256sum "$pkce_path" >"$scratch/pkce-input.sha256"
fi

unavailable() {
	local lane="$1" required="$2" reason="$3"
	if [[ $required == 1 ]]; then
		echo "[error] $lane required but unavailable: $reason"
		rc=1
	else
		echo "[skip] $lane unavailable: $reason"
	fi
}

broken_native_linker() {
	local host sysroot wrapper wrapper_target
	host="$(rustc -vV | sed -n 's/^host: //p')"
	sysroot="$(rustc --print sysroot)"
	wrapper="$sysroot/lib/rustlib/$host/bin/gcc-ld/ld.lld"
	[[ -f $wrapper ]] || return 1
	wrapper_target="$(sed -n 's#^"\(.*ld-wrapper\.sh\)".*#\1#p' "$wrapper" | head -n 1)"
	if [[ -n $wrapper_target && ! -e $wrapper_target ]]; then
		echo "$wrapper_target missing"
		return 0
	fi
	return 1
}

# Bind established case identities as well as non-vacuity. Explicit additions
# are allowed; replacing an established case with another ID is an error.
check_pkce_vectors() {
	python3 - "$ROOT/tests/verified_core_wasm/vectors/pkce_s256.json" <<'PY'
import hashlib
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
data = path.read_bytes()
vectors = json.loads(data)
expected = {
    "vectors": {"rfc7636-appendix-b", "alpha-43", "max-length-128", "unreserved-mix", "same-char-43"},
    "error_vectors": {"too-short", "too-long-129", "invalid-char-space", "challenge-mismatch"},
}
for group, required in expected.items():
    cases = vectors[group]
    if not isinstance(cases, list) or not cases:
        raise ValueError(f"empty or invalid PKCE group: {group}")
    ids = [case["id"] for case in cases]
    if len(set(ids)) != len(ids) or not required.issubset(ids):
        raise ValueError(f"missing or duplicate PKCE identities: {group}")
    for case in cases:
        if not isinstance(case["id"], str) or not case["id"] or not isinstance(case["verifier"], str):
            raise ValueError(f"invalid PKCE case: {group}")
        if group == "vectors" and not isinstance(case["challenge"], str):
            raise ValueError("invalid PKCE challenge")
        if group == "error_vectors" and case["expect"] not in {"invalid_argument", "invalid_claims"}:
            raise ValueError("invalid PKCE error expectation")
    print(f"PKCE_INPUT {group}={json.dumps(ids)}")
print(f"PKCE_INPUT sha256={hashlib.sha256(data).hexdigest()}")
PY
}

run_native() {
	check_pkce_vectors || return 1
	(cd "$ROOT" && env -u LD cargo test -p ffi --test equivalence_pkce_test \
		--no-run --message-format=json >"$scratch/native-build.json") || return 1
	python3 - "$scratch/native-build.json" "$ROOT" >"$scratch/native-binary" <<'PY' || return 1
import json
import pathlib
import sys

artifacts = set()
source = pathlib.Path(sys.argv[2]) / "crates/ffi/tests/equivalence_pkce_test.rs"
manifest = source.parent.parent / "Cargo.toml"
for line in pathlib.Path(sys.argv[1]).read_text().splitlines():
    record = json.loads(line)
    if record.get("reason") != "compiler-artifact":
        continue
    target = record.get("target", {})
    if (target.get("name") == "equivalence_pkce_test"
            and target.get("kind") == ["test"] and record.get("profile", {}).get("test") is True
            and pathlib.Path(target.get("src_path", "")).resolve() == source.resolve()
            and pathlib.Path(record.get("manifest_path", "")).resolve() == manifest.resolve()
            and record.get("executable")
            and record.get("package_id")):
        artifacts.add(record["executable"])
if len(artifacts) != 1:
    raise ValueError(f"expected exactly one native PKCE test executable; got {len(artifacts)}")
binary = pathlib.Path(artifacts.pop())
if not binary.is_file():
    raise ValueError("native executable missing")
print(binary)
PY
	local binary test
	binary="$(cat "$scratch/native-binary")"
	[[ -x $binary ]] || return 1
	echo "NATIVE_ARTIFACT $binary"
	sha256sum "$binary" || return 1
	"$binary" --list >"$scratch/native-list" || return 1
	cat "$scratch/native-list"
	for test in pkce_s256_generate_matches_vectors pkce_s256_verify_matches_vectors; do
		if ! grep -Fxq "$test: test" "$scratch/native-list"; then
			echo "[error] missing native test: $test"
			return 1
		fi
		if "$binary" "$test" --exact --nocapture >"$scratch/native-test" 2>&1; then
			cat "$scratch/native-test"
		else
			cat "$scratch/native-test"
			return 1
		fi
		if ! grep -Fq 'test result: ok. 1 passed; 0 failed; 0 ignored;' "$scratch/native-test"; then
			echo "[error] native test did not execute: $test"
			return 1
		fi
		python3 - "$scratch/native-test" "$ROOT/tests/verified_core_wasm/vectors/pkce_s256.json" "$test" <<'PY' || return 1
import hashlib
import json
import pathlib
import sys

output = pathlib.Path(sys.argv[1]).read_text()
data = pathlib.Path(sys.argv[2]).read_bytes()
vectors = json.loads(data)
digest = hashlib.sha256(data).hexdigest()
if f"NATIVE_PKCE_INPUT sha256={digest}" not in output:
    raise ValueError("native test did not bind the selected PKCE input")
route = "generate" if sys.argv[3] == "pkce_s256_generate_matches_vectors" else "verify"
for case in vectors["vectors"]:
    if f'NATIVE_PKCE_CASE {route}/{case["id"]} passed' not in output:
        raise ValueError(f"native case did not complete: {route}/{case['id']}")
if route == "verify":
    for case in vectors["error_vectors"]:
        if f'NATIVE_PKCE_CASE error/{case["id"]} passed (existing native assertions)' not in output:
            raise ValueError(f"native error case did not complete: {case['id']}")
PY
	done
}

echo "=== Native PKCE and WASM regression execution ==="
echo "[1/2] Native PKCE regression"
if ! command -v cargo >/dev/null 2>&1; then
	unavailable native "$require_native" "cargo missing"
elif ! command -v rustc >/dev/null 2>&1; then
	unavailable native "$require_native" "rustc missing"
elif ! command -v python3 >/dev/null 2>&1; then
	unavailable native "$require_native" "python3 missing"
elif reason="$(broken_native_linker)"; then
	unavailable native "$require_native" "broken native linker wrapper ($reason)"
elif run_native; then
	native_state=passed
else
	native_state=failed
	rc=1
fi

echo "[2/2] WASM vector, ABI and adapter regressions"
if [[ -d $WASM ]]; then
	if ! find -L "$WASM" -type f -name '*.wasm' -print0 >"$scratch/wasm-paths"; then
		echo "[error] WASM artifact scan failed"
		wasm_state=failed
		rc=1
	else
		mapfile -d '' -t wasm_files <"$scratch/wasm-paths"
		if [[ ${#wasm_files[@]} == 1 ]]; then
			WASM="${wasm_files[0]}"
		else
			echo "[error] expected one WASM artifact, found ${#wasm_files[@]}"
			wasm_state=failed
			rc=1
		fi
	fi
fi

node_command=(node)
if [[ $wasm_state != failed ]]; then
	if [[ ! -f $WASM ]]; then
		unavailable wasm "$require_wasm" "WASM artifact missing: $WASM"
	else
		printf 'type Probe = number; console.log(0);\n' >"$scratch/node-probe.ts"
		if ! command -v node >/dev/null 2>&1 ||
			! node --experimental-strip-types "$scratch/node-probe.ts" >/dev/null 2>&1; then
			if [[ $require_wasm == 0 ]] && command -v nix >/dev/null 2>&1 &&
				nix develop "$ROOT#typescript" --command node --experimental-strip-types "$scratch/node-probe.ts" >/dev/null 2>&1; then
				node_command=(nix develop "$ROOT#typescript" --command node)
			else
				unavailable wasm "$require_wasm" "Node with type stripping missing (pinned fallback unavailable)"
				node_command=()
			fi
		fi
		if [[ ${#node_command[@]} -gt 0 ]]; then
			if check_pkce_vectors && "${node_command[@]}" --experimental-strip-types \
				"$SCRIPT_DIR/test_equivalence_wasm.ts" "$WASM"; then
				wasm_state=passed
			else
				wasm_state=failed
				rc=1
			fi
		fi
	fi
fi

if [[ $native_state == passed || $wasm_state == passed ]]; then
	if [[ ! -f $scratch/pkce-input.sha256 ]] || ! sha256sum -c "$scratch/pkce-input.sha256"; then
		echo "[error] shared PKCE input changed during execution"
		rc=1
	fi
fi
echo "NATIVE_RESULT=$native_state WASM_RESULT=$wasm_state"
if [[ $rc != 0 ]]; then
	echo "REGRESSION EXECUTION FAILED"
elif [[ $native_state == passed && $wasm_state == passed ]]; then
	echo "REGRESSION EXECUTION COMPLETE: shared PKCE success vectors and scoped WASM regressions passed"
	echo "Native invalid-length PKCE checks have distinct existing assertions; this is not universal equivalence or release-server validation."
else
	echo "REGRESSION EXECUTION INCOMPLETE: one or more lanes skipped"
fi
exit "$rc"
