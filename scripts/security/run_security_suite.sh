#!/usr/bin/env bash

# Reject inherited functions before even `set`: they can shadow builtins or
# promote an explicit nonfuzz selection into fuzz dispatch after admission.
# Use only shell syntax until an explicit external interpreter path.
security_function_path="${PATH-}"
security_function_pending=1
security_function_python=""
while [[ $security_function_pending -eq 1 && -z $security_function_python ]]; do
	case "$security_function_path" in
	*:*)
		security_function_directory="${security_function_path%%:*}"
		security_function_path="${security_function_path#*:}"
		;;
	*)
		security_function_directory="$security_function_path"
		security_function_pending=0
		;;
	esac
	security_function_candidate="${security_function_directory:-.}/python3"
	if [[ -f $security_function_candidate && -x $security_function_candidate ]]; then
		security_function_python="$security_function_candidate"
	fi
done
security_function_status=1
if [[ -n $security_function_python ]]; then
	# Bash cannot import slash-named functions. Inspect keys only, never bodies.
	if "$security_function_python" -I -c 'import os, sys; sys.exit(any(key.startswith("BASH_FUNC_") and key.endswith("%%") for key in os.environ))'; then
		security_function_status=0
	fi
fi
if [[ $security_function_status -ne 0 ]]; then
	security_function_error=""
	# Expansion fails before dispatch even if exit, exec or : was imported.
	"${security_function_error:?[security] security suite requires external Python and no inherited shell functions}"
fi

# Aggregated security checks (used by `nix run .#security-suite`).

set -euo pipefail

SECURITY_ENTRY_ARGS=("$@")

FUZZ_LONG=0
SECURITY_STAGES=()
while [[ $# -gt 0 ]]; do
	case "$1" in
	--fuzz-long)
		FUZZ_LONG=1
		shift
		;;
	--stage)
		if [[ $# -lt 2 ]]; then
			echo "[security] --stage requires a value" >&2
			exit 1
		fi
		SECURITY_STAGES+=("$2")
		shift 2
		;;
	--)
		shift
		break
		;;
	*)
		break
		;;
	esac
done

validate_stages() {
	local known=(
		supply-chain
		runtime-tests
		jose-boundaries
		cargo-vet
		fuzz
		sanitizers
		sbom
		geiger
		udeps
	)
	local stage found
	for stage in "${SECURITY_STAGES[@]}"; do
		found=0
		for known_stage in "${known[@]}"; do
			if [[ $stage == "$known_stage" ]]; then
				found=1
				break
			fi
		done
		if [[ $found -eq 0 ]]; then
			echo "[security] unknown stage: $stage" >&2
			echo "[security] allowed stages: ${known[*]}" >&2
			exit 1
		fi
	done
}

validate_stages

stage_enabled() {
	local requested="$1"
	if [[ ${#SECURITY_STAGES[@]} -eq 0 ]]; then
		return 0
	fi
	local stage
	for stage in "${SECURITY_STAGES[@]}"; do
		if [[ $stage == "$requested" ]]; then
			return 0
		fi
	done
	return 1
}

# Clear only the inherited WASI compiler values handled by the native fallback.
# Preflight must validate the same effective inputs that native builds will use.
if [[ ${CC:-} == *"wasm32-unknown-wasi"* ]]; then
	unset CC
fi
if [[ ${CXX:-} == *"wasm32-unknown-wasi"* ]]; then
	unset CXX
fi

# Anchor the caller's Cargo home lexically before any preflight or setup.
# Keep the same destination through validation and later directory creation.
if [[ -n ${CARGO_HOME:-} ]]; then
	if [[ $CARGO_HOME != /* ]]; then
		CARGO_HOME="$PWD/$CARGO_HOME"
	fi
	export CARGO_HOME
fi

if stage_enabled "fuzz"; then
	# Resolve the physical script route before any override-influenced Git call
	# or prior-receipt invalidation. Other stages retain their existing dispatch.
	fuzz_guard_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)" || exit 1
	python3 -I "$fuzz_guard_root/scripts/fuzz/manage_fuzz_corpus.py" --validate-git-environment || exit 1
fi

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
export ROOT
SECURITY_ARTIFACT_DIR="${SECURITY_ARTIFACT_DIR:-artifacts/security/latest}"
SECURITY_HISTORY_DIR="${SECURITY_HISTORY_DIR:-artifacts/security/history}"
export SECURITY_ARTIFACT_DIR SECURITY_HISTORY_DIR

# Retire previous fuzz results before any directory setup or suite logging can fail.
# Relative evidence and target paths keep their repository-root interpretation.
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target/security-suite}"
if stage_enabled "fuzz"; then
	fuzz_receipt_dir="${SECURITY_ARTIFACT_DIR:-artifacts/security/latest}/fuzz"
	if [[ $fuzz_receipt_dir != /* ]]; then
		fuzz_receipt_dir="$ROOT/$fuzz_receipt_dir"
	fi
	# Use the same suite-owned collection destinations for every helper action.
	# An inherited helper-only route must not change the source exclusions midway.
	export FUZZ_RUN_ARTIFACT_DIR="$fuzz_receipt_dir" FUZZ_HISTORY_DIR="$SECURITY_HISTORY_DIR"
	python3 -I "$ROOT/scripts/fuzz/manage_fuzz_corpus.py" --validate-preflight "$fuzz_receipt_dir" || exit 1
	if ! rm -f -- "$fuzz_receipt_dir/collection.ok" "$fuzz_receipt_dir/execution.json" \
		"$fuzz_receipt_dir/run_summary.json"; then
		echo "[security] cannot invalidate previous fuzz results; retaining transient outputs" >&2
		exit 1
	fi
	python3 -I "$ROOT/scripts/fuzz/manage_fuzz_corpus.py" --validate-cache "$fuzz_receipt_dir" || exit 1
fi

# Only create the already validated caller-owned Cargo home after invalidation.
if [[ -n ${CARGO_HOME:-} ]]; then
	mkdir -p "$CARGO_HOME"
fi
cd "$ROOT"

# The handled WASI values were cleared before preflight. Complete the existing
# native-tool fallback only after validation and receipt invalidation.
if [[ -z ${CC:-} ]] && command -v cc >/dev/null 2>&1; then
	CC="$(command -v cc)"
	export CC
fi
if [[ -z ${CXX:-} ]] && command -v c++ >/dev/null 2>&1; then
	CXX="$(command -v c++)"
	export CXX
fi

ARTIFACT_BASE="$SECURITY_ARTIFACT_DIR"
LOG_DIR="$ARTIFACT_BASE/summary"
LOG_FILE="$LOG_DIR/security.log"
if stage_enabled "sanitizers"; then
	# Validate sanitizer-owned evidence before shared logging can create outputs.
	# shellcheck source=scripts/sanitizers/sanitizer_paths.sh
	source "$ROOT/scripts/sanitizers/sanitizer_paths.sh"
	# Shared validators report through the wrapper's existing diagnostics.
	fail() { echo "[security] $*" >&2; }
	preflight_route "$ARTIFACT_BASE" || exit 1
	ARTIFACT_BASE=$PREFLIGHT_ROUTE
	sanitizer_validate_output "$ARTIFACT_BASE" "$ROOT" || exit 1
	LOG_DIR="$ARTIFACT_BASE/summary"
	preflight_route "$LOG_DIR" || exit 1
	LOG_DIR=$PREFLIGHT_ROUTE
	LOG_FILE="$LOG_DIR/security.log"
fi
SECURITY_LOG_PATH=$LOG_FILE

reset_cargo_target_dir() {
	local dir="${CARGO_TARGET_DIR:-}"
	if [ -z "$dir" ]; then
		return 0
	fi
	rm -rf "$dir" || true
	mkdir -p "$dir" || true
}

cleanup_fuzz_outputs() {
	local cache
	cache="$(python3 -I scripts/fuzz/manage_fuzz_corpus.py --cleanup-cache "$1" "$2")" || return 1
	# The terminal sentinel preserves even trailing newlines in a configured path.
	[[ $cache == *$'\n.' ]] || return 1
	cache="${cache%$'\n.'}"
	rm -rf -- "$cache" fuzz/artifacts fuzz/corpus fuzz/corpus_archive
}

prepare_sanitizer_attempt() {
	SANITIZER_EVIDENCE_ROUTE_CHANGED=0
	SANITIZER_CLEANUP_BINDING=""
	preflight_route "$ARTIFACT_BASE/sanitizers" || return 1
	SANITIZER_ARTIFACT_DIR=$PREFLIGHT_ROUTE
	sanitizer_validate_output "$SANITIZER_ARTIFACT_DIR" "$ROOT" || return 1
	sanitizer_initialize_evidence || return 1
	SANITIZER_EVIDENCE_BINDING=$(sanitizer_target_binding prepare "$SANITIZER_ARTIFACT_DIR") || return $?
	# Retire stale success before rejecting flags, but never initialize target outputs.
	if sanitizer_validate_cargo_flags "${SANITIZER_CARGO_FLAGS:-}" "${SANITIZER_BUILD_EXTRA_ARGS:-}"; then
		:
	else
		local flag_status=$?
		if sanitizer_target_binding validate "$SANITIZER_EVIDENCE_BINDING"; then
			preflight_receipt cargo-flags "$flag_status" || return 1
		fi
		return "$flag_status"
	fi
	preflight_route "${SANITIZER_TARGET_DIR:-target/sanitizers}" || return 1
	SANITIZER_VALIDATED_TARGET=$PREFLIGHT_ROUTE
	sanitizer_validate_output "$SANITIZER_VALIDATED_TARGET" "$ROOT" || return 1
	# Cleanup can never contain or remove retained evidence or other stage logs.
	preflight_route "$ARTIFACT_BASE" || return 1
	sanitizer_validate_pair "$SANITIZER_VALIDATED_TARGET" "$PREFLIGHT_ROUTE" cleanup || return 1
	SANITIZER_CLEANUP_BINDING=$(sanitizer_target_binding prepare "$SANITIZER_VALIDATED_TARGET") || return $?
}

cleanup_sanitizer_outputs() {
	[[ -n $SANITIZER_CLEANUP_BINDING ]] || return 1
	sanitizer_target_binding cleanup "$SANITIZER_CLEANUP_BINDING"
}

discover_devtools_manifests() {
	local dir="${1:-dev-tools}"
	if [ ! -d "$dir" ]; then
		return 0
	fi
	find "$dir" -mindepth 2 -maxdepth 2 -type f -name Cargo.toml -print 2>/dev/null | sort
}

devtool_name_from_manifest() {
	local manifest="$1"
	local tool_dir
	tool_dir="$(dirname "$manifest")"
	basename "$tool_dir"
}

run_devtool_cargo_deny() {
	local manifest="$1"
	shift
	local tool_dir tool_name
	tool_dir="$(dirname "$manifest")"
	tool_name="$(devtool_name_from_manifest "$manifest")"
	local lockfile="$tool_dir/Cargo.lock"
	if [ ! -f "$lockfile" ]; then
		echo "[security] dev-tools/$tool_name: Cargo.lock not found at $lockfile" >&2
		return 1
	fi
	(
		cd "$tool_dir"
		cargo deny --config "$ROOT/deny.toml" check "$@"
	)
}

run_devtool_cargo_audit() {
	local manifest="$1"
	local tool_dir tool_name
	tool_dir="$(dirname "$manifest")"
	tool_name="$(devtool_name_from_manifest "$manifest")"
	local lockfile="$tool_dir/Cargo.lock"
	if [ ! -f "$lockfile" ]; then
		echo "[security] dev-tools/$tool_name: Cargo.lock not found at $lockfile" >&2
		return 1
	fi
	# Run from $ROOT so the workspace-level `.cargo/audit.toml` is respected.
	local audit_args=()
	if [ -n "${CARGO_AUDIT_ARGS:-}" ]; then
		read -r -a audit_args <<<"$CARGO_AUDIT_ARGS"
	fi
	cargo audit --file "$lockfile" "${audit_args[@]}"
}

run_devtool_cargo_vet() {
	local manifest="$1"
	local tool_name
	tool_name="$(devtool_name_from_manifest "$manifest")"
	local vet_args=()
	if [ -n "${CARGO_VET_ARGS:-}" ]; then
		read -r -a vet_args <<<"$CARGO_VET_ARGS"
	fi
	cargo vet \
		--cache-dir "$CARGO_VET_CACHE_DIR" \
		--store-path "$ROOT/supply-chain" \
		--manifest-path "$manifest" \
		"${vet_args[@]}"
}

run_fuzz_cargo_deny() {
	local manifest="fuzz/Cargo.toml"
	local tool_dir lockfile
	tool_dir="$(dirname "$manifest")"
	lockfile="$tool_dir/Cargo.lock"
	if [ ! -f "$lockfile" ]; then
		echo "[security] fuzz: Cargo.lock not found at $lockfile" >&2
		return 1
	fi
	(
		cd "$tool_dir"
		cargo deny --config "$ROOT/deny.toml" check "$@"
	)
}

run_fuzz_cargo_audit() {
	local manifest="fuzz/Cargo.toml"
	local tool_dir lockfile
	tool_dir="$(dirname "$manifest")"
	lockfile="$tool_dir/Cargo.lock"
	if [ ! -f "$lockfile" ]; then
		echo "[security] fuzz: Cargo.lock not found at $lockfile" >&2
		return 1
	fi
	# Run from $ROOT so the workspace-level `.cargo/audit.toml` is respected.
	local audit_args=()
	if [ -n "${CARGO_AUDIT_ARGS:-}" ]; then
		read -r -a audit_args <<<"$CARGO_AUDIT_ARGS"
	fi
	cargo audit --file "$lockfile" "${audit_args[@]}"
}

run_fuzz_cargo_vet() {
	local manifest="fuzz/Cargo.toml"
	local vet_args=()
	if [ -n "${CARGO_VET_ARGS:-}" ]; then
		read -r -a vet_args <<<"$CARGO_VET_ARGS"
	fi
	cargo vet \
		--cache-dir "$CARGO_VET_CACHE_DIR" \
		--store-path "$ROOT/supply-chain" \
		--manifest-path "$manifest" \
		"${vet_args[@]}"
}

run_step() {
	local name="$1" result
	shift
	echo "[security] >>> $name" | tee -a "$LOG_FILE" || return 1
	if "$@" >>"$LOG_FILE" 2>&1; then
		echo "[security] <<< $name: ok" | tee -a "$LOG_FILE" || return 1
	else
		result=$?
		echo "[security] <<< $name: failed" | tee -a "$LOG_FILE" || return "$result"
		return "$result"
	fi
}

warn_step() {
	local name="$1"
	shift
	echo "[security] >>> $name (non-blocking)" | tee -a "$LOG_FILE"
	if "$@" >>"$LOG_FILE" 2>&1; then
		echo "[security] <<< $name: ok" | tee -a "$LOG_FILE"
		return 0
	fi
	echo "[security] <<< $name: reported findings (non-blocking)" | tee -a "$LOG_FILE"
	return 0
}

sanitize() {
	SANITIZER_ARTIFACT_DIR="$SANITIZER_ARTIFACT_DIR" \
		SANITIZER_TARGET_DIR="$SANITIZER_VALIDATED_TARGET" \
		nix develop .#asan --command bash scripts/sanitizers/run_sanitizers.sh
}

DEFAULT_FUZZ_TARGETS=(
	fuzz_bearer_token
	fuzz_dpop_proof
	fuzz_pkce_verifier
	fuzz_jose_parsing
	fuzz_ffi_parsers
	fuzz_introspection
	fuzz_par
)
# An explicitly empty selection or budget must fail rather than use defaults.
FUZZ_TARGETS="${FUZZ_TARGETS-${DEFAULT_FUZZ_TARGETS[*]}}"
FUZZ_TIMEOUT="${FUZZ_TIMEOUT-60s}"
FUZZ_MAX_TOTAL="${FUZZ_MAX_TOTAL-30}"
FUZZ_TOTAL_TIMEOUT="${FUZZ_TOTAL_TIMEOUT-}"
if [ "$FUZZ_LONG" -eq 1 ]; then
	FUZZ_TOTAL_TIMEOUT="${FUZZ_TOTAL_TIMEOUT_OVERRIDE-600s}"
	FUZZ_TIMEOUT="${FUZZ_TIMEOUT_OVERRIDE-auto}"
	FUZZ_MAX_TOTAL="${FUZZ_MAX_TOTAL_OVERRIDE-auto}"
fi
export FUZZ_TARGETS FUZZ_TIMEOUT FUZZ_MAX_TOTAL FUZZ_TOTAL_TIMEOUT FUZZ_LONG

run_fuzz_targets() (
	# Every required operation has a checked return: callers may invoke this
	# function in a conditional, which disables Bash's errexit inside functions.
	local dir="$1" configuration internal watchdog host target rc record_result result=0
	local fuzz_cmd=(cargo fuzz)
	configuration="$(python3 -I scripts/fuzz/manage_fuzz_corpus.py --prepare-run "$dir")" || return 1
	read -r internal watchdog host <<<"$configuration"
	if ! command -v cargo >/dev/null 2>&1 ||
		! command -v cargo-fuzz >/dev/null 2>&1 ||
		! command -v rustc >/dev/null 2>&1 ||
		! command -v timeout >/dev/null 2>&1 || [[ $host == missing ]]; then
		echo "[security] cargo, cargo-fuzz, rustc and timeout with a host target are required" >&2
		return 1
	fi
	if ! "${fuzz_cmd[@]}" --help >"$dir/cargo-fuzz-help.log" 2>&1; then
		echo "[security] cargo-fuzz not available" >&2
		return 1
	fi

	unset NIX_CFLAGS_COMPILE NIX_CFLAGS_COMPILE_FOR_BUILD \
		NIX_CFLAGS_COMPILE_FOR_TARGET NIX_CFLAGS_COMPILE_FOR_HOST
	unset NIX_CFLAGS_LINK NIX_CFLAGS_LINK_FOR_BUILD \
		NIX_CFLAGS_LINK_FOR_TARGET NIX_CFLAGS_LINK_FOR_HOST
	unset NIX_LDFLAGS NIX_LDFLAGS_FOR_BUILD \
		NIX_LDFLAGS_FOR_TARGET NIX_LDFLAGS_FOR_HOST RUSTFLAGS RUSTDOCFLAGS
	# Retain the established LeakSanitizer policy on ptrace-restricted runners.
	export ASAN_OPTIONS="${ASAN_OPTIONS:+${ASAN_OPTIONS}:}detect_leaks=0"
	export LSAN_OPTIONS="${LSAN_OPTIONS:+${LSAN_OPTIONS}:}detect_leaks=0"
	if [[ -n ${CC:-} ]]; then
		local cc_support_dir nix_cflags=""
		cc_support_dir="$(dirname "$CC")/../nix-support" || return 2
		if [[ -d $cc_support_dir ]]; then
			if [[ -f "$cc_support_dir/cc-cflags" ]]; then
				nix_cflags+=" $(<"$cc_support_dir/cc-cflags")"
			fi
			if [[ -f "$cc_support_dir/libc-cflags" ]]; then
				nix_cflags+=" $(<"$cc_support_dir/libc-cflags")"
			fi
			if [[ -n ${nix_cflags// /} ]]; then
				export CFLAGS="${CFLAGS:-}${nix_cflags}"
				export CXXFLAGS="${CXXFLAGS:-}${nix_cflags}"
			fi
		fi
	fi
	python3 -I scripts/fuzz/manage_fuzz_corpus.py --record-environment "$dir" || return 2
	local targets_text targets=()
	targets_text="$(python3 -I -c 'import os; print(" ".join(os.environ["FUZZ_TARGETS"].split()))')" || return 2
	read -r -a targets <<<"$targets_text"
	local target_dir
	target_dir="$(python3 -I scripts/fuzz/manage_fuzz_corpus.py --execution-cache "$dir")" || return 2
	[[ $target_dir == *$'\n.' ]] || return 2
	target_dir="${target_dir%$'\n.'}"
	for target in "${targets[@]}"; do
		mkdir -p "$dir/$target" || return 2
		echo "[security] Building $target"
		if "${fuzz_cmd[@]}" build --target-dir "$target_dir" --target "$host" "$target" \
			>"$dir/$target/build.log" 2>&1; then
			rc=0
		else
			rc=$?
		fi
		if python3 -I scripts/fuzz/manage_fuzz_corpus.py --record-target "$dir" "$target" build "$rc"; then
			:
		else
			record_result=$?
			[[ $record_result -eq 1 ]] || return 2
			result=1
			continue
		fi
		echo "[security] Fuzzing $target (internal=${internal}s, watchdog=${watchdog}s)"
		if timeout --kill-after=10s "${watchdog}s" \
			"${fuzz_cmd[@]}" run --target-dir "$target_dir" --target "$host" "$target" \
			-- "-max_total_time=$internal" >"$dir/$target/run.log" 2>&1; then
			rc=0
		else
			rc=$?
		fi
		if python3 -I scripts/fuzz/manage_fuzz_corpus.py --record-target "$dir" "$target" run "$rc"; then
			:
		else
			record_result=$?
			[[ $record_result -eq 1 ]] || return 2
			result=1
		fi
	done
	return "$result"
)

run_fuzz() {
	local dir="$ARTIFACT_BASE/fuzz" result=0
	mkdir -p "$dir" "$SECURITY_HISTORY_DIR" || return 1
	# A receipt from an earlier attempt must never satisfy this invocation.
	rm -f "$dir/collection.ok" "$dir/execution.json" "$dir/run_summary.json" || return 1
	if run_fuzz_targets "$dir" >"$dir/run.log" 2>&1; then
		result=0
	else
		result=$?
	fi
	cat "$dir/run.log" || result=1
	# Collect corpus and crash archives even after setup, build or run failures.
	# Collection writes its marker only after all evidence has been checked.
	if ! python3 -I scripts/fuzz/manage_fuzz_corpus.py --finish-run "$dir" "$result"; then
		result=1
	fi
	return "$result"
}

run_geiger() {
	scripts/security/run_geiger.sh
}

run_supply_chain_stage() {
	# Supply-chain checks with optional offline mode.
	# Set AEG_SECURITY_OFFLINE=1 to skip network-dependent checks in CI.
	if [ "${AEG_SECURITY_OFFLINE:-0}" = "1" ]; then
		echo \
			"[security] OFFLINE mode: skipping cargo deny advisories + cargo audit" \
			"(network required)" | tee -a "$LOG_FILE"
		run_step "cargo deny check (bans/licenses/sources)" cargo deny check bans licenses sources
		while IFS= read -r manifest; do
			[ -n "$manifest" ] || continue
			tool_name="$(devtool_name_from_manifest "$manifest")"
			run_step \
				"cargo deny check (bans/licenses/sources) (dev-tools/$tool_name)" \
				run_devtool_cargo_deny "$manifest" bans licenses sources
		done < <(discover_devtools_manifests "dev-tools")
		if [ -f fuzz/Cargo.toml ]; then
			run_step \
				"cargo deny check (bans/licenses/sources) (fuzz)" \
				run_fuzz_cargo_deny bans licenses sources
		fi
	else
		run_step "cargo deny check" cargo deny check
		local audit_args=()
		if [ -n "${CARGO_AUDIT_ARGS:-}" ]; then
			read -r -a audit_args <<<"$CARGO_AUDIT_ARGS"
		fi
		run_step "cargo audit" cargo audit "${audit_args[@]}"
		while IFS= read -r manifest; do
			[ -n "$manifest" ] || continue
			tool_name="$(devtool_name_from_manifest "$manifest")"
			run_step "cargo deny check (dev-tools/$tool_name)" run_devtool_cargo_deny "$manifest"
			run_step "cargo audit (dev-tools/$tool_name)" run_devtool_cargo_audit "$manifest"
		done < <(discover_devtools_manifests "dev-tools")
		if [ -f fuzz/Cargo.toml ]; then
			run_step "cargo deny check (fuzz)" run_fuzz_cargo_deny
			run_step "cargo audit (fuzz)" run_fuzz_cargo_audit
		fi
	fi
}

run_runtime_tests_stage() {
	run_step "bearer tls enforcement tests" cargo test -p aegaeon-server transport
	run_step "client tls validation tests" cargo test -p aegaeon-client
	run_step "registration pkce policy test" \
		cargo test -p aegaeon-server --lib \
		endpoints::registration::tests::registration_enforces_public_pkce_policy
	run_step "registration sender method policy test" \
		cargo test -p aegaeon-server --lib \
		endpoints::registration::tests::registration_rejects_disallowed_sender_method
	run_step "metadata core fields test" \
		cargo test -p aegaeon-server --lib metadata::tests::metadata_core_fields_are_non_empty
	run_step "metrics integration unit tests" \
		cargo test -p aegaeon-server metrics_integration_test
	run_step "resource metrics snapshot" collect_resource_metrics_snapshot
	reset_cargo_target_dir
}

collect_resource_metrics_snapshot() (
	set -euo pipefail
	local dir="$ARTIFACT_BASE/resource"
	mkdir -p "$dir"
	local port="${SECURITY_RESOURCE_PORT:-19180}"
	local wait_secs="${SECURITY_RESOURCE_WAIT_SECS:-120}"
	local runtime_issuer_host="${AEGAEON_RUNTIME_ISSUER_HOST:-${SECURITY_RUNTIME_ISSUER_HOST:-}}"
	local database_url="${AEGAEON_DATABASE_URL:-}"
	if [ -z "$database_url" ] || [ -z "$runtime_issuer_host" ]; then
		{
			echo "resource metrics snapshot skipped"
			echo "reason: AEGAEON_DATABASE_URL and AEGAEON_RUNTIME_ISSUER_HOST/SECURITY_RUNTIME_ISSUER_HOST are required"
		} >"$dir/resource-metrics.skipped.txt"
		echo "[security] skipping resource metrics snapshot; PostgreSQL runtime config and issuer host selector are required"
		return 0
	fi
	echo "[security] launching server for metrics snapshot on port $port"
	env -u BASE_URL \
		AEGAEON_RUNTIME_ISSUER_HOST="$runtime_issuer_host" \
		AEGAEON_EXPOSE_METRICS_ON_MAIN=1 \
		cargo run --bin aegaeon-server -- --host 127.0.0.1 --port "$port" \
		>"$dir/server.log" 2>&1 &
	local server_pid=$!
	# shellcheck disable=SC2329 # invoked by trap.
	cleanup() {
		if kill "$server_pid" 2>/dev/null; then
			wait "$server_pid" 2>/dev/null || true
		else
			wait "$server_pid" 2>/dev/null || true
		fi
	}
	trap cleanup EXIT INT TERM

	for _ in $(seq 1 "$wait_secs"); do
		if curl -sf "http://127.0.0.1:${port}/health" >/dev/null 2>&1; then
			break
		fi
		sleep 1
	done

	curl -sv -o "$dir/bearer_failure.response" \
		-H "Authorization: Bearer invalid-token" \
		"http://127.0.0.1:${port}/resource" || true
	curl -sv -o "$dir/dpop_failure.response" \
		-H "Authorization: DPoP invalid-token" \
		-H "DPoP: invalid-proof" \
		"http://127.0.0.1:${port}/resource" || true
	curl -sf "http://127.0.0.1:${port}/metrics" \
		>"$dir/resource-metrics.prom"
)

run_jose_boundaries_stage() {
	run_step "TLV parity tests" run_tlv_parity
	warn_step "Context boundary tests (optional)" run_context_boundary
	reset_cargo_target_dir
}

run_cargo_vet_stage() {
	CARGO_VET_CACHE_DIR="${CARGO_VET_CACHE_DIR:-$PWD/.cargo-vet-cache}"
	mkdir -p "$CARGO_VET_CACHE_DIR"
	local vet_args=()
	if [ -n "${CARGO_VET_ARGS:-}" ]; then
		read -r -a vet_args <<<"$CARGO_VET_ARGS"
	fi
	warn_step "cargo vet check" cargo vet --cache-dir "$CARGO_VET_CACHE_DIR" "${vet_args[@]}"
	while IFS= read -r manifest; do
		[ -n "$manifest" ] || continue
		tool_name="$(devtool_name_from_manifest "$manifest")"
		warn_step "cargo vet check (dev-tools/$tool_name)" run_devtool_cargo_vet "$manifest"
	done < <(discover_devtools_manifests "dev-tools")
	if [ -f fuzz/Cargo.toml ]; then
		warn_step "cargo vet check (fuzz)" run_fuzz_cargo_vet
	fi
}

run_fuzz_stage() {
	local result=0 cleanup_result=0 recovery_run_id dir="$ARTIFACT_BASE/fuzz"
	# Retire every result before stage logging or child setup can fail.
	if ! rm -f -- "$dir/collection.ok" "$dir/execution.json" "$dir/run_summary.json"; then
		echo "[security] cannot invalidate previous fuzz results; retaining transient outputs" >&2
		return 1
	fi
	if run_step "cargo fuzz smoke" run_fuzz; then
		result=0
	else
		result=$?
	fi
	# A collected failure still needs its raw corpus and crashes for upload.
	if [[ $result -eq 0 && -f "$dir/collection.ok" ]]; then
		if recovery_run_id="$(python3 -I scripts/fuzz/manage_fuzz_corpus.py --backup-cleanup "$dir")"; then
			if cleanup_fuzz_outputs "$dir" "$recovery_run_id"; then
				cleanup_result=0
			else
				cleanup_result=$?
			fi
			if [[ $cleanup_result -ne 0 ]]; then
				result=1
				python3 -I scripts/fuzz/manage_fuzz_corpus.py --restore-cleanup \
					"$dir" "$recovery_run_id" "$cleanup_result" removal || result=1
			elif python3 -I scripts/fuzz/manage_fuzz_corpus.py --cleanup-result "$dir" 0; then
				: # Keep the bound recovery copies as execution evidence.
			else
				result=1
				python3 -I scripts/fuzz/manage_fuzz_corpus.py --restore-cleanup \
					"$dir" "$recovery_run_id" 0 receipt || result=1
			fi
		else
			echo "[security] fuzz recovery copy incomplete; retaining transient outputs" >&2
			result=1
		fi
	else
		echo "[security] fuzz stage failed or evidence incomplete; retaining transient outputs" >&2
		result=1
	fi
	return "$result"
}

sanitizer_stage_log() {
	# The open log inode remains the destination if a child swaps artifact parents.
	echo "$*" | tee -a "/proc/self/fd/$sanitizer_log_fd"
}

sanitizer_logging_failure() {
	local phase=$1 logging_status=$2 primary_status=${3:-$2}
	if sanitizer_target_binding validate "$SANITIZER_EVIDENCE_BINDING"; then
		preflight_receipt "$phase" "$primary_status" "$logging_status" || return 1
	else
		SANITIZER_EVIDENCE_ROUTE_CHANGED=1
		return 1
	fi
}

run_sanitizers_stage() {
	local status=0 cleanup_status=0 evidence_status=0 logging_status=0
	prepare_sanitizer_attempt || return $?
	if sanitizer_stage_log "[security] >>> sanitizer smoke"; then
		:
	else
		logging_status=$?
		sanitizer_logging_failure initial-log "$logging_status" || true
		return "$logging_status"
	fi
	if sanitize >&"$sanitizer_log_fd" 2>&1; then
		status=0
	else
		status=$?
		sanitizer_stage_log "[security] <<< sanitizer smoke: failed (exit=$status)" || logging_status=$?
	fi
	cleanup_sanitizer_outputs >&"$sanitizer_log_fd" 2>&1 || cleanup_status=$?
	if [[ $cleanup_status -ne 0 ]]; then
		sanitizer_stage_log "[security] <<< sanitizer cleanup: failed (exit=$cleanup_status)" || logging_status=$?
	fi
	if sanitizer_target_binding validate "$SANITIZER_EVIDENCE_BINDING" >&"$sanitizer_log_fd" 2>&1; then
		if [[ $status -ne 0 || $cleanup_status -ne 0 ]]; then
			preflight_receipt cleanup "$((status != 0 ? status : cleanup_status))" >&"$sanitizer_log_fd" 2>&1 || evidence_status=1
		fi
	else
		evidence_status=1
		SANITIZER_EVIDENCE_ROUTE_CHANGED=1
		sanitizer_stage_log "[security] sanitizer evidence route changed; historical summaries held" || logging_status=$?
	fi
	if [[ $status -eq 0 && $cleanup_status -eq 0 && $evidence_status -eq 0 ]]; then
		sanitizer_stage_log "[security] <<< sanitizer smoke: ok" || logging_status=$?
	fi
	if [[ $logging_status -ne 0 ]]; then
		sanitizer_logging_failure final-log "$logging_status" "$((status != 0 ? status : cleanup_status != 0 ? cleanup_status : logging_status))" || evidence_status=1
	fi
	if [[ $status -ne 0 ]]; then
		return "$status"
	fi
	if [[ $cleanup_status -ne 0 ]]; then
		return "$cleanup_status"
	fi
	if [[ $logging_status -ne 0 ]]; then
		return "$logging_status"
	fi
	return "$evidence_status"
}

run_sbom_stage() {
	warn_step "SBOM scan" nix develop . --command scripts/security/run_sbom_scan.sh
}

run_geiger_stage() {
	run_step "cargo geiger scan completeness" run_geiger
}

run_udeps_stage() {
	# shellcheck disable=SC2016 # script body is evaluated by bash -c.
	run_step "cargo udeps" bash -c '
		set -euo pipefail
		dir="${SECURITY_ARTIFACT_DIR:-artifacts/security/latest}/udeps"
		mkdir -p "$dir"
		log="$dir/run.log"
		: >"$log"
		exec > >(tee -a "$log") 2>&1
		if ! command -v cargo-udeps >/dev/null 2>&1; then
			echo "cargo-udeps not installed" >&2
			exit 1
		fi
		cargo udeps --workspace --all-targets --all-features
	'
}

# TLV parity tests with artifact collection on failure
run_tlv_parity() {
	local dir="$ARTIFACT_BASE/tlv-parity"
	mkdir -p "$dir"
	local log="$dir/run.log"
	: >"$log"
	(
		set +e # Don't exit on test failure, we want to collect artifacts
		exec > >(tee -a "$log") 2>&1
		echo "[security] Running TLV parity tests across JOSE profiles"

		local -a profiles=(
			"default|"
			"everparse-jose-header-entry|everparse_jose_header_entry"
			"verified-claim|verified-claim"
			"ffi-jose-header-tlv|ffi_jose_header_tlv"
			"ffi-jose-header-tlv-verified-claim|ffi_jose_header_tlv,verified-claim"
		)
		local -a failed_profiles=()
		local exit_code=0

		: >"$dir/test-output.txt"

		for entry in "${profiles[@]}"; do
			IFS='|' read -r profile features <<<"$entry"
			local output="$dir/${profile}.txt"
			echo "[security] Running TLV parity tests (${profile})"

			if [ -n "$features" ]; then
				cargo test -p aegaeon-jose --test tlv_parity --features "$features" -- --test-threads=1 2>&1 |
					tee "$output"
			else
				cargo test -p aegaeon-jose --test tlv_parity -- --test-threads=1 2>&1 |
					tee "$output"
			fi
			local profile_exit=${PIPESTATUS[0]}
			cat "$output" >>"$dir/test-output.txt"

			if [ "$profile_exit" -ne 0 ]; then
				failed_profiles+=("$profile")
				exit_code=$profile_exit
			fi
		done

		if [ "$exit_code" -eq 0 ]; then
			echo "[security] TLV parity tests: PASS"
			return 0
		else
			echo "[security] TLV parity tests: FAILED (exit code: $exit_code)"

			# Collect failure artifacts
			echo "[security] Collecting failure artifacts..."

			# Create human-readable summary
			{
				echo "=== TLV Parity Test Failures ==="
				echo "Timestamp: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
				echo "Git commit: $(git rev-parse HEAD 2>/dev/null || echo 'unknown')"
				echo "Git branch: $(git branch --show-current 2>/dev/null || echo 'unknown')"
				echo ""
				echo "Failed profiles:"
				for profile in "${failed_profiles[@]}"; do
					echo "- $profile"
				done
				echo ""
				echo "Failed tests:"
				# Extract test names from failure output
				grep -E "^test .* \.\.\. FAILED$" "$dir/test-output.txt" 2>/dev/null |
					sed 's/^test //' | sed 's/ \.\.\. FAILED$//' || echo "(no failures parsed)"
				echo ""
				echo "Failure summary:"
				grep -A 5 "^failures:$" "$dir/test-output.txt" 2>/dev/null || echo "(see test-output.txt)"
				echo ""
				echo "Full output in: test-output.txt"
			} >"$dir/failure-summary.txt"

			# Save git diff if there are uncommitted changes
			if ! git diff --quiet HEAD 2>/dev/null; then
				echo "[security] Saving git diff..."
				git diff HEAD >"$dir/git-diff.patch" 2>/dev/null || true
			fi

			# Copy relevant source files
			echo "[security] Copying source files..."
			mkdir -p "$dir/sources"
			cp crates/jose/tests/tlv_parity.rs "$dir/sources/" 2>/dev/null || true
			cp crates/jose/src/json_lowstar.rs "$dir/sources/" 2>/dev/null || true
			cp crates/jose/src/jws.rs "$dir/sources/" 2>/dev/null || true
			cp crates/jose/src/jwe.rs "$dir/sources/" 2>/dev/null || true
			cp crates/jose/src/tlv.rs "$dir/sources/" 2>/dev/null || true

			# Save Cargo.toml for dependency info
			cp crates/jose/Cargo.toml "$dir/sources/jose-Cargo.toml" 2>/dev/null || true
			cp crates/ffi/Cargo.toml "$dir/sources/ffi-Cargo.toml" 2>/dev/null || true

			# Save environment info
			{
				echo "=== Environment Info ==="
				echo "Rustc version:"
				rustc --version 2>/dev/null || echo "rustc not available"
				echo ""
				echo "Cargo version:"
				cargo --version 2>/dev/null || echo "cargo not available"
				echo ""
				echo "Build profile: test (unoptimized + debuginfo)"
				echo ""
				echo "Profiles checked:"
				printf '%s\n' "${profiles[@]}"
			} >"$dir/environment.txt"

			echo "[security] Artifacts collected in: $dir"
			echo "[security] Summary: $dir/failure-summary.txt"
			return "$exit_code"
		fi
	)
}

# Context boundary tests with artifact collection on failure
run_context_boundary() {
	local dir="$ARTIFACT_BASE/context-boundary"
	mkdir -p "$dir"
	local log="$dir/run.log"
	: >"$log"
	(
		set +e # Don't exit on test failure, we want to collect artifacts
		exec > >(tee -a "$log") 2>&1
		echo "[security] Running context boundary tests"

		# Run tests and capture output
		cargo test -p aegaeon-jose --test context_boundary 2>&1 | tee "$dir/test-output.txt"
		local exit_code=$?

		if [ "$exit_code" -eq 0 ]; then
			echo "[security] Context boundary tests: PASS"
			return 0
		else
			echo "[security] Context boundary tests: FAILED (exit code: $exit_code)"

			# Collect failure artifacts
			echo "[security] Collecting failure artifacts..."

			# Create human-readable summary
			{
				echo "=== Context Boundary Test Failures ==="
				echo "Timestamp: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
				echo "Exit code: $exit_code"
				echo ""
				echo "=== Test Output ==="
				tail -100 "$dir/test-output.txt" 2>/dev/null || echo "(no test output)"
			} >"$dir/failure-summary.txt"

			# Copy relevant source files
			echo "[security] Copying source files..."
			mkdir -p "$dir/sources"
			cp crates/jose/tests/context_boundary.rs "$dir/sources/" 2>/dev/null || true
			cp crates/jose/src/jws.rs "$dir/sources/" 2>/dev/null || true
			cp crates/jose/src/jwe.rs "$dir/sources/" 2>/dev/null || true
			cp crates/jose/src/policy.rs "$dir/sources/" 2>/dev/null || true
			cp crates/ffi/src/lib.rs "$dir/sources/" 2>/dev/null || true

			# Save Cargo.toml for dependency info
			cp crates/jose/Cargo.toml "$dir/sources/jose-Cargo.toml" 2>/dev/null || true
			cp crates/ffi/Cargo.toml "$dir/sources/ffi-Cargo.toml" 2>/dev/null || true

			# Save environment info
			{
				echo "=== Environment Info ==="
				echo "Rustc version:"
				rustc --version 2>/dev/null || echo "rustc not available"
				echo ""
				echo "Cargo version:"
				cargo --version 2>/dev/null || echo "cargo not available"
				echo ""
				echo "Build profile: test (unoptimized + debuginfo)"
				echo ""
				echo "=== Known Issues ==="
				echo \
					"If this failure involves Low*/generated C code," \
					"verify the Low* extraction outputs are in sync."
				echo "See: docs/verification/jose/phase4-verification-summary.md"
			} >"$dir/environment.txt"

			echo "[security] Artifacts collected in: $dir"
			echo "[security] Summary: $dir/failure-summary.txt"
			return "$exit_code"
		fi
	)
}

# Bind the shared log once, before truncation or initial logging. The helper
# re-execs this fixed wrapper with an inherited fd; a caller marker is insufficient.
if stage_enabled "sanitizers"; then
	prepare_sanitizer_attempt || exit $?
	mkdir -p "$LOG_DIR" || exit $?
	if [[ -n ${SANITIZER_SECURITY_LOG_FD:-} ]]; then
		python3 -I "$ROOT/scripts/sanitizers/open_security_log.py" validate \
			"$SECURITY_LOG_PATH" "$SANITIZER_SECURITY_LOG_FD" || exit $?
		sanitizer_log_fd=$SANITIZER_SECURITY_LOG_FD
	else
		exec python3 -I "$ROOT/scripts/sanitizers/open_security_log.py" open-exec \
			"$SECURITY_LOG_PATH" "${SECURITY_ENTRY_ARGS[@]}"
	fi
	SANITIZER_LOG_DESTINATION="/proc/self/fd/$sanitizer_log_fd"
	LOG_FILE=$SANITIZER_LOG_DESTINATION
else
	mkdir -p "$LOG_DIR"
	: >"$LOG_FILE"
fi
if echo "[security] starting security suite…" | tee -a "$LOG_FILE"; then
	:
else
	log_status=$?
	if stage_enabled "sanitizers"; then
		sanitizer_logging_failure shared-initial-log "$log_status" || true
	fi
	exit "$log_status"
fi

stage_enabled "supply-chain" && run_supply_chain_stage
stage_enabled "runtime-tests" && run_runtime_tests_stage
stage_enabled "jose-boundaries" && run_jose_boundaries_stage
stage_enabled "cargo-vet" && run_cargo_vet_stage
suite_result=0
if stage_enabled "fuzz"; then
	if run_fuzz_stage; then
		:
	else
		suite_result=$?
	fi
fi
if stage_enabled "sanitizers"; then
	if run_sanitizers_stage; then
		:
	else
		sanitizer_result=$?
		if [[ $suite_result -eq 0 ]]; then
			suite_result=$sanitizer_result
		fi
	fi
fi
if [[ ${SANITIZER_EVIDENCE_ROUTE_CHANGED:-0} -eq 1 ]]; then
	# No later logging/output stage may dereference the replaced artifact namespace.
	echo "[security] unsafe sanitizer evidence; remaining output stages held" |
		tee -a "$SANITIZER_LOG_DESTINATION" || true
	exit "$suite_result"
fi
stage_enabled "sbom" && run_sbom_stage
stage_enabled "geiger" && run_geiger_stage
stage_enabled "udeps" && run_udeps_stage

if echo "[security] suite finished. log: $SECURITY_LOG_PATH" | tee -a "$LOG_FILE"; then
	:
else
	log_status=$?
	if stage_enabled "sanitizers"; then
		sanitizer_logging_failure shared-final-log "$log_status" "$((suite_result != 0 ? suite_result : log_status))" || true
	fi
	if [[ $suite_result -eq 0 ]]; then
		suite_result=$log_status
	fi
fi
mkdir -p "$ARTIFACT_BASE" "$SECURITY_HISTORY_DIR"
exit "$suite_result"
