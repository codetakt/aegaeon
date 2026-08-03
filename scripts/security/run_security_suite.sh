#!/usr/bin/env bash

# Aggregated security checks (used by `nix run .#security-suite`).

set -euo pipefail

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

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
export ROOT
cd "$ROOT"

# The dev shell exports WASI tooling for verified-core extraction. Some environments
# also export CC/CXX pointing at the WASI compiler, which breaks native builds
# (e.g. aws-lc-sys) during `cargo test`. Ensure native checks use a native compiler.
if [[ ${CC:-} == *"wasm32-unknown-wasi"* ]]; then
	unset CC
fi
if [[ ${CXX:-} == *"wasm32-unknown-wasi"* ]]; then
	unset CXX
fi
if [[ -z ${CC:-} ]] && command -v cc >/dev/null 2>&1; then
	CC="$(command -v cc)"
	export CC
fi
if [[ -z ${CXX:-} ]] && command -v c++ >/dev/null 2>&1; then
	CXX="$(command -v c++)"
	export CXX
fi

SECURITY_ARTIFACT_DIR="${SECURITY_ARTIFACT_DIR:-artifacts/security/latest}"
SECURITY_HISTORY_DIR="${SECURITY_HISTORY_DIR:-artifacts/security/history}"
export SECURITY_ARTIFACT_DIR SECURITY_HISTORY_DIR

ARTIFACT_BASE="$SECURITY_ARTIFACT_DIR"
LOG_DIR="$ARTIFACT_BASE/summary"
LOG_FILE="$LOG_DIR/security.log"
mkdir -p "$LOG_DIR"
: >"$LOG_FILE"

CARGO_HOME="${SECURITY_ARTIFACT_DIR}/cargo-home"
mkdir -p "$CARGO_HOME"
export CARGO_HOME

# Keep Rust build outputs in a dedicated target directory so we can prune it
# between phases in CI to avoid exhausting runner disk.
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target/security-suite}"

echo "[security] starting security suite…" | tee -a "$LOG_FILE"

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

reset_cargo_target_dir() {
	local dir="${CARGO_TARGET_DIR:-}"
	if [ -z "$dir" ]; then
		return 0
	fi
	rm -rf "$dir" || true
	mkdir -p "$dir" || true
}

cleanup_fuzz_outputs() {
	rm -rf fuzz/target fuzz/artifacts fuzz/corpus fuzz/corpus_archive || true
}

cleanup_sanitizer_outputs() {
	rm -rf target/sanitizers || true
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
		cargo deny check --config "$ROOT/deny.toml" "$@"
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
		cargo deny check --config "$ROOT/deny.toml" "$@"
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
	local name="$1"
	shift
	echo "[security] >>> $name" | tee -a "$LOG_FILE"
	if "$@" >>"$LOG_FILE" 2>&1; then
		echo "[security] <<< $name: ok" | tee -a "$LOG_FILE"
	else
		echo "[security] <<< $name: failed" | tee -a "$LOG_FILE"
		return 1
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
	local dir="$ARTIFACT_BASE/sanitizers"
	mkdir -p "$dir"
	SANITIZER_ARTIFACT_DIR="$dir" \
		nix develop .#asan --command scripts/sanitizers/run_sanitizers.sh
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
FUZZ_TARGETS="${FUZZ_TARGETS:-${DEFAULT_FUZZ_TARGETS[*]}}"
FUZZ_TIMEOUT="${FUZZ_TIMEOUT:-1m}"
FUZZ_MAX_TOTAL="${FUZZ_MAX_TOTAL:-30}"
FUZZ_TOTAL_TIMEOUT="${FUZZ_TOTAL_TIMEOUT:-}"

if [ "$FUZZ_LONG" -eq 1 ]; then
	FUZZ_TOTAL_TIMEOUT="${FUZZ_TOTAL_TIMEOUT_OVERRIDE:-600s}"
	FUZZ_TIMEOUT="${FUZZ_TIMEOUT_OVERRIDE:-5m}"
	FUZZ_MAX_TOTAL="${FUZZ_MAX_TOTAL_OVERRIDE:-300}"
	echo \
		"[security] long fuzz mode enabled" \
		"(timeout=$FUZZ_TIMEOUT, max_total=$FUZZ_MAX_TOTAL, total_timeout=$FUZZ_TOTAL_TIMEOUT)" |
		tee -a "$LOG_FILE"
fi

run_fuzz() {
	local dir="$ARTIFACT_BASE/fuzz"
	local history_dir="$SECURITY_HISTORY_DIR"
	mkdir -p "$dir" "$history_dir"
	local log="$dir/run.log"
	: >"$log"
	(
		set -euo pipefail
		exec > >(tee -a "$log") 2>&1
		echo "[security] Running fuzz smoke (targets=$FUZZ_TARGETS)"
		if [ ! -d fuzz ]; then
			echo "[security] fuzz directory not found" >&2
			exit 1
		fi
		if ! command -v cargo >/dev/null 2>&1; then
			echo "[security] cargo not available" >&2
			exit 1
		fi
		unset NIX_CFLAGS_COMPILE NIX_CFLAGS_COMPILE_FOR_BUILD \
			NIX_CFLAGS_COMPILE_FOR_TARGET NIX_CFLAGS_COMPILE_FOR_HOST
		unset NIX_CFLAGS_LINK NIX_CFLAGS_LINK_FOR_BUILD \
			NIX_CFLAGS_LINK_FOR_TARGET NIX_CFLAGS_LINK_FOR_HOST
		unset NIX_LDFLAGS NIX_LDFLAGS_FOR_BUILD \
			NIX_LDFLAGS_FOR_TARGET NIX_LDFLAGS_FOR_HOST
		echo \
			"[security] fuzz env: cleared NIX_CFLAGS_* and NIX_LDFLAGS_*" \
			"for include ordering"
		echo \
			"[security] fuzz compiler: CC=${CC:-unset} CXX=${CXX:-unset}" \
			"cc=$(command -v cc || echo missing) c++=$(command -v c++ || echo missing)"
		echo \
			"[security] fuzz flags: NIX_CFLAGS_COMPILE=${NIX_CFLAGS_COMPILE:-unset}" \
			"NIX_LDFLAGS=${NIX_LDFLAGS:-unset}"
		unset RUSTFLAGS RUSTDOCFLAGS
		FUZZ_CMD="cargo fuzz"
		# LeakSanitizer is unreliable under ptrace-restricted runners; disable leak detection
		if [ -n "${ASAN_OPTIONS:-}" ]; then
			export ASAN_OPTIONS="${ASAN_OPTIONS}:detect_leaks=0"
		else
			export ASAN_OPTIONS="detect_leaks=0"
		fi
		if [ -n "${LSAN_OPTIONS:-}" ]; then
			export LSAN_OPTIONS="${LSAN_OPTIONS}:detect_leaks=0"
		else
			export LSAN_OPTIONS="detect_leaks=0"
		fi
		if [[ -n ${CC:-} ]]; then
			local cc_support_dir
			cc_support_dir="$(cd "$(dirname "$CC")/../nix-support" && pwd)"
			if [[ -d $cc_support_dir ]]; then
				local nix_cflags=""
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
		if ! sh -c "$FUZZ_CMD --help" >/dev/null 2>&1; then
			echo "[security] cargo-fuzz not installed" >&2
			exit 1
		fi

		local timeout="$FUZZ_TIMEOUT"
		local max_total="$FUZZ_MAX_TOTAL"
		if [ -n "$FUZZ_TOTAL_TIMEOUT" ]; then
			local total_seconds=0
			if printf "%s" "$FUZZ_TOTAL_TIMEOUT" | grep -Eq '^[0-9]+[sSmMhH]?$'; then
				local unit value
				unit=$(printf "%s" "$FUZZ_TOTAL_TIMEOUT" | sed -n 's/^[0-9]\+\([sSmMhH]\)$/\1/p')
				value=$(printf "%s" "$FUZZ_TOTAL_TIMEOUT" | sed 's/[sSmMhH]$//')
				[ -z "$value" ] && value=0
				case "$unit" in
				"" | s | S) total_seconds=$value ;;
				m | M) total_seconds=$((value * 60)) ;;
				h | H) total_seconds=$((value * 3600)) ;;
				*) total_seconds=0 ;;
				esac
			fi
			if [ "$total_seconds" -gt 0 ]; then
				local count
				count=$(echo "$FUZZ_TARGETS" | wc -w | tr -d ' ')
				if [ "$count" -gt 0 ]; then
					local per=$((total_seconds / count))
					[ "$per" -lt 30 ] && per=30
					timeout="${per}s"
					max_total="$per"
				fi
			fi
		fi

		for target in $FUZZ_TARGETS; do
			echo "[security] Building $target"
			"$FUZZ_CMD" build "$target"
			echo "[security] Fuzzing $target (timeout=$timeout, max_total_time=$max_total)"
			if ! timeout "$timeout" "$FUZZ_CMD" run "$target" -- -max_total_time="$max_total"; then
				echo "[security] WARNING: fuzzing $target failed" >&2
			fi
		done

		FUZZ_RUN_ARTIFACT_DIR="$dir" \
			FUZZ_HISTORY_DIR="$history_dir" \
			python3 scripts/fuzz/manage_fuzz_corpus.py || true
		if [ -f fuzz/corpus_meta/history.jsonl ]; then
			cp fuzz/corpus_meta/history.jsonl "$history_dir/fuzz_history.jsonl" || true
		fi
	)
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
	warn_step "cargo fuzz smoke" run_fuzz
	cleanup_fuzz_outputs
}

run_sanitizers_stage() {
	warn_step "sanitizer smoke" sanitize
	cleanup_sanitizer_outputs
}

run_sbom_stage() {
	warn_step "SBOM scan" nix develop . --command scripts/security/run_sbom_scan.sh
}

run_geiger_stage() {
	warn_step "cargo geiger" run_geiger
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

validate_stages

stage_enabled "supply-chain" && run_supply_chain_stage
stage_enabled "runtime-tests" && run_runtime_tests_stage
stage_enabled "jose-boundaries" && run_jose_boundaries_stage
stage_enabled "cargo-vet" && run_cargo_vet_stage
stage_enabled "fuzz" && run_fuzz_stage
stage_enabled "sanitizers" && run_sanitizers_stage
stage_enabled "sbom" && run_sbom_stage
stage_enabled "geiger" && run_geiger_stage
stage_enabled "udeps" && run_udeps_stage

echo "[security] suite finished. log: $LOG_FILE" | tee -a "$LOG_FILE"
mkdir -p "$ARTIFACT_BASE" "$SECURITY_HISTORY_DIR"
