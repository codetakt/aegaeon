#!/usr/bin/env bash
# Sanitizer stage functions sourced by the security-suite dispatcher after its
# interpreter admission and path-policy setup. No stage runs while sourcing.

sanitizer_check_cargo_flags() {
	# Retire stale success before rejecting flags, but never initialize target outputs.
	if sanitizer_validate_cargo_flags "${SANITIZER_CARGO_FLAGS:-}" "${SANITIZER_BUILD_EXTRA_ARGS:-}"; then
		:
	else
		local flag_status=$?
		# Bound attempts record preparation failure only through their original
		# initialization snapshot in sanitizer_preparation_failure.
		if [[ -z ${SANITIZER_CLEANUP_BINDING:-} ]] && sanitizer_target_binding validate "$SANITIZER_EVIDENCE_BINDING"; then
			preflight_receipt cargo-flags "$flag_status" || return 1
		fi
		return "$flag_status"
	fi
}

prepare_sanitizer_attempt() {
	local initial_summary
	if [[ -n ${SANITIZER_EVIDENCE_BINDING:-} ]]; then
		# A later attempt must not rebind a replaced evidence namespace.
		if [[ ${SANITIZER_EVIDENCE_ROUTE_CHANGED:-0} == 1 ]]; then
			return 1
		fi
		if ! sanitizer_target_binding validate "$SANITIZER_EVIDENCE_BINDING"; then
			SANITIZER_EVIDENCE_ROUTE_CHANGED=1
			return 1
		fi
		if [[ -n ${SANITIZER_CLEANUP_BINDING:-} ]]; then
			# Continue the original admitted invocation across opener/stage handoff.
			# Replacements must never become a newly initialized evidence or target.
			[[ ${SANITIZER_ARTIFACT_DIR:-} == "$ARTIFACT_BASE/sanitizers" ]] || return 1
			sanitizer_check_cargo_flags || return $?
			preflight_route "${SANITIZER_TARGET_DIR:-target/sanitizers}" || return 1
			[[ ${SANITIZER_VALIDATED_TARGET:-} == "$PREFLIGHT_ROUTE" ]] || return 1
			"$security_function_python" -I "$ROOT/scripts/sanitizers/open_security_log.py" validate-bound \
				"$SANITIZER_ARTIFACT_DIR" "$SANITIZER_EVIDENCE_BINDING" \
				"$SANITIZER_VALIDATED_TARGET" "$SANITIZER_CLEANUP_BINDING" || return 1
			return 0
		fi
	else
		# Only an initial attempt discards an inherited caller marker.
		SANITIZER_EVIDENCE_ROUTE_CHANGED=0
	fi
	SANITIZER_CLEANUP_BINDING=""
	preflight_route "$ARTIFACT_BASE/sanitizers" || return 1
	SANITIZER_ARTIFACT_DIR=$PREFLIGHT_ROUTE
	sanitizer_validate_output "$SANITIZER_ARTIFACT_DIR" "$ROOT" || return 1
	sanitizer_initialize_evidence || return 1
	SANITIZER_EVIDENCE_BINDING=$(sanitizer_target_binding prepare "$SANITIZER_ARTIFACT_DIR") || return $?
	initial_summary=$(sanitizer_target_binding summary-snapshot "$SANITIZER_EVIDENCE_BINDING") || return $?
	SANITIZER_EVIDENCE_BINDING=$("$security_function_python" -I -c \
		'import json, sys; binding = json.loads(sys.argv[1]); binding["initial_summary"] = json.loads(sys.argv[2]); print(json.dumps(binding))' \
		"$SANITIZER_EVIDENCE_BINDING" "$initial_summary") || return $?
	sanitizer_check_cargo_flags || return $?
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

sanitize() {
	SANITIZER_ARTIFACT_DIR="$SANITIZER_ARTIFACT_DIR" \
		SANITIZER_TARGET_DIR="$SANITIZER_VALIDATED_TARGET" \
		nix develop .#asan --command bash scripts/sanitizers/run_sanitizers.sh
}

sanitizer_stage_log() {
	# The open log inode remains the destination if a child swaps artifact parents.
	echo "$*" | tee -a "/proc/self/fd/$sanitizer_log_fd"
}

sanitizer_logging_failure() {
	local phase=$1 logging_status=$2 primary_status=${3:-$2}
	if sanitizer_target_binding validate "$SANITIZER_EVIDENCE_BINDING"; then
		preflight_receipt "$phase" "$primary_status" "$logging_status" "${4:-}" || return 1
	else
		SANITIZER_EVIDENCE_ROUTE_CHANGED=1
		return 1
	fi
}

sanitizer_early_logging_failure() {
	local phase=$1 logging_status=$2 cleanup_status=""
	if [[ -n ${SANITIZER_CLEANUP_BINDING:-} ]]; then
		cleanup_status=0
		cleanup_sanitizer_outputs || cleanup_status=$?
	fi
	sanitizer_logging_failure "$phase" "$logging_status" "$logging_status" "$cleanup_status" || true
	return "$logging_status"
}

run_sanitizers_stage() {
	local status=0 cleanup_status=0 evidence_status=0 logging_status=0 initial_summary
	prepare_sanitizer_attempt || {
		sanitizer_preparation_failure $?
		return $?
	}
	if sanitizer_stage_log "[security] >>> sanitizer smoke"; then
		:
	else
		logging_status=$?
		sanitizer_early_logging_failure initial-log "$logging_status"
		return $?
	fi
	if initial_summary=$(sanitizer_target_binding summary-snapshot "$SANITIZER_EVIDENCE_BINDING"); then
		if sanitize >&"$sanitizer_log_fd" 2>&1; then
			status=0
		else
			status=$?
			# Only our still-identical initialization receipt can describe a
			# launcher failure. Detailed child receipts retain their own bytes.
			sanitizer_target_binding launcher-failure "$SANITIZER_EVIDENCE_BINDING" \
				"$initial_summary" "$status" >&"$sanitizer_log_fd" 2>&1 || evidence_status=1
			sanitizer_stage_log "[security] <<< sanitizer smoke: failed (exit=$status)" || logging_status=$?
		fi
	else
		status=$?
		evidence_status=1
	fi
	cleanup_sanitizer_outputs >&"$sanitizer_log_fd" 2>&1 || cleanup_status=$?
	if [[ $cleanup_status -ne 0 ]]; then
		sanitizer_stage_log "[security] <<< sanitizer cleanup: failed (exit=$cleanup_status)" || logging_status=$?
	fi
	if sanitizer_target_binding validate "$SANITIZER_EVIDENCE_BINDING" >&"$sanitizer_log_fd" 2>&1; then
		if [[ $cleanup_status -ne 0 ]]; then
			preflight_receipt cleanup "$((status != 0 ? status : cleanup_status))" "" "$cleanup_status" >&"$sanitizer_log_fd" 2>&1 || evidence_status=1
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

initialize_sanitizer_log() {
	prepare_sanitizer_attempt || { sanitizer_preparation_failure $? || exit $?; }
	if mkdir -p "$LOG_DIR"; then
		:
	else
		log_status=$?
		sanitizer_early_logging_failure shared-log-directory "$log_status" || exit $?
	fi
	if [[ -n ${SANITIZER_SECURITY_LOG_FD:-} ]]; then
		if "$security_function_python" -I "$ROOT/scripts/sanitizers/open_security_log.py" validate \
			"$SECURITY_LOG_PATH" "$SANITIZER_SECURITY_LOG_FD"; then
			:
		else
			log_status=$?
			sanitizer_early_logging_failure shared-log-descriptor "$log_status" || exit $?
		fi
		sanitizer_log_fd=$SANITIZER_SECURITY_LOG_FD
	else
		exec "$security_function_python" -I "$ROOT/scripts/sanitizers/open_security_log.py" open-exec-bound \
			"$SECURITY_LOG_PATH" "$SANITIZER_ARTIFACT_DIR" "$SANITIZER_EVIDENCE_BINDING" \
			"$SANITIZER_VALIDATED_TARGET" "$SANITIZER_CLEANUP_BINDING" -- "${SECURITY_ENTRY_ARGS[@]}"
	fi
	SANITIZER_LOG_DESTINATION="/proc/self/fd/$sanitizer_log_fd"
	LOG_FILE=$SANITIZER_LOG_DESTINATION
}

initialize_sanitizer_routes() {
	# Shared validators report through the wrapper's existing diagnostics.
	fail() { echo "[security] $*" >&2; }
	# Caller-only cleanup fields cannot survive into a fresh sanitizer attempt.
	if [[ -z ${SANITIZER_EVIDENCE_BINDING:-} ]]; then
		SANITIZER_CLEANUP_BINDING=""
	fi
	preflight_route "$ARTIFACT_BASE" || { sanitizer_preparation_failure 1 || exit $?; }
	ARTIFACT_BASE=$PREFLIGHT_ROUTE
	sanitizer_validate_output "$ARTIFACT_BASE" "$ROOT" || { sanitizer_preparation_failure 1 || exit $?; }
	LOG_DIR="$ARTIFACT_BASE/summary"
	preflight_route "$LOG_DIR" || { sanitizer_preparation_failure 1 || exit $?; }
	LOG_DIR=$PREFLIGHT_ROUTE
	LOG_FILE="$LOG_DIR/security.log"
}

sanitizer_hold_unsafe_outputs() {
	[[ ${SANITIZER_EVIDENCE_ROUTE_CHANGED:-0} == 1 ]] || return 0
	# No later logging/output stage may dereference replaced artifact parents.
	echo "[security] unsafe sanitizer evidence; remaining output stages held" |
		tee -a "$SANITIZER_LOG_DESTINATION" || true
	exit "$1"
}
