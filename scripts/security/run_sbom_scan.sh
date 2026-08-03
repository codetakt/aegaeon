#!/usr/bin/env bash
set -euo pipefail

INFO="[INFO]"
WARN="[WARN]"
FAIL="[FAIL]"

OUTPUT_DIR=${OUTPUT_DIR:-artifacts/sbom}
GRYPE_FAIL_ON=${GRYPE_FAIL_ON:-medium}
GRYPE_EXTRA_ARGS=${GRYPE_EXTRA_ARGS:-}
TRIVY_SEVERITY=${TRIVY_SEVERITY:-CRITICAL,HIGH}
TRIVY_EXIT_CODE=${TRIVY_EXIT_CODE:-1}
RUN_TRIVY=${RUN_TRIVY:-auto}

mkdir -p "$OUTPUT_DIR"

echo "$INFO Generating SBOM artifacts under $OUTPUT_DIR"
OUTPUT_DIR="$OUTPUT_DIR" bash scripts/release/generate_sbom.sh

SBOM_FILE="$OUTPUT_DIR/aegaeon-sbom-latest.json"
if [[ ! -f $SBOM_FILE ]]; then
	echo "$FAIL Unable to locate SBOM at $SBOM_FILE"
	exit 1
fi

echo "$INFO SBOM located at $SBOM_FILE"
RUN_ID="$(date -u +"%Y%m%d_%H%M%S")"

scanner_used=0

if command -v grype >/dev/null 2>&1; then
	scanner_used=1
	echo "$INFO Updating grype vulnerability database"
	if ! grype db update >/dev/null 2>&1; then
		echo "$WARN grype database update failed; continuing with existing cache"
	fi

	GRYPE_REPORT="$OUTPUT_DIR/grype-report-$RUN_ID.json"
	echo "$INFO Running grype scan (fail-on=$GRYPE_FAIL_ON, output=$GRYPE_REPORT)"
	set +e
	grype sbom:"$SBOM_FILE" --fail-on "$GRYPE_FAIL_ON" -o json $GRYPE_EXTRA_ARGS >"$GRYPE_REPORT"
	grype_status=$?
	set -e
	ln -sf "$(basename "$GRYPE_REPORT")" "$OUTPUT_DIR/grype-report-latest.json"
	if command -v jq >/dev/null 2>&1; then
		echo "$INFO grype summary (by severity):"
		jq -r '
				(.matches // [])
				| map(.vulnerability.severity // "Unknown")
				| group_by(.)
				| map({severity: .[0], count: length})
				| sort_by(.severity)
				| map("  \(.severity): \(.count)")
				| .[]
			' "$GRYPE_REPORT" || true
	fi
	if [[ $grype_status -ne 0 ]]; then
		echo "$FAIL grype reported vulnerabilities meeting the threshold ($GRYPE_FAIL_ON)"
		exit $grype_status
	fi
	echo "$INFO grype scan completed with no blocking findings"
else
	echo "$WARN grype not available; skipping grype scan"
fi

run_trivy=false
case "${RUN_TRIVY,,}" in
"auto")
	if command -v trivy >/dev/null 2>&1; then
		run_trivy=true
	fi
	;;
"1" | "true" | "yes")
	run_trivy=true
	;;
*)
	run_trivy=false
	;;
esac

if [[ $run_trivy == true ]]; then
	if ! command -v trivy >/dev/null 2>&1; then
		echo "$WARN trivy requested but not available; skipping"
	else
		scanner_used=1
		echo "$INFO Updating trivy vulnerability database"
		if ! trivy --download-db-only >/dev/null 2>&1; then
			echo "$WARN trivy database update failed; continuing with existing cache"
		fi
		TRIVY_REPORT="$OUTPUT_DIR/trivy-report-$RUN_ID.json"
		echo \
			"$INFO Running trivy scan " \
			"(severity=$TRIVY_SEVERITY, exit-code=$TRIVY_EXIT_CODE, " \
			"output=$TRIVY_REPORT)"
		set +e
		trivy sbom \
			--severity "$TRIVY_SEVERITY" \
			--exit-code "$TRIVY_EXIT_CODE" \
			--format json \
			"$SBOM_FILE" >"$TRIVY_REPORT"
		trivy_status=$?
		set -e
		ln -sf "$(basename "$TRIVY_REPORT")" "$OUTPUT_DIR/trivy-report-latest.json"
		if command -v jq >/dev/null 2>&1; then
			echo "$INFO trivy summary (by severity):"
			jq -r '
					([.Results[]? | .Vulnerabilities[]? | .Severity] | map(. // "Unknown"))
					| group_by(.)
					| map({severity: .[0], count: length})
					| sort_by(.severity)
					| map("  \(.severity): \(.count)")
					| .[]
				' "$TRIVY_REPORT" || true
		fi
		if [[ $trivy_status -ne 0 ]]; then
			echo "$FAIL trivy reported vulnerabilities meeting the threshold ($TRIVY_SEVERITY)"
			exit $trivy_status
		fi
		echo "$INFO trivy scan completed with no blocking findings"
	fi
else
	if [[ $RUN_TRIVY != "auto" ]]; then
		echo "$INFO Skipping trivy scan by configuration"
	elif command -v trivy >/dev/null 2>&1; then
		echo "$INFO Trivy available; set RUN_TRIVY=1 to enable its scan"
	fi
fi

if [[ $scanner_used -eq 0 ]]; then
	echo "$FAIL No vulnerability scanner executed (grype/trivy missing)."
	exit 1
fi

echo "$INFO SBOM scanning completed successfully"
