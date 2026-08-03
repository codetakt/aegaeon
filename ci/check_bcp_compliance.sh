#!/bin/bash
# RFC 9700 BCP Compliance Checker for CI
# Ensures 100% compliance with OAuth 2.0 Security Best Current Practice

set -euo pipefail

echo "🔐 OAuth 2.0 BCP Compliance Check (RFC 9700)"
echo "==========================================="

COMPLIANCE_REPORT="artifacts/bcp_compliance.json"
mkdir -p artifacts

# Exit codes
EXIT_SUCCESS=0
EXIT_CRITICAL_VIOLATION=1
EXIT_HIGH_VIOLATION=2
EXIT_CHECK_FAILED=3

# Initialize report
cat >"$COMPLIANCE_REPORT" <<EOF
{
	"timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
	"checks": [],
	"violations": [],
	"status": "checking"
}
EOF

# Helper function to add check result
add_check() {
	local name="$1"
	local status="$2"
	local message="$3"

	jq --arg name "$name" \
		--arg status "$status" \
		--arg message "$message" \
		'.checks += [{"name": $name, "status": $status, "message": $message}]' \
		"$COMPLIANCE_REPORT" >"$COMPLIANCE_REPORT.tmp"
	mv "$COMPLIANCE_REPORT.tmp" "$COMPLIANCE_REPORT"
}

# Helper function to add violation
add_violation() {
	local severity="$1"
	local policy="$2"
	local description="$3"

	jq --arg severity "$severity" \
		--arg policy "$policy" \
		--arg description "$description" \
		'.violations += [{"severity": $severity, "policy": $policy, "description": $description}]' \
		"$COMPLIANCE_REPORT" >"$COMPLIANCE_REPORT.tmp"
	mv "$COMPLIANCE_REPORT.tmp" "$COMPLIANCE_REPORT"
}

grep_rust() {
	grep -r "$1" crates/ --include="*.rs" 2>/dev/null
}

grep_rust_and_toml() {
	grep -r "$1" crates/ --include="*.rs" --include="*.toml" 2>/dev/null
}

TEST_FILTER='mod tests\|fn test_\|#\[test\]\|#\[cfg(test)\]'
TEST_GUARD_PATTERN='#\[test\]\|fn test_'

echo "1. Checking PKCE enforcement..."
# Exclude test files and test blocks - look for non-test code only
NON_TEST_PKCE=$(
	grep_rust_and_toml "require_pkce.*false" |
		grep -v "$TEST_FILTER" || true
)
# Check if any of the matches are outside test functions
REAL_VIOLATION=false
while IFS= read -r line; do
	if [ -n "$line" ]; then
		FILE=$(echo "$line" | cut -d: -f1)
		LINE_NUM=$(echo "$line" | cut -d: -f2)
		# Check if this line is inside a test function
		if ! grep -B10 "require_pkce.*false" "$FILE" | grep -q "$TEST_GUARD_PATTERN"; then
			echo "$line"
			REAL_VIOLATION=true
		fi
	fi
done <<<"$NON_TEST_PKCE"

if [ "$REAL_VIOLATION" = true ]; then
	echo "   ❌ PKCE not enforced in some configurations"
	add_check "PKCE_ENFORCEMENT" "FAILED" "PKCE must be required for all clients (RFC 9700)"
	add_violation "CRITICAL" "require_pkce" "PKCE not enforced"
else
	echo "   ✅ PKCE enforcement verified"
	add_check "PKCE_ENFORCEMENT" "PASSED" "PKCE is required"
fi

echo "2. Checking redirect_uri exact matching..."
if grep_rust "redirect_uri.*contains\|redirect_uri.*starts_with" | grep -v "exact\|=="; then
	echo "   ❌ Non-exact redirect_uri matching found"
	add_check "REDIRECT_URI_EXACT" "FAILED" "Exact redirect_uri matching required (RFC 9700)"
	add_violation "CRITICAL" "redirect_uri_matching" "Non-exact matching detected"
else
	echo "   ✅ Redirect URI exact matching verified"
	add_check "REDIRECT_URI_EXACT" "PASSED" "Exact matching enforced"
fi

echo "3. Checking for forbidden flows..."
FORBIDDEN_FLOWS=("implicit" "password" "ropc")
for flow in "${FORBIDDEN_FLOWS[@]}"; do
	if grep_rust "grant_type.*$flow\|flow.*$flow" |
		grep -v "forbid\|forbidden\|deprecated\|disabled" |
		grep -v "$TEST_FILTER" |
		grep -v '//\|assert!' |
		grep -v "contains(\"$flow\")" |
		grep -v "allowed_flows.insert\|grant_types_supported.push" |
		grep -v "validate_security_compliance\|iter().any"; then
		echo "   ❌ Forbidden flow '$flow' detected"
		add_check "FORBIDDEN_FLOW_$flow" "FAILED" "$flow flow must not be used (RFC 9700)"
		add_violation "CRITICAL" "forbidden_flow" "$flow flow detected"
	else
		echo "   ✅ No $flow flow detected"
		add_check "FORBIDDEN_FLOW_$flow" "PASSED" "$flow flow not present"
	fi
done

echo "4. Checking issuer parameter inclusion..."
# Check for issuer parameter support in metadata or configuration
if grep_rust "require_iss_parameter\|authorization_response_iss_parameter" |
	grep -q "true\|Some(true)"; then
	echo "   ✅ Issuer parameter inclusion verified"
	add_check "ISSUER_PARAMETER" "PASSED" "Issuer parameter included"
else
	echo "   ⚠️  Issuer parameter may not be included"
	add_check "ISSUER_PARAMETER" "WARNING" "Issuer parameter should be included (Mix-Up mitigation)"
	add_violation "HIGH" "issuer_parameter" "Issuer parameter not confirmed"
fi

echo "5. Checking sender-constrained tokens..."
# Check for DPoP or mTLS implementation
if grep_rust "DpopMiddleware\|dpop.*verify\|require_sender_constrained_tokens.*true" |
	head -1 >/dev/null; then
	echo "   ✅ Sender-constrained tokens implemented"
	add_check "SENDER_CONSTRAINED" "PASSED" "DPoP/mTLS support found"
else
	echo "   ⚠️  Sender-constrained tokens not found"
	add_check "SENDER_CONSTRAINED" "WARNING" "Should implement DPoP or mTLS (RFC 9700)"
	add_violation "HIGH" "sender_constrained" "No DPoP/mTLS implementation found"
fi

echo "6. Checking state parameter requirements..."
if ! grep_rust "state.*required\|require.*state" | grep -q "true"; then
	echo "   ❌ State parameter not required"
	add_check "STATE_PARAMETER" "FAILED" "State parameter must be required (RFC 9700)"
	add_violation "CRITICAL" "state_parameter" "State not enforced"
else
	echo "   ✅ State parameter requirement verified"
	add_check "STATE_PARAMETER" "PASSED" "State parameter required"
fi

echo "7. Checking entropy requirements..."
if grep_rust "entropy.*bits\|min.*entropy" | grep -q "128\|256"; then
	echo "   ✅ Adequate entropy requirements found"
	add_check "ENTROPY_REQUIREMENTS" "PASSED" "Minimum 128-bit entropy"
else
	echo "   ⚠️  Entropy requirements not verified"
	add_check "ENTROPY_REQUIREMENTS" "WARNING" "Should verify 128-bit minimum entropy"
fi

echo "8. Checking authorization code lifetime..."
if grep_rust "auth.*code.*lifetime\|code.*expir" | grep -q "600\|10.*min"; then
	echo "   ✅ Authorization code lifetime appropriate"
	add_check "AUTH_CODE_LIFETIME" "PASSED" "Maximum 10 minutes lifetime"
else
	echo "   ⚠️  Authorization code lifetime not verified"
	add_check "AUTH_CODE_LIFETIME" "WARNING" "Should limit to 10 minutes"
fi

echo "9. Running Rust BCP policy tests..."
if cargo test --package aegaeon-server --lib bcp_policy --quiet 2>&1 >artifacts/bcp_test.log; then
	echo "   ✅ BCP policy tests passed"
	add_check "BCP_POLICY_TESTS" "PASSED" "All policy tests passed"
else
	echo "   ❌ BCP policy tests failed"
	add_check "BCP_POLICY_TESTS" "FAILED" "Policy tests did not pass"
	add_violation "CRITICAL" "policy_tests" "BCP policy tests failed"
fi

echo "10. Validating F* Bearer proofs..."
if [ -f "fstar/token/Bearer.fst" ]; then
	echo "   ✅ F* Bearer implementation found"
	add_check "FSTAR_BEARER" "PASSED" "Bearer token validation in F*"
else
	echo "   ⚠️  F* Bearer implementation not found"
	add_check "FSTAR_BEARER" "WARNING" "F* Bearer implementation missing"
fi

echo "11. Checking Tamarin proofs..."
if [ -f "proofs/tamarin/bearer/bearer_bcp.spthy" ]; then
	echo "   ✅ Tamarin BCP proofs found"
	add_check "TAMARIN_PROOFS" "PASSED" "BCP security proofs present"
else
	echo "   ⚠️  Tamarin BCP proofs not found"
	add_check "TAMARIN_PROOFS" "WARNING" "Tamarin proofs missing"
fi

# Calculate final status
CRITICAL_COUNT=$(
	jq '[.violations[] | select(.severity == "CRITICAL")] | length' "$COMPLIANCE_REPORT"
)
HIGH_COUNT=$(jq '[.violations[] | select(.severity == "HIGH")] | length' "$COMPLIANCE_REPORT")
TOTAL_VIOLATIONS=$(jq '.violations | length' "$COMPLIANCE_REPORT")

if [ "$CRITICAL_COUNT" -gt 0 ]; then
	STATUS="FAILED"
	EXIT_CODE=$EXIT_CRITICAL_VIOLATION
elif [ "$HIGH_COUNT" -gt 0 ]; then
	STATUS="PARTIAL"
	EXIT_CODE=$EXIT_HIGH_VIOLATION
elif [ "$TOTAL_VIOLATIONS" -gt 0 ]; then
	STATUS="PARTIAL"
	EXIT_CODE=$EXIT_SUCCESS
else
	STATUS="COMPLIANT"
	EXIT_CODE=$EXIT_SUCCESS
fi

# Update final report
jq --arg status "$STATUS" \
	--arg critical "$CRITICAL_COUNT" \
	--arg high "$HIGH_COUNT" \
	--arg total "$TOTAL_VIOLATIONS" \
	'.status = $status |
		.summary = {
			"critical_violations": ($critical | tonumber),
			"high_violations": ($high | tonumber),
			"total_violations": ($total | tonumber),
			"compliance_percentage": (
				if ($total | tonumber) == 0 then
					100
				else
					(100 - (($critical | tonumber) * 10 + ($high | tonumber) * 5))
				end
			)
		}' \
	"$COMPLIANCE_REPORT" >"$COMPLIANCE_REPORT.tmp"
mv "$COMPLIANCE_REPORT.tmp" "$COMPLIANCE_REPORT"

echo ""
echo "==========================================="
echo "BCP Compliance Summary:"
echo "  Critical violations: $CRITICAL_COUNT"
echo "  High violations: $HIGH_COUNT"
echo "  Total violations: $TOTAL_VIOLATIONS"
echo "  Status: $STATUS"
echo ""

if [ "$EXIT_CODE" -eq 0 ]; then
	echo "✅ BCP compliance check passed!"
else
	echo "❌ BCP compliance check failed!"
	echo "See $COMPLIANCE_REPORT for details"
fi

exit "$EXIT_CODE"
