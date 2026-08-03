#!/bin/bash
# Comprehensive RFC MUST Requirements Compliance Test Suite
# Tests all 15 tracked RFCs for MUST requirement compliance

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "=== Aegaeon RFC Compliance Test Suite ==="
echo "Testing MUST requirements for all tracked RFCs"
echo ""

# Run all RFC tests and capture output
echo "Running RFC compliance tests..."
if cargo test --package aegaeon-server rfc_tests --no-fail-fast 2>&1 | tee /tmp/rfc_test_output.txt; then
	TEST_EXIT=0
else
	TEST_EXIT=$?
fi

echo ""

# Also run JOSE RFC 7520 test vectors
echo "Running RFC 7520 JOSE test vectors..."
if cargo test --package aegaeon-jose --test rfc7520_vectors 2>&1 | tee -a /tmp/rfc_test_output.txt; then
	JOSE_EXIT=0
else
	JOSE_EXIT=$?
fi

echo ""

# Parse results
if grep -q "test result: ok" /tmp/rfc_test_output.txt; then
	# Extract counts from all test runs
	TOTAL_PASSED=0
	TOTAL_FAILED=0

	while IFS= read -r line; do
		if [[ $line =~ ([0-9]+)\ passed ]]; then
			TOTAL_PASSED=$((TOTAL_PASSED + ${BASH_REMATCH[1]}))
		fi
		if [[ $line =~ ([0-9]+)\ failed ]]; then
			TOTAL_FAILED=$((TOTAL_FAILED + ${BASH_REMATCH[1]}))
		fi
	done </tmp/rfc_test_output.txt

	TOTAL_TESTS=$((TOTAL_PASSED + TOTAL_FAILED))

	# Summary
	echo "════════════════════════════════════════════════"
	echo "RFC Compliance Test Summary"
	echo "════════════════════════════════════════════════"
	echo ""
	echo "Total Tests: $TOTAL_TESTS"
	echo -e "${GREEN}Passed: $TOTAL_PASSED${NC}"

	if [ $TOTAL_FAILED -gt 0 ]; then
		echo -e "${RED}Failed: $TOTAL_FAILED${NC}"
	fi

	echo ""

	if [ $TOTAL_FAILED -eq 0 ] && [ $TEST_EXIT -eq 0 ] && [ $JOSE_EXIT -eq 0 ]; then
		echo -e "${GREEN}✅ All RFC MUST requirements validated${NC}"
		exit 0
	else
		echo -e "${RED}❌ Some RFC MUST requirements failed validation${NC}"
		exit 1
	fi
else
	echo -e "${RED}Failed to run RFC compliance tests${NC}"
	exit 1
fi
