#!/usr/bin/env bash
# Generate Software Bill of Materials (SBOM) for Aegaeon
# Release preparation: SBOM generation and vulnerability scanning

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
OUTPUT_DIR="${OUTPUT_DIR:-./artifacts/sbom}"
SBOM_FORMAT="${SBOM_FORMAT:-cyclonedx}"
SBOM_VERSION="${SBOM_VERSION:-1.5}"
TIMESTAMP=$(date -u +"%Y%m%d_%H%M%S")

echo -e "${GREEN}=== Aegaeon SBOM Generation ===${NC}"
echo "Output directory: $OUTPUT_DIR"
echo "Format: $SBOM_FORMAT v$SBOM_VERSION"
echo "Timestamp: $TIMESTAMP"

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Function to check if tool is available
check_tool() {
	if ! command -v "$1" &>/dev/null; then
		echo -e "${RED}Error: $1 is not installed${NC}"
		echo "Please install it using: cargo install $2"
		exit 1
	fi
}

# Check required tools
echo -e "\n${YELLOW}Checking required tools...${NC}"
check_tool "cargo-cyclonedx" "cargo-cyclonedx"

# Generate Rust dependencies SBOM
echo -e "\n${YELLOW}Generating Rust dependencies SBOM...${NC}"
# Use workspace-level generation (generates multiple files)
cargo cyclonedx --format json --spec-version "$SBOM_VERSION" --describe crate >/dev/null 2>&1 &
CYCLONE_PID=$!

# Wait for completion with timeout (60 seconds)
TIMEOUT=60
ELAPSED=0
while kill -0 $CYCLONE_PID 2>/dev/null; do
	if [ $ELAPSED -ge $TIMEOUT ]; then
		echo -e "${YELLOW}Warning: cargo-cyclonedx taking longer than expected, continuing...${NC}"
		break
	fi
	sleep 1
	ELAPSED=$((ELAPSED + 1))
done

# Find the most recent aegaeon-server.cdx.json (main artifact)
SBOM_FILE=$(find . -name "aegaeon-server.cdx.json" -o -name "aegaeon-*.cdx.json" | grep -v node_modules | head -1)
if [ -n "$SBOM_FILE" ] && [ -f "$SBOM_FILE" ]; then
	cp "$SBOM_FILE" "$OUTPUT_DIR/rust-sbom-$TIMESTAMP.json"
	ln -sf "rust-sbom-$TIMESTAMP.json" "$OUTPUT_DIR/rust-sbom-latest.json"
else
	echo -e "${RED}Error: Failed to generate SBOM${NC}"
	exit 1
fi

# Generate comprehensive SBOM with additional metadata
echo -e "\n${YELLOW}Enhancing SBOM with metadata...${NC}"
cat >"$OUTPUT_DIR/sbom-metadata.json" <<EOF
{
  "metadata": {
    "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
    "tools": [
      {
        "vendor": "CycloneDX",
        "name": "cargo-cyclonedx",
        "version": "$(cargo cyclonedx --version | cut -d' ' -f2)"
      }
    ],
    "authors": [
      {
        "name": "Aegaeon Development Team",
        "email": "security@aegaeon.example"
      }
    ],
    "component": {
      "type": "application",
      "bom-ref": "aegaeon-oauth-server",
      "name": "aegaeon-server",
      "version": "0.9.0-beta",
      "description": "RFC-compliant OAuth 2.x authorization server with formal verification",
      "licenses": [
        {
          "license": {
            "id": "Apache-2.0"
          }
        }
      ],
      "external_references": [
        {
          "type": "vcs",
          "url": "https://github.com/cariandrum22/aegaeon"
        },
        {
          "type": "website",
          "url": "https://aegaeon.example"
        }
      ]
    },
    "properties": [
      {
        "name": "cdx:security:verification",
        "value": "F* formal verification, Tamarin protocol proofs"
      },
      {
        "name": "cdx:security:tcb",
        "value": "F* core, KaRaMeL extraction, HACL*/EverCrypt"
      },
      {
        "name": "cdx:compliance:oauth",
        "value": "RFC 6749, 6750, 7636, 9126, 9449, 7009, 7662, 9700"
      },
      {
        "name": "cdx:compliance:jose",
        "value": "RFC 7515-7519"
      }
    ]
  }
}
EOF

# Merge metadata with the generated SBOM
echo -e "\n${YELLOW}Creating final SBOM...${NC}"
if command -v jq &>/dev/null; then
	jq -s '.[0] * .[1]' "$OUTPUT_DIR/rust-sbom-$TIMESTAMP.json" "$OUTPUT_DIR/sbom-metadata.json" >"$OUTPUT_DIR/aegaeon-sbom-$TIMESTAMP.json"

	# Create a latest symlink
	ln -sf "aegaeon-sbom-$TIMESTAMP.json" "$OUTPUT_DIR/aegaeon-sbom-latest.json"

	# Generate human-readable report
	echo -e "\n${YELLOW}Generating SBOM report...${NC}"
	REPORT_FILE="$OUTPUT_DIR/sbom-report-$TIMESTAMP.txt"
	jq -r '
        "=== Aegaeon SBOM Report ===\n" +
        "Generated: " + .metadata.timestamp + "\n" +
        "Component: " + .metadata.component.name + " v" + .metadata.component.version + "\n" +
        "\nDependencies Summary:\n" +
        "Total components: " + (.components | length | tostring) + "\n" +
        "\nLicense Distribution:\n" +
        (.components | group_by(.licenses[0].license.id // "Unknown") | 
         map("  " + .[0].licenses[0].license.id + ": " + (length | tostring)) | 
         join("\n")) +
        "\n\nSecurity Properties:\n" +
        (.metadata.properties | map("  " + .name + ": " + .value) | join("\n"))
    ' "$OUTPUT_DIR/aegaeon-sbom-latest.json" >"$REPORT_FILE"
	ln -sf "$(basename "$REPORT_FILE")" "$OUTPUT_DIR/sbom-report-latest.txt"

	echo -e "${GREEN}✓ SBOM generated successfully${NC}"
	echo "  JSON: $OUTPUT_DIR/aegaeon-sbom-$TIMESTAMP.json"
	echo "  Report: $OUTPUT_DIR/sbom-report-$TIMESTAMP.txt"
	echo "  Latest: $OUTPUT_DIR/aegaeon-sbom-latest.json"
else
	echo -e "${YELLOW}Warning: jq not found, metadata not merged${NC}"
	mv "$OUTPUT_DIR/rust-sbom-$TIMESTAMP.json" "$OUTPUT_DIR/aegaeon-sbom-$TIMESTAMP.json"
fi

# Validate SBOM format
echo -e "\n${YELLOW}Validating SBOM...${NC}"
if [ -f "$OUTPUT_DIR/aegaeon-sbom-latest.json" ]; then
	# Basic validation - check for required fields
	if jq -e '.bomFormat and .specVersion and .components' "$OUTPUT_DIR/aegaeon-sbom-latest.json" >/dev/null; then
		echo -e "${GREEN}✓ SBOM validation passed${NC}"
	else
		echo -e "${RED}✗ SBOM validation failed: missing required fields${NC}"
		exit 1
	fi
fi

# Generate SBOM signature (if cosign is available and explicitly enabled)
if [ "${ENABLE_COSIGN_SIGNING:-0}" = "1" ] && command -v cosign &>/dev/null; then
	echo -e "\n${YELLOW}Signing SBOM with cosign...${NC}"
	cosign sign-blob --yes \
		--output-signature "$OUTPUT_DIR/aegaeon-sbom-$TIMESTAMP.sig" \
		--output-certificate "$OUTPUT_DIR/aegaeon-sbom-$TIMESTAMP.crt" \
		"$OUTPUT_DIR/aegaeon-sbom-$TIMESTAMP.json" 2>/dev/null || {
		echo -e "${YELLOW}Note: Cosign signing requires authentication${NC}"
	}
else
	if command -v cosign &>/dev/null; then
		echo -e "\n${YELLOW}Cosign signing disabled (set ENABLE_COSIGN_SIGNING=1 to enable)${NC}"
	fi
fi

echo -e "\n${GREEN}=== SBOM Generation Complete ===${NC}"
