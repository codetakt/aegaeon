#!/usr/bin/env bash
# Create an annotated release tag.

set -euo pipefail

DEFAULT_VERSION="v0.9.0-beta"
VERSION="${1:-$DEFAULT_VERSION}"
if [[ $VERSION != v* ]]; then
	VERSION="v${VERSION}"
fi
CRATE_VERSION="${VERSION#v}"
RELEASE_DATE="$(date -u +"%Y-%m-%d")"

echo "=== Aegaeon Beta Release Script ==="
echo "Version: $VERSION"
echo "Date: $RELEASE_DATE"
echo ""

# Check if we're on the correct branch
CURRENT_BRANCH=$(git branch --show-current)
echo "Current branch: $CURRENT_BRANCH"

# Check for uncommitted changes
if ! git diff --quiet || ! git diff --cached --quiet; then
	echo "❌ Error: Uncommitted changes detected"
	echo "Please commit or stash your changes before creating a release"
	exit 1
fi

# Check if tag already exists
if git rev-parse "$VERSION" >/dev/null 2>&1; then
	echo "❌ Error: Tag $VERSION already exists"
	echo "To delete existing tag: git tag -d $VERSION"
	exit 1
fi

# Verify all crates are at 0.9.0-beta
echo ""
echo "Verifying crate versions..."
for crate in server client jose observability loadtest; do
	if grep -q "version = \"${CRATE_VERSION}\"" "crates/$crate/Cargo.toml"; then
		echo "  ✓ $crate: ${CRATE_VERSION}"
	else
		echo "  ✗ $crate: version mismatch (expected ${CRATE_VERSION})"
		exit 1
	fi
done

# Create annotated tag
echo ""
echo "Creating annotated tag $VERSION..."

TAG_MESSAGE="Aegaeon - Beta Release ${VERSION}

First beta release with comprehensive RFC compliance:
- RFC 6749: OAuth 2.0 Framework
- RFC 6750: Bearer Token Usage
- RFC 7636: PKCE
- RFC 7009: Token Revocation
- RFC 7662: Token Introspection
- RFC 7515-7519: JOSE/JWT Suite
- RFC 7591: Dynamic Client Registration
- RFC 8414: AS Metadata
- RFC 9126: PAR
- RFC 9449: DPoP
- RFC 9700: Security BCP

Features:
- Formal verification with F* and Tamarin
- Complete JOSE/JWT implementation
- Observability with metrics and tracing
- Security scanning and SBOM generation
- Comprehensive test coverage
- Daily conformance validation

See CHANGELOG.md for full details."

git tag -a "$VERSION" -m "$TAG_MESSAGE"

echo "✅ Tag $VERSION created successfully"
echo ""
echo "Tag details:"
git show "$VERSION" --no-patch

echo ""
echo "Next steps:"
echo "1. Push the tag: git push origin $VERSION"
echo "2. Push the branch: git push origin $CURRENT_BRANCH"
echo "3. Create GitHub release from tag"
echo "4. Attach SBOM and security reports to release"
echo ""
echo "GitHub release command:"
echo "gh release create $VERSION \\"
echo "  --title \"Aegaeon $VERSION\" \\"
echo '  --notes-file CHANGELOG.md \'
echo '  --prerelease \'
echo "  --target $CURRENT_BRANCH"
