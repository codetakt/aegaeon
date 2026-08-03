#!/usr/bin/env python3
"""
RFC Update Monitor for Aegaeon
Checks for updates to tracked RFCs and creates GitHub issues when changes are detected
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Any, cast

# Configuration
RFC_TRACKING_FILE = Path(".rfc-tracking.json")
GITHUB_OUTPUT = os.environ.get("GITHUB_OUTPUT", "")

# RFCs we track for compliance
TRACKED_RFCS = {
    "6749": {
        "title": "The OAuth 2.0 Authorization Framework",
        "url": "https://datatracker.ietf.org/doc/rfc6749/",
        "must_requirements": [
            "authorization_code",
            "access_token",
            "refresh_token",
            "client_credentials",
        ],
    },
    "6750": {
        "title": "The OAuth 2.0 Authorization Framework: Bearer Token Usage",
        "url": "https://datatracker.ietf.org/doc/rfc6750/",
        "must_requirements": ["bearer_header", "form_encoded_body", "uri_query"],
    },
    "7636": {
        "title": "Proof Key for Code Exchange by OAuth Public Clients",
        "url": "https://datatracker.ietf.org/doc/rfc7636/",
        "must_requirements": ["code_challenge", "code_verifier", "S256_method"],
    },
    "7009": {
        "title": "OAuth 2.0 Token Revocation",
        "url": "https://datatracker.ietf.org/doc/rfc7009/",
        "must_requirements": ["revocation_endpoint", "token_type_hint"],
    },
    "7662": {
        "title": "OAuth 2.0 Token Introspection",
        "url": "https://datatracker.ietf.org/doc/rfc7662/",
        "must_requirements": ["introspection_endpoint", "active_claim"],
    },
    "7515": {
        "title": "JSON Web Signature (JWS)",
        "url": "https://datatracker.ietf.org/doc/rfc7515/",
        "must_requirements": ["compact_serialization", "signature_validation"],
    },
    "7516": {
        "title": "JSON Web Encryption (JWE)",
        "url": "https://datatracker.ietf.org/doc/rfc7516/",
        "must_requirements": ["compact_serialization", "content_encryption"],
    },
    "7517": {
        "title": "JSON Web Key (JWK)",
        "url": "https://datatracker.ietf.org/doc/rfc7517/",
        "must_requirements": ["kty_parameter", "use_parameter"],
    },
    "7518": {
        "title": "JSON Web Algorithms (JWA)",
        "url": "https://datatracker.ietf.org/doc/rfc7518/",
        "must_requirements": ["HS256", "RS256", "none_rejection"],
    },
    "7519": {
        "title": "JSON Web Token (JWT)",
        "url": "https://datatracker.ietf.org/doc/rfc7519/",
        "must_requirements": ["iss_claim", "exp_claim", "signature_validation"],
    },
    "7591": {
        "title": "OAuth 2.0 Dynamic Client Registration Protocol",
        "url": "https://datatracker.ietf.org/doc/rfc7591/",
        "must_requirements": ["registration_endpoint", "client_metadata"],
    },
    "8414": {
        "title": "OAuth 2.0 Authorization Server Metadata",
        "url": "https://datatracker.ietf.org/doc/rfc8414/",
        "must_requirements": ["issuer", "authorization_endpoint", "token_endpoint"],
    },
    "9126": {
        "title": "OAuth 2.0 Pushed Authorization Requests",
        "url": "https://datatracker.ietf.org/doc/rfc9126/",
        "must_requirements": ["par_endpoint", "request_uri"],
    },
    "9449": {
        "title": "OAuth 2.0 Demonstrating Proof-of-Possession at the Application Layer (DPoP)",
        "url": "https://datatracker.ietf.org/doc/rfc9449/",
        "must_requirements": ["dpop_header", "htm_claim", "htu_claim", "jti_claim"],
    },
    "9700": {
        "title": "OAuth 2.0 Security Best Current Practice",
        "url": "https://datatracker.ietf.org/doc/rfc9700/",
        "must_requirements": ["pkce_mandatory", "state_parameter", "nonce_parameter"],
    },
}


def fetch_rfc_metadata(rfc_number: str) -> dict[str, Any] | None:
    """Fetch RFC metadata from IETF datatracker API"""
    try:
        api_url = f"https://datatracker.ietf.org/api/v1/doc/document/rfc{rfc_number}/"
        req = urllib.request.Request(api_url, headers={"User-Agent": "Aegaeon-RFC-Monitor/1.0"})

        with urllib.request.urlopen(req, timeout=10) as response:
            data_str = response.read().decode("utf-8")
            data = cast("dict[str, Any]", json.loads(data_str))

            return {
                "rfc": rfc_number,
                "title": data.get("title", ""),
                "abstract": data.get("abstract", ""),
                "updated": data.get("time", ""),
                "rev": data.get("rev", ""),
                "pages": data.get("pages", 0),
                "hash": hashlib.sha256(data_str.encode()).hexdigest(),
            }
    except Exception as e:
        print(f"Error fetching RFC {rfc_number}: {e}", file=sys.stderr)
    return None


def load_tracking_data() -> dict[str, dict[str, Any]]:
    """Load previously tracked RFC data"""
    if RFC_TRACKING_FILE.exists():
        with open(RFC_TRACKING_FILE) as f:
            return cast("dict[str, dict[str, Any]]", json.load(f))
    return {}


def save_tracking_data(data: dict[str, dict[str, Any]]) -> None:
    """Save current RFC tracking data"""
    with open(RFC_TRACKING_FILE, "w") as f:
        json.dump(data, f, indent=2)


def check_for_updates() -> list[dict[str, str]]:
    """Check all tracked RFCs for updates"""
    previous_data = load_tracking_data()
    current_data: dict[str, dict[str, Any]] = {}
    updates: list[dict[str, str]] = []

    for rfc_num, rfc_info in TRACKED_RFCS.items():
        print(f"Checking RFC {rfc_num}: {rfc_info['title']}")

        current_metadata = fetch_rfc_metadata(rfc_num)
        if current_metadata:
            current_data[rfc_num] = current_metadata

            # Check for changes
            if rfc_num in previous_data:
                prev = previous_data[rfc_num]
                curr = current_metadata

                if prev.get("hash") != curr.get("hash"):
                    updates.append(
                        {
                            "rfc": rfc_num,
                            "title": str(rfc_info["title"]),
                            "url": str(rfc_info["url"]),
                            "previous_rev": prev.get("rev", "unknown"),
                            "current_rev": curr.get("rev", "unknown"),
                            "change_detected": datetime.utcnow().isoformat(),
                        }
                    )
                    print(f"  ⚠️  Update detected for RFC {rfc_num}")
                else:
                    print(f"  ✓  No changes for RFC {rfc_num}")
            else:
                print(f"  📝 First time tracking RFC {rfc_num}")
                current_data[rfc_num] = current_metadata

    # Save current state
    save_tracking_data(current_data)

    return updates


def generate_issue_body(updates: list[dict[str, str]]) -> str:
    """Generate GitHub issue body for RFC updates"""
    body = "# RFC Update Notification\n\n"
    body += "The following RFCs have been updated and may require implementation changes:\n\n"

    for update in updates:
        body += f"## RFC {update['rfc']}: {update['title']}\n"
        body += f"- **URL**: {update['url']}\n"
        body += f"- **Previous Revision**: {update['previous_rev']}\n"
        body += f"- **Current Revision**: {update['current_rev']}\n"
        body += f"- **Change Detected**: {update['change_detected']}\n\n"

        # Add MUST requirements that need verification
        if update["rfc"] in TRACKED_RFCS:
            must_reqs = TRACKED_RFCS[update["rfc"]].get("must_requirements", [])
            if must_reqs:
                body += "### MUST Requirements to Verify:\n"
                for req in must_reqs:
                    body += f"- [ ] {req}\n"
                body += "\n"

    body += "## Action Required\n"
    body += "1. Review the RFC changes\n"
    body += "2. Update implementation if necessary\n"
    body += "3. Update conformance tests\n"
    body += "4. Run full compliance validation\n\n"
    body += "_This issue was automatically generated by the RFC update monitor._\n"

    return body


def generate_compliance_matrix() -> str:
    """Generate RFC compliance matrix for documentation"""
    matrix = "# RFC Compliance Matrix\n\n"
    matrix += "| RFC | Title | MUST Requirements | Status |\n"
    matrix += "|-----|-------|------------------|--------|\n"

    for rfc_num, rfc_info in TRACKED_RFCS.items():
        must_count = len(rfc_info.get("must_requirements", []))
        matrix += f"| {rfc_num} | {rfc_info['title'][:40]}... | {must_count} requirements | "
        matrix += "🟢 Tracked |\n"

    return matrix


def main() -> int:
    print("=== Aegaeon RFC Update Monitor ===")
    print(f"Checking {len(TRACKED_RFCS)} RFCs for updates...\n")

    # Check for updates
    updates = check_for_updates()

    # Generate compliance matrix
    matrix = generate_compliance_matrix()
    matrix_file = Path("docs/rfc-compliance-matrix.md")
    matrix_file.parent.mkdir(exist_ok=True)
    with open(matrix_file, "w") as f:
        f.write(matrix)
    print(f"\n📊 Compliance matrix saved to {matrix_file}")

    # Handle updates
    if updates:
        print(f"\n⚠️  Found {len(updates)} RFC update(s)")

        # Generate issue body
        issue_body = generate_issue_body(updates)

        # Output for GitHub Actions
        if GITHUB_OUTPUT:
            with open(GITHUB_OUTPUT, "a") as f:
                f.write("updates_found=true\n")
                f.write(f"rfc_list={','.join([u['rfc'] for u in updates])}\n")
                # Escape multiline string for GitHub Actions
                escaped_body = issue_body.replace("\n", "%0A").replace("\r", "%0D")
                f.write(f"issue_body={escaped_body}\n")

        # Also save to file for manual review
        with open("rfc-updates.json", "w") as f:
            json.dump(updates, f, indent=2)

        print("\nIssue content:")
        print("-" * 50)
        print(issue_body)
        print("-" * 50)

        return 1  # Exit with error to trigger issue creation
    print("\n✅ All tracked RFCs are up to date")
    if GITHUB_OUTPUT:
        with open(GITHUB_OUTPUT, "a") as f:
            f.write("updates_found=false\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
