#!/usr/bin/env python3
"""Auto-populate ``runtime_link`` fields in the compliance matrix.

Uses heuristics to derive the Rust implementation file from the existing
``module`` field:

1. ``module`` starts with ``crates/`` → use as-is (already Rust).
2. ``module`` starts with ``fstar/`` → look up in FSTAR_TO_RUST_MAP.
3. ``module`` starts with ``docs/`` → use first Rust file from ``tests[]``.
4. Fallback → unmapped (requires manual assignment).

Modes:
    --dry-run   Print what would be written (default).
    --write     Update the YAML in-place.
    --report    Print a summary of mapped/unmapped entries.
"""

from __future__ import annotations

import argparse
import pathlib
import sys
from typing import Any, cast

import yaml

MATRIX_FILE = pathlib.Path("spec/compliance-matrix.yaml")

# F* spec module → primary Rust implementation file
FSTAR_TO_RUST_MAP: dict[str, str] = {
    # authcode
    "fstar/authcode/AuthCode.Store.fst": "crates/server/src/authcode/store.rs",
    "fstar/authcode/AuthCode.Flow.fst": "crates/server/src/authcode/mod.rs",
    # token
    "fstar/token/Token.fst": "crates/server/src/authcode/token.rs",
    "fstar/token/Bearer_validation.fst": "crates/server/src/middleware/mod.rs",
    # dpop
    "fstar/dpop/Dpop.Ath_validation.fst": "crates/server/src/middleware/dpop.rs",
    "fstar/dpop/Dpop.Claims.fst": "crates/server/src/middleware/dpop.rs",
    "fstar/dpop/Dpop.Header.fst": "crates/server/src/middleware/dpop.rs",
    "fstar/dpop/Dpop.Htm_validation.fst": "crates/server/src/middleware/dpop.rs",
    "fstar/dpop/Dpop.Htu_validation.fst": "crates/server/src/middleware/dpop.rs",
    "fstar/dpop/Dpop.Iat_validation.fst": "crates/server/src/middleware/dpop.rs",
    "fstar/dpop/Dpop.Replay.fst": "crates/server/src/middleware/replay_store.rs",
    "fstar/dpop/Dpop.Signature.fst": "crates/server/src/middleware/dpop.rs",
    "fstar/dpop/Dpop.Token_binding.fst": "crates/server/src/middleware/dpop.rs",
    # introspection
    "fstar/introspection/Introspection.fst": "crates/server/src/web/token_lifecycle.rs",
    # jose
    "fstar/jose/Jose.Alg_policy.fst": "crates/jose/src/policy.rs",
    "fstar/jose/Jose.Hmac_verification.fst": "crates/jose/src/jws.rs",
    "fstar/jose/Jose.Jwe_aad.fst": "crates/jose/src/jwe.rs",
    "fstar/jose/Jose.Jwe_header.fst": "crates/jose/src/jwe.rs",
    "fstar/jose/Jose.Jwk_metadata.fst": "crates/jose/src/jwk.rs",
    "fstar/jose/Jose.Jwk_structure.fst": "crates/jose/src/jwk.rs",
    "fstar/jose/Jose.Jwk_thumbprint_uri.fst": "crates/jose/src/jwk.rs",
    "fstar/jose/Jose.Jws_header.fst": "crates/jose/src/jws.rs",
    "fstar/jose/Jose.Jws_serialization.fst": "crates/jose/src/jws.rs",
    "fstar/jose/Jose.Jws_signature.fst": "crates/jose/src/jws.rs",
    "fstar/jose/Jose.Jwt_claims.fst": "crates/jose/src/jwt.rs",
    "fstar/jose/Jose.Jwt_validation.fst": "crates/jose/src/jwt.rs",
    "fstar/jose/Jose.LowStar.fst": "crates/jose/src/json_lowstar.rs",
    "fstar/jose/Jose.Rsa_signatures.fst": "crates/jose/src/jws.rs",
    "fstar/jose/Jose.TlvResultSpec.fst": "crates/jose/src/tlv.rs",
    "fstar/jose/LowStar/Json/Jose.LowStar.Json.Stack.fst": "crates/jose/src/json_lowstar.rs",
    # par
    "fstar/par/Authorization.fst": "crates/server/src/web/authorize_endpoint.rs",
    "fstar/par/Client_auth.fst": "crates/server/src/client_registry.rs",
    "fstar/par/Lifetime.fst": "crates/server/src/web/par_endpoint.rs",
    "fstar/par/ParBinding.fst": "crates/server/src/web/par_endpoint.rs",
    "fstar/par/Request_uri.fst": "crates/server/src/web/par_endpoint.rs",
    "fstar/par/Response.fst": "crates/server/src/web/par_endpoint.rs",
    # pkce
    "fstar/pkce/Pkce.Challenge.fst": "crates/server/src/authcode/mod.rs",
    "fstar/pkce/Pkce.Method_selection.fst": "crates/server/src/authcode/mod.rs",
    "fstar/pkce/Pkce.Verification.fst": "crates/server/src/authcode/mod.rs",
    "fstar/pkce/Pkce.Verifier.fst": "crates/server/src/authcode/mod.rs",
    # revocation
    "fstar/revocation/Revocation.fst": "crates/server/src/web/token_lifecycle.rs",
    # stepup
    "fstar/stepup/StepUp.fst": "crates/server/src/stepup.rs",
}


def derive_runtime_link(entry: dict[str, Any]) -> str | None:
    """Derive runtime_link from an entry's module and tests fields."""
    module: str = entry.get("module", "")

    # Strategy 1: module is already a Rust crate file
    if module.startswith("crates/"):
        return module

    # Strategy 2: F* module → lookup in map
    if module.startswith("fstar/"):
        return FSTAR_TO_RUST_MAP.get(module)

    # Strategy 3: docs/ module → first Rust file from tests[]
    if module.startswith("docs/"):
        tests = entry.get("tests", [])
        for t in tests:
            if isinstance(t, str) and t.startswith("crates/"):
                return t
        return None

    return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true", help="Print what would be set (default)")
    mode.add_argument("--write", action="store_true", help="Update YAML in-place")
    mode.add_argument("--report", action="store_true", help="Print summary only")
    args = parser.parse_args()

    if not MATRIX_FILE.exists():
        print(f"ERROR: {MATRIX_FILE} not found", file=sys.stderr)
        return 1

    data = cast("dict[str, object]", yaml.safe_load(MATRIX_FILE.read_text()))

    mapped = 0
    unmapped: list[tuple[str, str]] = []  # (id, module)
    already_set = 0
    categories = {"crates_direct": 0, "fstar_mapped": 0, "docs_mapped": 0}

    for key, entries in data.items():
        if key == "metadata" or not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            if entry.get("status") != "verified":
                continue

            entry_id = entry.get("id", "<unknown>")
            module = entry.get("module", "")

            if entry.get("runtime_link"):
                already_set += 1
                continue

            link = derive_runtime_link(entry)
            if link:
                mapped += 1
                if module.startswith("crates/"):
                    categories["crates_direct"] += 1
                elif module.startswith("fstar/"):
                    categories["fstar_mapped"] += 1
                elif module.startswith("docs/"):
                    categories["docs_mapped"] += 1

                if args.write:
                    entry["runtime_link"] = link
                elif not args.report:
                    print(f"  {entry_id}: {link}")
            else:
                unmapped.append((entry_id, module))

    # Summary
    print()
    print("=" * 60)
    print("Runtime Link Population Report")
    print("=" * 60)
    print(f"  Already set : {already_set}")
    print(f"  Auto-mapped : {mapped}")
    print(f"    crates/   : {categories['crates_direct']}")
    print(f"    fstar/    : {categories['fstar_mapped']}")
    print(f"    docs/     : {categories['docs_mapped']}")
    print(f"  Unmapped    : {len(unmapped)}")
    print("=" * 60)

    if unmapped:
        print()
        print("Unmapped entries (require manual assignment):")
        for eid, mod in unmapped:
            print(f"  {eid}: module={mod}")

    if args.write:
        # WARNING: yaml.dump() reformats the entire file. For incremental
        # updates, prefer the surgical line-insertion approach used during
        # initial population (see commit history).
        MATRIX_FILE.write_text(
            yaml.dump(
                data, default_flow_style=False, allow_unicode=True, sort_keys=False, width=120
            )
        )
        print(f"\nWrote {MATRIX_FILE}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
