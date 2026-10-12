# Upstream issuer policy verification scope

Last updated: 2026-10-10

Status: current implementation baseline

Owner: Verification

Audience: verification reviewers, maintainers

The issuer gate preserves configured identifier bytes, freezes `iss` presence as
profile-required OR discovery-supported, and rejects serialized authorization
records without policy version 1. This gate permits continuation; it does not
authenticate an upstream response or establish a login session.

| Evidence | Production correspondence | Domain and remaining boundaries |
| --- | --- | --- |
| Kani `upstream_issuer` | Calls unconditional `aegaeon_pure::upstream_issuer` functions used by authorization, callback and Redis decode | All u32 versions, all profile/discovery policy combinations, byte equality for independent lengths 0..=8. Longer inputs, URL admission, serde and Redis are outside the bounded equality proof. |
| F* `OidcRp.IssuerPolicy` | Functional model of policy freeze, exact equality and version admission | Arbitrary strings and optional natural-number versions; simplified model, not extracted Rust or a decoding/storage refinement. Positive matching/optional-omission lemmas prevent rejection-only vacuity. |
| Tamarin `upstream_issuer_policy` | Immutable policy record and attacker-supplied success/error callback parameters | Unbounded symbolic traces with per-record linear consumption. Legacy records exist and can receive callbacks, but cannot pass the version gate. Browser binding, expiry, valid URL syntax, trusted metadata and storage integrity remain suppliers. |
| Native server tests | Actual management input mapping, runtime validator, callback routing, discovery cache/federation equality and Redis decoding/consumption | Finite examples, including legacy/unknown versions left unconsumed and a current record consumed once. This is not live discovery HTTP/DNS/TLS or complete session provisioning. |

The Tamarin model distinguishes profile-required, discovery-required and optional
initializations. Both present and absent callback paths share version admission.
Safety lemmas cover origin, legacy rejection, exact present issuer, required
presence and single consumption; reachability covers normal/error callbacks and
legacy, missing and mismatched input. Symbolic equality does not implement URL
canonicalization. The old browser-binding models are separate: their composition
with this gate, numerical clocks, parsers, crypto suppliers and the actual release
artifact remains an obligation. No matrix row is promoted to `verified` by adding
these models. Full product assurance and final review remain separate.
