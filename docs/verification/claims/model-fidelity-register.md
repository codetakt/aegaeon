# Model Fidelity Register

Last updated: 2026-08-05

Status: current implementation baseline

Owner: Verification

Audience: verification reviewers, maintainers

This register classifies every checked-in F* module by how directly it mirrors
the current implementation semantics. The machine-readable inventory is
`model-fidelity.yaml`; `verify_verified_reqs.py --strict` rejects `toy-stub`
modules as grounding for `status: verified` entries.

## Classification

- `faithful`: the module is intended to model the implementation behavior used
  by the referenced claim.
- `simplified`: the module intentionally abstracts implementation detail, but
  may ground a verified entry when the matrix row states the narrowed claim.
- `toy-stub`: the module contains placeholder behavior or toy data and must not
  ground a verified matrix entry.

## Initial High-Risk Entries

| Module | Classification | Reason |
|---|---|---|
| `fstar/pkce/Pkce.Verification.fst` | `toy-stub` | `base64url_encode` returns a constant 43-character placeholder at lines 34-39; verified PKCE S256 rows must use `fstar/pkce/Pkce.fst`, whose S256 model delegates through `Verified.Crypto.Bridge.sha256_of_string`. |
| `fstar/token/Bearer_validation.fst` | `toy-stub` | `validate_bearer` is a constant-`true` stub at lines 5-6 and is referenced only by implemented rows `6750-001` and `6750-003`, not by verified grounding. |
| `fstar/HACL_Wrapper.fst` | `toy-stub` | AEAD/HMAC wrappers return zero-filled placeholder outputs or unconditional decrypt success at lines 19-43; HACL grounding must use the bridge modules or linked C integration. |
| `fstar/par/Client_auth.fst` | `toy-stub` | Lines 5-14 define a toy in-memory registry for `client_a`; partial rows `9126-002` and `9700-004` may reference it, but verified rows must not. |
| `fstar/par/Request_uri.fst` | `simplified` | Lines 62-72 model request URI issuance as a sequential counter; this preserves uniqueness reasoning but does not model RFC 9126 entropy. Runtime entropy remains evidenced by tests and runtime code. |
| `fstar/dpop/Dpop.Htu_validation.fst` | `simplified` | `validate_htu` models only the final exact string comparison; the runtime (`crates/ffi/src/lib.rs` DPoP checks) additionally rejects `?`/`#` in the proof `htu` and strips query/fragment from the request URI before the modeled comparison. The trace for `9449-006` claims the comparison step; the normalization prefix remains evidenced by runtime tests. |
| `fstar/stepup/StepUp.fst` | `simplified` | The F* module is a small pure model that binds a challenge to one immutable `session`. It does not model the runtime successor transfer during login session rotation (`crates/server/src/web/local_auth/post.rs` `complete_stepup_for_local_login`) or authorize-endpoint error responses. Its four lemmas are shallow properties discharged by definition unfolding with `()` proofs. |

## Review Rule

When adding a F* module or using a new module in `spec/compliance-matrix.yaml`,
update `model-fidelity.yaml` in the same change. Do not cite a `toy-stub`
module from a `verified` row; replace the block with a faithful or explicitly
simplified model, or downgrade the row status.
