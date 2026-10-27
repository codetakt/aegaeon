# Upstream callback browser binding model

`upstream_browser_binding.spthy` models admission of an upstream callback's
stored context. It does not assert successful upstream authentication, token
validation, user resolution, or session creation. The `code` and `error`
reachability witnesses dispatch an accepted context to the corresponding branch.
Both use the same binding and single-consumption rules.

## Correspondence to the implementation

| Model transition or term | Source and boundary |
| --- | --- |
| `Initiate`, fresh state and independent secret | `crates/server/src/web/upstream_authorize/flow.rs`: `store_upstream_authorize_request`; a fresh state generation is never reused in this model. |
| Private `Cookie(browser, state, secret)`, public state | `upstream_browser_binding.rs`: state-specific `__Host-` cookie with Secure, HttpOnly, Path=/ and SameSite=Lax; authorize redirect discloses state but not the secret. Browser identities identify separate cookie jars, not an upstream issuer or OAuth client identity. |
| `Browser_Submit`, `Attacker_Submit` | Arbitrary network-controlled state, route, callback kind and known cookie material; browser cookie delivery is private. A browser may submit its cookie from another state, overapproximating the cookie-name check. The attacker can navigate any browser, including the initiating browser. This is possession/route binding, not proof of user intent. |
| `Read_Snapshot`, `Validate_Snapshot` | `crates/server/src/upstream/auth_store.rs`: GET, decode, validate state, digest, redirect URI and freshness in `consume_bound`; `upstream_callback_state.rs` obtains the cookie digest and constructs the expected route from the callback path. Historical snapshots remain readable, overapproximating delayed GET responses and concurrency. |
| `Store(state, raw)`, `Atomic_Consume` | `CONSUME_STATE_SCRIPT` compares exact payload bytes and freshness before atomic DEL. The linear fact is the current stored value; failed binding or a different-value comparison cannot consume it. `raw` is an opaque serialization identity, not a hash. |
| `Replace_Stored_Value` | An arbitrary number of trusted replacements with fresh byte identities, preserving the original decoded binding. This is a race fault model, not an externally writable production API. Concurrent workers may validate before replacement or another worker's consumption. |
| `Deadline_Open`, `Deadline_Passes` | Nondeterministic end of a coherent, monotone logical freshness interval, shared by validation, atomic consume and return. Expiry may occur between any two steps, including after deletion. |
| `Return_Fresh_Context`, `Reject_Expired_Return` | The second Rust freshness check after the Redis script returns. A delayed return may require restart after deleting the record. This check does not restore the record. |
| `Dispatch_Code`, `Dispatch_Error` | `upstream_callback.rs`: bound context is consumed before subsequent issuer/error/exchange handling. Later rejections and errors can consume state; the model does not claim all rejected callbacks preserve it. |

Paths without a crate prefix in the table are relative to
`crates/server/src/web/`.

## Assumptions and exclusions

The symbolic hash is ideal and collision-free. Secrets and states have fresh,
unpredictable symbolic identities; probabilistic collisions, RNG failure,
constant-time execution and concrete SHA-256 behavior are outside the model.
TLS and the host cookie channel protect the secret from disclosure, injection
into another browser's cookie jar, and script access. Browser compromise, XSS,
malicious extensions, duplicate/malformed cookie parsing and HTTP/header/URL
canonicalization require separate implementation checks. Guessable candidate
secrets remain available to `Attacker_Submit`; no rule reveals the real secret.

The store and decoder are trusted. Each payload identity has immutable decoded
contents. Replacements preserve those contents and always use new bytes;
malicious record forgery, byte-identical restoration (ABA), reusing a state
value after expiry/deletion, Redis rollback/failover and externally injected
records are excluded. Exact byte comparison detects different values, **not**
an intervening identical-byte reinsertion. Consequently `single_consumption`
is conditional on fresh state generation and no restoration; it is not a
permanent tombstone or generation-counter guarantee. `no_stale_snapshot_consumed`
rejects snapshots whose different-byte replacement has already occurred under
that same no-restoration assumption. Private mutation controls detect disabled binding and deletion checks. The
F* companion model supplies a separate same-byte reinsertion witness; incomplete
Tamarin control searches are not counted as detected faults.

The logical deadline is an explicit abstraction, not a proof that the Rust
`SystemTime` samples and Redis TIME share a clock or remain monotone. There is
no adopted clock-skew tolerance here. Numeric precision, strict boundary
arithmetic, TTL rounding/expiry, transport delay and system-clock changes need
separate checks. No guarantee is made about freshness after the modeled return
or the later application response. Availability and fairness are not proved;
normal and error execution witnesses show only that the model permits those
paths.

These are unbounded symbolic protocol traces under the stated assumptions,
not a refinement proof of Rust, Lua, Redis, the browser, or a release artifact.
The model makes no product-assurance discharge or timing claim.

## Admission

All lemmas, including normal, error, concurrent, stale, expiry, delayed-return
and adversarial-submission witnesses, are selected by `ci/tamarin_proofs.sh`.
The pinned tool results must pass `scripts/validation/admit_tamarin_lemmas.py`
under `spec/tamarin-evidence.json`; no wellformedness exception is registered
for this theory. Exit status alone is insufficient. The model has no trace
restrictions that encode its security conclusions. The inductive
`store_lifecycle` and `deadline_lifecycle` lemmas are proved and admitted on the
same theory before their results are reused by the other lemmas; they are not
axioms. Wrong-browser and wrong-route read witnesses also allow a subsequent
legitimate acceptance, demonstrating that such attempts need not destroy state.
