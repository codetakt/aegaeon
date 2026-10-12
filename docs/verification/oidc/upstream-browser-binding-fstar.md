# Upstream callback functional model

Last updated: 2026-10-10

Status: current implementation baseline

Owner: Verification

Audience: verification reviewers, maintainers

The `OidcRp.BrowserBinding` F* module models the composition of callback
admission, exact snapshot consumption and code/error continuation. It is a
simplified functional contract, not extracted Rust or a proof of Redis/Lua.
`OidcRp.BrowserBindingWitnesses` provides reachable normal, upstream-error,
late-return, issuer-failure, and recoverable mismatch executions.

## Source correspondence

| Model element | Production source and meaning |
| --- | --- |
| Stored state, digest, route, deadline, opaque context | `crates/server/src/web/upstream_authorize/flow.rs::store_upstream_authorize_request` generates independent state and browser secret, stores the secret digest and constructed callback URI before returning the redirect. Other request fields remain opaque preserved context. |
| Optional cookie secret and input validity | `crates/server/src/web/upstream_browser_binding.rs::browser_digest` and `upstream_callback_state.rs::consume_upstream_callback_context` reject missing/malformed/duplicate selected cookies and required state/code failures. The model consumes their admission result; it does not implement the byte parser. |
| Supplied hash, optional stored digest | `sha256_hex` and `upstream/store.rs::valid_browser_binding_digest`. Symbolic digests are natural-number identifiers, without fixed width or hash injectivity. `input_valid` includes the caller's format check; digest syntax and constant-time comparison remain outside the model. |
| Supplied decoder and read snapshot | `upstream/auth_store.rs::consume_bound` GET, serde DTO decoding and `into_request`. Decoder failure includes malformed data, invalid fractions, context and platform timestamp reconstruction failures. Decoder correctness is a supplier obligation; the model quantifies over arbitrary deterministic decoder functions. |
| `bound` and first `live` | `consume_bound` checks exact state, digest, redirect URI and local freshness before calling Lua. Each mismatch has a separate theorem naming fields directly. |
| Current slot equality and Redis `live` | `CONSUME_STATE_SCRIPT` GET and byte equality against the validated payload, Redis TIME, strict deadline comparison, then atomic DEL. The model's current slot may differ arbitrarily from the read snapshot. |
| Last `live` and `ConsumedLate` | Rust filters a consumed result by local freshness again; a late response leaves the state consumed and yields no accepted callback. |
| `BoundError`, `ConsumedIssuerFailure`, `AcceptedCode` | `upstream_callback.rs::complete_bound_upstream_callback` validates callback issuer and handles upstream errors after consumption. `AcceptedCode` only permits further connection validation/token exchange; it is not an authenticated session. Later failures never restore the consumed slot. |

A single slot abstracts a single hashed state key and atomic Redis operations.
The in-memory test backend, full keyspace isolation, hash collisions between
state keys, Redis execution correctness and distributed failure modes are not
proved by this abstraction.

## Domains and theorem boundaries

Seconds range over every natural number through `u64::MAX`, nanoseconds over
0 through 999,999,999, and Redis microseconds over 0 through 999,999. These are
post-Unix timestamp observations. Their exact lexicographic comparison preserves
live final fractions and rejects equality. Platform `SystemTime` reconstruction,
pre-Unix values, machine arithmetic/overflow, decimal serialization and Lua
number/string operations remain distinct implementation obligations.

Local precheck, Redis execution and local return clocks are independent inputs.
No synchronization, monotonicity or coherent physical clock is assumed. Accepted
output implies freshness at all three observations, not correctness of wall time.
The successful final-fraction witness does not assert nanosecond physical clock
precision from Redis's microsecond observation.

The consuming function returns both its outcome and the new slot. Pre-admission
rejection preserves the current slot, including an intervening changed-byte
replacement. Deletion leaves an absent slot even when return freshness or issuer
validation subsequently fails. Two invocations without intervening insertion
cannot both consume. This is not a global lifetime uniqueness theorem: byte-CAS
cannot distinguish identical-byte ABA reinsertion, and a positive reinsertion
witness deliberately records that limitation. Fresh state generation has its own
entropy/collision assumptions.

The decoder and hash are total function parameters. The model does not assume
that successful decoding is reachable for actual wire bytes; explicit decoder
witnesses establish model nonvacuity only. The hash need not be injective, and the
witness hash deliberately collides for distinct secrets. Matching digests do not
prove that two browser identities or secrets are equal.

Transport loss after Redis execution can leave completion unknown. This total
model covers known atomic outcomes; it makes no preservation or retry-liveness
claim for an ambiguous backend error. Browser cookie/HTTPS enforcement, RNG,
crypto timing, connection/database suppliers and release-artifact composition
remain separate obligations.

## Verification

Both modules are explicitly selected in `scripts/flake/verify_fstar.sh` and
classified `simplified` in the model-fidelity inventory. Symbolic lemmas cover
binding mismatch preservation, decoder failure, validated snapshot preservation,
three freshness checks, changed-byte CAS rejection, single consumption and
upstream-error exclusion from code continuation. Witnesses cover normal/error
admission, consumed late/issuer failure, legitimate use after a rejected wrong
route/browser attempt, legacy whole-second deadlines with a present digest, and
same-byte reinsertion.

Run the pinned `nix build .#verify-fstar -L` for the complete gate. A focused
invocation must preserve its command, selected modules, dependencies, actual
solver identity, complete output and failed attempts. Route-check, CAS, deletion
and late-return-check mutations are useful private negative controls; success of
the original model alone does not establish source refinement. The old RP
session model and `UpstreamRefresh` do not supply this contract implicitly.
