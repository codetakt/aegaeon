# LTI transactional publication correspondence

Last updated: 2026-11-03

Status: current implementation baseline

Owner: Protocol Engineering / Verification

Audience: implementers, verification reviewers, release managers

Evidence scope: conditional model results; product discharge remains open.

The model [launch_publication.spthy](../../../../proofs/tamarin/lti/launch_publication.spthy)
addresses the publication boundary of an authenticated `LtiResourceLinkRequest`.
It is associated with LTI-CORE-001, not a projection of all Core 1.3 or Security
Framework requirements. Its lemma count is not a count of atomic obligations.

## State and adversary

A binding contains issuer, client, registration revision, deployment, resource
link, subject, authenticated session and an opaque, previously authorized role
set. A fresh revision abstracts a never-reused `(registration ID, revision)`
generation. Revision numbers themselves need not be globally unique or secret.
All binding fields and intent handles are disclosed to the adversary. Requests
arrive through `In`; the result does not depend on keeping those values secret.

Opening and validation can read historical registrations even after revocation.
This deliberately admits more stale workers than the implementation. There is
no bound on intents or workers and no mutual-exclusion assumption about their
validation. Successful commit alone consumes the linear intent and requires the
current linear revision. A rollback consumes a worker without consuming its
intent. A committed response lost before delivery consumes the intent without
publishing output. No trace restriction assumes a security conclusion.

## Correspondence and premises

| Model element | Actual boundary | Required premise and limitation |
| --- | --- | --- |
| Registration and binding | `lti::intents::create`, immutable registration history and `web::lti::current_intent` | Authenticated producer, canonical client/subject ownership, admitted placement and original role ceiling. These are inputs to this slice, not proved by it. |
| Open intent | `lti::intents::load` locks the Environment-scoped intent `FOR UPDATE`; `authorize::process` requires `initiated` | Successful browser initiation and authenticated session binding are abstracted. The SQL lock is stronger than the model's overlapping validation. |
| Validated request | `authorize::process`, `authorize::resume`, and `issue` check the stored client/hints, request snapshot and session | The model assumes the actual comparisons and decoding implement exact equality. Parameter parsing, hashing and session-store authority are separate obligations. |
| Active revision | `current_intent` compares registration and runtime revisions; shared Environment/client/registration/owner locks survive through the transaction | Revision generations cannot be reactivated after replacement. Administrative authorization and a non-restored store history are premises. |
| Commit | `issue` conditionally updates exactly one `initiated` row and writes the issuance audit; both caller paths commit before returning the response | SQL atomicity, affected-row correctness, isolation and rollback on failure must be supplied by the actual restricted database and callers. |
| Lost response | The SQL commit succeeds but no signed HTTP body reaches the Tool | The consumed intent is durable. An ambiguous commit returns failure; a later retry cannot consume an already committed intent. Supplier restoration is outside this model. |

The reviewed Rust paths are
[`intents.rs`](../../../../crates/server/src/lti/intents.rs),
[`store.rs`](../../../../crates/server/src/lti/store.rs),
[`web/lti.rs`](../../../../crates/server/src/web/lti.rs), and
[`authorize.rs`](../../../../crates/server/src/web/lti/authorize.rs).
This mapping is a source review, not machine-checked refinement.

## Results and negative controls

Tamarin 1.12.0 with Maude 3.5.1 accepts all eight selected lemmas without registered
wellformedness exceptions. Publication, overlapping validations followed by a
commit, and rollback followed by successful retry are reachable. Universal
lemmas establish one commit per intent, immutable authority binding, validation
before commit and no commit after the bound revision's revocation. A reusable
inductive lemma follows the linear revision through arbitrarily many commits.

Two mutation controls produce counterexamples with the same tool and admission
parser. Removing `Open(intent)` from both commit rules falsifies
`intent_single_commit`. Removing the current `Active(r)` guard and its return
from both commit rules falsifies `revoked_revision_cannot_commit`; that control
also removes the supporting lemma's `reuse` hint so it cannot assume the broken
invariant. Tool exit zero alone is not accepted as verification.

The shared selection in `ci/tamarin_proofs.sh` executes all eight lemmas, including
the supporting invariant and reachability. Run the selected model locally with:

```sh
nix develop path:.#verification --command \
  python3 scripts/validation/admit_tamarin_lemmas.py run \
  --out-dir /tmp/lti-publication-evidence \
  --proofs-root proofs/tamarin --registry spec/tamarin-evidence.json -- \
  lti/launch_publication.spthy:publication_reachable,overlapping_workers_reachable,rollback_retry_reachable,intent_single_commit,immutable_authority_binding,request_validated_before_commit,revision_revocation,revoked_revision_cannot_commit
```

Use a new output directory for each distinct execution and retain unsuccessful
results. Earlier exploration timeouts remain unsuccessful evidence; subsequent
proof search does not turn them into passing runs.

## Actual-code tests and remaining composition

The real PostgreSQL/router tests in `web/lti/tests.rs` race two authorizations of
one intent, independently validate the single returned JWT using JWKS, check one
issuance audit and refuse replay. `tests/authority.rs` covers independent launches,
shared authority locks, configuration writers and producer revocation.
`tests/failures.rs` and `tests/resource_urls.rs` retain failure before consumption,
repair and successful retry. Those finite observations support the correspondence;
they do not establish SQL refinement for all executions.

Remaining obligations include cryptographic correctness and key supply, nonce and
ticket entropy, wall-clock expiry, DPoP, all browser/Tool behavior, truthful
producer authority, original grant ceilings, resource bounds, and retained store
state across restoration. Session and SQL state are separate consistency domains:
the model does not assert distributed atomicity for session revocation. It also
does not prove fair scheduling, normal service availability, production supplier
qualification or final source-to-distribution correspondence. All applicable
normative clauses and those composition conditions remain required for assurance.
