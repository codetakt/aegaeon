# Organizations recovery security and verification assessment

Last updated: 2026-11-05

Status: active plan

Owner: Engineering

Audience: implementers, security reviewers, verification maintainers

The [adopted responsibility rules](recovery-responsibilities.md) replace generic
application-level storage replay. This assessment binds the design to the current
PR base candidate `aa44e360d36ff7e91b65634f284e8eed9c853035`; later changes must
record their actual tests. Historical evidence remains evidence of its own source.

## Trust and attacker model

Trusted premises are authenticated selection of the application DB, correctly
configured transaction/durability semantics within the operator's failure model,
protected operational credentials, authenticated clocks within documented skew,
and the lifecycle mechanism excluding old writers. These are explicit premises,
not facts inferred from a hash, Redis marker or successful model check.

An attacker can send concurrent/repeated/malformed requests, keep old credentials,
race revocation, exploit lost responses, trigger load and encounter process death,
network interruption, partial cache loss or a restoration. Cache contents confer
no authority by themselves. Arbitrary compromise of the selected DB administrator
or control of every trusted custody system is not claimed to be repaired by the
application. Unauthorized restore/selection must not become ordinary serving.

Authorized PITR is a modeled operator action. It selects historical business state
including durable credentials and revocation status, and starts a new session
generation; it is not an attacker replay of current
authority. An operator may deliberately undo a membership change. That does not
authorize acceptance of an old session/token. New authentication with the restored active password or client secret is
expected. Audit does not automatically reapply post-target changes. Identity
ownership is evaluated against the selected durable state; see
[REC-D01](restore-credential-decision.md).

## Threats and PR acceptance

| ID | Threat | Required mitigation and direct check |
| --- | --- | --- |
| SEC-01 | Stale positive cache grants access after membership change/restore | Read current authority or validated version; mismatch/loss discards cache; stale-positive and cache-miss controls |
| SEC-02 | Lost replay/consumption history accepts the same credential twice | Atomic durable uniqueness or complete dependent-credential invalidation; concurrent consume, partial/whole loss and old credential replay |
| SEC-03 | Lost limit counters permit extra guesses | Persistent budget or conservative window refusal; test loss at limit, expiry, skew and repeated reset |
| SEC-04 | Old process writes after PITR | Fence/exclude old credentials and deferred workers; actual old connection and delayed commit tests |
| SEC-05 | Lost COMMIT response causes duplicate mutation | Same-authority idempotency receipt and current authorization; inject before/after-commit disconnect and cancellation |
| SEC-06 | Recovered outbox repeats an external effect | Stable event identity and recipient deduplication; before/after delivery/ACK failures and restore reconciliation |
| SEC-07 | Audit erased by PITR or declared complete despite missing tail | Protected independent custody, explicit delivery gap and restore event; unacknowledged-tail and historical branch tests |
| SEC-08 | Capacity/read-only failure permanently stops the service | Typed pre-admission failure, bounded retry, no global poison; saturation then successful admission and periodic progress |
| SEC-09 | Mutation uncertainty mislabeled as harmless preflight | Set mutation stage before first possible write; cancellation at each stage, unknown completion must not be cleared |
| SEC-10 | Old identity ownership is reassigned after restore | Enforce selected durable ownership records and fresh identifiers; reject conflicting caches; test collision and stale-worker creation |
| SEC-11 | Cache refresh changes issuer/key/policy trust | Validate fetched keys under current registration/policy; stale/changed-key and foreign-issuer cases |
| SEC-12 | Failure diagnostics leak secrets or hide readiness loss | Stable bounded reason codes, secret-bearing fault inputs, audit backlog/gap and readiness assertions |

Redis noeviction alone does not establish persistence across failover or arbitrary
partial loss. A generation marker alone does not establish completeness of
negative security records. A clean shutdown fixture does not cover interrupted
work. Each migration must close its concrete defect before the old guard is
removed. Rejecting a request is not sufficient acceptance if normal recovery
permanently stops the service without a justified remaining uncertainty.

## Verification allocation

| Tool / evidence | Current PR responsibility | Task 1b / Task 3 handoff |
| --- | --- | --- |
| Rust unit / actual PostgreSQL / Redis / HTTP faults | Implemented loss classifications, transaction/receipt behavior, stale credential rejection, capacity recovery and relevant integration regressions | Wider standards inventory, independent adversarial acceptance and full deployment combinations |
| Kani | Check changed production decision kernels without replacing them with a test-only implementation; arbitrary inputs, state transitions and cancellation disposition | Full native-call refinement, concurrency/memory/resource composition and complete obligation projection |
| Tamarin | Review or check effective credential-generation, replay and authority-selection model when that lifecycle is implemented; include reachable legitimate reset/reissue and attack controls | Full OAuth/OIDC/Organizations composition, detailed compromise models and source/artifact refinement |
| F\* | Review affected invariants and model premises; run directly affected existing proofs when changed | Refined durable-state/volatile-projection relation, transaction-to-Rust/SQL simulation and composed product claims |
| Performance | Remove avoidable global serialization and poison paths; bounded-resource tests and reliable load accounting | Qualified 10,000 HTTP/s/p99 campaign, high precision timing and provider/DR qualification |

No current PR requires re-proving PostgreSQL WAL or preserving arbitrary memory
across PITR. No proof/test may assume that loss means an empty unused replay set.
Unrelated paused verification/measurement campaigns remain paused.

### Kani obligations

- K-01: read-only preflight failure/cancellation cannot create a permanent closure.
- K-02: potentially mutating or admitted uncertain work cannot be classified as
  harmless solely by timeout; a completed guard is never rearmed.
- K-03: capacity exhaustion is retryable only before any application work starts;
  closed admission and unknown failures remain distinct.
- K-04: loss classification never authorizes from missing negative security state.
- K-05: generation mismatch rejects old volatile sessions/tokens even if their signature and
  expiry would otherwise pass.
- K-06: retry/attempt counters and deadlines remain bounded without wraparound.

Each kernel must be called by the production path to claim implementation-bound
evidence. A new enum or standalone model alone does not migrate a backend.

### Tamarin model revision

Use explicit durable authority, current runtime generation, credential issuance,
use/consume, volatile loss, authorized restore and old-worker exclusion events.
Restore may change business facts to an authorized earlier state including credentials and revocations while generating
a fresh session generation. Restored active passwords can issue new sessions;
this is a reachability requirement, not an attack. Audit has no mutation rule. Do not model volatile loss as harmless erasure of
linear replay facts while retaining an acceptance rule for old credentials.

Required properties: no old-generation session acceptance after activation, no acceptance
without current selected authority, single-use within the applicable credential
lifetime, and reachability of fresh authorized use after a reset. A variant that
omits the generation check or reconstructs a consumed capability must expose the
attack. Do not add a uniqueness restriction equivalent to the claimed theorem.
Asynchronous external delivery needs a separate observation/deduplication model.

The selected-state diagnostic at
`proofs/tamarin/organizations/restore_credentials.spthy` now checks restored
password login, selection provenance, old-session refusal, fresh-session use and
an omitted-generation negative control. All five are admitted with no registered
wellformedness exception. Operator authorization, PostgreSQL behavior and native
implementation refinement are outside that finite model. The previous
credential-disabling alternative is withdrawn; its results are historical.

### F\* model revision

Define the relation between durable domain state and disposable projections.
Prove that a cache miss cannot introduce authority, incompatible projections are
discarded, accepted transactions preserve domain/audit/outbox invariants, and
restoration establishes the chosen new state under stated lifecycle premises.
Use explicit preconditions for DB atomicity and operator restore authorization;
do not turn unimplemented fencing or loss detection into an untracked axiom.

The existing `AuthCode.Store` and `Dpop.Replay` models do not by themselves prove
PITR/volatile-loss composition. Existing Organizations Kani bounds/progress checks
cover their named production arithmetic, not store durability. No new F\* module
is labeled faithful or cited by a verified requirement before refinement review.

The S16 review also identifies concrete limits in `fstar/stepup/StepUp.fst`:
`challenge_valid_at` includes the expiry instant, whereas the current Rust/SQL
acceptance interval is strict at expiry. `lemma_complete_rejects_replay` proves
refusal of a second completion on a retained value; it does not model deletion
of completed state, concurrent consumption or successor-session transfer.
The model uses unbounded naturals and its RNG interface differs from the runtime
UUID representation. Its old registration is not evidence for the new SQL path.
Task 3 must reconcile those premises and provide an actual consumption relation
before asserting refinement. The current PR checks actual SQL expiry after lock
waits, single-winner completion/consumption, and GET/POST age enforcement.

Similarly, `proofs/tamarin/stepup/stepup_soundness.spthy` has a reachable challenge
completion/issuance trace, but omits browser-session identity, expiry, fresh-login
alternatives and restored-generation activation. It must not be treated as the
composition of S16 with the selected-state model. The source-bound tests and
generation negative controls retain their distinct evidence boundaries.

For S14, the effective transaction model now includes a shared lock on the current
management-session row during final Organizations authorization. Session deletion
or capacity eviction orders against that lock; final authorization must reuse the
domain transaction's connection. Current-PR SQL/HTTP checks cover that behavior and
read cancellation ownership. Task 3 retains SQL isolation/clock assumptions and
the Rust/SQL simulation proof. Neither this lock nor a finite Kani kernel proves
the operational exclusion of old writers after PITR; the implemented connection
fence and its provider premises are assessed separately.

The token effective model now includes current subject generation, positive
refresh-family/root authority, retained rotated nodes, and exact code/OIDC
publication in a single SQL transaction. Subject generation is selected-domain
state, not an external non-rollback revocation source. Revoke-all takes its
exclusive subject lock; publication holds a shared subject lock. Retained-root
checks inside delegated Organizations operations reuse and hold the domain
transaction connection. The current PR tests actual concurrent SQL interleavings,
missing authority, collision rollback and post-lock expiry. Task 3 must relate
those operations, PostgreSQL isolation/clock premises and Rust transition kernels;
Kani arithmetic checks and the selected-state Tamarin diagnostic do not discharge
that simulation or whole-protocol theorem. The serving-generation lifecycle is implemented by selected-state connection
fences. Its operational old-writer exclusion and provider premises still require
separate qualification; passing local tests does not establish them.

For S05, the existing `proof_kid_reuse_violation_detected` checks one bounded
pair comparison. The `kani_jwks_circuit.rs` reproducer forces a local half-open
state and uses threshold one; it does not test accumulated closed-state failures,
remote SQL ownership, expiry, stale completion or cached-body authority. In
particular, threshold one cannot expose the old Redis allow script resetting a
closed circuit's failure count. The current native SQL adapter tests a threshold
of three, one winner among 32 fetch contenders, expired owners and stale replies.
Its positive body-authority check is a separate integration obligation; passing
the pair-comparison proof cannot substitute for it.

The OIDC Tamarin model's published public-key fact is not a model of dynamic JWKS
fetching or selected database/cache correspondence. Task 3 must supply that
composition with explicit authenticated-source, digest, clock, namespace and SQL
isolation premises before using it for a dynamic-key conformance claim. Current
PR work includes actual positive-authority lookups, cache invalidation, wrong-key,
late-owner and transport failures. No old formal obligation is newly discharged
by the S05 adapter or its isolated tests.

## Handoff contract

| Handoff | Owner | Deliverable / closure condition |
| --- | --- | --- |
| REC-H01 | Task 1b | Map changed session, code, DPoP, refresh, revocation and assertion behavior to applicable protocol clauses; close actual protocol defects in the PR before handoff |
| REC-H02 | Task 3 | Replace the all-history interpretation of ORG-P11 with separate ordinary durability, authorized PITR, lifecycle exclusion, selected-state ownership and audit properties; preserve frozen adoption history |
| REC-H03 | Task 3 | Full Tamarin/F\*/Kani refinement and composition, including premises for runtime selection, external custody, clocks and old writers |
| REC-H04 | Task 3 | Independent provider/backup/PITR qualification, audit-tail durability and restore drills for declared fault domains |
| REC-H05 | Task 3 | Qualified performance/timing evaluation at the user's target; no extrapolation from arithmetic or bounded model checks |

Handoffs carry source revision/diff, exact tests and failures, assumptions, open
implementation items and acceptance criteria. They do not close the existing
8,805 baseline obligations or claim a new atomic/composite discharge. Known
functional/security defects and required migration tests stay in PR #295.

## Browser-session implementation boundary

S07 now keeps current session identity in PostgreSQL with payload/index binding,
strict freshness, original-authentication checks and no memory fallback. Management
inventory uses bounded keyset reads; individual revocation uses an authorized
subject plus exact session digest. Cursors select a page, not an authorization.
The opaque cursor change invalidates old offset cursors during stopped-worker
upgrade. The recoverable ID envelope uses a per-session HKDF-SHA-256 subkey and
AES-256-GCM context binding; see [browser-session design](durable-browser-sessions.md).

The current PR owns concrete namespace/subject swaps, corrupted payload/envelope,
wrong-key, expiry, concurrent capacity, rollback, pagination and actual HTTP checks,
plus the HKDF RFC 5869 vectors. These checks do not prove the crypto provider,
root-key custody, entropy quality, memory erasure outside the returned buffer,
or whole-system cryptographic composition. Task 3 receives the exact subkey/AAD
composition and generation binding for rigorous refinement review. Task 1b retains
any standards dependency. No existing proof obligation or vendor/provider claim
is discharged by this addition, and the unrelated paused F\*/timing work stays paused.

## Final lifecycle and proof boundary

The current production path excludes independent control/history recovery. Its
physical SQL sessions check the selected generation; reserved revocation capacity
is part of the configured connection total. The actual pool-partition function is
called by production and checked by Kani over arbitrary `u32` inputs. The three
preflight Kani harnesses now describe retained predecessor fixtures: their earlier
success must not be relabeled as proof of the replacement. Other historical
control/store-progress harnesses have the same source-bound limitation.

The additional finite Tamarin model `organizations/external_proof_recovery.spthy`
checks fresh-nonce reachability, old-proof exclusion, durable single use, assertion
horizon ordering and resumed assertions. Removing nonce selection or the wait
admits the retained consumed-proof negative controls. All seven selected lemmas
pass without registered warning exceptions. The first malformed node-equality
formula was rejected and retained, then corrected; it is not passing evidence.
Proof facts abstract successful cryptographic verification, replay slots abstract
atomic SQL uniqueness, and the expiry transition explicitly assumes an established
acceptance horizon. This does not prove JWT cryptography, wall-clock accuracy,
SQL isolation, provider failover or Rust/SQL refinement.

Actual HTTP tests verify temporary, no-cache 503 responses for private-key JWT
on token/device/introspection/revocation/PAR routes, JWT bearer grants and signed
Request Objects. Native signed DPoP tests verify generation/role nonce separation
and single use. SQL tests cover durable policy bounds and same-generation restart.
The monotonic boundary and arithmetic test cover opposite old/new worker and
activation/reload database clock errors, including a failing two-margin model.
The operational absolute clock bound is a premise, not a clock service implemented
by this PR. Audit never restores passwords, keys, membership or revocations.

No F\* model or provider/tool pin changes here. The reviewed F\* abstract set/expiry
models do not supply the SQL consumption, post-lock expiry or namespace simulation;
those exact relations, the external-proof clock model and the complete
cryptographic/transport composition are REC-H01/H03 deliverables. No new product
or composite discharge is declared, and the 8,805 frozen obligations remain.

Current operator evidence must preserve the selected restore point, activation
receipt, exported tail and explicit audit gap independently. Delivery IDs/digests
support deduplication; absent post-target events remain historical evidence rather
than application mutation commands. Provider PITR drills and independent custody
qualification are REC-H04. The target remains 10,000 HTTP/s and ordinary p99 at most
200 ms, unmeasured; the user excludes measurement in this implementation round.

## Administrative membership follow-up

The [non-superuser provisioning repair](managed-postgres-provisioning.md) treats
bootstrap-granted ADMIN-only authority on both protected groups as existing DBA
control. It is outside the execute-only maintenance boundary. Runtime membership
in either group and ordinary maintenance membership in the owner group are
refused even without INHERIT/SET. The required real-PostgreSQL checks cover both
creator settings and exact positive/negative privilege outcomes; they do not
prove arbitrary PostgreSQL role-graph equivalence or provider behavior.

Task 3's database-privilege refinement must include ADMIN delegation, grantor
identity and transitive membership, rather than only effective INHERIT/SET. No
Tamarin/Kani/F* proof is newly discharged by this source change. Functional
installation and known privilege escapes remain this PR's responsibility.
