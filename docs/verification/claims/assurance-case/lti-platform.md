# LTI Core Platform assurance obligations

Last updated: 2026-11-03

Status: active plan

Owner: Protocol Engineering / Verification

Audience: implementers, Task1b and Task3 reviewers, release managers

## Adopted scope

1EdTech Learning Tools Interoperability Core 1.3, document version 3, is an adopted
Platform conformance and formal/security-assurance target. The existing
[server contract](assurance-contract.md) and [source register](../../../../spec/server-assurance-contract.v1.json)
govern it; this record does not introduce another claim authority. The register
pins Core, Security Framework 1.0 and both official errata status pages, reusing
the adopted OIDC Core errata set 2 and Form Post sources. All six retained source
digests were checked against the adopted bytes before this integration.

Applicable Platform requirements remain obligations even if the compliance matrix
omits them or the implementation lacks them. Classify optional features and roles
from their normative conditions. Implementation omission cannot make a mandatory
requirement inapplicable. The clause review below covers the declared resource-link
family and identifies its shared dependencies. Atomic proof projection and
transitive proof discharge remain incomplete; three composite matrix entries are
not three atomic obligations.

The current implementation slice is authenticated, top-level
`LtiResourceLinkRequest` with manual Tool/deployment/resource-link registration.
Separate Advantage specifications, dynamic registration and the Tool implementation
are outside this slice. No 1EdTech certification or Advantage Complete claim is
established. The Aegaeon secure-default policy and explicit permitted relaxations
are assessed separately from normative LTI/OIDC conformance.

## Task1b implementation closure

The current integration includes published main `02a2e5bf2f25bb6cbf2359148e315394f71a8192`
and its canonical subject ownership/local attribute API. The new LTI migrations
follow that complete history; existing migration bytes and applied ledger rows
are retained. Earlier unmerged LTI/ownership candidates are historical inputs,
not an interchangeable installation history.

The upgrade runbook now lists all four LTI migrations, including the admission
index and its physical catalog successor. The earlier two-file sequence omitted
those required revisions. Compiled Atlas preflight rejects that partial upgrade
before startup, including with LTI disabled; this is an availability defect in
the instructions, not permission to accept an incomplete catalog. Task1b retains
the stopped upgrade and complete-history requirement. Task3 must bind migration
and startup evidence to the final four-file sequence and compiled inventory;
correcting the instructions alone discharges no proof obligation.

Destination validation requires an explicit HTTPS authority. The previous
standalone URL parse accepted same-scheme abbreviations that a browser could
resolve on the issuer origin; Form Post then consumed the intent before CSP
blocked submission. Registration writes and stored-document reads share this
validation. Task1b tracks refusal for login, redirect and target-link fields and
preservation of valid absolute URI strings. Task3 retains browser resolution,
CSP and intent consumption as distinct composition obligations; validation of
these cases does not establish the complete browser or protocol contract.

Resolve launch/profile, identity, recipient, current authorization, SQL concurrency,
replay and error-path defects within this feature. Required acceptance includes
independent Tool-side JWT/JWKS validation, normal browser round trips, malformed
input, cross-owner/context references, revision revocation, simultaneous use,
DPoP replay, signing/store failures and recovery. Preserve tests for ordinary OIDC
and local attribute APIs when composing the feature. Tests must use the actual
restricted runtime and compiled source; an administrator-only fixture is insufficient.

The launch authority reads reuse the caller's locked SQL transaction. The producer
endpoint always requires `lti:launch` and its own audience, even if generic token
policy toggles are disabled. A real restricted-PostgreSQL launch with a one-connection
pool and the relaxed-policy denial regression cover these fixes; the pool must be
validated again after replacement before it can supply the subject namespace.
The local integration ran 46 launch/management/OIDC regressions plus seven mapping
and four Form Post tests. A requested ignored-only mapping selector selected zero
tests; the seven ordinary mapping tests were then run explicitly and are counted
once. This is bounded regression evidence, not complete protocol assurance.

The same two regressions detect the original published launch implementation:
one connection returns 503 instead of creating the launch, and missing scope is
accepted with 201 instead of 403. The original implementation still passes its
ordinary signed resource-launch/replay control. An initial control selector found
zero tests; the correctly named control was subsequently executed separately.

The Nix source inventory now accepts the adopted canonical LTI host and source-ID
archive names. The two runtime manifest changes bind the added ID-token Form Post
helper and LTI module registration. Existing OAuth response paths remain covered;
these digest updates do not discharge the matrix entries that reference those files.

The management reference client registers all three LTI OpenAPI operations for
its generic `requestOperation` interface. Regression coverage checks escaped
Team/Environment paths, opaque UTF-8 client queries, write CSRF/Origin handling,
request bodies and conflict propagation without retries. This closes the client
inventory mismatch found by the full assurance-integrity job; it is not proof
of a browser or whole-provider interaction.

The four LTI HTML pages have volatile Drupal asset-cache and theme-token fields.
The archive fetch restores only these fields to their saved values and requires
the entire result to match the original adopted SHA-256. It does not substitute
visible-text equality, remove arbitrary markup or update the source pins. Metadata
records the restoration method. A changed body, host, markup, extra/missing field,
inconsistent cache tokens or oversized page fails closed. The saved and currently
fetched four documents reproduce the original bytes exactly. This is retrieval
reconstruction, not a new source edition or a new protocol proof.

The serving bootstrap now accepts distinct runtime and management PostgreSQL
credentials, validates their actual role authority and live database identity,
and rejects LTI activation without that boundary. The runtime cannot mutate local
attribute sources, including through column grants, SET ROLE or inherited roles.
Management mutations use the explicit writer pool and refuse its failure without
falling back. Each launch transaction rechecks the reader's current authority.
The existing migrations and permanent subject validator ACL remain unchanged.

Task1b retains the source-bound regression and distribution checks for this
separation. Task3 must compose database identity, role-graph stability and pool
reconnection with the real supplier's failover/restore contract. The SQL checks
and bounded tests do not prove arbitrary proxy behavior or malicious database
administration. External source ingestion, historical account-link proof and
whole-provider composition remain explicit integration obligations. A handoff
does not authorize serving an unresolved dependency.

The launch producer retains any original application authorization snapshot and
checks its current projection before creating an intent and at every subsequent
intent boundary. The projection and bound identity rows use the existing launch
transaction, so a one-connection pool remains usable and concurrent revocation
cannot cross the publication transaction. Missing or failed authority refuses use;
updated grants cannot enlarge an earlier intent. This shares the existing optional
application adapter's supplier assumptions and does not introduce new native
Organizations membership guarantees.

RFC 6749 sections 3.1/4.1.2.1 distinguish omitted or empty required parameters
(`invalid_request`) from supplied unsupported values. The launch producer's
refusal challenge retains the presented Bearer/DPoP scheme under RFC 9449
section 7.1. Dedicated browser tests run only in their required Nix check, outside
the ordinary pre-migration and ignored-database sweeps.

## Task3 assurance closure

The dedicated authentication request now preserves signed ID Token hints through
GET and POST continuation. Signature, issuer, Tool audience, authorized party and
the current intent-bound session are checked; a past hint is not a session or a
revocation bypass. The shared signature/duplicate/ID-Token-type decoder is reused,
while logout retains its previous time validation. Unsupported Request Objects
and inline registration receive their OIDC error codes only after redirect
admission. Optional claims requests add no release authority. Task1b tracks these
concrete protocol repairs; Task3 retains key-retention, session/revocation,
duplicate-safe decoding and stored-request correspondence as composition premises.
These regressions and source inspection add no formal proof discharge.

OIDC Core sections 3.1.2.1 and 15.1 require maximum authentication age and minimum
ACR preference support. The dedicated LTI parser previously rejected both
parameters. The request now retains `max_age`, checks the actual authentication
time at signing and final session observation, and returns `login_required` when
the silent flow cannot satisfy it. ACR preferences do not imply an achieved ACR.
The final database clock read follows the potentially delayed session lookup.
Regression coverage includes fresh/stale/zero/invalid limits, POST continuation
and ordinary signed launches. This does not discharge clock accuracy, cross-store
revocation atomicity, or time bounds absent from the publication model.

Registration replacement must support repairing previously accepted abbreviated
HTTPS destinations. Only its private predecessor loader uses bounded structural
decoding; new configurations, activation and ordinary reads retain full current
validation. Compare-and-swap, canonical client identity, permanent placement
ownership and terminal retirement still constrain repair. Task1b covers the real
authenticated management repair, staged activation and immutable history, with
the old loader as a negative control. Task3 retains those source-bound outcomes
without treating administrative repair as proof of whole-provider conformance.

Project normative clauses and incorporated dependencies onto stable atomic
obligations before reporting added, changed or reused proof counts. Retain the
existing obligation inventory and historical dispositions. New discharge is zero.
For each obligation bind its source edition, applicability, real code and callers,
store and supplier assumptions, proof model and security tests. Cover successful
behavior as well as denial, finite resources, concurrency, cancellation, rollback
and restoration. Bind the final build and distribution to the reviewed evidence.

The producer is an authenticated source of membership facts; its claims are not
independent proof that those facts are true. Record that premise and the explicit
producer/context/role ceiling. Session and SQL state are separate consistency
domains: qualification must assess the actual revocation/issuance boundary, not
assume distributed atomicity. Form Post, signing keys and ordinary OAuth state
require composition analysis. Models and passing finite tests alone do not close
these whole-system obligations or activate a product claim.

## Consent and concurrent authority reads

The consent response permits form redirects only to its own origin and the stored
Tool initiation origin. All other authentication HTML keeps its existing policy.
The browser regression uses Chromium with CDP transport to the actual router and
PostgreSQL state: approval, cancellation, replay, a foreign destination and the
original self-only CSP are separate cases. It does not qualify production TLS.

The additional packaged-runtime check supplies real TLS sockets, a trusted local
ingress, the distribution launcher/release executable, restricted PostgreSQL,
Redis and an independent Tool. It covers actual password authentication and
cookies, default consent, GET/POST launches, JWKS signature checking, nonce and
DPoP token binding, replay, session-store permission failure/recovery and pending
launch refusal after logout. Task1b retains this as an executable distribution
regression. Task3 must preserve the distinction between this owned reference
composition and qualification of deployment proxy/CA/key/store suppliers,
concurrent revocation and rollback/restore. The original router/browser evidence
remains distinct, and neither suite supplies new atomic proof discharge.

Browser requests retain shared Environment and registration locks; configuration
writes and admission count-and-insert retain exclusive Environment locks. Each
intent retains its exclusive consumption lock. Concurrent independent launches,
writer exclusion, revocation and the existing consume-once race remain regression
conditions. A forward Environment/time index supports bounded-window admission;
its successor physical catalog preserves previous migration bytes and ledger.
Task1b tracks these implementation conditions; Task3 still requires the complete
caller/store/supplier, normative and artifact-bound proof composition.

Producer admission also locks the current producer registration and revalidates
its client-credentials authority in the intent transaction, before consuming the
admission budget. A real PostgreSQL regression holds that registration, revokes
its scope while creation waits, then confirms refusal with no new intent; restored
original authority succeeds. Substituting the previous producer implementation
returns 201 before the lock, so the same regression detects the defect. The normal
launch/consume-once control still passes. This closes that concrete creation race,
not the separate distributed membership and supplier assumptions above.

## Resource URLs in mapped claims

Core 1.3 section 3.5 requires HTTPS for URLs to resources included in messages.
The LTI adapter checks the final disclosed `profile`, `picture` and `website`
values before composing and signing the message. Mapping schemas only establish
string types; they cannot establish this transport condition. Current local
attributes are rechecked even when they changed after launch initiation.

The product profile additionally requires explicit authority, bounded length and
no user information, control characters, spaces or backslashes. Resource fragments
are preserved; launch destinations retain their separate no-fragment restriction.
Role vocabulary URIs identify roles and need not use HTTPS. The `TestUser` marker
is accepted with an authorized real role, as described by Appendix A.2.4.

The unit and actual-router regressions reject insecure mapped resources, retain
an unconsumed intent without an issuance audit, then verify a signed successful
message after repairing the local value and reject replay. The previous adapter
accepts an HTTP resource and returns a signed success in the same regressions.
This closes that concrete implementation gap; complete normative projection,
formal refinement and supplier qualification remain separate obligations.

## Transactional publication model

The [publication correspondence](lti-transactional-publication.md) maps the
Tamarin model to the locked intent, current registration, request validation and
SQL commit boundary. Eight model lemmas pass, including successful publication,
overlapping workers and rollback/retry reachability. Removing either the linear
intent or current-revision guard produces a counterexample. The shared CI proof
selection includes the model. These are conditional model results, with no
machine-checked refinement or new whole-product proof discharge.

Management export uses shared authority and Environment locks, retaining the
registration's existing shared lock. A compatible management read can proceed,
while authority or issuer changes wait until the export transaction finishes.
The actual-router regression covers both lock properties and refusal after an
authority downgrade; it does not establish a throughput or availability bound.

## Signing-key overlap with the LTI lifetime

Security Framework 6.4 recommends retaining an old public key across rotation.
The shared rotation implementation previously derived overlap only from the
ordinary OIDC TTL. With a one-second OIDC policy it could remove a key while an
already issued 60-second LTI token was still valid. Retirement now applies the
LTI lifetime as a minimum for the OIDC signing usage. Token expiry and explicit
revocation retain their own semantics. Task1b tracks the real management lifecycle
regression with a reduced policy and its previous-code control. Task3 retains
general historical OIDC TTL changes, publication/reload timing, key compromise
and rollback/restoration as separate shared obligations; this LTI bound does not
discharge them.

Retirement uses the clock after acquiring the Environment lock. Time spent
waiting for an in-flight launch cannot shorten the public-key overlap. The
regression holds that lock across a transaction-start time boundary before
allowing the real management activation to complete.

## Management writer and protected history

Review identified that an attribute writer could also hold parameter authority to
disable identity/history triggers. Pool acceptance now checks the permanent
subject serving-role restrictions for the management principal without granting
it any definer or maintenance entry. The read-only projection includes schema and
relation ownership, immutable identity/Atlas mutation, competing triggers, every
audit descendant, private helper execution, parameter authority and mixed
SET/inherited role paths. The actual session must retain origin trigger behavior.

Task1b tracks direct and indirect privilege fault cases, activation refusal and
the packaged server's refusal/recovery fixture in this PR. Task3 retains the SQL
catalog/role projection correspondence, concurrent DBA exclusion, restored-cluster
and pool reconnection assumptions. Validation of a connection is not a guarantee
against later malicious administration. Published migrations and validator ACLs
remain byte-for-byte unchanged.

## Optional standard claim syntax

Core 5.3.6 incorporates OIDC standard-claim semantics. Previously, only the string
type was checked for email, locale and zoneinfo, allowing malformed values to be
signed. The adapter now validates the final disclosed value against its documented
RFC5322 generation subset, existing dated BCP47 admission profile and byte-pinned
IANA Zone/Link inventory. No content is rewritten or promoted to verified identity.

Task1b tracks unit and actual-router refusal/repair/replay tests and the previous
adapter control. The IANA archive/member digests and generated table are checked
by the required Nix claim-source check. Task3 retains parser soundness, registry
edition and update policy, truthful attribute provenance and shared ordinary-OIDC
output validation. Finite fixtures and table reproduction do not prove those
whole-domain obligations or authorize unrelated proof work.

## Resource-link clause and caller review

The following is an author review against the six pinned sources in the source
register. It separates Platform duties, Tool duties, conditional capabilities and
Aegaeon's policy. It is an implementation review, not independent certification or
an atomic proof-obligation inventory. Core sections 1–6 and Appendices A–E,
Security sections 3 and 5–6 with the service conditions in section 4, both errata
notices, Form Post sections 1–4, and the incorporated OIDC clauses listed below
were considered. Normative dependency references retain their shared assurance
obligations; this does not claim full transitive proof closure.

Paths in this table are relative to `crates/server/src`; test names refer to the
corresponding module's tests unless an explicit repository path is given.

| Source and condition | Platform implementation and caller | Evidence and retained boundary |
| --- | --- | --- |
| Core 3.1.3, 5.3.3: every deployment | `lti/store.rs`, `lti/validation.rs`: canonical Tool client; issuer-scoped, immutable deployment ID; ASCII length bound | Revision/CAS and permanent-placement tests; historical store restoration remains a shared premise. |
| Core 3.1.4, 3.2, 5.3.5: resource placement | Same store and validation; stable resource ID and parent/context binding; copies require fresh IDs | Real management and launch regressions; no identity reuse after retirement. |
| Core 3.3, 5.3.6; Security 5.1.2: authenticated user | `web/lti.rs`, `web/lti/authorize.rs`: permanent subject and exact current session owner; mapping cannot override identity | Subject-namespace refusal and independent signed-token tests; producer truth and complete historical ownership remain explicit premises. |
| Core 3.2, 5.4.1: included context | `lti/claims.rs`, `lti/validation.rs`: immutable context, ID, optional label/title/type; empty optional type omitted | Mapping and placement tests; no assertion that syntax proves real membership. |
| Core 3.5: resource URLs | Registration admission and final mapped resource validation require absolute HTTPS; vocabulary URIs are identifiers | URL unit/API tests, old-behavior controls and actual browser transport. |
| Core 4; Security 5.1.1.1: initiation | `web/lti/browser.rs`: issuer, opaque login/message hints, target, client and deployment parameters bind an authenticated intent | Consent, cross-owner, continuation and packaged-browser tests. |
| Core 5.1–5.3.4: required message fields | `lti/claims.rs`: exact message type/version/deployment/target; protocol names are reserved | Adapter and independent JWT tests; publication model binds authority, not all serialization bytes. |
| Core 5.3.7, Appendix A: roles | Exact principal/subrole vocabulary, optional extensions and empty set; producer/deployment ceilings | Role and current-authority tests; actual institutional facts come from the authorized producer. |
| Core 5.4.6–5.4.7: configured extensions | String-valued custom map; fully qualified HTTPS extension names; no verified-identity fabrication | Mapping admission/disclosure tests; empty custom strings are valid, null is not. |
| Core 5.3.6.1, 5.3.7.1, 5.4.2–5.4.5, Appendices B–D: optional capabilities | Anonymous launch, platform instance, mentor/LIS/presentation claims, substitutions and cartridge import are not advertised by this profile | Reserved output contracts prevent accidental capability injection; reconsider these conditions before enabling them. |
| Core 6; Security 4: LTI services | Resource-link messages advertise no Advantage/service endpoint or service grant; the producer API is an Aegaeon extension | Its own scope/audience/DPoP tests do not establish conformance for an unimplemented LTI service. |
| Core errata through 2021-07-01 | Optional platform instance, TestUser role, substitution/target clarifications and conditional service client assertions reviewed | Security's retained errata notice lists no erratum; certification rules remain distinct. |
| Security 3: transport | HTTPS admission plus explicit TLS 1.2/1.3 ingress supplier | Packaged fixture observes TLS 1.3 and rejects an untrusted certificate; it does not qualify an operator's proxy. |
| Security 5.1.1.2; OIDC 3.1.2.1, 3.2.2.1: authentication request | `lti/request.rs`, `web/lti/authorize.rs`: exact redirect, GET/POST decoding, required openid/id_token/form_post/none, unchanged nonce | Malformed/duplicate input, trusted-redirect and silent-session tests. |
| Security 5.1.1.3–5; OIDC 3.2.2.5–6: response | Signed ID token; echo supplied state exactly; omit absent/empty state; errors only to admitted redirects | Current API and real browser tests; shared form encoding remains a refinement obligation. |
| Security 5.1.2; OIDC 2, 3.2.2.10: token | Exact issuer/subject/audience/nonce, NumericDate iat/exp, auth_time; no access token/code is returned, so their hash claims are not required | Independent JWT verification and age tests; OIDC-1-002 remains partial and is not promoted by reuse. |
| Security 5.1.3: Tool validation | Platform supplies the signed message and JWKS; the Tool owns signature, issuer/audience, time, state and nonce validation | Independent Tool fixture and tampering controls exercise interoperability; arbitrary Tools are not certified. |
| Security 5.2–5.3: Tool-originating messages | Not implemented by this Platform-originating resource-link family | Do not apply the Tool-sender claim namespace rule to Platform extensions; reproject before adding inbound Tool messages. |
| Security 6.1–6.4: signing and key management | Required RS256, public RSA n/e and kid, fresh key IDs and old-key overlap measured after the Environment lock | Real management lifecycle, blocked rotation and previous-code controls; key custody and ordinary OIDC TTL history remain shared. |
| OIDC 3.1.2.1, 15.1: max_age/acr_values | Check original authentication time before and after signing; accept preferences without inventing an ACR | Fresh/stale/zero/malformed age and stored-POST tests; the publication model is untimed. |
| OIDC 3.1.2.1, 5.5, 6.1–6.2, 7.2.1: optional inputs | Signed hint constrains existing session; unsupported objects/registration return defined errors; claims preferences add no disclosure | Unit, GET/POST and expired-hint tests; hints cannot authenticate users. |
| OIDC 5.1, 5.7; RFC5322 3.4.1: optional user attributes | Final standard-claim syntax checks and distinct source/release authority | Unit/API refusal, repair, replay and source-table checks; no mailbox-possession or universal parser proof. |
| Form Post 2, 4 | `form_post.rs`: registered form action, POST encoding, escaping, no-store/no-cache, CSP-compatible submission | Actual Chromium and Tool plus shared Form Post regressions; caller commits before returning the form. |
| Aegaeon secure-default policy | Explicit activation, DPoP, consent, original grant ceiling, current authority, finite budget/TTL and no failure fallback | DPoP, authority, application, failure/recovery and concurrency tests; assessed separately from LTI's normative requirements. |
| Aegaeon storage policy | Restricted reader/writer, same live database, protected history, atomic consume/audit before response | Catalog upgrade, privilege faults, four startup refusals and rollback/lost-response tests; stable routing and stopped administration remain supplier conditions. |

JWS/JWA/JWK/JWT, OAuth/DPoP, TLS, JSON/HTML/URI handling, mapping and permanent
identity reuse their existing inventories, including their recorded gaps. The
publication model's eight lemmas and two guard-removal controls apply only to
the conditional transaction boundary described in
[its correspondence record](lti-transactional-publication.md). They do not prove
parser soundness, cryptographic implementations or cross-store atomicity.

## Remaining shared assurance work

These identifiers track handoffs, not new atomic obligations or discharged
claims. They preserve concrete next actions and completion criteria.

| ID | Owner and next action | Completion evidence |
| --- | --- | --- |
| LTI-SHARED-01 | Task1b/Task3: evaluate ordinary OIDC mapped standard claims and historical token lifetimes across policy reduction; retain the LTI final-value checks and 60-second key floor | Actual ordinary callers and previous-behavior controls; shared policy/model correspondence. No LTI serving defect is waived by this handoff. |
| LTI-SHARED-02 | Task3: project applicable normative and policy requirements into the adopted atomic inventory; compose mapping, parsing, RS256, subject ownership and publication models | Stable source/role/condition IDs, full domains and own preconditions, model-to-code/caller correspondence and independently reviewed discharge. Counts remain unchanged until then. |
| LTI-SHARED-03 | Task1b/Task3: qualify stopped restore/failover and credential changes against complete permanent history, current registration/runtime revisions and consumed intents | Version-bound restore/recovery traces; stale authority and consumed tickets cannot become usable. Restoring SQL/Redis snapshots alone is not an authorized recovery procedure. |
| LTI-SHARED-04 | Task3: qualify actual transport, clock, key custody and SQL/session suppliers, including reconnection and revocation ordering | Supply-specific records bound to the executable/configuration; no inference of distributed atomic revocation from the final session read. |

Feature integration, successful tests and conditional formal results remain
separate from full product assurance. These handoffs do not activate a verified
LTI claim or certify a deployment. Unrelated paused assurance and timing work
remain paused.
