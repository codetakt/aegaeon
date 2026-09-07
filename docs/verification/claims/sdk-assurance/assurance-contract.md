# SDK Assurance Contract

Last updated: 2026-09-07

Document revision: **2026-09-07-r3**.

Status: current implementation baseline

Owner: Verification / SDK Engineering / Security

Audience: SDK implementers, verification reviewers, release managers

## Authority and target claim

Contract ID: **aegaeon-sdk-assurance-v1**. This contract defines the obligations
for an **assumption-qualified formally verified and security-tested OAuth/OIDC
client and RP SDK**, and for its separately identified management-client profile.
Adoption is not proof completion or permission to use that release claim.
[Contract status](contract-status.md) records the remaining work.

The document revision identifies this contract revision. The [evaluation rules](../assurance-evaluation.md)
are normative for requirement closure, model adequacy, composition, security
plans, review and continuing validity. This revision does not attest SDK outputs.

The [public assurance statement specification](../assurance-statement.md) defines
the finalized release wording, required disclosures, and combined server/SDK
statement. It does not reduce this contract's obligations.

This contract and the [standards/output baseline](standards-baseline.md), including
the [versioned register](../../../../spec/sdk-assurance-contract.v1.json), control
scope. Existing client-core promotions, algorithm profiles, matrix labels,
TypeScript checks, SDK package versions, and hosted evidence gates cannot reduce
these obligations. A security-tested wrapper around a verified core is a narrower
claim than a verified SDK implementation.

MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY have their RFC 2119 / RFC 8174 meanings.
Specification conformance, implementation refinement, symbolic protocol security,
empirical security testing, and external certification MUST be stated separately.
Guarantees cover specified behavior and security properties, not every possible
property of a package or the absence of unknown vulnerabilities.

## Product and output profiles

The initial profiles are **sdk-rp-node-v1**, **sdk-rp-web-v1**, and
**sdk-management-v1**. The register assigns all six current package families:
`@aegaeon/verified-core`, `@aegaeon/runtime-node`, `@aegaeon/runtime-web`,
`@aegaeon/rp-core`, `@aegaeon/issuer-spa`, and `@aegaeon/management-client`.

The RP profiles require Authorization Code with PKCE S256, transaction-bound
state/nonce, issuer discovery and trusted key selection, OIDC ID Token validation
including RS256, authenticated-session admission, and RP-initiated logout.
Public-client protections MUST be enforced without inventing a client secret.
Confidential-client authentication applies only to a trusted server runtime;
browser-delivered secrets MUST NOT be treated as confidential authentication.
Implicit and resource-owner password grants MUST NOT be enabled. Hybrid and other
response/grant types need explicit admission under a revised or extension profile.

Exposed DPoP, refresh, UserInfo, registration, PAR/JAR, other logout channels, and
other extensions acquire the corresponding client/consumer requirements. A
low-level verifier does not promise a complete sender-side DPoP flow, nor does
`startFederatedLogin` alone promise OpenID Federation trust-chain validation.
Roles and directions MUST be named for every supported feature.

The management profile covers the exported control-plane operations, their
transport, authentication/session handling, scoping, and response interpretation.
It does not claim that the client enforces server RBAC or that an admin UI is
formally verified. Server authorization remains a counterpart obligation;
SDK request construction and security decisions remain SDK obligations.

The target outputs are emitted JavaScript, WASM, package exports, TypeScript
declarations, manifests, and supporting shipped assets. The source languages are
TypeScript and the identified verified-core sources/extraction chain. Each release
MUST enumerate package versions and digests, entrypoints, runtime/engine versions,
crypto profiles, providers, transports, stores, and supported build/bundle modes.
Theorem and test domains MUST cover these actual outputs and enforce their bounds.

Core-only packages can carry a scoped component claim; they MUST NOT be described
as a complete verified RP. Rust, Ruby, PHP, Python, Java, Go, .NET, native-app
profiles, and other generated targets require their own admitted output profile
and evidence. Code generation, FFI reuse, or the presence of `crates/client` does
not transfer the TypeScript/WASM claim to another language or runtime.

## Selection of requirements and precedence

For release configuration C, **R_sdk(C)** contains all role-applicable normative
requirements of the pinned specifications for mandatory and triggered features,
plus the security-relevant public API and project requirements for the selected
packages. Accepted inputs, callable exports, configuration, advertised support,
and effects on shared state determine applicability, independently of available
proofs or matrix rows. Error paths, mandatory-to-implement algorithms, metadata,
security considerations, and incorporated normative dependencies are included.

Each MUST/MUST NOT requires closure. SHOULD deviations require documented impact
and an approved specification-consistent rationale and MUST NOT weaken an
unconditional guarantee. Missing mandatory behavior cannot be classified as
inapplicable. Requirements belonging to an OP, AS, RS, host application, or
storage provider need explicit role disposition and boundary assumptions.

RFC 9700 updates the selected OAuth requirements. OAuth 2.1 targets draft-16;
OIDC Core/Discovery/Registration use errata set 2. Exact remaining editions and
source digests are fixed in the register. Later drafts, errata, IANA changes, or
additional specification families need impact review and explicit versioning.
Conflicting clauses MUST be resolved before activation. Rejecting required valid
behavior is not conformant merely because it appears more restrictive.

Before activation, every requirement MUST have a stable ID, exact source
section/anchor or API operation, role/direction, trigger, disposition, guarantee
IDs, implementation/export mapping, assumptions, and evidence. Current server
matrix roll-ups and client-core inventories are inputs to this work, not the
completed SDK requirement inventory. Its absence does not narrow R_sdk(C).

## Execution and trust model

The model includes malicious authorization/token responses and metadata, wrong or
compromised issuers outside the configured trust set, mix-up, replay, reordering,
concurrent callbacks/tabs/workers/processes within the supported sharing domain,
async exceptions, cancellation, timeouts, lost acknowledgements, crashes,
restoration, key rotation, and declared clock skew. Security state includes
transactions, PKCE material, accepted identities, tokens and sender keys, sessions,
logout/revocation state, discovery/JWKS caches, and management contexts.

There MUST be a specified logical commit point for every accepted operation.
Emitted requests, returned success, and stored state MUST agree. An external
token exchange with an uncertain outcome MUST NOT justify fabricated success or
blind reuse of a consumed authorization code. Unsupported sharing/recovery modes
MUST be rejected or prevented by the admitted deployment profile.

Assumptions may include cryptographic hardness and finite-execution bad events,
OS/device entropy quality, specified external primitive behavior, compiler/prover
and JS/WASM engine soundness, platform interfaces, and explicit application/peer
contracts. Each MUST name its meaning, affected guarantees, provider/version,
configuration, violation consequences, and enforceable preconditions.

Arbitrary same-origin script execution or a compromised host can violate browser
or Node isolation assumptions. Those limits MUST be disclosed; script-readable
storage MUST NOT be sold as resistant to arbitrary same-origin code execution.
SDK-created injection, credential leakage, unsafe defaults, parser decisions,
signature-preverification glue, store coordination, and callback orchestration
MUST NOT be hidden in a generic browser/host/adapter assumption.

## Guarantee obligations

The following guarantees are mandatory at each applicable boundary. The register
maps package/profile and specification families to them. A guarantee declaration
is an obligation, not existing evidence that it is satisfied.
The register's guarantee lists are minimum cross-references, not exhaustive scope.
Development/reference source paths locate code to assess; they do not designate
a conforming reference implementation. In particular, the existing RP completion
and session helpers do not establish C-06/C-07/C-18 closure.

### C-01 — Public API meaning and authority

Every exported security-relevant operation MUST have specified inputs, outputs,
errors, preconditions, state effects, and trust level. Issuer/client/subject,
audience/resource, origin, and team/tenant/environment context MUST remain bound
through the operation. Caller extras, overloads, generic request helpers, and
low-level exports MUST NOT silently override protected decisions or turn decoded
data into authenticated identity. JavaScript callers receive the same checks as
typed callers; declarations alone do not enforce a security contract.

### C-02 — Parsing and representation agreement

Compact JOSE bytes, duplicate JSON/query/form members, UTF-8, base64url, URI
components, array/string claims, integer precision, lengths, and time units MUST
have an unambiguous specification-correct meaning. JS number/BigInt conversion,
typed arrays, serialization, and WASM integer widths MUST preserve it or reject
the input. Signature verification, claim checks, persistence, and outputs MUST
refer to the same values. Accepted inputs MUST fit the proof's actual bounds.

### C-03 — Discovery, issuer, and key trust

The configured issuer, discovery result, authorization/token/UserInfo/logout
endpoints, and selected JWKS MUST remain consistently bound. An untrusted `iss`,
`jku`, `x5u`, `kid`, redirect, cache entry, or metadata field MUST NOT select its
own trust root. HTTPS, endpoint/redirect admission, issuer comparison, key use,
rotation, cache freshness/invalidation, and server-side SSRF checks MUST follow
the selected profile. Browser fetch restrictions alone do not validate an issuer.

### C-04 — Authorization transaction construction

Authorization requests MUST bind issuer, client, redirect URI, scope/resource,
response mode, state, nonce, and PKCE verifier/challenge to the intended
transaction. Random material MUST use the admitted entropy interface with the
required length/encoding and no own-code reuse. Transactions MUST expire and be
isolated across users, issuers, tabs, and login attempts. Caller-supplied parameters
MUST NOT downgrade S256 or replace the protected transaction context.

### C-05 — Callback and token exchange

Success and error callbacks MUST be correlated to an existing transaction and
the correct issuer, redirect, response mode, and state. Duplicates, mixed error
and success responses, injected codes, and replay MUST receive specified rejection.
Code exchange MUST use the original verifier, client authentication where
applicable, and admitted token endpoint. Consumption, retries, cancellation, and
concurrent completion MUST have a legal state transition without duplicate
authenticated-session creation or a surviving reusable transaction.

### C-06 — Token validation and verification provenance

Before an authenticated result is returned or persisted, the actual ID Token
MUST pass its signature, allowed algorithm/key, issuer, audience/azp, expiry/time,
nonce, and applicable hash-claim checks against the transaction. Token classes
MUST be distinguished; access tokens are not ID Tokens. Provider-side validation
or a transport callback returning a token object is not SDK validation.

For host-verified signatures, the admitted decision MUST be inseparably bound to
the exact signed bytes, key, algorithm, token type, and validated claims. A public
`SIGNATURE_PREVERIFIED` flag, mutable payload, or caller-provided boolean MUST NOT
be sufficient to manufacture successful high-level authentication. Low-level
preconditions MUST be explicit and every SDK caller MUST discharge them.

An untrusted public flag, object or restored session MUST NOT confer verification
authority. A preverification capability must originate from the admitted verifier,
remain bound to the verified inputs and policy, and be unforgeable across the
declared caller/host boundary. Public options MUST reject or remove reserved
authority bits. A raw core ABI relying on trusted caller preconditions must be
identified as such and isolated from the qualified high-level authentication API;
every admitted adapter call must prove those preconditions. This does not require
a particular masking scheme or forbid justified internal provider selection.

### C-07 — Authenticated sessions and claim use

Session creation, restoration, account selection, claim mapping, UserInfo
consumption, and authorization helpers MUST preserve the validated issuer/client/
subject and audience context. UserInfo subject MUST match the validated ID Token
subject. auth_time/acr/amr and freshness decisions MUST derive from validated
events and an explicit policy; labels cannot manufacture MFA. Unvalidated stored
or callback data MUST NOT regain authenticated status merely by deserialization.

### C-08 — Refresh, expiry, and revocation

When refresh tokens are accepted or used, their issuer/client/subject/resource
and sender-key bindings MUST survive storage and rotation. Concurrent refresh,
lost responses, expiry, rejection, and provider reuse detection MUST follow a
specified state machine that cannot resurrect replaced tokens or confuse
sessions. Revocation requests and local invalidation MUST have explicit effects;
the SDK MUST NOT promise immediate remote invalidation of an offline JWT without
an applicable server/RS contract. Refresh secrets MUST NOT cross an endpoint or
authority boundary on retry.

### C-09 — Sender constraints and replay

Exposed DPoP operations MUST satisfy their producer or verifier requirements,
including key/signature, typ, htm, htu, iat, jti, ath where applicable, nonce,
and token/key binding. Generated proofs MUST describe the actual outgoing request;
redirect or retry handling MUST NOT forward an obsolete proof or downgrade to
Bearer. Nonce retries MUST be bounded and correctly scoped. Replay verification,
when provided, MUST be atomic across its declared acceptance domain for the full
window. Enabled mTLS requires an identified transport and certificate binding.

### C-10 — Logout and session termination

RP-initiated logout MUST bind the issuer, hint, registered post-logout redirect,
and relay state as applicable. Received front/back-channel logout messages MUST
validate their channel-specific issuer/audience/session/replay requirements.
Local logout, remote logout initiation, and confirmed remote completion MUST be
distinct outcomes. Failed or cancelled logout and concurrent refresh MUST NOT
restore a locally terminated session. Cache/storage propagation and any delay
MUST be bounded and disclosed by the chosen session contract.

### C-11 — Storage, concurrency, and recovery

Transaction/session/replay stores MUST specify atomic operations, isolation,
retention, durability, failure, and restoration semantics. SDK-owned read/check/
write coordination MUST preserve the invariants under permitted concurrency;
declaring storage external does not discharge that proof. In-memory stores do
not establish multi-process guarantees, and browser storage events do not alone
establish atomic consumption. Corruption, quota errors, stale restores, and
eviction MUST fail closed without silently reinstating invalidated authority.

### C-12 — Transport, confidentiality, and bounded work

URLs, headers, cookies, bodies, logs, errors, browser history, referrers, caches,
and persistent storage MUST respect credential and privacy boundaries. Tokens,
authorization codes, verifiers, secrets, and management credentials MUST NOT leak
to an unintended origin or observer. TLS, origin/CSRF handling, fetch credentials,
redirects, and callback hosting MUST have explicit contracts. Network/parser work,
response sizes, retries, key refresh, and retained state MUST be bounded. SDK
formatting/rendering helpers MUST not introduce injection; UI appearance and
arbitrary consumer application logic are outside this implementation claim.

### C-13 — Management-client correctness

Each exported management operation MUST match the pinned API method, path,
parameters, request/response schema, authentication mode, and error semantics.
Team/tenant/environment selection, path/query encoding, CSRF/origin/cookies,
configuration version preconditions, and credential lifecycle MUST preserve the
caller's intended authority. Extra headers or generic helpers MUST NOT silently
replace protected context. Conflicts, partial failure, and cancellation MUST NOT
be reported as committed success; non-idempotent mutations MUST NOT be blindly
retried. SDK-side authorization hints are not server enforcement.

### C-14 — Cryptographic integration and randomness

Each operation, direction, algorithm, key purpose, provider, entropy source,
encoding, and key lifetime MUST have a concrete implementation or explicit
external primitive contract. Cryptographic hardness does not establish provider
correctness. SDK-owned seed handling, algorithm dispatch, key import/export,
length checks, failure handling, and binding remain proof obligations. Concrete
hash injectivity or a theorem concluding `True` MUST NOT stand for collision
resistance or unforgeability. No fallback or profile switch may silently weaken
the selected guarantee.

### C-15 — WASM, FFI, and loader boundary

WASM/FFI ownership, memory bounds, handles, lifetimes, ABI versions, imports,
initialization, and error codes MUST preserve the verified operation semantics.
Async mutation, handle reuse, reentrancy, traps, and partial initialization MUST
not create success or expose another caller's state. Loaded core bytes MUST match
the approved artifact and ABI under an authenticated distribution/trust-root
contract. A hash fetched beside attacker-controlled code alone is insufficient.
Development mocks and test imports MUST NOT enter an attested runtime unnoticed.

### C-16 — Source-to-output implementation correspondence

Every security-relevant shipped implementation MUST have a checked refinement or
invariant relationship to its specification under explicit toolchain assumptions.
This includes the core, TypeScript orchestration/adapters, and own-code I/O glue.
The F*/Low*/extracted-C/WASM and TypeScript/emitted-JavaScript paths MUST each be
accounted for, including generators, preprocessing, target semantics, and flags.
Native proof results do not automatically apply to wasm32 or JS numeric semantics.

Tests on source files, generated-looking files, declarations, or a reference
adapter do not prove the shipped package. Supported export conditions, bundles,
minification/transforms, loaders, and dependency substitutions MUST preserve the
proved behavior. Unassessed consumer transformations require separate admission;
they MUST NOT inherit the packaged-output claim by implication.

### C-17 — Package identity and release provenance

Each shipped package/archive and dependency closure MUST be identified by digest
and linked to the exact backend/core and SDK source revisions, lockfiles,
toolchains, outputs, proofs, tests, and configuration. The inventory MUST include
JS, WASM, declarations, subpath exports, assets, and shipped install/build hooks.
Package dependencies MUST resolve to the assessed versions, not an unspecified
future semver-compatible core. Source declarations and actual export behavior
MUST agree. License/NOTICE obligations and redistribution permissions MUST be
accounted for across generated code and dependencies.

Registry custody, signatures/provenance, trust-root/key changes, and package
retrieval MUST bind the installed artifact to the reviewed release. A signed
SBOM, workflow name, or provenance flag alone does not attest successful proofs
or tests. Publication metadata and claim documents MUST identify the same bytes.

### C-18 — Composition and external callbacks

Transport, token-exchange, storage, clock, crypto, and application callbacks MUST
have precise contracts with enforced or explicitly discharged preconditions.
SDK call sites MUST prove that callback results preserve the contract before
returning authenticated success. Exceptions, reentrancy, and async races are
included. An unchecked callback that returns claims or tokens MUST NOT be used
to move the entire authentication decision outside the claimed SDK.

Enabled extensions MUST satisfy their pinned role-specific requirements and all
applicable guarantees. Compat or excluded APIs sharing state/keys MUST preserve
the qualified profile or be isolated with evidence. General interoperability
cannot be inferred from an Aegaeon-only test, nor can a client prove an arbitrary
IdP's internal behavior. Server and SDK contracts compose only when their actual
interface assumptions, algorithms, versions, and state semantics match.
The evaluation rules' IF-01 through IF-10 inventory MUST record actual paired
guarantees/assumptions and their discharge before a combined claim can activate.

### C-19 — Security testing of distributed outputs

The exact packed/installed release packages MUST undergo threat-directed tests
for protocol attacks, malformed inputs, parser/ABI faults, forged verification
results, callback injection, management scoping, concurrency/recovery, credential
leakage, dependencies, and distribution boundaries. Required Node/browser/version/
crypto/store combinations MUST be exercised on built outputs. Real-provider
interoperability and browser tests MUST identify the exact flow/provider/version;
mock success is insufficient for a real-provider claim.

Results MUST record tools, versions, inputs/bounds, artifact/configuration digests,
execution status, failures, skips, findings, and disposition. Relevant timing and
resource-abuse tests MUST state platform limits; they do not prove that all side
channels or unknown vulnerabilities are absent. Named audits/certifications
require their own scoped evidence.

### C-20 — Release decision and continuing validity

A reviewed release decision MUST establish complete R_sdk(C) coverage, discharged
applicable guarantees, audited assumptions, implementation/output correspondence,
successful required tests, and authenticated artifact binding. Unresolved
guarantee violations or applicable Critical/High findings block activation.
False-positive/non-applicability decisions require recorded grounds. Mandatory
skips, stale or mismatched reports, file presence, and legacy `ready` booleans
MUST NOT count as successful closure.

The public claim MUST name the activated package/output profiles, supported
configurations, exclusions, permitted SHOULD deviations, external assumptions,
and evidence. Specification, API, guarantee, or applicability changes require a
versioned contract impact review. Code/toolchain/provider/dependency changes
require refreshed affected evidence. Security advisories and supported-version
policy MUST describe when a claim is superseded or withdrawn.

## Evidence closure and adoption

Closure requires machine-checked implementation refinement or invariant proofs for C-01 through
C-18 where applicable, adversarial symbolic evidence for the relevant protocol
properties and composition, and empirical evidence for C-19/C-20 and external
integration. Bounds MUST be disclosed and enforced. Model fidelity and axiom
dependencies MUST be audited. Authentication/replay models MUST have reachability
witnesses and relevant defense-removal mutation results with the evaluation rules'
capability/disposition analysis. Timeouts are inconclusive; redundant defenses
require a dependency argument and targeted mutations. Differential tests,
oracles, traces, code scans, and type checking support this work but do not
substitute for implementation correspondence.

Existing `client-claim-boundary`, `client-claim-promotion`, `released-client-claim`,
and server/client gates remain additional release controls. Their old core/slice
completion or publication-readiness rules do not discharge this contract. Their
evaluators and release records MUST be reconciled with C-20 before using the new
qualified SDK wording. Until then the contract is specified and the new claim is
inactive, even if an older promotion report says `ready: true`.

The normative contract is maintained in `aegaeon`; SDK releases MUST archive the
adopted contract/register bytes and source pins with their own evidence. Updating
a backend document does not update a separately distributed SDK artifact.
No particular proof language, extraction architecture, store, browser vendor,
registry provider, or UI framework is mandated. Any design must discharge the
same obligations for its actual supported outputs.
