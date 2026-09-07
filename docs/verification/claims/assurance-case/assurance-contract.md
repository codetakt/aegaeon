# Server Assurance Contract

Last updated: 2026-09-07

Document revision: **2026-09-07-r3**.

Status: current implementation baseline

Owner: Verification / Security

Audience: implementers, verification reviewers, release managers

## Authority and adoption

Contract ID: **aegaeon-server-assurance-v1**. This is the fixed normative
contract for the target phrase **assumption-qualified formally verified and
security-tested OAuth/OIDC foundation**. Adopting this contract does not attest
that an implementation satisfies it. [Contract status](contract-status.md)
records the outstanding activation work.

The document revision identifies this unactivated contract revision, covering review,
role and evidence requirements; it does not attest the implementation. The
[evaluation rules](../assurance-evaluation.md) are normative for requirement
closure, model adequacy, composition, security plans, review and continuing validity.

The [public assurance statement specification](../assurance-statement.md) defines
the finalized release wording, required disclosures, and combined server/SDK
statement. It does not reduce this contract's obligations.

This contract and the [standards baseline](standards-baseline.md), including its
[machine-readable register](../../../../spec/server-assurance-contract.v1.json),
define obligations independently of proof availability. The compliance matrix
indexes evidence; it does not select away unsatisfied obligations. Product
wording, roadmaps, historical promotions, and proof counts cannot override this
contract. Specification conformance, implementation proofs, symbolic security
proofs, and empirical security tests are separate claims.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY in this contract are
interpreted under RFC 2119 and RFC 8174. Uppercase keywords have those special
meanings. RFC 8176 instead defines Authentication Method Reference values.

## Foundation profile

The profile **server-foundation-v1** covers the server as authorization server
(AS), OpenID Provider (OP), and the resource server (RS) for its own OAuth-protected
resources, including UserInfo. Cookie/API-key management endpoints remain subject
to G-01/G-03/G-09/G-10/G-14; they are not OAuth RS endpoints merely because they
require authentication. Each endpoint's actual auth mode determines the applicable
protocol duties. The required capabilities are Authorization Code, PKCE S256, refresh
rotation, PAR, DPoP, revocation, introspection, OIDC Code Flow, discovery, JWKS,
and UserInfo. Both public and confidential clients are covered; public client
identification MUST NOT be mistaken for confidential client authentication.

- Code flows MUST enforce PKCE S256, validated redirects, issuer/client binding,
  and authorization-session integrity. Implicit and resource-owner password
  grants MUST NOT be enabled in this profile.
- Refresh tokens, when issued, MUST rotate with family reuse detection. DPoP
  support is required; when negotiated or required by client/resource policy,
  its binding MUST survive issuance, refresh, and resource acceptance. The
  release configuration MUST state which requests require sender constraints
  and nonce enforcement. The claim MUST NOT describe bearer-only requests as
  sender-constrained.
- The applicable OP signing requirements, including RS256 support, MUST be
  satisfied. Every signing/verification direction, surface, algorithm, and
  provider MUST be identified. An unverified crypto provider is an explicit
  implementation trust dependency, not merely a hardness assumption.
- The server's own authentication, consent, management, recovery, and storage
  paths that influence these capabilities are included in the corresponding
  obligations below. A separate UI or an external identity provider does not
  remove the server-side admission and authorization obligations.

The standards register assigns every existing matrix group a base, conditional,
guidance, deferred, or project role. Conditional obligations are triggered by
accepted requests, advertised metadata, active configuration, or effects on
foundation state. They cannot be disabled by changing a matrix status. Deferred
capabilities MUST remain unavailable until explicitly admitted under a contract
revision or extension profile. Excluded code sharing keys/state with the
foundation requires evidence that it preserves these obligations.

The foundation does not claim a standalone RP/SDK, all grant types, every JOSE
algorithm, all OIDC response types, Federation OP publication, or certification.
Server-side upstream RP/federation use triggers its own consumer obligations;
external RP code and browser rendering remain outside implementation proof scope.

### Dynamic OP compatibility constraint

OIDC Core errata set 2 section 15.2 applies to OPs establishing relationships with
RPs without a pre-configured relationship. Such OPs MUST implement its dynamic-OP
capabilities, including Request URI retrieval and the required response types.
Discovery section 3 also requires dynamic OPs to support `code`, `id_token`,
`id_token token`, and the `authorization_code`/`implicit` grants. This conflicts
with this profile's implicit prohibition. RFC 9700 section 2.1.2 does not waive
those OP MUSTs; excluding implicit from OAuth 2.1 does not amend OIDC Core.

Consequently a configuration establishing those dynamic relationships cannot
activate `server-foundation-v1` under the current combined baseline. It requires
a separately resolved, versioned profile and appropriately scoped wording; an
undisclosed MUST deviation is forbidden. Existing registration features and their
obligations remain in the inventory. This constraint does not remove them from
R(C) or assert that the current implementation enforces it.

The presence of a registration endpoint alone does not determine the section 15.2
role. A deployment claiming only pre-configured relationships MUST document and
enforce that restriction, including registration authority and metadata. Admitted
discovery metadata MUST explicitly describe actual grants/Request URI support;
omitted fields whose defaults imply unsupported capabilities are not acceptable.
PAR's `request_uri` reference alone does not discharge OIDC Request Object retrieval.

For G-15, the release's Discovery requirements and tests MUST include these fields
from Discovery section 3:

| Metadata field | Requirement for this profile |
| --- | --- |
| `response_types_supported` | REQUIRED by Discovery; explicitly enumerate exactly the admitted response types |
| `grant_types_supported` | Explicitly enumerate admitted grants; omission defaults to `authorization_code` and `implicit`, contradicting this profile |
| `request_uri_parameter_supported` | Explicitly state the implemented OIDC Request URI capability; omission defaults to `true` and cannot represent unsupported retrieval |
| `require_request_uri_registration` | Match actual Request URI registration policy; explicitly publish `true` when registration is required. Omission defaults to `false` and is permitted only when that describes the policy |

Explicit publication of `request_uri_parameter_supported` is a project-profile
requirement, including when the value is `true`. The conditional rule for
`require_request_uri_registration` does not turn an optional field with an accurate
default into a universal standards MUST. Additional metadata fields remain subject
to their own applicable requirements; this table is not the complete inventory.

## Requirement selection and precedence

For a release configuration C, let R(C) contain **all role-applicable normative
requirements** in the pinned specifications for the required and triggered
capabilities, including relevant error behavior, metadata, and security
considerations. Normative dependencies apply to the extent incorporated by
those requirements. R(C) is independent of matrix membership and status.

Each MUST/MUST NOT requires closure. A SHOULD/SHOULD NOT deviation requires a
documented analysis of the consequences and an approved rationale consistent
with the specification; it cannot weaken an unconditional contract guarantee.
An optional feature that is enabled must satisfy its conditional requirements.
Mandatory-to-implement features cannot be declared inapplicable merely because
they are missing. Requirements solely on another role require an explicit role
disposition, including what the server assumes and enforces at that boundary.

Use RFC 9700's updates to RFC 6749/6750/6819. OAuth 2.1 is the pinned **draft-16**
target, not a published RFC or evidence of current compatibility. OIDC Core,
Discovery, and Registration use errata set 2. Other editions and source digests
are fixed by the register. Later drafts, errata, and IANA registry updates require
an impact review; an unversioned reference cannot widen the contract.

If combined specifications conflict, record the exact clauses, apply explicit
updates and profile rules, and resolve the disposition before activation. A
stricter implementation is not automatically conformant if it rejects behavior
that the selected role is required to support.

Before release activation, R(C) MUST have a requirement-level inventory with
stable IDs, exact source sections/anchors, role, trigger, disposition, guarantee
IDs, and evidence. Existing OIDC roll-ups are migration links, not that inventory.
This extraction work is outstanding evidence work; it does not narrow R(C).

## State and execution semantics

Security state includes issuer/environment/client identities, authentication
and authorization sessions, grants, code/PAR/replay consumption, refresh
families, revocation, key/policy versions, and trusted upstream metadata. An
accepted security operation has one logical commit point. Its response and
credentials MUST agree with the validated input and committed state.

The supported execution model includes malicious inputs and clients, message
replay/reordering, concurrent workers/instances, cancellation, dependency failure,
lost commit acknowledgements, crash/restart, supported failover/restore, and
clock skew within declared bounds. State changes on rejection, such as refresh
family revocation, MUST be explicitly specified. Availability during dependency
outages is not guaranteed; issuing authority from an unresolved state is forbidden.

A release instantiates time tolerances, token lifetimes, replay retention,
resource limits, consistency/durability configuration, and permitted algorithms
as parameters C. The proof MUST cover those values and the runtime MUST enforce
them. Bounded evidence is insufficient for inputs the runtime accepts beyond its
bounds. Unsupported recovery or configuration changes MUST prevent service
resumption until a validated state is established.

## Guarantee obligations

Each guarantee below is mandatory when its stated trigger applies. References
from matrix groups to these IDs appear in the machine-readable register. Every
guarantee requires an explicit theorem/test obligation at the relevant boundary;
the text is a contract, not a claim that such evidence already exists.
Group-level guarantee lists are minimum cross-references, not exclusions of other
applicable guarantees. Implementation obligations require machine-checked
refinement or invariant proofs as specified below; tests provide additional evidence.

### G-01 — Authority isolation

Issuer, environment, tenant, client, subject, audience/resource, and trust-anchor
bindings MUST remain consistent through admission, lookup, policy evaluation,
issuance, refresh, introspection, logout, and management. An identifier or cached
result from another authority MUST NOT grant access. Scope and delegated rights
MUST stay within the authenticated principal's and grant's authority.

### G-02 — Input and output interpretation

Raw signed bytes, JSON/query/form members, encodings, lengths, URIs, and numeric
times MUST have an unambiguous, specification-correct interpretation at every
boundary. Duplicate/unsupported security fields MUST receive the specified
rejection behavior. Parsing, signature verification, policy checks, persistence,
and emitted tokens MUST refer to the same values. Safe FFI ownership, bounds,
error handling, and serialization are part of implementation correspondence.

### G-03 — Authentication and authorization

The selected client authentication method and the user's authenticated session,
consent/authorization, CSRF protection, and redirect validation MUST precede
grant issuance. Untrusted input MUST NOT fabricate a principal or authentication
result. A public client uses the specified public-client protections; it is not
required to possess a confidential-client secret.

Enabled local credential flows MUST specify password hashing/parameters and
verification, online attempt limits, enrollment/reset authority, token binding,
expiry and single use, and session rotation against fixation. Credential changes
and recovery MUST have explicit effects on existing sessions/grants. Supported
authentication methods, MFA availability and assurance mappings MUST be disclosed;
configuration labels cannot substitute for authentication evidence. Relevant
project specifications require release-specific pins and requirement dispositions.

### G-04 — Authorization codes

A code MUST bind its issuer, client, authorized subject, redirect, granted scope,
PKCE challenge, and applicable nonce/session context. Redemption MUST validate
those bindings and expiry and commit at most one grant per code, including
concurrent and recovered executions. Reuse MUST produce the specified rejection
and applicable revocation behavior. Invalid redirects MUST NOT receive redirects
containing credentials or attacker-selected error destinations.

### G-05 — Refresh families

Rotation MUST preserve client, subject, scope/resource, and sender bindings and
establish the successor and associated access-token state atomically in the
observable abstract state. Physical storage need not be a single transaction,
but its refinement MUST prevent any observer from accepting an intermediate
state that violates that atomic transition. Visibility ordering, fencing and
recovery require proof; later compensation cannot undo an already accepted
invalid grant. Reuse
MUST invalidate the family to the specified extent. Expiry, cleanup, cancellation,
and retries MUST NOT resurrect ancestors or orphan active descendants. Internal
operation retry MUST NOT become an attacker-controlled replay exception.

### G-06 — Pushed and signed authorization requests

PAR references MUST bind the validated request, client, issuer, expiry, and
authorized use. Consumption MUST respect the declared single-use semantics.
When JAR/request_uri is enabled, signature, audience, time, retrieval policy,
and replay checks MUST preserve that binding; outer parameters MUST NOT override
security decisions made on the protected request.

### G-07 — Proof of possession and replay

For DPoP, signature/key, typ, htm, htu, iat, jti, ath where applicable, and nonce
policy MUST be checked against the actual request and token. Replay admission
MUST be atomic across the token/proof's acceptance domain and retained for its
entire acceptance window. Region-local namespaces alone do not establish this.
Enabled mTLS MUST bind the validated certificate through issuance and use.

### G-08 — JOSE and token semantics

Algorithms, key types, key purposes, trusted key selection, crit handling,
signature/encryption ordering, and token types MUST prevent substitution or
downgrade. ID/access/logout/assertion tokens MUST satisfy their distinct issuer,
subject, audience/azp, time, nonce, hash-claim, cnf, and claim-release rules.
UserInfo identity MUST agree with the authorized subject. RP-side validation is
also required when this server consumes upstream tokens.

### G-09 — Authentication strength and sessions

auth_time, max_age, prompt, acr, and amr MUST derive from validated authentication
events and an explicit assurance policy. A configuration label MUST NOT elevate
password authentication to MFA. Upstream assurance mapping MUST bind the trusted
issuer, validated result, subject, and freshness. Session creation, reauthentication,
termination, credential recovery, and enabled step-up MUST preserve these facts.

### G-10 — Configuration and management

Bootstrap and management MUST authorize the affected environment and operation.
Configuration, client registration/update/deletion, key changes, and policy
activation MUST preserve the contract. Invalid changes MUST be rejected; accepted
changes MUST have a defined version/order relative to in-flight requests. Stale
policy snapshots MUST NOT bypass a revocation or restriction. UI exclusion does
not exclude the API's authorization, session, or state-transition obligations.

### G-11 — Cryptographic integration and key lifecycle

Concrete primitive specifications, provider behavior, key generation/use,
entropy handling, DRBG state, encoding, and key-purpose binding MUST be linked to
the implementation or explicitly identified external contracts. Own-code seed
reuse, length/error handling, and provider dispatch remain verification targets.
Key rotation, retirement, compromise response, and encrypted key handles MUST
preserve issuer/purpose/algorithm/version binding and prevent unauthorized use.

### G-12 — Revocation, introspection, and logout

Revocation and introspection MUST enforce caller authority and the specified
token/family/session state. Logout mechanisms, when enabled, MUST validate their
own issuer/audience/session/replay bindings. A release MUST define propagation
semantics: an offline JWT verifier does not provide immediate revocation by
default. Acceptance delay MUST be bounded and disclosed by the selected lifetime
or online validation contract; tests/proofs MUST use the same semantics.

### G-13 — Durable transitions and recovery

Completed operations MUST correspond to legal state transitions under concurrency,
partial failure, timeout, crash, and supported recovery. No consumed credential,
revocation, policy restriction, or replay record may silently roll back into an
accepting state. Lost acknowledgements MUST be resolved without issuing a second
grant. Fencing, persistence, restore epochs, and transaction semantics require
explicit contracts; Lua exclusion, SET NX, or a database's name alone is not proof.
An uncertain outcome may resolve to rejection and contract-consistent invalidation,
or to an authenticated idempotent response to the original operation if permitted
by its protocol. It MUST NOT create a second grant or permit credential replay.
No availability guarantee during a partition is implied. Recovery epochs, fencing
and cross-store visibility semantics MUST be fixed in C and included in the proof.

### G-14 — Transport, confidentiality, and resource boundaries

Credential/token handling, redirects, logs, errors, storage, and caches MUST
respect the specified confidentiality and privacy boundaries. TLS/proxy identity
and outbound fetch/SSRF policy MUST bind to the validated endpoint. Input size,
fanout, retention, and resource limits MUST prevent unbounded security-critical
work within the declared service envelope. Network-stack correctness and physical
side channels remain separately disclosed trust/test boundaries.

### G-15 — Discovery and advertised capabilities

Discovery, JWKS, metadata, error responses, and registered client capabilities
MUST describe the actual issuer and enabled behavior. Required interoperability
features cannot be advertised without working admission/verification paths.
Unsupported capabilities MUST have the specified rejection behavior. Source or
test-only helpers do not constitute a production endpoint or support claim.
Every required/enabled capability needs implementation-linked normal-execution
evidence and successful tests on release outputs under the evaluation rules.
The server MUST disclose counterparty preconditions with interface IDs; a combined
SDK claim requires the populated IF-01 through IF-10 composition inventory to close.

### G-16 — Extension and upstream composition

Enabled device grants, token exchange, assertions, resource indicators, RAR,
JWT introspection/access tokens, SD-JWT, registration, logout, step-up, and
federation/brokering MUST satisfy their pinned role-specific requirements and
G-01 through G-15 as applicable. Shared state/keys MUST NOT allow an extension
to invalidate the foundation. Trust-chain signatures, anchor selection, metadata
policy, cache revalidation, outbound fetch, and upstream session binding are
server obligations when those consumer paths are used.

### G-17 — Artifact and proof correspondence

The distributed artifact and enabled configuration MUST be identifiable by
digest and linked to the source, lockfile, extraction outputs, target/toolchain,
features, providers, formal results, and dependency closure used for assurance.
Compilation/extraction trust MUST be disclosed. Changing these inputs requires
impact review and refreshed affected evidence. A signature on an SBOM alone
does not attest to the binary's proof or test results.

### G-18 — Security testing and release decision

The actual release configuration MUST undergo threat-directed protocol, parser/FFI,
identity/management, concurrency/recovery, dependency, and operational-boundary
tests. Results MUST identify tools, inputs/bounds, artifact/configuration digests,
execution status, failures, skips, findings, and disposition. Unresolved violations
of these guarantees or applicable Critical/High findings block activation.
False-positive/non-applicability decisions require recorded grounds. Tests do not
prove absence of unknown vulnerabilities. Named audit/certification claims require
their own scope-specific evidence.

## Assumptions and evidence closure

The allowed assumption classes are cryptographic hardness/finite-execution bad
events; OS/device entropy quality; external primitive/KMS behavior; compiler and
proof-tool soundness; external OS/network/storage interface behavior; and explicit
counterparty behavior. Each premise MUST identify its guarantee dependencies,
precise meaning, provider/configuration, and consequence of violation.

Own Rust/Lua/SQL/FFI decisions, malformed-input rejection, orchestration, and
configuration validation MUST NOT be hidden in a generic host/storage assumption.
Existing assumption registers are inventories to audit, not evidence that every
listed axiom is valid. Concrete hash injectivity and conclusions of `True` MUST
NOT be presented as collision resistance or unforgeability.

Closure requires machine-checked implementation refinement or invariant proofs for applicable
G-01 through G-16, adversarial symbolic evidence for the relevant protocol
security properties and their composition, and empirical evidence for G-17/18
and external integration. Parameterized or bounded results MUST disclose and
enforce their domain. Model-only proofs, handwritten oracles, source scans,
runtime-link traces, and file existence are supporting evidence, not substitutes
for implementation correspondence. Defense mutations and reachability witnesses
MUST challenge replay/authentication models used to discharge this contract under
the evaluation rules' capability matrix, mutation dispositions and honest-run
witnesses. Inconclusive runs are not successful proofs or counterexamples.

## Activation and changes

Activation requires a complete R(C) inventory, discharged applicable guarantees,
audited assumptions, exact artifact/configuration binding, completed security
testing, and an approved release decision with no blocking findings. Every
required result MUST be checked for success and relevance; schema validation,
log presence, stale reports, or a `verified` matrix label alone cannot activate it.
The release record MUST enumerate exclusions and any permitted SHOULD deviations.

Changes to the specification editions, required capabilities, assumptions,
guarantee semantics, or applicability rules require a versioned contract change,
impact analysis, and renewed affected evidence. Implementation/evidence changes
may satisfy the contract without changing its obligations. No particular database,
proof-extraction architecture, or deployment vendor is mandated by this contract.
