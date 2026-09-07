# Server Assurance Standards Baseline

Last updated: 2026-09-07

Document revision: **2026-09-07-r4**.

Status: current implementation baseline

Owner: Verification / Protocol Engineering

Audience: implementers, verification reviewers, release managers

## Authority

This document defines specification selection for the
[server assurance contract](assurance-contract.md).
The [versioned register](../../../../spec/server-assurance-contract.v1.json)
is authoritative for exact source editions, URIs, SHA-256 content digests,
matrix-group assignments, triggers, and guarantee IDs. It contains no proof
completion or release attestation. Readable groups below explain that register;
the compliance matrix remains an evidence index.

Sources were retrieved from RFC Editor, the IETF draft archive, and OpenID
Foundation on 2026-09-07. Digests pin the exact retrieved UTF-8 source bytes,
including HTML presentation for OIDF documents. Archive those bytes with a
release's requirement inventory. A presentation-only digest change still requires
review before updating the pin; it does not imply a semantic standards change.
RFC sources use the published RFC edition, with no automatically applied errata.
Verified errata adopted later require an explicit baseline revision.
Dependency and errata review follows the [evaluation rules](../assurance-evaluation.md).
The present pin list is a starting source register, not a completed transitive
incorporation audit. Missing required dependency pins and dispositions block
release qualification; merely adding all cited documents would not establish
their role applicability or correctness.

## Fixed editions and roles

| Family | Pinned basis | Server obligations |
| --- | --- | --- |
| OAuth framework | RFC 6749, RFC 6750, RFC 9700; OAuth 2.1 draft-ietf-oauth-v2-1-16 (2026-09-03) | AS and own RS; code/refresh profile; no implicit/password grants |
| Code and sender protection | RFC 7636, RFC 9126, RFC 9449, RFC 7800, RFC 9207 | AS, own RS; PKCE S256, PAR, DPoP, issuer and cnf binding |
| Token lifecycle and metadata | RFC 7009, RFC 7662, RFC 8414 | AS/OP; authorized revocation/introspection and accurate discovery |
| OIDC | Core, Discovery, Dynamic Client Registration 1.0 incorporating errata set 2 (2023-12-15) | Core Code Flow/Discovery are base; registration is conditional; RP duties apply to server-side brokering |
| JOSE | RFC 7515, RFC 7517, RFC 7518, RFC 7519, RFC 8725; RFC 7516 when JWE is enabled | Producer/consumer duties for each token surface and algorithm, including OP-required RS256 |
| Registration | RFC 7591, RFC 7592; OIDC Registration errata set 2 | Registration authority, metadata validation, ownership, update/delete and credential lifecycle when enabled |
| Assertions and JAR | RFC 7521, RFC 7523, RFC 9101 | Consumer duties for enabled client authentication, assertion grants and protected authorization requests |
| Additional flows | RFC 8628, RFC 8693, RFC 8705, RFC 8707, RFC 9396, RFC 9470 | Device, exchange, mTLS, resource, RAR and step-up obligations triggered by use/advertisement |
| Additional token formats | RFC 9068, RFC 9701, RFC 9901 | Producer/consumer obligations for enabled JWT access/introspection tokens and SD-JWT |
| Resource metadata and thumbprints | RFC 9728, RFC 9278, RFC 7638 | Metadata/identifier obligations on enabled surfaces and supporting key-binding operations |
| Authentication methods | RFC 8176 | amr vocabulary and faithful interpretation when emitted/consumed; G-09 always protects claimed authentication strength |
| Logout | RP-Initiated and Front-Channel Logout 1.0 (2022-09-12); Back-Channel Logout 1.0 errata set 1 (2023-12-15) | OP and server-side RP duties for each enabled logout channel; exact session/propagation semantics |
| Form post | OAuth 2.0 Form Post Response Mode (2015-04-27) | Encoding, auto-submission, error and browser-boundary duties when enabled |
| Federation | OpenID Federation 1.0 (2026-02-17), content-pinned | Active server RP/trust-chain consumer; OP publication remains deferred and unavailable |
| Supporting specifications | RFC 2119, RFC 8174, RFC 3986, RFC 4648, RFC 8259, RFC 8037, RFC 7638 | Requirement language, URI/encoding/JSON, OKP/EdDSA and key-thumbprint semantics to the extent incorporated |
| Client/context guidance | RFC 6755, RFC 6819, RFC 8252; browser-based-apps draft-27 (2026-07-06) | Identifiers, threat context and server-facing/native-client obligations; no standalone client implementation attestation |
| Deferred assertion profile | RFC 7522 | SAML grant/client authentication cannot be claimed from a tracking row; admission requires a contract extension |

This selection covers all current matrix groups, including `global`,
`security_review`, combined JOSE header groups, and the OIDC aliases. A matrix
group can map to multiple source documents and guarantees. Server-side federation
consumer requirements apply independently of the deferred `openid_federation_op`
rows. No single matrix row asserts complete specification coverage.
The group's guarantee IDs are minimum cross-references, not an exhaustive list
of applicable obligations. The contract's dynamic-OP compatibility constraint
applies to conditional registration groups: an unanticipated-RP relationship
cannot qualify under the current implicit prohibition. Request URI retrieval
becomes mandatory when Core section 15.2 applies, independently of existing support.

## Applicability rules

- **base:** requirements for the foundation's mandatory roles/capabilities;
  missing implementation or proof remains an open obligation.
- **conditional:** requirements apply when the feature is accepted, advertised,
  configured, or affects foundation state. A release must enumerate these features.
- **guidance:** assign the actual role obligations and assumptions; absence of a
  new endpoint is not grounds to discard server requirements in client guidance.
- **deferred:** no production admission/support claim. If used, it must be
  explicitly admitted and fully assessed, not silently considered out of scope.
- **project:** cross-cutting guarantees/evidence rather than an external standard.

The contract is not satisfied by setting every optional feature to false while
leaving reachable or advertised implementations active. Disabled features require
rejection and state-isolation evidence under G-15/G-16. Matrix statuses remain
historical implementation/evidence classifications; applicability is decided here.

## Corrections and migration

RFC 8174 defines uppercase BCP 14 keyword interpretation. RFC 8176 defines AMR
values, not keyword case handling. The old `8176-001` entry is retained under its
correct subject, with evidence work reopened; it cannot be treated as proof of
authentication-strength enforcement.

The repository's `rfc_9123` / `9123-001` label for browser-based applications was
incorrect. It is replaced by `draft_oauth_browser_based_apps` /
`browser-apps-001`, pinned to draft-27. This is an identifier correction, not a
claim that a browser-app RFC has been published. Historical references require
this migration mapping when importing evidence.

OAuth 2.1's old unversioned rows must be reconciled against draft-16. OIDC Core's
ten roll-up entries must be expanded to individual role-applicable requirements.
No existing `verified` label is automatically promoted to conformance with these
pinned editions. The definition of R(C) in the contract is already fixed;
inventory extraction and evidence reconciliation are activation work.

## Maintenance

Run `python3 scripts/validation/validate_server_assurance_contract.py` to check
source pins, IDs, references, and coverage of the matrix's specification groups.
This is an offline contract-integrity check, not a standards-conformance check or
release gate. A new matrix group requires a disposition in the register. The
contract's guarantees also apply to relevant behavior with no matrix row yet.

## Reproducible original-source archive

`nix build .#assurance-standards` acquires the union of both registers using
fixed-output fetches. `.#verified-reqs` supplies that archive to both validators
with `--source-dir`, so absent or changed external bytes fail CI. Standalone
validation without that option checks source pins, not external bytes; SDK
project-source hashes are checked independently of that option.

Follow the [source acquisition and repinning procedure](../../runbooks/verification-ops.md#11-pinned-standards-acquisition-and-recovery)
for cache reuse, preservation of third-party notices, review-packet exports and
reviewed recovery from changed HTML bytes. A hash mismatch never authorizes
silently replacing a pin or skipping source validation.
