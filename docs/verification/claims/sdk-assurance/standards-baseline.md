# SDK Standards and Output Baseline

Last updated: 2026-09-07

Document revision: **2026-09-07-r4**.

Status: current implementation baseline

Owner: Verification / Protocol Engineering / SDK Engineering

Audience: implementers, verification reviewers, release managers

## Authority

This baseline instantiates the [SDK contract](assurance-contract.md). The
[register](../../../../spec/sdk-assurance-contract.v1.json) pins specification
editions, original source digests, project sources, package/output profiles,
crypto-profile dispositions, and guarantee IDs. It is not a release attestation.

External specification pins reuse the original bytes retrieved for the server
baseline on 2026-09-07 from RFC Editor, the IETF draft archive, and OIDF. The SDK
register carries its selected pins directly so it can be archived independently.
No server AS/OP proof is imported as an SDK client/RP proof. RFC pins have no
implicit errata overlay; source presentation changes also require review.
The [evaluation rules](../assurance-evaluation.md) require dependency, errata and
source-section completeness reviews. Current pins and guarantee cross-references
are not a complete requirement inventory or a completed transitive dependency audit.

## Specification families and roles

| Family | Fixed basis | SDK obligation |
| --- | --- | --- |
| OAuth client | RFC 6749/6750/9700; OAuth 2.1 draft-16 | Code-flow request/response, token use, client authentication, error and security behavior; no implicit/password grants |
| PKCE and issuer binding | RFC 7636, RFC 9207 | S256 generation and transaction binding; mix-up-resistant response validation |
| OIDC RP | Core and Discovery 1.0 errata set 2, 2023-12-15 | ID Token validation including RS256, issuer discovery/JWKS, sessions; UserInfo rules when consumed |
| JOSE and keys | RFC 7515/7517/7518/7519/8725/8037/7638; RFC 7516 if enabled | Exact producer/consumer, algorithm, purpose and provider; decoded claims are not validated identity |
| Sender constraints | RFC 9449/7800; RFC 8705 if enabled | Direction-specific DPoP generation/validation and actual request/token binding; mTLS transport contract |
| Token lifecycle | RFC 6749/7009/7662 | Refresh, revocation, introspection only for the actual client/authorized-consumer operations |
| Metadata | RFC 8414, RFC 9728 | AS/resource metadata consumption when used; SDK is not implicitly an AS/RS |
| Registration | RFC 7591/7592; OIDC Registration errata set 2 | Client metadata, registration credentials, updates and deletion when exposed |
| Protected requests | RFC 9126, RFC 9101; OIDC Core | PAR client and signed/encrypted Request Object producer/consumer directions when used |
| Logout | RP-Initiated/Front-Channel 1.0, 2022-09-12; Back-Channel errata set 1, 2023-12-15 | RP-initiated requests; received channel-specific messages only if admitted |
| Form post | OAuth 2.0 Form Post Response Mode, 2015-04-27 | Callback-host/receiver requirements if this mode is accepted |
| Additional flows | RFC 7521/7523/8628/8693/8707/9396/9470 | Assertions, device, exchange, resource, RAR and step-up duties only for exported/enabled roles |
| Additional token formats | RFC 9068/9701/9901 | JWT access/introspection tokens and SD-JWT in the explicitly supported role; opaque bearer use is not JWT validation |
| Federation | OpenID Federation 1.0, 2026-02-17 | Trust-chain/anchor/metadata-policy duties if SDK performs them; generic OIDC brokering is not this claim |
| Browser/native context | Browser-based-apps draft-27, 2026-07-06; RFC 8252/6819 | Browser/client/host dispositions; native-app output remains deferred |
| Supporting semantics | RFC 2119/8174/3986/4648/8259/8176 | Requirement language, URI/encoding/JSON, and faithful AMR interpretation |
| Management API | Content-pinned project API/auth and endpoint references | Consumer-side operations, schemas, auth, scoping, version conflicts and errors; release-specific OpenAPI must also be pinned |

**Base** means mandatory for the applicable profile. **Conditional** means the
obligation becomes mandatory when a feature is exported, accepted, configured,
advertised, or affects shared state. **Guidance** still requires explicit role
disposition. **Project** names API and cross-cutting obligations. A catalogue entry
is not a claim that the feature is implemented or supported in every profile.

Unsupported optional features need rejection/isolation evidence. New features
without a registered specification disposition block activation. FAPI, JARM,
SAML, OIDC Session Management, other response types, and native language outputs
are not implicitly admitted. Enabling one requires a versioned extension with
source pins and complete role/output obligations.

## Package and output profiles

| Profile | Required package composition | Output/role |
| --- | --- | --- |
| `sdk-rp-node-v1` | verified-core, runtime-node, rp-core | Installed JS/WASM and declarations; Node RP with admitted transports/stores |
| `sdk-rp-web-v1` | verified-core, runtime-web, rp-core, issuer-spa | Browser JS/WASM and declarations; public-client RP under explicit origin/storage/hosting assumptions |
| `sdk-management-v1` | management-client | Installed JS and declarations; selected management API operations in each admitted Node/browser environment |

The `@aegaeon/` prefix applies to all package names above. A release may activate
one profile independently, but must include its full transitive package closure
and every admitted export's obligations. Shared code has the same obligations in
every activated profile. A dependency on a package does not activate its other
profiles or optional APIs automatically.

Node/browser versions, JS/WASM engines, compiler versions/flags, ABI, bundle modes,
crypto providers, storage sharing/durability, callback transports, and supported
parameter bounds MUST be fixed in a release configuration. `Node >= version` or
"modern browsers" without a justified evidence domain is insufficient. Tests
must install packed outputs and follow their published exports; source-only or
preseeded scaffold output checks cannot attest the production build.

The management declaration file is currently maintained separately from its
implementation. Its agreement with emitted JS and the exact OpenAPI operation
inventory is a C-01/C-13/C-16 obligation, not a consequence of TypeScript syntax.
The project source pins do not replace a release-specific OpenAPI digest or
individual operation inventory. Conflicts between API prose, OpenAPI and actual
server behavior require explicit resolution before activation.

The [endpoint reference](../../../specs/management-plane/endpoint-reference.md)
is a non-exhaustive overview. The separately
pinned generated OpenAPI snapshot records an interface to reconcile, not an
independent proof that the generating code is correct. Every actual public
operation, including generic request helpers, requires a specified disposition,
request/response/auth/error semantics and source-to-output correspondence.
Missing or conflicting operations cannot be repaired by silently adopting whichever
inventory is smaller. Reference/scaffold sources are unattested development inputs;
they are not conforming reference implementations under the new SDK contract.

## Existing crypto-profile migration

| Existing selector | Contract disposition |
| --- | --- |
| `verified-core` | EdDSA component evidence; does not alone satisfy the full RP profile's RS256 requirement |
| `aegaeon-rs256` | Initial RP target: JWT EdDSA/RS256 and DPoP EdDSA where exposed; host RS256 primitive assumptions are explicit, SDK preverification glue still requires proof |
| `compat-interop` | JWT EdDSA/RS256/ES256 and DPoP EdDSA/ES256 inventory; not an activated qualified profile; must not bypass or corrupt a qualified profile |

These algorithm names do not establish verification or standards conformance.
The register mirrors the current selector inventory to detect silent scope drift.
The complete direction/token-class/provider list is still a release obligation.
No arbitrary provider-interoperability claim follows from first-party RS256 tests.

## Maintenance and handoff

Run `python3 scripts/validation/validate_sdk_assurance_contract.py` for contract
integrity. Optional `--source-dir` checks archived original specification bytes.
The check validates references, pins, packages, profiles and selector alignment;
it does not extract normative clauses, prove code, run security tests, or activate
a release. The SDK must adopt and archive an exact contract revision rather than
following an unversioned backend checkout. The status document tracks that work.

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
