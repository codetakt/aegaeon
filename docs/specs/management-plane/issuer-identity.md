# Public issuer identity and operator provisioning

Last updated: 2026-11-18

Status: active plan

Owner: Product / Engineering

Audience: implementers, reviewers, deployment operators

Design is adopted for implementation in [issue #363](https://github.com/codetakt/aegaeon/issues/363).
Acceptance completion depends on the exact implementation and its recorded evidence.

## Decision

An Environment owns one canonical public issuer. Its public DNS name is independent
of its Team, Tenant, region, Environment labels, infrastructure location and signing
key provider. Preserve the immutable Environment UUID, issuer uniqueness and subject
namespace history. Moving a server or rotating a key does not change its issuer.

The operator initializing an empty management database may supply `issuerHost`, for
example `auth.example.com`. Omitting it preserves the existing generated name:
`{environment}.{tenant}.{region}.{issuerBaseDomain}`. This is a provisioning default,
not the definition of an Environment's identity and not a DNS parsing convention.

This decision replaces the generated-name-only policy in the initial management
provisioning path. It does not give ordinary Team administrators domain allocation
authority or change the existing management API request shape.

## Protocol requirements and product scope

[OpenID Connect Discovery 1.0, errata set 2, sections 3 and 4.3](https://openid.net/specs/openid-connect-discovery-1_0.html)
require issuer agreement between configuration discovery and ID Tokens.
[RFC 8414, sections 2 and 3.3](https://www.rfc-editor.org/rfc/rfc8414.html)
requires the authorization server metadata issuer to agree with the expected issuer.
Neither standard requires internal topology labels in the public DNS name.

The supported local issuer profile remains `https://{issuerHost}`, without a trailing
slash. Paths, non-default ports, issuer aliases and multiple issuers per Environment
are outside this change. OIDC permits a broader URL space; this narrower profile is
an Aegaeon storage/routing contract, not an additional standards requirement.

`issuerHost` is a host, not a URL. Trim surrounding whitespace and lowercase ASCII
once at creation. Validate DNS label and total-length bounds. Reject empty values,
schemes, credentials, ports (including `:443`), paths, queries, fragments, wildcards,
trailing dots, Unicode host text, localhost names and IP literals. Reject numeric
forms that a URL parser interprets as an IP address and any URL-parser rewrite of
the normalized host. An ASCII IDNA A-label must also survive that check. The
resulting stored URL is the exact value clients must configure; runtime comparison
must not add normalization or treat slash/port variants as issuer aliases.

No DNS lookup or remote ownership probe runs during initialization. Syntax validation
does not prove DNS ownership, certificate issuance or reachability. The deployment
operator supplies those prerequisites and verifies them before exposing the service.

## Authority and input contract

| Entry point | Issuer choice | Authority |
| --- | --- | --- |
| `aegaeon-management-init` on an empty database | Optional explicit `issuerHost`, otherwise generated | Existing deployment-held database provisioning authority |
| Management Environment creation API | Generated from its existing authorized topology and installation base domain | Existing current Team/Tenant lifecycle authority |
| `aegaeon-hosted-bootstrap` | Existing HTTPS URL input, reduced to the same canonical host validation | Existing deployment-held database and KMS provisioning authority |
| Runtime startup | Select an existing registered host | No issuer allocation or update authority |

The strict initialization JSON keeps `ownerEmail`, `ownerPassword`, `allowedOrigins`
and `issuerBaseDomain` required. `issuerHost` is an optional string. Omission alone
selects the generated default; `null`, empty or invalid input is an error, never a
fallback. Unknown and duplicate fields, the 16 KiB input bound, password handling
and secret-safe error output keep their existing contracts.

`issuerBaseDomain` remains the installation policy for subsequent generated
Environments. An explicit initial host may be outside that domain: the provisioning
operator controls both choices. Never infer or replace the base-domain policy from
the explicit issuer, and never broaden `allowedOrigins` from either value. These
three inputs have independent purposes.

The initial labels remain Team `primary`, Tenant `primary`/region `local` and
Environment `dev`. They are management metadata and do not select a development
security mode. Public issuer selection does not rename them. Broader topology
customization is not required for this capability.

Ordinary management requests must not allocate an external issuer merely by adding
an `issuerHost` or `issuerUrl` field. Future self-service domain allocation requires
a separate explicit capability and lifecycle: bind verified domain control to the
installation, authorized Team/Tenant and exact host; reserve the host atomically;
check current authority when activating it; and define renewal, loss of control,
certificate/ingress readiness and permanent namespace reuse restrictions. A DNS
challenge alone does not grant Team or installation authority. Until that lifecycle
is implemented and tested, the existing generated-only API remains the supported
contract. This change adds no partially active domain-registration API.

## Construction, persistence and audit

Resolve and validate the issuer before database writes. Generated and explicit
names feed one canonical-issuer value and one initial configuration builder. The
builder must use that same value for the Environment row, active configuration
document and runtime projection; do not construct an independent issuer override
in the CLI or runtime. The hosted bootstrap reuses the host validator while
preserving its existing provider-specific URL input and KMS requirements.

Keep the serialized empty-database check and the single PostgreSQL transaction for
owner, policy, topology, subject namespace, active configuration and audit. Preserve
all existing schema preflight and packaged-launch checks. A host conflict, reserved
historical namespace or late audit failure rolls back the complete initialization.
Concurrent initializers have one winner; a losing request cannot replace its host,
owner or policy. A lost success response is handled by the existing inspect/login
procedure, not by resetting or silently reinitializing the database.

Record the canonical `issuerHost` and whether selection was explicit or generated
in the initialization audit, together with the existing base-domain policy. The
environment-creation audit continues to record the allocated host. Do not record
the owner password or raw rejected input. Preserve the existing non-secret CLI
output shape, which already includes `issuerHost`.

No catalog migration is required by the proposed representation: `environments`
already stores a host and derives its HTTPS URL, has a unique host index and guards
identity mutation. The permanent subject namespace also reserves the host. Verify
these contracts with the supported schema; do not weaken checks, rewrite migration
history or edit an existing issuer directly.

## Runtime, ingress and keys

`AEGAEON_RUNTIME_ISSUER_HOST` selects the registered Environment. The database is
the authority for the public URL and configuration; an environment variable,
request `Host`, forwarded header or Organization label cannot override it. Unknown
startup selectors and mismatched stored configuration fail closed. The current
backend selects one registered Environment at startup; it is not a per-request
Host router and may return its fixed metadata despite an unrelated Host header.
The deployment ingress must reject unregistered Host names, route only explicitly
configured issuer/management names, strip untrusted forwarding headers and present
a certificate for the chosen name. Test that ingress contract separately from the
backend's fixed issuer authority. The API listener's internal port is independent
of the public issuer.

Normal initialization does not create signing keys or enable OIDC implicitly.
Provision and activate keys and policy through the existing authenticated workflow
before serving discovery and tokens. A chosen DNS name does not require KMS and
does not relax key custody. KMS-backed hosted provisioning remains a distinct
workflow; this design does not claim Organizations/KMS deployment qualification
or add the hosted CLI to the packaged schema-guarded launcher.

DNS and ingress changes may move an issuer to another server while keeping the
same public URL. Preserve its authoritative data, identity history, credentials
and supported restore/cutover procedure. Renaming the issuer instead creates a
different trust and subject namespace. Do not rewrite tokens, silently link users
by email, or treat retaining signing keys as preserving issuer identity. A new
Environment and an explicit client/user/data migration are required; automatic
issuer migration and aliases are not delivered here.

## Compatibility and implementation sequence

1. Update this contract, configuration/database specifications and operator guide.
   Register the implementation issue with these acceptance criteria before code.
2. Add the bounded optional initialization field and common canonical host
   validation/configuration construction. Keep API authority, schema, key defaults
   and existing generated output compatible.
3. Add focused parser, real PostgreSQL/router and packaged Organizations checks.
   Verify final source/package correspondence before publishing test results.
4. Review the final implementation and evidence, then use normal CI and merge
   admission. No existing source/test result establishes the new path in advance.

Do not add an independent schema, key-provider, cloud provisioning or live domain
change to make this feature work. A future broader URL profile or domain-allocation
API needs its own representation, routing and compatibility design.

## Acceptance criteria

These identify required observations, not completed execution or new proof claims.

- **Input:** old JSON produces the unchanged generated host; explicit canonical and
  normalized host inputs produce the documented URL. Invalid/ambiguous hosts, null,
  duplicate/unknown fields and oversized input fail without echoing credentials.
- **Persistence:** explicit host, generated URL, configuration document, runtime
  projection and audit agree. The base-domain and Origin policies remain unchanged;
  no keys, clients or OIDC enablement are synthesized.
- **Authority:** authenticated normal API creation still uses its generated name
  even after custom-host initialization; custom-host fields cannot grant allocation
  authority. Preserve login, Origin, CSRF and Team/Tenant isolation checks.
- **Atomicity:** use actual PostgreSQL to exercise different-host initialization
  races, replay with changed host, reserved-host conflict and late audit failure.
  Failed initialization leaves no new owner/policy/topology/namespace/audit rows.
- **Identity:** reject existing-host/UUID mutation and configuration issuer mismatch;
  refuse an unregistered startup selector. A second Environment has a separate
  identity and state namespace, regardless of host spelling.
- **Packaged path:** initialize with the actual schema-guarded CLI, provision keys
  and policy using the supported workflow, start the Organizations distribution
  and complete an OIDC/Organization flow. Discovery and issued `iss` use the exact
  custom URL; a restart preserves the Environment and subject namespace. Record
  the actual source revision/tree and executed binary identities.
- **Routing:** wrong/unknown Host or unsupported forwarded-host substitution cannot
  change the issuer or select another Environment; validate using the supported
  packaged HTTP/TLS path, not only a mocked state object.
- **Compatibility:** generated-host initialization, existing runtime selectors,
  strict configuration matching, hosted-bootstrap validation and schema guards
  retain their contracts. No issuer migration or new KMS requirement occurs.

The existing initialization model covers abstract atomicity and separation under
its assumptions. It does not prove Rust/SQL/URL-parser refinement, DNS/TLS control,
provider qualification or complete product assurance. Keep these limits distinct
from the required functional acceptance checks above.

## Executable acceptance coverage

`web::management::issuer_identity::tests` and the initial-configuration/hosted-input
unit tests cover canonicalization and safe defaults. The PostgreSQL initialization
tests exercise the actual restricted database login, router authority, competing
initializers, rollback and the retained namespace of a soft-deleted Environment.
A retired Environment row remains because the namespace foreign key prevents
physical removal; a fixture must not invent an orphaned history row.

The `custom-issuer` case in `tests/organizations/current_runtime.py` uses the actual
schema-guarded initializer and Organizations launcher, a private PostgreSQL TLS
supplier, authenticated management key/policy/client/user/Organization operations,
and an HTTPS browser fixture. It checks real login, consent, PKCE/DPoP code exchange,
independent ID Token signature verification, exact discovery/issuer agreement,
restart identity and unknown startup selector refusal. Runtime-critical mutations
complete their required controlled restart before subsequent configuration.

The frontend fixture checks rejection of unregistered Host names and replacement
of untrusted forwarding authority. This is a deployment-contract test, not proof
of production DNS, certificate custody or third-party ingress configuration.
The Organization portion covers explicit operator capabilities and provisioning;
full invitation delivery, selected-Organization tokens and provider qualification
remain separate acceptance scopes.
