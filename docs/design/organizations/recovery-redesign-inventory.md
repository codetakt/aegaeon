# Organizations recovery state and caller inventory

Last updated: 2026-11-04

Status: future plan

Owner: Engineering

Audience: implementers and reviewers

This is a proposed migration inventory, not implemented backend coverage.

This inventory accompanies [the recovery proposal](recovery-redesign.md).
Source paths are relative to `crates/server/src/` unless another root is shown.
It assigns the configured shared stores, SQL authority families, runtime entry
classes and operator entrypoints to the proposed protocol. Static candidate
searches and this classification are not proof that every dynamic writer has
been fenced. Implementation acceptance must demonstrate the complete binding.

## Superseded recovery proposal

The 2026-11-05 [adopted responsibility rules](recovery-responsibilities.md)
supersede this proposal. Per-operation independent journals, three-phase
confirmation, complete application redo and reproduction of volatile state are
not implementation requirements. Source inventories remain useful references;
the numerical budgets tied to that architecture are withdrawn. See the
[current workplan](recovery-workplan.md) for implementation status.

## Configured shared stores

The enumeration is the twenty `SharedRuntimeStoreRequirement` declarations in
`config/runtime_boundary/shared_store/inventory.rs`. Optional feature triggers
remain explicit; an inactive option is not permanently out of scope. All security
state below moves to primary SQL and the operation journal before Redis can be
made optional for Organizations.

| ID | Existing setting suffix after `AEGAEON_` | Writer and read boundary | Dependency / retained state |
| --- | --- | --- | --- |
| S01 | `PAR_REDIS_URL` | `par/storage/redis_store.rs`; pushed authorization create/consume/cleanup | Environment, issuer, client, request URI, bindings and one-use expiry |
| S02 | `AUTH_CODE_REDIS_URL` | `authcode/code_store/redis_backend.rs`, `authcode/code_store/scripts.rs`; state/nonce/code publication and consumption | Client, redirect, PKCE, sender, consent, original authority, consumed-code history |
| S03 | `TOKEN_STORE_REDIS_URL` | `authcode/store/redis_backend.rs` and `authcode/store/redis_backend/`; mint, root publication, exchange, refresh, revocation and cleanup | Root/family lineage, subject and client registration, selected authority, output bindings and expiry |
| S04 | `DPOP_REDIS_URL` | `middleware/replay_store.rs`, `middleware/dpop.rs`; authenticated proof replay consumption | Existing exact issuer/key/proof namespace and accepted time window; GET is also a mutation |
| S05 | `JWKS_REDIS_URL` | `client_registry/jwks_runtime_state.rs`, `client_registry/jwks_runtime_state/redis_kid.rs`, `client_registry/jwks_runtime_state/redis_circuit.rs` | Key-fingerprint history is authoritative; move enforced fetch limits/coordination to SQL first; cache bodies alone may remain optional |
| S06 | `REQUEST_OBJECT_JTI_REDIS_URL` | `request_object_store/replay.rs`; request-object replay reservation/consume | Issuer/client/key/request-object identity and full accepted replay horizon |
| S07 | `AUTH_SESSION_REDIS_URL` | `web/auth_session/redis_backend/operations.rs`; browser login/consent session creation, update, consume and GC | Browser context, current subject/client, original authorization and credential cutoff |
| S08 | `DEVICE_CODE_REDIS_URL` | `device_authz/redis_backend.rs`, `device_authz/store/operations.rs`; issue, approve, deny, poll, consume and GC | Device/user code, client, current subject, approval, poll timing and terminal consumption |
| S09 | `DEVICE_CSRF_REDIS_URL` | `device_authz/csrf.rs`; challenge creation/one-use consumption | Device/browser/session and expiry; cannot reset to unused |
| S10 | `DEVICE_RATE_LIMIT_REDIS_URL` | `device_authz/rate_limit/redis_backend.rs`; increment/check/cleanup | Verification namespace, rate window and enforced quota; loss must not reset attempts |
| S11 | `LOCAL_AUTH_CSRF_REDIS_URL` | `device_authz/csrf.rs`, `web/local_auth.rs`; local-login CSRF lifecycle | Separate local-auth namespace, browser, session and expiry |
| S12 | `LOCAL_LOGIN_RATE_LIMIT_REDIS_URL` | `device_authz/rate_limit.rs`, `web/local_auth/post.rs`, `web/authorization_transactions.rs`; local-login and distinct `authorization:source` attempt limits | Existing source/account classification and window, trusted proxy/NAT binding; retain each namespace and protocol-visible policy |
| S13 | `STEPUP_REDIS_URL` | `stepup/redis_backend.rs`, `stepup/scripts.rs`; issue and consume step-up | Principal/session, original ceiling, authenticated MFA evidence, freshness and expiry |
| S14 | `MANAGEMENT_SESSION_REDIS_URL` | `web/management/state/session_store.rs`, `web/management/state/redis_sessions/`; create/read/touch/revoke/cleanup | Management identity, Team/topology, current grants, session cutoff and CSRF |
| S15 | `MANAGEMENT_LOGIN_RATE_LIMIT_REDIS_URL` | `web/management/session_support/rate_limit.rs`, `web/management/core/authentication/create/workflow/rate_limit.rs` | Management authentication attempt identity/window; enforced security bound |
| S16 | `UPSTREAM_AUTH_REDIS_URL` | `upstream/auth_store.rs`; upstream state start/callback/cleanup | Exact issuer, state/nonce, browser, PKCE, upstream code attempt and local linking policy |
| S17 | `UPSTREAM_LOGOUT_RELAY_REDIS_URL` | `web/upstream_logout_relay.rs`; relay create/consume/cleanup | Original authenticated logout/session bindings and expiry; no unbound retry |
| S18 | `DPOP_NONCE_REDIS_URL` | `middleware/dpop/nonce/redis_store.rs`; nonce lifecycle when nonce policy is enabled | Proof key/request context, required policy and time window; unavailable is not optional |
| S19 | `CLIENT_ASSERTION_REPLAY_REDIS_URL` | `client_registry/client_assertion_policy/replay.rs`; assertion replay when private-key JWT or JWT bearer is enabled | Exact issuer/subject/client/key and assertion validity; preserve cross-grant namespace semantics |
| S20 | `OIDC_LOGOUT_SESSION_REDIS_URL` | `oidc/session/redis.rs`, `oidc/session/redis/`; session/end-session/logout delivery when OIDC is enabled | Subject/client/session roots, revocation and stable delivery IDs |

The row order does not alter the source enumeration or define new public settings.
Existing Redis setting names are migration inputs. New SQL backend selection must
be validated as a coherent deployment configuration; setting an individual URL
to empty cannot silently select an in-memory implementation.

S03 includes direct and code grants, token revocation by token/family/subject,
exchange-root snapshots and retained refresh state. S05 does not treat a remote
key as authentic merely because Redis contains it. S10/S12/S15 distinguish
enforced authentication limits from optional nonsecurity traffic shaping.
Expiry for every row uses the existing protocol's acceptance window, including
clock skew. Do not derive retention from a generic cache TTL.

## SQL authority families and positive readers

| ID | Source boundary | Writes | Readers and conflict scope |
| --- | --- | --- | --- |
| P01 | `organizations/repository.rs`, `organizations/operators/mutations/` | Domains, organizations, role policy, target/client bindings, member revisions and tombstones | Token selection, introspection, delegated APIs; domain/membership aggregate plus shared client and identity dependencies |
| P02 | `organizations/invitations/`, `organizations/invitation_capabilities.rs` | Invitation issue, recipient proof, first/delegated acceptance, delivery and cancellation | Enrollment/acceptance; exact recipient, domain, invitation, identity, membership and last-admin aggregate |
| P03 | `organizations/identity.rs`, `web/organization_resource/identity/`, `subject_ownership/` | Registration, password recovery, identity cutoff, immutable subject ownership and reservations | Every identity/session/token use; shared subject dependency, never only the selected organization |
| P04 | `organizations/operators.rs`, `organizations/operators/mutations/support_policy/` | Administrative grants, original root/MFA binding, expiry and revocation | Scoped management/temporary support; Team, principal, original root and target policy |
| P05 | `organizations/commands.rs`, `organizations/commands/` | Idempotent command receipts, pending commands and capacity accounting | Receipt replay rechecks current authorization; operation input/principal/scope are inseparable |
| P06 | `organizations/audit.rs`, `organizations/audit/` | Immutable event append, export grants, delivery/ACK, custody and retention | Audit consumer and export; grant revocation, cursor/history, stored digest and stable event IDs |
| P07 | `runtime_configuration/`, `runtime_authority.rs`, `runtime_authority_queries.rs`, `runtime_clients/`, `web/management/` | Tenant/Team/Environment lifecycle, configuration activation, management users/API keys and runtime commands | All current policy reads; topology/client/shared-principal changes can span multiple Environments |
| P08 | `dcr_persistence/`, `client_registry/registry_store.rs`, `upstream/store.rs` | Client registrations/keys/credentials and upstream configuration | Authentication, discovery, token publication and sender binding; registration incarnations cannot be substituted |
| P09 | `application_authorization/`, `attribute_mapping/` | Original consent/application authorization, attribute state and mapping configuration | Token claims and LTI outputs; inherited ownership and current configuration, not cached client fields |
| P10 | `lti/store.rs`, `lti/database/`, `lti/intents.rs` | Launch intents, one-use replay and cleanup | LTI launch, authorization and mapping consumers; issuer/deployment/client/subject/context dependencies |
| P11 | `organizations/snapshot/`, `organizations/witness/history/`, `subject_ownership/history/` | Export custody, inactive import, comparison, permanent-history restoration/adoption | Maintenance-only plan and exact source/destination generation; domain export is not full database DR |
| P12 | `organizations/witness/`, `organizations/store_observation/`, `db/organization-witness/` | Control decisions, epoch/fence, catalog, accepted histories, receipt and recovery state | Every protected caller; independent control custody and new-vs-old schema semantics |
| P13 | `web/authorization_transactions.rs`, `config/authorization_admission.rs`, `web/authorize_endpoint/consent/storage/` | Login/consent/logout continuation snapshots, insertion/retained-capacity accounting and expiry cleanup | Exact Environment/table/source budgets and public protocol continuations; S12 is also a dependency |

Public entrypoints include `web/observed_dispatch.rs`, `web/token_endpoint.rs`,
`web/authorize_endpoint.rs`, `web/token_lifecycle/introspection.rs`,
`web/organization_resource/`, `web/organization_resource/support/`, `web/management/`,
`web/local_auth/`, `web/lti.rs`, and logout/upstream callback paths. Route
classification and authenticated principals establish scope; request payloads do
not override it. Where an existing endpoint delegates to a shared facade, both
the facade and its deferred/cleanup workers must carry the operation context.

## Background and detached work

| ID | Entry | Required treatment |
| --- | --- | --- |
| B01 | `main/background_tasks/cleanup.rs` | Each authoritative expiry/command-reconciliation mutation has an operation ID; finite batches, retention floor and Environment scope |
| B02 | `main/background_tasks/runtime_config.rs` | Monitor reads use current-head validation; client synchronization writes use P07/P08 operations |
| B03 | `main/background_tasks/runtime_config/notifications.rs` | LISTEN is a wakeup hint; reconnect and rescan durable revision, never trust notification delivery as state |
| B04 | `client_registry/jwks_refresh/background.rs` and its children | Retain fetch ownership, S05 history, current policy and finite network limits; no detached allow decision |
| B05 | `organizations/invitations/worker.rs`, `server_runtime.rs` | Stable outbox delivery ID, current grant check, authenticated receiver and ambiguous-ACK handling |
| B06 | `oidc/session/redis/delivery.rs`, `web/upstream_logout_relay.rs` | Same durable delivery/consume identities; preserve remote-outcome uncertainty |
| B07 | `organizations/request_work/async_store.rs`, `redis_io/`, `dcr_persistence/admitted_connection.rs` | Blocking tasks, cancelled BEGIN, rollback/pool return and response bodies retain ownership until terminal receipt or explicit recovery fence |
| B08 | Proposed operation reconciler | Reserved capacity, current primary/control selection, exact receipt/attempt inspection and bounded retries; no age-based pending deletion |
| B09 | `web/browser_authorization_admission.rs` | Separate eight-owner browser semaphore, unfinished-drop closure and spawned response ownership must join the bounded recovery design; changing only the Organizations four-slot limit is insufficient |

The current three observed supervisors are not the entire writer inventory.
Spawned JWKS work, synchronous Redis workers, transaction cleanup and CLI delivery
remain separate dependency edges. Shared instance pointers or matching file bytes
do not establish that those edges carry the new owner.

## Executable and operational entrypoints

The source contains fourteen `src/bin/*.rs` files plus the default `main.rs`.
This supersedes the older thirteen-file count for inventory purposes only.

| Entry | Proposed mode |
| --- | --- |
| `aegaeon-server` | Legacy preactivation path; unavailable as an alternate writer for an activated deployment |
| `aegaeon-organizations-server` | Runtime SQL operation/read protocol for HTTP, startup and background |
| `aegaeon-organization-delivery` | Outbox delivery worker under a registered runtime identity |
| `aegaeon-organization-witness` | Maintenance-only lifecycle/control mutation; diagnostics never authorize activation |
| `aegaeon-organization-epoch-prepare` | Maintenance-only epoch preparation; install and inspect exact primary/control attempt fences |
| `aegaeon-organization-history` | Exclusive history import/reconstruction with immutable source and operation identities |
| `aegaeon-organization-import-inspect` | Bounded inspection of selected inactive stores; no authority mutation |
| `aegaeon-organization-import-prepare` | Bounded inactive import preparation; full authority comparison before activation |
| `aegaeon-organization-store-inspect` | Diagnostics only; observation never upgrades to a serving capability |
| `aegaeon-organization-subject-ownership` | Scoped maintenance adoption preserving permanent identities and tombstones |
| `aegaeon-subject-ownership` | Legacy bootstrap excluded after activation |
| `aegaeon-management-init` | Preactivation-only management provisioning |
| `aegaeon-hosted-bootstrap` | Preactivation-only runtime provisioning |
| `aegaeon-observability-seed` | Preactivation-only configuration/key seed |
| `aegaeon-registration-preflight` | Read-only predecessor inspection, closed before cutover |

Also inventory the packaged Python operators in `scripts/operations/organization_*.py`,
`organization_selected_worker.py`, the shell launchers in `nix/`, Atlas/schema
migration and every `.sql` repair/provisioning script in `scripts/operations/`.
They either execute a registered exclusive maintenance plan or are denied live
credentials against activated stores. A diagnostic label is not an exemption.
The managed adapter replaces systemd/OS/ACL-file assumptions with qualified
provider lifecycle and SQL fencing; it cannot simply skip those checks.

## Implementation closure rule

Every direct SQL connection, transaction, Redis command, store facade, background
spawn and operational entry in the enabled dependency closure must be classified
as a protected read, a recorded mutation, an external effect, or a denied
preactivation/maintenance-only entry. Bind its actual code path to an inventory
row and acceptance case. An unknown ordinary scope refuses enablement; a known
exclusive maintenance path can use the conservative deployment gate. For an
unclassified effect refuse activation. New source entries must fail that
closure check until classified. Test-only or disabled-feature exclusions retain
their exact condition; text searches alone do not establish unreachability.

Migration must preserve the existing exact namespaces, key/subject ownership,
client/root bindings, expiry and error contracts. Shared protocol backends cannot
be migrated only for `/organizations` while `/token`, login, logout or cleanup
still mutates the old authoritative copy. All primary schema tables and trigger
effects must be assigned a reconstruction policy before complete-source-loss
recovery is enabled.
