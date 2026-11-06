# Organizations Invitation Capabilities

Last updated: 2026-10-30

Status: active plan

Owner: Engineering / Verification

Audience: implementers, security reviewers, operators

## Component boundary

This component refines ORG-R13/R14/R15/R16/R20/R21, ORG-G04/G09/G11/G13
and ORG-P02/P05/P06/P07/P12/P13/P14. It defines the secret and lifetime
primitives before their storage and HTTP consumers. It does not authenticate a
recipient, prove address control, consume an invitation or activate membership.
Those operations must be implemented and tested before the feature is shipped.

Invitation and recipient-challenge object IDs are ordinary UUIDs. Secret
capabilities are a separate namespace, containing 32 random bytes encoded as
43 canonical unpadded base64url characters. They have no object-type prefix.
Reject whitespace, padding, alternate encodings, wrong lengths and malformed
input. A capability's representation is never parsed as an object identifier.

## Generation and retained hashes

Use the existing cryptographic OS random supplier through `ring::rand::SystemRandom`.
Generation failure refuses issuance; it never substitutes a predictable value.
The secret wrapper has no `Debug`, `Display` or serialization implementation.
Only an explicit transfer into the delivery boundary exposes its string.
This limits accidental representation; it is not a memory-zeroization guarantee.

Persist only SHA-256 of a domain-separated byte sequence binding the purpose,
Environment UUID, domain UUID, object UUID, positive delivery revision and the
32 secret bytes. The invitation link and fresh recipient challenge use different
purposes. A retained hash from another object, scope, revision or purpose cannot
validate a presented capability in this context. Compare equal-length digests
using the existing constant-time equality implementation.

Delivery attempts must mint a new capability and advance the retained delivery
revision in the same transaction as the protected outbox claim. Commit before
transferring the secret to the configured transport. Never persist the secret
in an outbox payload, receipt, audit event or export. A lost delivery result may
require another attempt with a new hash; an older capability then refuses.
Transport acknowledgment does not grant membership or prove recipient control.

## Time contract

An invitation defaults to 86,400 seconds and supports explicitly requested
lifetimes from 60 through 86,400 seconds. The separate fresh recipient challenge
has a maximum lifetime of 300 seconds. Calculate deadlines with checked integer
arithmetic from the authoritative issuance time. Refuse negative issuance time,
overflow, expired intervals and a current time earlier than issuance. The expiry
boundary is exclusive. Stored intervals must also satisfy their purpose-specific
duration bounds. A resend never extends the original invitation deadline.

These time checks do not qualify the clock supplier or replace current state
checks. Acceptance must recheck the active principal, intended recipient proof,
inviter authority, exact role ceiling and versions, organization state and
retained invitation state in the same transaction. A valid hash is not that
authority. The existing DPoP and original-grant rules continue to govern every
Organizations OAuth credential and delegated issuer.

## Remaining integration contract

Before wiring a consumer, separately specify its authenticated HTTP/API inputs,
fresh recipient-proof producer, delivery configuration and finite queue/retry
budgets. Issuance, resend, cancellation and acceptance must use scoped receipts
and commit state, audit and outbox atomically. GET never accepts. Concurrent POSTs
have one effect. First-administrator acceptance and organization activation are
atomic; existing suspended or removed identities/memberships cannot be revived.
Unregistered recipients complete the independently enabled registration or
recovery policy first, with no email-based automatic account linking.

The component tests establish strict encoding and binding behavior only. Runtime
integration, store faults, concurrency, normal delivery, replay, restoration,
formal composition and artifact correspondence remain separate obligations.

The registered `organization-invitation-lifetimes` Kani group calls the actual
unconditional functions in `crates/pure/src/organization_invitations.rs`. Its
three obligations compare all signed 64-bit inputs with independent signed
128-bit arithmetic and interval predicates. Cryptographic generation, hashes,
recipient authentication and acceptance are outside these propositions. A
successful component receipt does not discharge a composite work unit.
