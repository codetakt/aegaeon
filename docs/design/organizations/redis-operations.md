# Bounded Redis operations

Last updated: 2026-10-30

Status: active plan

Owner: Engineering

Audience: implementers and operators

## Contract and scope

This prerequisite implements the store lifetime portion of ORG-G03/G11 and
ORG-P08/P12/P13. It does not discharge those composite obligations. The token,
authorization-code, replay and DPoP nonce backends retain their synchronous
interfaces, exact commands, atomic Lua scripts, namespaces and persisted IDs.
Each connection uses an owned thread and asynchronous Redis driver. A process
admits at most 32 such owners, with immediate failure when capacity is exhausted.
Connection preparation (DNS, TCP, TLS, authentication and database selection)
has a five-second response deadline; each command also has five seconds. The
entire connection, including idle time, has a thirty-second lifetime. These are
internal upper bounds, not a promise that every operation receives that budget.

The owner retains its permit until its runtime and transport have been dropped.
A caller timeout or disconnect cannot return this permit. DNS uses the existing
platform resolver; an uncancellable resolver may outlive the response deadline,
but its owner and capacity remain reserved until actual completion. Exhaustion
fails closed; there is no replacement worker, retry queue or permit reset. This
does not establish bounded resolver termination or host failure recovery.

The original Redis client supplies TLS hostname verification and credentials.
No IP substitution, plaintext fallback, automatic reconnect or retry after an
uncertain command outcome is introduced. A timeout poisons the connection. An
explicit Redis NOSCRIPT response may still trigger the library's existing
SCRIPT LOAD/EVALSHA sequence: that response establishes that the script was not
executed. Connection initialization retains redis-rs compatibility negotiation.
Peer response allocation remains governed by the pinned Redis decoder; this
change is not a proof of an adversarial peer memory bound.

## Synchronous compatibility

Single commands are passed to the asynchronous driver unchanged. Encoded
pipelines are decoded only from locally generated requests, reconstructed and
required to match byte for byte before any I/O. MULTI/EXEC framing, offsets,
counts, ignored results and error responses must retain their original meaning.
Arbitrary binary arguments are preserved. This adapter is not a Redis server,
cluster router, pubsub client or replacement wire-protocol parser.

Async HTTP consumers must isolate synchronous proof/store work from executor
threads and retain their request admission through that actual work. The
Organizations route requires this isolation before public activation. Tests
must cover a stalled handshake, a stalled command after receipt, no duplicate
mutation, capacity exhaustion/recovery, ordinary transactions and scripts, and
actual DPoP/token-store HTTP failure without executor starvation. An owned fake
peer complements real Redis regressions; neither alone establishes shipment.

## HTTP proof workers

Token, PAR, generic resource, userinfo and upstream-link DPoP verification use
an immediate process-wide limit of16 blocking proof workers. Malformed headers
and requests without proofs retain their existing cheap checks and error order.
The worker owns admission through signature/nonce/replay verification even if
its caller disappears. Capacity exhaustion and worker failure return the
existing DPoP backend-unavailable response. The dedicated Organizations resource
retains its separate four-request admission through the same blocking work.
These are local concurrency limits; they do not authorize requests, configure
Organizations, or establish a distributed request-rate limit. Client assertion
and other replay consumers require separate caller-path review.

## Browser authorization stores

Before browser authorization is enabled for Organizations, the authentication
session, step-up, PAR, OIDC session, upstream authentication and shared JWKS
backends use the same bounded connection owners. Their existing IDs, Redis
namespaces, record versions, TTLs and Lua atomicity remain unchanged. The
connection adapter does not make an inline synchronous caller asynchronous;
each actual HTTP path must also be checked for executor isolation and admission.

PAR's final Request Object replay check and request persistence execute on one
owned blocking worker, with immediate admission of at most eight workers and
a thirty-second response deadline. The worker keeps its permit through actual
completion after caller cancellation or timeout. Admission failure returns
no-cache HTTP 503; it cannot skip replay or persistence. DPoP verification
precedes this admission, so retries require a fresh DPoP proof. A caller timeout
does not prove that the one-use replay claim or PAR record was never written;
the existing short expiry bounds an unreachable record. No uncertain write is
automatically replayed. This is a component limit, not a whole browser-flow or
platform resolver termination guarantee.
