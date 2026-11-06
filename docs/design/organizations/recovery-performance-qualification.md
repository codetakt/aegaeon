# Organizations performance qualification plan

Last updated: 2026-11-05

Status: future plan

Owner: Performance / Engineering / Verification

Audience: implementers and reviewers

The target is 10,000 scheduled HTTP requests/second and ordinary-API p99 at most
200 ms. This document contains no measured performance result. It replaces the
withdrawn independent-journal recovery workload and numerical RPO/RTO proposal.

## Current PR

Use directly affected local functional checks to establish bounded admission,
explicit overload refusal, current-database authority, atomic consumption,
concurrent idempotency, cancellation ownership and cleanup. Test exhausted pools,
read-only/unavailable SQL, old-generation reconnect, current authorization changes,
slow response consumers and cleanup backlog. Check both positive success and
negative outcomes. Do not count a skipped/zero-test filter as evidence.

Review the resource issues listed in the [runtime design](recovery-performance.md),
especially aggregate response memory, transport ownership, reserved revocation
capacity and bulk operations. Known functional or unbounded-resource defects stay
in this PR; moving rigorous proofs to Task 1b/Task 3 does not defer those defects.

## Later qualification

Before execution, fix the deployment topology, replica and database resources,
connection limits, protocol mix, dataset size/skew, issuer/key distribution, cache
conditions, signer and transport settings. Specify duration, statistical method,
arrival schedule, failure budget, cost bound and teardown procedure. Qualification
requires separately authorized infrastructure; this plan does not launch a cloud
campaign or change CI.

Measure at least these distinct conditions:

- Positive ordinary API load with 10,000 scheduled arrivals/s; report full latency
  distribution, successful goodput, failures, refused/late arrivals and saturation.
- Same total load with hot membership/creation selectors and realistic key skew.
- Authentication and revocation with concurrent ordinary traffic, including
  password KDF and external upstream latency as separately reported profiles.
- Warm and empty disposable caches; conditional JWKS refresh, unavailable upstream
  and current durable key-policy changes.
- Pool exhaustion, client cancellation, slow response consumption and overload
  recovery, recording actual memory and retained tasks/connections.
- Supported PostgreSQL failover/replacement with source/version/topology evidence;
  old-generation refusal and reachable fresh login after controlled activation.

A load result must bind the exact binary, configuration, data/model assumptions,
request inventory and raw unsuccessful outcomes. Do not merge local, hosted and
managed-provider observations into one sample. Report end-to-end queueing and
complete-body latency; actual-send-only latency is supplementary. Attribute CPU,
RSS, SQL statements/commits, lock wait, connection occupancy, network bytes and
cleanup accumulation separately. Report confidence and precision before making
a throughput/latency claim.

## Handoff boundaries

Task 1b retains precise protocol requirements and any unresolved conformance
mapping. Task 3 retains rigorous model/source/artifact refinement, whole-product
composition and high-precision/provider/load qualification. The PR's diagnostic
models and local concurrent tests are functional evidence only; new product proof
discharge remains zero. The restored external-proof acceptance policy is tracked
in [runtime generation](runtime-generation.md) and is adopted. Qualification must include that policy's temporary refusal
window and subsequent fresh authentication.
