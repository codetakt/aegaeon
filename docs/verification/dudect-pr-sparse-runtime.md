# Private PR sparse runtime candidate

Last updated: 2026-10-16
Status: draft
Owner: Aegaeon maintainers
Audience: verification maintainers
Status note: Implemented for evaluation; not formally adopted.

This change implements the reviewed two/three-exception supplement in the normal
collector and package validator. It expands which previously inconclusive PR
records can satisfy the monitoring gate. It adds no rejection or detection power
in this domain, and is not formal contract adoption or a CI restart.

The immutable base contract is `case-contract-base-v5.json`. The candidate case
contract and numerical implementation receive new SHA256 identities. Structural
JSON schema 5 and AEGTIM05 framing remain unchanged. Old native bindings cannot
admit the new gate. Old records are reanalysed separately using their original
consumer and never become fresh native success evidence.

Each PR look verifies its original raw prefix before ACK. A separate process
checks the native header, ordered case/frame inventory, fixed-class/control
inputs, all prepared class counts, independently reconstructed pilot, all 102
retained counts and the complete native histograms used by supplements. It never
waits for a later frame or EOF at a look. Exact binary64 transformations, support
and moments are checked before the existing exact kernel runs. Only original
`degenerate_variance` tests with two or three pooled exceptions are supplemented.
Existing eligible tests and all current/past detections remain unchanged. The
original and effective decisions, inclusive-tail rational p, rational alpha,
non-rejection lower bound and transformed values are recorded separately.

The worker has a 256 MiB address-space ceiling and a parent-enforced 10 second
per-look limit, capped by the remaining 900 second case budget. Evidence is
flushed and time rechecked before every ACK, including the last look. A completed
case alone starts the next case budget. Missing evidence, altered evidence,
worker failure, storage failure and resource/deadline exhaustion fail collection;
none become a successful fallback. Final raw framing and diagnostics verification
are included in the final case deadline. Worker startup is included in the first
case budget. The worker inherits the collector CPU placement.

`sparse-prefixes.jsonl` contains prefix lengths and hashes, row hashes, native
bindings, separate histories and resource receipts. The report validator independently
replays every proof from raw evidence and compares both decision files. Derived
effective summaries are not admission authority without this replay. Periodic
uses its original inference rules and has no new sparse runtime branch.

The inference premise is conditional uniform label allocation. Exact arithmetic
does not establish exchangeability of physical measurements, equal execution
distributions, or cryptographic constant time. The same positive-control roles,
21 cases, 102 statistics, eight looks, alpha, floors and timer remain. Four
exceptions, prepass, trimming and retries are not part of this implementation.

The extra collector work changes ACK wait time. Native injected-clock fixtures
are functional evidence only. Fresh verification must use these actual integrated
packages/collector before any physical or operational acceptance.
