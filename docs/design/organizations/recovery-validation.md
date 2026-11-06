# Organizations recovery validation and handoff

Last updated: 2026-11-05

Status: current implementation baseline

Owner: Engineering / Verification

Audience: implementers, reviewers and operators

## Local completion

REC-T01–12 are complete within the authorized implementation scope. The adopted
responsibility and external-proof policies are implemented; no human policy answer
is pending. The record below describes the prepublication local checkpoint.
The two commits were subsequently signed, published as `df595702e` and reviewed.
Published CI then exposed defects tracked in [candidate CI repair](ci-repair.md).
PR #295 remains Draft; local completion did not establish complete CI health.
No AWS deployment, production activation, queue admission or merge was performed.

The implementation is the first local commit, tree
`cef244777aebc153a760bab63162e25b29bc44c8`. The second commit records final status
and this handoff; it does not change runtime code or add a migration. Original
20-commit development history and dirty inputs were preserved privately before
reconstruction. The temporary signing exception applies only locally: every
introduced commit must be re-signed with the designated key and its tree checked
before publication.

## Final affected checks

| Boundary | Result and artifact / record |
| --- | --- |
| Published DB upgrade | `flqcd0xixbn0k9hwwjas4ab630a0q8a8-aegaeon-organizations-catalog-upgrade`: unchanged 24-file baseline to one new migration, preserved data/ledger, fresh/schema/dump equivalence, late failure rollback and same-source retry; 13 corruption cases and predecessor checker refused |
| Lifecycle and external proofs | `swz37g2mkxm0hi6q6lvhvg5zjmzldsb2-aegaeon-database-tests-0.0.0`: nine real PostgreSQL lifecycle tests and one HTTP test covering seven affected authentication routes pass |
| Actual distribution | `s6fwcv6aryyhfxmviixgiprnadgdpxai-aegaeon-organizations-production-runtime`: enabled/disabled startup, configuration refusal, signal drain, same-generation restart and live activation refusal pass; enabled case checks active-worker/wrong-generation maintenance refusal and offline inventory success |
| Runtime suppliers | Distribution fixture uses owned TLS PostgreSQL with no Redis or control supplier; all owned test suppliers stopped |
| Resource regressions | Five browser SQL checks, six OIDC SQL checks, two aggregate response-budget tests, finite/lazy/disconnect/trailer HTTP cases and actual reserved-pool behavior pass in their recorded increments |
| Rust and source | Final server development Clippy `93kp4bq88dvfv44jc05zdvqz2f1i2hw0`; ten process-local source guards; final native artifact matches 3,021 declared crate/database/native inputs and executable modes |
| Repository admission checks | Full-PR hooks pass, including formatting, documentation structure, Python/Nix/shell/workflow checks; strict verified-requirement reference validation passes |
| Historical fixture isolation | `n3s0lw9km0dnll9vcdbl53m6gh376syw-aegaeon-organization-maintenance-control-tests` passes after relocation; this is predecessor test maintenance, not current runtime acceptance |

The final SQL policy waits even when no predecessor or Environment exists. Its
regression checks both an empty restored database and the explicit first-ever
installation assertion, including rejection with a populated Environment, an
existing generation or a malformed policy. Signed HTTP assertions/JAR receive a
temporary no-cache 503 during the barrier. Native signed DPoP checks exercise the
fresh generation/role nonce and durable single-use decision.

The distribution is `c014llr978fj40fsm5wh85xwir8hgzr9-aegaeon-server-distribution`.
Its release compilation inputs match the final implementation except the later
`cfg(test)` empty-restore regression, which is checked in the final native artifact.
No runtime behavior changed after the distribution check. Earlier resource and
protocol increments retain their own artifact bindings; this is not a new full
suite or a sum of overlapping test inventories.

## Formal-model boundary

The selected-state Tamarin model has five admitted lemmas. The separate external
proof model has seven, including reachable fresh use and omitted-nonce/wait attack
controls. Neither is a cryptographic or Rust/SQL refinement proof. The horizon
transition requires the stated operational clock bound and old-writer exclusion.

Kani accepts the current production pool-partition arithmetic harness. The three
retained preflight harnesses also pass but now describe predecessor test-only
code. Their partial runner result is not the full Kani gate. F-star models and
provider/tool pins were not changed; review identified the SQL consumption,
post-lock expiry, generation relation and composition work still required.

The frozen 8,805-obligation baseline is unchanged. New product/composite discharge
is zero. Reference validation and model registration do not establish new proof
fulfillment. See [the security model and handoffs](recovery-security.md).

## Retained failures and limits

Private command/result records preserve unsuccessful fixture/tooling attempts,
zero-test filters, the initial rejected Tamarin formula and subsequent repairs.
The final empty-restore fixture initially lacked the actual schema/table owner;
that fixture was corrected without expanding runtime privileges. Earlier SQL
backend, catalog, transport, packaging and lint failures remain in their increment
records. They are not erased, averaged away or counted as passing checks.

The scoped record names are `final-acceptance-record.json`,
`final-native-source-binding.json`, `final-release-source-binding.json`,
`replay-integration-canonical-final.json`, `final-full-pr-hooks-v1.log` and
`pending-local-resigning.json`. They remain in the existing private recovery-work
evidence directory; supplier credentials and private custody inputs are not
published with this document.

## Task 1b and Task 3 transfer

[REC-H01–05](recovery-security.md#handoff-contract) define the closure conditions:
Task 1b receives exact protocol-clause mapping and standards qualification;
Task 3 receives full model/source/artifact refinement, composition, provider and
audit-custody/PITR qualification, independent security acceptance and high precision
testing. They receive the selected-state semantics, source tree, scoped passing
and failing records, clock/old-writer/DB premises and explicit claim limits.
Known functional/security defects are not transferred as completed implementation.

The target remains 10,000 HTTP requests/second and ordinary API p99 at most 200 ms.
No performance measurement was requested or performed in this round. Pool/payload
and bulk bounds do not establish throughput, total RSS, provider failover behavior
or latency. Unrelated paused proof and timing campaigns remain paused.
