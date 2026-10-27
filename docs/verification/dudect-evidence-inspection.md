# External Dudect evidence correspondence

Last updated: 2026-10-22

Status: draft

Status note: offline receipt inspection implemented; authentication, commissioning and CI admission remain open.

Owner: Engineering

Audience: CI maintainers, verification reviewers

The limited measurement contract was approved after the final contract review.
That approval does not authenticate a future measurement or bind it to a new
PR or merge-group revision. This component checks the correspondence required
between an execution request, a producer result and an independent replay result.
It is a proposed transport projection, not a replacement numerical contract.

The implementation is [inspect_dudect_evidence.py](../../scripts/ci/inspect_dudect_evidence.py).
It performs no physical execution or raw-frame replay. A successful CLI exit
means only `correspondence_checked`; `ci_admission`, `authentication_performed`,
`raw_replay_performed` and `request_consumed` are always false. Existing PR,
release and periodic migration holds remain in place. No workflow consumes this
command's exit status as qualification success.

## Inputs and ownership

The CLI accepts four JSON files, each limited to 4 MiB, and an explicit UTC epoch
inspection time. Duplicate keys, non-integer numbers and oversized inputs are
rejected. Missing fields or files return a rejected report and nonzero exit.
The fixture in [the tests](../../tests/ci/test_dudect_evidence_inspection.py)
defines a complete synthetic example with all 21 cases and both compilers.
It contains no new timing observations or producer credentials.

| Input | Required binding and meaning |
| --- | --- |
| Inspection context | Expected request ID and state, subject, exact SHA256 of the three documents, producer and verifier IDs, verifier runtime digest, full case-role map and finite round inventory |
| Request | `external-dudect-request/1`, request ID, target repository/event/revision, source tree, artifact manifest, analysis, environment and adopted contract digests; ordered case/compiler/round/role/ELF inventory; issuance, acquisition, recovery and expiry times |
| Producer | `external-dudect-result/1`, request digest, producer ID, identical subject and ordered inventory, fresh ordinary execution, completion/recovery times, recovery and lifecycle digests, per-observation raw/original/effective decision digests |
| Replay | `external-dudect-replay/1`, exact producer/request/recovery bindings, distinct verifier ID and pinned runtime, original observation time retained, and one result per planned observation |

The context's bytes and authority are **not authenticated by this component**.
A production adapter must obtain the expected request and authenticated producer
and verifier document digests from protected state. Supplying a JSON file with
those hashes is not authentication. Different ID strings do not demonstrate
independence; the verifier's code, runtime, credentials and execution must be
separately established. This component deliberately offers no admission mode.

The full expected inventory is the product of the protected 21-case role map,
GCC/Clang and the fixed rounds. No missing, extra, repeated or reordered producer
entry is accepted. Exact request digests include ordering and deadlines, so an
import cannot refresh the original observation or attach it to another request.

Every replay row binds its raw manifest, original and effective decisions and
audit digest. Collection, prefix verification, numeric validity and retention of
original evidence must be complete; eight PR looks and
`observation_contract_satisfied` are required for every planned case. The pinned
replay evaluator, not this transport component, applies count floors, designated
raw0/101 obligations, characterization and the seven-case crop replacement.
Retaining original decisions is not an OR gate for original and replacement crops.
An unresolved or failed role cannot be substituted with a producer's success flag.

## Required connection before admission

The next adapter must fix the following as one reviewable execution boundary:

1. Obtain the exact event target, protected policy and unique request from trusted
   CI state; do not execute a PR-provided admission verifier with privileged access.
2. Authenticate producer and independent replay outputs, including full recovery
   and lifecycle evidence, before creating the inspection context. Pin the measured
   artifacts and analysis runtime; source correspondence does not transfer physical
   qualification to a rebuilt ELF.
3. Project actual ordinary execution and replay records into this format without
   inventing missing fields. Test this on retained evidence, preserving its original
   request and observation time. That import is not a fresh CI execution.
4. Atomically consume an open, unexpired request and publish a result for its exact
   target after validation. A stale `open` flag is not concurrency control. Retries
   must not allocate replacement statistical opportunities.
5. Keep performance, managed-provider and other qualification obligations distinct.
   Dudect approval cannot clear their migration holds or establish operating rates.

The authentication mechanism and protected producer deployment are not selected
by this implementation. Before connecting the Required checks result, review
those concrete bindings, the retained-evidence projection, replay/nonce race and
cancel/failure tests. The approved limited measurement contract does not need
another review merely because this separate adapter is being implemented.

## Validation scope

Tests exercise a full synthetic 42-case inventory and reject changed bytes,
request/revision mixing, missing or duplicated results, compiler/ELF/order/role
substitution, imported observations, expired or consumed requests, late recovery,
wrong verifier/runtime, incomplete prefixes, numeric uncertainty and failed roles.
Rebound private fixtures reach checks beyond the outer digest boundary. The CLI
is tested for both correspondence-only success and a missing-file rejection.

These are transport checks. They do not repeat the existing numerical/functional
qualification, verify a real signature or recover physical data. Public historical
qualification/adoption receipts are not fresh producer attestations for this path.
