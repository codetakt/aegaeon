# Organizations Arithmetic Verification Boundary

Last updated: 2026-10-30

Status: active plan

Owner: Engineering / Verification

Audience: implementers, proof reviewers, release reviewers

## Claims and production correspondence

This component contributes to ORG-R05, ORG-R06, ORG-R08 and ORG-R21, gaps ORG-G05,
ORG-G06, ORG-G11 and ORG-G12, and composite work units ORG-P04 and ORG-P12.
It does not discharge either composite work unit or increase the accepted atomic
obligation count. The original 24 requirements, 14 gaps and 15 composite work
units retain their separate implementation and assurance states.

The unconditional production implementations are in
`crates/pure/src/organization_bounds.rs`. Native organization and membership
transitions call `next_revision`; native access issuance calls `selected_expiry`.
The Kani harness imports these exact functions through the same pure crate,
without a separate table model, replacement arithmetic or a Kani-only production
branch. The extraction preserves the preceding native return/error behavior.

Target registration also calls the same nonterminal increment through
`model::increment`. It first locks current configure authority, validates the
positive stored revision and exact expected revision, and places the increment
in the target/event/outbox/receipt transaction. Its PostgreSQL regression checks
refusal at `i64::MAX - 1` before the count limit is reached. This connects the
arithmetic reserve to a concrete caller; it does not prove the SQL transaction,
operator authentication or all reachable histories.

The target-stage comparison retains the earlier three accepted Kani component
results. Thirty-nine of forty recorded repository inputs match, including the
production arithmetic, harness and Rust dependency inputs; the compliance
matrix differs after prerequisite integration. This is scoped reuse of unchanged
arithmetic code, not a fresh run on the current whole source or a new composite
discharge. The earlier solver receipt and both rejected mutations remain at
their original source identities.

## Propositions and domains

The `organization-arithmetic` group in `spec/kani-evidence.json` registers:

- Exact counter behavior for every signed 64-bit input and terminal flag,
  compared with an independent signed 128-bit successor/range oracle.
- Every successful nonterminal increment leaves capacity for a subsequent
  terminal increment. The final positive revision is reserved for terminal use;
  its successor is refused, with no wrap or saturation that reuses a revision.
- Exact selected-token expiry for every signed 64-bit ceiling, parent and current
  second value, compared with an independent signed 128-bit horizon oracle.
  Success is strictly after a nonnegative current time and at most the parent,
  original ceiling and 300-second horizon. Overflow and nonlive inputs refuse.

These loop-free integer propositions do not restrict inputs to sampled values
or impose an arbitrary history-length bound. A one-step capacity proposition
does not itself prove the calling state machine's reachable-state invariant.

## Retained role-policy fold

The role-policy representation folds every validated retained role version from
an initial revision of 1 using production `add_role_version`. The added harness
checks all signed 64-bit argument pairs against independent signed 128-bit
addition: invalid nonpositive inputs and exhausted sums refuse; success is exact,
strictly increases the accumulator and leaves one terminal successor available.
This is a component proposition, not proof that the input contains exactly the
current complete catalog. The actual catalog reader, retention checks, definition
comparison, version increment, domain lock and atomic receipt require separate
correspondence. HTTP regressions exercise competing compare-and-set updates,
retained replay, the configuration quota, reserved disable and stored exhaustion.
Earlier three-harness receipts remain historical; a new four-harness receipt is
required for this source. Neither receipt discharges a composite work unit.

## Preconditions still to establish

Transitions validate objects, compare the requested revision, authorize the
transition and update revision/state together. The repository must bind those
calls to the authenticated caller and current locked rows. Imports and recovery
must preserve reserved revisions and immutable ownership. Security suspension,
last-administrator policy, SQL constraints, concurrency and replay require their
own correspondence arguments and tests.

Issuance must obtain the original ceiling, parent expiry and current time from
the required trusted suppliers. Capturing the ceiling, validating root liveness,
DPoP and target bindings, serializing the result and rechecking after publication
are outside these arithmetic functions. The helper theorem cannot supply any
of those missing producer or caller premises.

## Evidence admission

Run the registered group with the pinned Kani toolchain and retain its exact
source, compiler, solver, requests, properties, failures and receipt. A partial
group run is not the full Kani CI gate or product assurance. Separately execute
native access/transition regressions on the compiled server and bind its source
and artifact. A mutation removing the terminal reserve or an expiry bound must
fail the corresponding proof. Tool success, implementation correspondence,
supplier qualification and final composite acceptance are distinct results.

## Administrative-access deadline component

Activation calls production `administrative_expiry`. Its two additional Kani
harnesses cover all signed 64-bit arguments: the exact root/parent/original MFA
minimum and refusal conditions, and equality of successful expiry values at
different activation times under unchanged original inputs. Independent i128
arithmetic supplies the range oracle. These are registered component obligations;
execution evidence must name the actual source and solver outcome. They do not
prove MFA provider semantics, current SQL/root authority, DPoP, audit durability,
or the composite ORG-P09 obligation. The 15 composite units are unchanged.
