# Dudect CI evidence admission

Last updated: 2026-10-23

Status: draft

Status note: implementation and functional validation of the external admission boundary; production identities and dispatch are not commissioned by this document.

Owner: Engineering

Audience: CI maintainers, verification reviewers

## Scope and execution order

The current work closes Dudect qualification and connects its result to ordinary
CI. It does not require completion of Auth0, performance or full product assurance.
The owner confirmed this sequencing: Dudect qualification and ordinary CI first,
reviewed PR integration and functional completeness next, full assurance later.
Existing unrelated functional checks remain required. Task3 remains paused.

The limited measurement contract and its review remain closed. Historical
observations retain their original identities and dates. A successful import or
functional CI run does not turn those observations into a fresh measurement of a
rebuilt ELF or a new revision.

## Admission boundary

The protected controller owns a durable request ledger, immutable request bytes,
the expected repository/event/revision and complete case/compiler inventory. It
registers each request once before execution. PR-supplied code cannot write the
ledger or supply its authentication policy. A successful measurement is insufficient
without the separately authenticated replay and complete lifecycle/recovery record.

Producer and verifier sign distinct, domain-separated statements over the exact
document bytes. The initial adapter uses detached OpenPGP signatures, a pinned
`gpgv` executable, an explicit pinned public keyring and distinct authorized primary
fingerprints. No default keyring, downloaded key or replacement production identity
is accepted. Key ownership and separate verifier execution are commissioning
conditions; two signatures alone do not prove independent operation.

The controller authenticates both documents before applying the existing receipt
correspondence checks. It then rechecks cancellation, expiry, policy identity and
the exact target while holding a bounded transaction. Successful validation consumes
the request once and stores the result in the same transaction. A durable outbox
allows publication to resume after a crash without a new statistical opportunity.
Invalid packets do not consume an open request. Cancellation and admission are
serialized; a cancelled request cannot subsequently succeed. Cancellation after
admission prevents unpublished delivery and requires withdrawing an already
published result through the owning GitHub adapter.

The ledger directory is local, controller-owned, mode 0700. It is not a shared
untrusted filesystem or an authorization substitute. The HTTP/GitHub controller
must authenticate requests, derive event targets from trusted CI state and enforce
current target/expiry again when publishing. No public CLI here grants arbitrary
callers those privileges.

## Retained evidence projection

The existing ordinary replay report supplies raw-prefix verification, the exact
native/analysis identities, original and effective result bindings, and preserved
detection differences. Projection verifies the expected report digest, internal
receipt digest, case order and every expected identity. It produces an explicitly
historical projection for retained observations, not a fresh producer attestation.
Historical evidence without a pre-existing CI request stays outside fresh admission.

## Verification and activation

Functional verification covers real detached-signature verification, byte and role
substitution, expiry, cancellation, concurrent consumers, restart/outbox handling,
policy changes, wrong targets and retained-evidence projection. Test-only keys are
not production trust anchors. No physical timing is required for these tests.

Before activation, bind the actual producer/verifier credentials, protected runtime,
request issuer and GitHub publication owner. Verify the concrete lifecycle path and
failure recovery. Missing configuration remains an explicit admission failure.
Ordinary functional CI can run while activation is pending; its success is reported
as functional success, not external measurement success. Release/periodic and other
qualification responsibilities are separate from this Dudect PR boundary.

The signature interface follows the [GnuPG status format](https://github.com/gpg/gnupg/blob/master/doc/DETAILS)
and [gpgv's explicit keyring interface](https://gnupg.org/documentation/manuals/gnupg-devel/gpgv.html).
