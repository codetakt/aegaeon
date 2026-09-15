# Application authorization revision bounds

Last updated: 2026-09-15

Status: current implementation baseline

Owner: Verification

Audience: verification reviewers, maintainers

The management projection update reserves a final revision for disabling an
authorization. An enabled update cannot use either counter's final usable
value. The arithmetic must also reject overflow, negative revisions and
reactivation of an exhausted tombstone.

`Authorization.ProjectionRevision` states the integer transition and proves
that every accepted enable leaves room for a disable with a strictly newer
source revision. It also proves exact increment, the terminal boundary and a
reachable final disable. Four expected-rejection cases exercise the reserved
revision, reserved source revision, negative base and overflow boundaries.

The `application-authorization-revision` Kani group calls the production
`next_projection_revision` helper for every pair of `i64` counters and both
values of `enabled`, without restricting those inputs. It compares the result
with an `i128` arithmetic domain and checks the subsequent disable by calling
the same helper. Metadata fields are empty because this helper does not read
them. There is no claim about accepted HTTP request metadata.

The model is `simplified`. The result covers only this arithmetic boundary;
it does not prove subject/client identity binding, source authority, database
CAS, row locking, audit persistence, revocation propagation, or the complete
management transaction. A reserved numeric revision does not itself guarantee
that an external authority will supply a newer source revision. No compliance
or premise status is promoted.

```sh
env -u PYTHONPATH nix develop .#verification -c python3 \
  scripts/validation/run_kani_evidence.py --scope partial \
  --groups application-authorization-revision \
  --output artifacts/application-authorization-revision-evidence
```

The full `verify-kani` and `verify-fstar` lanes include the registered harness
and model. `TestAuthorizationProjectionRevision` is a separate required control
gate without detailed-error expansion, with retained log and source hashes. It
is not an admitted proof pass or an SMT counterexample proof. A partial Kani run
remains a partial result.
