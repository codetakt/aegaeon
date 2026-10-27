# PR four-exception supplement

Last updated: 2026-10-16
Status: draft
Owner: Aegaeon maintainers
Audience: verification maintainers

Status note: private implementation candidate, not formally adopted. The CI hold and
Task 3 pause remain. This is a separate analysis policy; the native numerical
contract and the existing two/three-exception implementation are unchanged.

The supplement expands the pass domain: a narrowly defined old inconclusive
result becomes an eligible non-rejection. It adds no detection sensitivity and
is not evidence of equivalence or of a timing distribution's physical cause.

## Domain and exact rule

The original statistic must be ineligible specifically because of
`degenerate_variance`. A valid existing decision is never replaced. The PR
configuration must match the reviewed settings digest, including 16 measured
batches of 65,536 inputs, the 11 original exclusions per batch, eight fixed
looks, each-class inference floor 10,001, raw floor 200,000, 900 seconds, and
alpha's exact binary64 ratio. A settings change needs a new review even if the
following inequality would still hold.

Reconstruct the complete original population from the current raw prefix using
the original fixed pilot cutoff and sample admission rules. Let n0 and n1 be
its class counts, N their sum, and m their minimum. Exactly four observations
in the pooled histogram must differ from its unique mode. Require:

```
B = (m)_4 / (N)_4 >= alpha
alpha = 5511632216234413 / 9444732965739290427392
```

The falling factorial uses exact integers. The bound follows because the
inclusive permutation tail contains the observed allocation, whose probability
is at least B. Unlike the reviewed three-exception domain, four exceptions do
not have a sufficient uniform bound over the whole PR budget. An unconditional
“up to four” rule is not implemented.

Enumerate the at most 16 multiplicity allocations with their hypergeometric
weights. The statistic is absolute class mean difference; ties belong to the
tail. Save the exact numerator and denominator, histogram, transformed values,
B, alpha, and the policy digest. Compare integers, not display floats. A result
below B is an inconsistency and fails the operation, never a new rejection.

Native ticks must be in the existing safe representation range below 2^53.
Statistic 101 uses the exact rational representation of the original binary64
subtraction and multiplication; a transformed-value collision remains
unsupported. Counts, support endpoints and moments must agree with native
records before a certificate is accepted. At most five distinct native values
per class are materialized for this branch; endpoints alone are not a
histogram certificate.

This conditional exact interpretation assumes uniform label allocation given
the pooled population and class counts. Arithmetic does not establish that
measurement premise. Equality of means alone is insufficient. The supplement
itself preserves the rejection set point by point because it changes only
unsupported tests and cannot reject. The distinct Student interval correction
may change a legacy binary64 threshold decision; that is not this guarantee.

## Integration and evidence

`tests/dudect_analysis/sparse_four.py` defines the separate policy. Analysis
identity schema 3 includes its policy and implementation digests. Prefix proof
schema 2 keeps the original sparse proof intact and adds four-exception
certificates separately. The current prefix is retained only for the active
transaction, including the last look; no future frame or final EOF is needed
before ACK. The shared 10-second/256-MiB worker bound and case deadline apply.

The policy applies to original native populations only. In distributed mode,
HMAC message crops 1–100 are explicitly excluded before reading their original
histograms; their new reserved/test partition is not the old population.
Periodic is outside this analysis contract. Same-look detections, previous
look detections and the positive controls' specified 0/101 requirements remain.

Old raw keeps its old binding and decisions. Cross-version offline reanalysis
creates a separate record. It cannot become a successful new native execution.
The retained HMAC key example is distinct from legacy HMAC key rejection:

```
class 0: 609 x 209465
class 1: 583 x 4, 609 x 209625
p = 160669154419514236441 / 1285370456524178743251
```

Independent index-allocation enumeration, adjacent class-count values across
the exact bound, unsupported settings/representation/collisions, full active
prefix/ACK fixtures and saved failure regression cover the implementation.
Three-, four- and five-exception injected-clock fixtures exercise the actual
HMAC key callback: three retains the old supplement, four uses the new branch,
and five stays inconclusive. These fixtures are not physical timing trials.
