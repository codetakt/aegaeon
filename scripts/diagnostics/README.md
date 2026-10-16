# Dudect input-preparation comparison

This research workflow tests whether a class-dependent preparation write contributes
to `ct_eq_128` timing differences. The suffix denotes the input stride; the measured
callback compares the first 32 bytes 1,000 times. Production sources and admission
contracts are unchanged. The previous reliability campaign remains stopped.

## Fixed interventions

Each compiler receives one fresh hosted allocation. The original pinned Nix native
package supplies O and the original controls. A generated overlay supplies S/P/U
from one ELF, selected before input generation:

| Arm | Extra preparation after original input generation |
| --- | --- |
| O | Original saved package, unchanged |
| S | Allocate the diagnostic arena; no copy or extra slot writes |
| P | Copy accepted slots, zero class-0 slots, restore every slot |
| U | Copy accepted slots, zero every slot, restore every slot |

Only `ct_eq_128` receives the intervention. P/U use identical source/destination
layouts and full-slot restore order. A compiler barrier preserves the zero writes;
it does not serialize the CPU. Fresh kernel RNG calls, final bytes, labels, measured
callback, timer, counts, original 16 batches / 8 looks, and alpha remain unchanged.
S includes arena allocation and a rebuild, so O/S is an explicit bridge. P/U still
contain different conditional writes; the experiment does not identify a particular
cache or microarchitectural cause. No prepass or callback warm-up is added.

All seven provider cases run in original order, including later cases. State carried
from ct128 into them is retained, not assumed absent. Each process has new inputs;
these are not paired identical corpora. ct128 slots and original timestamp/context
records are retained. Unknown mode, changed source/binary, missing receipt, incomplete
collection or deadline failure stops the allocation; statistical failures are saved
and the fixed schedule continues.

## Fixed schedule and limits

| Compiler | Process order |
| --- | --- |
| GCC | Nix controls, O, S, P, U, legacy controls, signal0, signal16 |
| Clang | Nix controls, U, P, S, O, legacy controls, signal16, signal0 |

Each allocation has 8 processes / 40 cases; total 16 / 80. Controls retain all three
original roles and specified statistics 0/101. Sensitivity uses a separate ELF and
explicit original ct32/64/128 prefix. It wraps the actual callback with a fixed
16 dependent integer additions for a nonzero first operand byte, outside preparation.
Both doses use the same ELF and uniform preparation. The diagnostic positive requires
ct128 raw statistic 0 detection; dose 0 retains the negative-control requirement.
This checks one fixed signal, not a minimum detectable leak or universal power.
No dose adjustment or replacement measurement is permitted after results.

Original per-case deadline is 900 seconds; additional whole-process cap is 2,100
seconds and acquisition cap 9,000 seconds per allocation. Process gaps are 10 seconds.
Allocation setup is capped at 60 minutes; whole job at 240 minutes including retention.
The collector catches deadlines/cancellation and terminates its native process group.
Builds finish before acquisition; collector and native use different exposed physical
cores. SMT, guest/host interference and events remain observed limitations. A non-AMD
allocation is retained as configuration failure without replacement. Two allocations
are not evidence of two independent physical hosts or a CI failure rate.

## Interpretation and verification

The primary target is ct128. Retain all original per-look decisions, effective sparse
supplements, role results, context, input and artifact bindings. Common-boundary
class-0 minus class-1 mean differences are descriptive direct contrasts. Use the
historical ct128 cutoffs 4,654 (GCC) and 2,990 (Clang), selected from the
previous failed hosted slot, plus local exploratory coordinates 6,820 and 6,928;
these coordinates are fixed before examining new hosted results; arm-specific cutoffs remain the original gate coordinates. Do not infer an
intervention effect merely from a significant/non-significant pair.

If O/S do not reproduce a detection, this campaign supplies bridge/functional evidence
but no historical repair contrast. If P detects and U does not, assess the direct
contrast and retained signal/control results; this supports preparation involvement
only in the observed conditions. U detection, control failure, new later-case detection,
or collection failure remains unresolved. Neither successful acquisition nor all roles
passing adopts a production fix or restarts the 299-opportunity campaign.

Before timing, functional builds compare all seven cases against verbatim original
preparation using identical deterministic RNG draws: full bytes, labels, request count,
request size, RNG state and actual callback return. Unknown modes fail. Original source
and generated source are separately hashed; the normal native contains no fixture RNG.
Saved evidence is replayed after acquisition; this is not a new physical trial.

## Collection-format correction

The initial hosted comparison stopped after the original Nix controls: sorting JSON
object keys reordered the provider binding map, so the collector expected ct128 before
ct32. Both failures and partial raw records remain retained. They are not completed
preparation contrasts and are not replaced in the reliability record.

Plan version 2 carries a separate ordered `cases` array. Before acquisition, every
serialized invocation is checked against its actual ELF's non-timing case receipt.
The corrected comparison is a new fixed eight-process allocation per compiler; it uses
the same interventions, order, signal doses and bounds. It does not resume the stopped
reliability campaign. A further collection failure stops this comparison for review.
