# Owned scheduler functional experiment

This prototype tests an OTHER bootstrap, two independent pidfd guards, finite
RTTIME limits, a PID1 deadline timer, self FIFO/1 promotion and same-PID exec.
Existing processes and background service settings are not modified. It is not
a Dudect timing launcher or CI admission decision.

The fixed local plan has 26 fault/normal scenarios followed by 44 actual ELF
processes: GCC/Clang, 21 cases, OTHER/FIFO, 84 non-timing self-test results. An
LD_PRELOAD constructor observes the actual target's loader entry only for these
functional checks. It does not establish uninstrumented timing equivalence.

Each generation has absolute start, execution, stop and cleanup deadlines at
4/7/10/15 seconds. The OTHER monitors use a 750ms heartbeat/ACK lease. Native
RTPRIO is 1:1 (0:0 in the denial fixture), with no effective/permitted/ambient
capabilities. RTTIME is 2/3 seconds, or 50/150ms for the busy-limit fixture.
The independent PID1 timer expires at 7 seconds; RuntimeMaxSec=12 is another
fallback. These short limits are functional fixture values, not adopted timing
budgets. Every invocation has a new generation; terminal generations are not
reused.

The separate Hosted plan has exactly one allocation and the same 26 helpers,
zero Dudect cases, no timing, no replacement. It rechecks the frozen kernel
identity/configuration and topology before starting any owned unit. Unknown
configuration or a functional failure stops the plan and retains partial
encrypted evidence. It never resumes old campaigns. Runtime and source bindings
are retained. A successful functional opportunity does not authorize a timing
campaign or ordinary CI restart.

Stop delivery precedes mutable state writes. PID1 or kernel failure can still
prevent confirmation; unknown stopping/cleanup is not success. Process identity,
heartbeat and sibling checks are observations at discrete times. PID1 stalls
are modeled, not induced on the shared host. Kernel global RT throttling is
unchanged. FIFO is not CPU isolation.

The user permits temporary unsigned publication for this work. Re-sign every
introduced commit before merge on a nontrigger branch and verify signatures
and exact tree/artifact correspondence. Consumed trigger branches must not be
reused. CI remains no-go and product Task3 remains paused.
