# Owned scheduler comparison

Research only. This does not admit ordinary CI, replace the numerical contract,
or resume the stopped reliability campaign.

Both arms use the same newly created units, collector, authenticated descriptor
transfer, heartbeat frequency, prefix verification, and fixed deadlines. Only
the native process's own policy differs: OTHER/0 versus FIFO/1, with reset-on-fork.
The supervisor, collector, worker, and two independent guards use the other core.
Existing processes, service properties, cgroups, and global RT budgets are unchanged.

The native starts as OTHER. It verifies identity, limits and guard registration,
receives the original timing/stdin/stdout descriptors, changes its own scheduler,
then executes the bound native ELF without a fork or preload. The collector
authenticates each current prefix and saves the analysis before sending an ACK.
It records actual native scheduler/affinity/limits at each look. This is observed
configuration, not proof of uninterrupted isolation from IRQs or the hypervisor.

Case deadlines remain 900 seconds; intermediate looks do not renew them. Prefix
validation and completion have a 10-second bound. The diagnostic process has an
additional 150-second absolute cap, with stop/cleanup due within another 5/20
seconds. The non-renewable PID1 timer is armed before native startup. RTLIMIT CPU
budgets are 60/90 seconds soft/hard in both arms. These apply only to controls and
the three-case CT signal prefix: retained complete process times were at most
13.916/21.431 seconds. These bounds provide engineering headroom, not a probability
guarantee or an appropriate budget for the full Ed25519 provider. A failure is
retained, never rescued by enlarging a limit.

The proposed Hosted diagnostic schedule has two allocations, opposite A/B order,
16 processes/48 cases each. Each arm contains original controls from both suites
and compilers, plus the unchanged fixed signal0/16 ELF for both compilers. Native
case order is preserved. Inputs are fresh, not matched pairs. The fixed signal16
requires raw0; cropped detections cannot replace it. The variance control requires
101 at any scheduled look. Statistical failures retain the fixed schedule;
operational failures stop further starts. No replacements or dose tuning.

The native and analysis packages remain pinned to the previously published build.
The analysis uses the existing enclosed Student tails and sparse handling; none of
these cases uses distributed HMAC calibration. Original rows and effective
decisions are separate. The new execution/monitoring path is a new reference,
not a physically equivalent copy of old Hosted execution.

An allocation has a fixed 1,200-second measurement budget and 10-second gaps,
including the new supervisor. Preparation and encrypted recovery are separately
bounded by the workflow. Evidence is private and authenticated; no plaintext
upload fallback. A failed baseline need not recur. Absence of recurrence is not
repair evidence. This finite comparison cannot establish the CI failure rate or
universal sensitivity.
