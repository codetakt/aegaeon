# Guard attachment and retirement

`owned_process.py` supplies the attachment and retirement component for a new
controller. It does not restart or modify any frozen campaign.

At launch, persist schema `owned-guard-process/1`, the owned PID, the exact
guard script path and `/proc/<pid>/stat` start ticks. Capture these while the
launching controller owns the live child; a missing launch identity cannot be
reconstructed from a later numeric PID lookup.

A resumed controller calls `attach_guard(receipt_path, expected_script)`.
Attachment opens a pidfd, verifies the recorded identity, and checks that the
same process has not exited during verification. Thereafter signals and exit
confirmation use that descriptor. No repeated command-line read or numeric-PID
signal is used during termination.

After the controller independently confirms the cloud instance identity and
terminated state, cleanup, recovery and immutable inputs, it may call
`retire_guard(guard, actual_termination_verified=True, timeout=15)`. This flag is
an assertion by the caller, not an AWS verification performed by this module.
The next finite controller must connect it to the existing read-back checks.
On completion or failure, the caller closes the descriptor in `finally`.

An exit observation is not an exit status or proof that a deadline fired.
Missing identity, descriptor/permission errors, and a guard that ignores TERM
remain failures. Do not fall back to `os.kill(pid, ...)` or fabricate successful
retirement. The independent cloud deadline remains in force while retirement
is unconfirmed.

The local integration tests use real owned child processes and persisted launch
receipts. They do not constitute a new cloud-controller lifecycle test.
