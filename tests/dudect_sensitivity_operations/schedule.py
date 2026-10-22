# Preserve import/annotation behavior of the measured checkpoint.
# ruff: noqa: I002
"""Absolute acquisition cutoff, checked before allowing the next native case."""

import contextlib
import time

import analysis_runtime
from dudect_support import require

BaseStream = analysis_runtime.Stream


class Stream(BaseStream):
    def __init__(self, *args, absolute_deadline, **kwargs):
        super().__init__(*args, **kwargs)
        self.absolute_deadline = absolute_deadline

    def observe(self, line):
        require(self.deadline is not None, "Missing case deadline")
        self.deadline = min(self.deadline, self.absolute_deadline)
        previous = self.index
        super().observe(line)
        require(time.monotonic() < self.absolute_deadline, "Acquisition cutoff before ACK")
        if previous < self.index < len(self.cases):
            # Native waits for this final-look ACK before starting the next case.
            require(
                time.monotonic() + 900 <= self.absolute_deadline,
                "Insufficient remaining budget for next case; ACK withheld",
            )


@contextlib.contextmanager
def installed(cutoff):
    require(time.monotonic() + 900 <= cutoff, "Insufficient initial case budget")
    old = analysis_runtime.Stream
    analysis_runtime.Stream = lambda *args, **kwargs: Stream(
        *args, absolute_deadline=cutoff, **kwargs
    )
    try:
        yield
    finally:
        analysis_runtime.Stream = old
