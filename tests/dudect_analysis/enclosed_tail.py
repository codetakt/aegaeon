"""Certified tail kernel for the opt-in research gate; not an adopted contract.

FLINT/Arb encloses the mathematical two-sided Student tail at exact input
binary64 t and df. This does not certify upstream moments/t/df or the Welch
sampling model. A production caller must preempt the worker at its deadline;
the checks here cannot interrupt a running C-library call.
"""

from __future__ import annotations

import math
import time
from fractions import Fraction

from flint import arb, ctx, fmpq

ALPHA = Fraction(5511632216234413, 9444732965739290427392)
PRECISIONS = (128, 256, 512, 1024)


def ball(q: Fraction):
    return arb(fmpq(q.numerator, q.denominator))


def fraction(q):
    return Fraction(int(q.numerator), int(q.denominator))


def classify(lower, upper, alpha=ALPHA):
    if not 0 <= lower <= upper <= 1 or not 0 < alpha < 1:
        msg = "Invalid probability interval or alpha"
        raise ValueError(msg)
    if upper < alpha:
        return "detected"
    if lower >= alpha:
        return "nondetected"
    return "numerically_unresolved"


# Keep every precision/termination branch together for numerical review.
def enclose_squared(  # noqa: C901, PLR0911, PLR0912, PLR0915
    t_squared, degrees, *, alpha=ALPHA, precisions=PRECISIONS, deadline=None
):
    if t_squared < 0 or degrees <= 0 or not 0 < alpha < 1:
        msg = "Invalid exact Student inputs"
        raise ValueError(msg)
    if not precisions or any(type(p) is not int or p < 32 for p in precisions):
        msg = "Invalid precision schedule"
        raise ValueError(msg)
    if tuple(sorted(set(precisions))) != tuple(precisions):
        msg = "Unordered precision schedule"
        raise ValueError(msg)
    attempts = []
    for bits in precisions:
        if deadline is not None and time.monotonic() >= deadline:
            return {
                "decision": "numerically_unresolved",
                "reason": "deadline",
                "attempts": attempts,
            }
        methods = (
            ("zero",)
            if t_squared == 0
            else ("complement", "direct")
            if t_squared <= degrees
            else ("direct", "complement")
        )
        for method in methods:
            if deadline is not None and time.monotonic() >= deadline:
                return {
                    "decision": "numerically_unresolved",
                    "reason": "deadline",
                    "attempts": attempts,
                }
            with ctx.workprec(bits):
                z, df = ball(t_squared), ball(degrees)
                if method == "zero":
                    p = arb(1)
                elif method == "complement":
                    p = 1 - (z / (df + z)).beta_lower(arb(1) / 2, df / 2, regularized=True)
                else:
                    p = (df / (df + z)).beta_lower(df / 2, arb(1) / 2, regularized=True)
                if not p.is_finite():
                    attempts.append({"bits": bits, "method": method, "finite": False})
                    continue
                # Outward rounding yields bounded-size certificates, including
                # when p is too small for ordinary floating-point display.
                scale = 1 << bits
                lo = Fraction(int((p.lower() * scale).floor().fmpz()), scale)
                hi = Fraction(int((p.upper() * scale).ceil().fmpz()), scale)
                lo, hi = max(Fraction(0), lo), min(Fraction(1), hi)
                decision = classify(lo, hi, alpha)
                attempts.append(
                    {
                        "bits": bits,
                        "method": method,
                        "finite": True,
                        "lower": [lo.numerator, lo.denominator],
                        "upper": [hi.numerator, hi.denominator],
                    }
                )
            if deadline is not None and time.monotonic() >= deadline:
                return {
                    "decision": "numerically_unresolved",
                    "reason": "deadline",
                    "attempts": attempts,
                }
            if decision != "numerically_unresolved":
                return {"decision": decision, "attempts": attempts}
    return {"decision": "numerically_unresolved", "reason": "precision_limit", "attempts": attempts}


def enclose(t, degrees, **kwargs):
    if type(t) is not float or type(degrees) is not float:
        msg = "Require the frozen binary64 t and df"
        raise ValueError(msg)
    if not math.isfinite(t) or not math.isfinite(degrees) or degrees <= 0:
        msg = "Invalid binary64 Student inputs"
        raise ValueError(msg)
    return {
        "target": "mathematical_student_tail_at_frozen_binary64_t_df",
        "t_hex": t.hex(),
        "degrees_hex": degrees.hex(),
        **enclose_squared(Fraction(t) ** 2, Fraction(degrees), **kwargs),
    }


def exact_moment_alternative(pair):
    """Separate diagnostic target; does not replace the frozen-t/df norm."""
    n = [m["n"] for m in pair]
    if min(n) <= 10000:
        msg = "Ineligible counts"
        raise ValueError(msg)
    means = [Fraction(m["sum"], m["n"]) for m in pair]
    s = [Fraction(m["n"] * m["sum2"] - m["sum"] ** 2, m["n"] ** 2 * (m["n"] - 1)) for m in pair]
    if min(s) <= 0:
        msg = "Ineligible variances"
        raise ValueError(msg)
    t_squared = (means[0] - means[1]) ** 2 / sum(s)
    degrees = sum(s) ** 2 / sum(s[g] ** 2 / (n[g] - 1) for g in (0, 1))
    return {
        "target": "separate_exact_sum_Welch_not_existing_binary64_t_df",
        **enclose_squared(t_squared, degrees),
    }
