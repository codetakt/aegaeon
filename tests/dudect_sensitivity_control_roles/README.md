# Dudect qualification by case role

This separately bound candidate evaluates complete PR observations according to
the existing case roles. It replaces crop1–100 for the fixed seven-case scope:
Nix CT32/64/128, SHA256, HMAC message, HMAC key, and legacy compare, with the same
calibration rule for GCC and Clang. Raw0/101, the remaining 14 cases, periodic,
alpha, count floors, look schedule and native measurement remain unchanged.

Protected and negative cases require complete, numerically valid nondetections
with all 102 final statistics eligible. Original positive controls retain their
designated statistic0/101 requirement. Deliberate positive fixtures require an
eligible witness in the preregistered statistic set and retain the common
evidence, raw-count and numerical checks. Characterization requires a complete
valid observation report; it is not a claim of nondetection. Ineligible statistics
retain their reason and counts rather than receiving a synthetic p-value.

`obligations.json` is the frozen candidate contract. Its historical status fields
record its creation state; physical execution receipts are separate documents.
Publishing or replaying this candidate does not adopt it as the CI acceptance
contract, authorize another allocation, or revise an earlier failure.

## Local functional checks

From the repository root, use the pinned numerical interpreter. Each test group
uses a separate process because the legacy standalone modules have overlapping
module names. These commands perform functional checks, not hardware timing:

```bash
dudect_python=$(nix eval --raw .#dudect-analysis.python.outPath)
dudect_paths="$PWD/tests/dudect_analysis:$PWD/tests/constant_time"
dudect_paths="$dudect_paths:$PWD/tests/dudect_calibration_scope:$PWD/tests/dudect_sensitivity"
dudect_paths="$dudect_paths:$PWD/tests/dudect_sensitivity_control_roles"
dudect_paths="$dudect_paths:$PWD/tests/dudect_sensitivity_live:$PWD/tests/dudect_sensitivity_operations"
for group in dudect_calibration_scope dudect_sensitivity dudect_sensitivity_control_roles \
  dudect_sensitivity_live dudect_sensitivity_operations; do
  PYTHONPATH="$PWD/tests/$group:$dudect_paths" \
    "$dudect_python/bin/python" -B -m unittest discover -s "tests/$group" -v || exit
done
```

The compare receipt tests generate their own full framing fixture. They require
no private capture or credentials. Real callback/clock trials and authenticated
replay of measured artifacts remain distinct validation steps.

## Publication correspondence

The publication copy preserves the measured implementation's executable syntax,
import order, contracts and C hooks. Python formatting and explanatory lint
annotations change source digests. The self-contained receipt test is a separate
test-only change. Original source digests and physical results must therefore be
retained alongside the publication correspondence record; they are not rewritten
to the publication tree. Syntax correspondence alone is not physical equivalence
or admission for a rebuilt artifact.

The original four/six-case failures, the previous 75/84 integration result, and
historical Hosted detections remain evidence for their original configurations.
An assessment from this evaluator cannot replace those records.
