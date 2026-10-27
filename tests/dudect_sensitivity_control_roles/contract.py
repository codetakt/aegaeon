# Preserve import/annotation behavior of the measured checkpoint.
# Inline validation reasons remain part of the evidence error protocol.
# ruff: noqa: EM101, I002, TRY003
"""Separate design-2 identity; never mutate the design-1 contract/evaluator."""

import hashlib
import json
from pathlib import Path

from analysis_contract import SOURCE
from enclosed_tail import ALPHA

HERE = Path(__file__).resolve().parent


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


CONTRACT = json.loads((HERE / "obligations.json").read_text())
BASE_PATH = HERE.parent / "dudect_sensitivity/obligations.json"
if sha(BASE_PATH) != CONTRACT["base"]["sha256"]:
    raise ValueError("Design-1 base contract changed")
BASE = json.loads(BASE_PATH.read_text())
CONTRACT_SHA256 = sha(HERE / "obligations.json")
TARGETS = frozenset(CONTRACT["scope"]["cases"])
OBLIGATIONS = {x["profile"]: x for x in BASE["signal_obligations"]}
PROFILES = ("ordinary", "zero", *OBLIGATIONS)
CASE_PATH = SOURCE / "tests/constant_time/contracts/case-contract-candidate.json"
ROLES = {x["stable_id"]: x["proposed_role"] for x in json.loads(CASE_PATH.read_text())["cases"]}
LOOKS = BASE["schedule"]["look_batches"]
FLOOR = BASE["numeric_contract"]["minimum_statistic_class_count"]
RAW_FLOOR = BASE["numeric_contract"]["minimum_raw_class_count"]


def identity():
    return {
        "id": CONTRACT["id"],
        "contract_sha256": CONTRACT_SHA256,
        "base_sha256": sha(BASE_PATH),
        "case_contract_sha256": sha(CASE_PATH),
        "implementation": {
            n: sha(HERE / n) for n in ("contract.py", "qualification.py", "kernel_v2.py")
        },
        # design-2 replaces eligibility only. Keep the existing binary64
        # threshold, represented exactly, rather than silently replacing it
        # with the nearby nominal rational 1/1713600 from the prose.
        "inherited_alpha": [ALPHA.numerator, ALPHA.denominator],
        "adopted": False,
    }
