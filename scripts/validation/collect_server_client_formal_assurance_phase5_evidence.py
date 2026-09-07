#!/usr/bin/env python3
"""Collect an unapproved server/client assurance preflight; retain the legacy CLI."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
from typing import Any, cast

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
DEFAULT_CLAIM = REPO_ROOT / "spec/server-client-formal-assurance-claim.current.json"
DEFAULT_OUTPUT = (
    REPO_ROOT / "docs/releases/evidence/server-client-formal-assurance-phase5-internal-bundle.json"
)
PRE_PUBLIC_BLOCKER_REPORT = REPO_ROOT / "docs/releases/evidence/phase5-pre-public-blockers.json"

# Generation inventories review obligations; it cannot issue approvals or carry
# approvals over from a different contract, wording or implementation revision.
REVIEW_SCOPES = (
    "claim-wording",
    "formal-boundary",
    "server-implementation",
    "sdk-adapter",
    "release-custody",
    "external-security",
)


def load_json(path: pathlib.Path) -> dict[str, Any]:
    return cast("dict[str, Any]", json.loads(path.read_text()))


def repo_relative(path: pathlib.Path) -> str:
    return str(path.resolve().relative_to(REPO_ROOT))


def sha256_file(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def resolve_evidence_path(evidence_uri: object) -> pathlib.Path | None:
    if not isinstance(evidence_uri, str) or not evidence_uri:
        return None
    if evidence_uri.startswith(("https://", "s3://", "gs://")):
        return None
    raw_path = evidence_uri.split("#", maxsplit=1)[0]
    if not raw_path:
        return None
    path = (REPO_ROOT / raw_path).resolve()
    try:
        path.relative_to(REPO_ROOT)
    except ValueError:
        return None
    return path if path.exists() else None


def evidence_status(raw_status: object) -> str:
    if raw_status == "complete":
        return "complete"
    if raw_status == "in_progress":
        return "in_progress"
    if raw_status in {"planned", "missing"}:
        return "blocked"
    return "blocked"


def collect_evidence_items(
    claim: dict[str, Any],
    output_path: pathlib.Path,
) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for item in cast("list[dict[str, Any]]", claim["required_evidence"]):
        if item["id"] == "phase5-internal-evidence-bundle":
            items.append(
                {
                    "id": item["id"],
                    "status": "complete",
                    "path": repo_relative(output_path),
                    "fresh": True,
                    "sha256": None,
                    "notes": (
                        "Self-reference to this generated preflight inventory; no review approval."
                    ),
                },
            )
            continue

        evidence_path = resolve_evidence_path(item.get("evidence_uri"))
        status = evidence_status(item.get("status"))
        complete_local = status == "complete" and evidence_path is not None
        sha256 = (
            sha256_file(evidence_path)
            if status == "complete" and evidence_path is not None
            else None
        )
        items.append(
            {
                "id": item["id"],
                "status": status,
                "path": repo_relative(evidence_path) if evidence_path else None,
                "fresh": complete_local,
                "sha256": sha256,
                "notes": item["description"],
            },
        )
    return items


def snapshot_released_client_claim(path: pathlib.Path) -> tuple[str, bool, str]:
    doc = load_json(path)
    active = bool(doc["current_state"]["released_client_claim_active"])
    status = "ready" if active else "in_progress"
    notes = (
        "Released client claim is active."
        if active
        else "Released client claim remains inactive; public server/client wording is blocked."
    )
    return status, active, notes


def snapshot_client_boundary(path: pathlib.Path) -> tuple[str, bool, str]:
    doc = load_json(path)
    active = bool(doc["released_client_claim_active"])
    default_profile = doc.get("default_profile")
    ready = active and default_profile != "compat-interop"
    status = "ready" if ready else "in_progress"
    notes = f"Client boundary default profile is {default_profile}; released claim active={active}."
    return status, ready, notes


def snapshot_client_promotion(path: pathlib.Path) -> tuple[str, bool, str]:
    doc = load_json(path)
    required_lanes = doc.get("required_lanes", [])
    notes = "Promotion policy is source-managed; hosted release evidence remains open."
    status = "in_progress" if required_lanes else "blocked"
    return status, False, notes


def snapshot_phase4(path: pathlib.Path) -> tuple[str, bool, str]:
    doc = load_json(path)
    public_ready = bool(doc.get("public_claim_ready"))
    status = "ready" if public_ready else "in_progress"
    notes = "Phase 4 preflight is internally complete; public blockers remain."
    return status, public_ready, notes


def dependent_gate_snapshot(gate: dict[str, Any]) -> dict[str, Any]:
    path = REPO_ROOT / cast("str", gate["path"])
    kind = gate["kind"]
    if kind == "released-client-claim":
        status, ready, notes = snapshot_released_client_claim(path)
    elif kind == "client-boundary":
        status, ready, notes = snapshot_client_boundary(path)
    elif kind == "client-promotion":
        status, ready, notes = snapshot_client_promotion(path)
    elif kind == "evidence-preflight":
        status, ready, notes = snapshot_phase4(path)
    else:
        status, ready, notes = "blocked", False, f"Unsupported dependency kind {kind}."

    return {
        "id": gate["id"],
        "path": gate["path"],
        "status": status,
        "ready_for_activation": ready,
        "notes": notes,
    }


def collect_blockers(claim: dict[str, Any]) -> list[str]:
    blockers: list[str] = []
    if PRE_PUBLIC_BLOCKER_REPORT.exists():
        report = load_json(PRE_PUBLIC_BLOCKER_REPORT)
        blockers.extend(
            f"{item['id']}: {item['required_next_evidence']}"
            for item in cast("list[dict[str, Any]]", report["activation_blockers"])
        )

    # A historical closure report cannot hide obligations added to the current gate.
    for item in cast("list[dict[str, Any]]", claim["required_evidence"]):
        if item.get("required_for_activation") is True and item.get("status") != "complete":
            blockers.append(f"{item['id']}: {item['description']}")
    blockers.append("Current inputs require review; generation does not issue approvals.")
    return list(dict.fromkeys(blockers))


def build_bundle(
    claim_path: pathlib.Path,
    output_path: pathlib.Path,
    generated_at: str,
) -> dict[str, Any]:
    claim = load_json(claim_path)
    return {
        "$schema": (
            "https://aegaeon.dev/spec/server-client-formal-assurance-evidence-bundle.schema.json"
        ),
        "schema_version": 1,
        "bundle_id": "server-client-assurance-preflight-2026-09-07",
        "generated_at": generated_at,
        "claim_target": "server-client-formal-assurance",
        "claim_gate_path": repo_relative(claim_path),
        "claim_gate_sha256": sha256_file(claim_path),
        "release_stage": "internal-preflight",
        "public_claim_ready": False,
        "dependent_gate_snapshots": [
            dependent_gate_snapshot(gate)
            for gate in cast("list[dict[str, Any]]", claim["dependent_gates"])
        ],
        "evidence_items": collect_evidence_items(claim, output_path),
        "review_passes": [
            {
                "id": f"{scope}-review",
                "scope": scope,
                "reviewer": "unassigned",
                "status": "pending",
                "evidence_uri": None,
            }
            for scope in REVIEW_SCOPES
        ],
        "blockers": collect_blockers(claim),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--claim", type=pathlib.Path, default=DEFAULT_CLAIM)
    parser.add_argument("--output", type=pathlib.Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--check", action="store_true")
    parser.add_argument(
        "--generated-at",
        default="2026-09-07T08:39:47Z",
        help="Timestamp to embed in the generated bundle.",
    )
    args = parser.parse_args()

    claim_path = args.claim if args.claim.is_absolute() else (REPO_ROOT / args.claim)
    output_path = args.output if args.output.is_absolute() else (REPO_ROOT / args.output)
    bundle = build_bundle(claim_path.resolve(), output_path.resolve(), args.generated_at)
    rendered = json.dumps(bundle, indent=2) + "\n"

    if args.check:
        if not output_path.exists():
            print(f"[invalid] missing generated bundle: {repo_relative(output_path)}")
            return 1
        current = output_path.read_text()
        if current != rendered:
            print(f"[invalid] stale generated bundle: {repo_relative(output_path)}")
            return 1
        print(f"[ok] {repo_relative(output_path)} is up to date")
        return 0

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(rendered)
    print(f"[ok] wrote {repo_relative(output_path)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
