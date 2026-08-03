"""Repository documentation structure checks."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from datetime import date, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs"
DOCS_INDEX = DOCS / "index.md"
DOCS_INDEX_DATE = "2026-07-08"
DOCS_INDEX_STATUS = "current implementation baseline"
DOCS_INDEX_OWNER = "Documentation"
DOCS_INDEX_AUDIENCE = "contributors, maintainers"
DEFAULT_LONG_DOC_THRESHOLD = 500
DEFAULT_DENSE_README_THRESHOLD = 8

ROOT_MARKDOWN = ["README.md", "CHANGELOG.md", "CONTRIBUTING.md", "AGENTS.md"]
REPO_RELATIVE_MARKDOWN_PREFIXES = (
    "artifacts/",
    "crates/",
    "docs/",
    "infra/",
    "nix/",
    "proofs/",
    "scripts/",
    "spec/",
)

ALLOWED_STATUS = {
    "current implementation baseline",
    "active plan",
    "future plan",
    "historical record",
    "snapshot",
    "draft",
    "archived",
}

STATUS_NOTE_REQUIRED = {"draft", "snapshot"}

STALE_PATHS = [
    "docs/specs/client-sdk-architecture.md",
    "docs/specs/runtime-adapter-design.md",
    "docs/specs/oidc-kms-signing-design.md",
    "docs/specs/management-plane-phase1-database.md",
    "management-plane-phase1-database.md",
    "docs/specs/sdk-ci-plan.md",
    "docs/specs/sdk-implementation-guide.md",
    "docs/specs/sdk-repository-plan.md",
    "docs/specs/sdk-source-language-plan.md",
    "docs/specs/verified-core-api-plan.md",
    "docs/specs/verified-core-claims-runtime-plan.md",
    "docs/specs/external-boundary-naming-plan.md",
    "docs/design/client-sdk-architecture.md",
    "docs/design/sdk-ci-plan.md",
    "docs/design/sdk-implementation-guide.md",
    "docs/design/sdk-repository-plan.md",
    "docs/design/sdk-source-language-plan.md",
    "docs/program-management/launch-assets",
    "program-management/launch-assets",
    "../launch-assets",
    "docs/program-management/roadmaps/current-program-summary.md",
    "docs/program-management/roadmaps/program-master-plan.md",
    "docs/program-management/roadmaps/current-execution-plan.md",
    "docs/program-management/roadmaps/compliance-matrix-action-plan.md",
    "docs/program-management/roadmaps/enterprise-readiness-certification-ui-claim-plan.md",
    "docs/program-management/roadmaps/external-conformance-and-beta-plan.md",
    "docs/program-management/roadmaps/future-projects.md",
    "docs/program-management/roadmaps/management-platform-follow-on-plan.md",
    "docs/program-management/roadmaps/oauth-rfc-coverage-roadmap.md",
    "docs/program-management/roadmaps/oidc-spec-coverage-roadmap.md",
    "docs/program-management/roadmaps/proofs-roadmap.md",
    "docs/program-management/roadmaps/verified-oidc-server-client-backlog.md",
    "docs/program-management/roadmaps/verified-server-client-formal-claim-roadmap.md",
    "docs/program-management/roadmaps/aegaeon-pr-plan-2026.md",
    "docs/program-management/initiatives/jose/lowstar/context-migration-phase1-4-summary.md",
    "docs/program-management/initiatives/jose/raw-json-phase1-contract.md",
    "docs/program-management/initiatives/jose/raw-json-phase1-structural-parser-plan.md",
    "docs/publication/launch-assets/aegaeon-event-announcement-draft.md",
    "docs/publication/launch-assets/aegaeon-event-demo-runbook.md",
    "docs/publication/launch-assets/aegaeon-event-exhibition-plan.md",
    "docs/publication/launch-assets/aegaeon-event-faq-and-objection-handling.md",
    "docs/publication/launch-assets/aegaeon-event-one-page-handout.md",
    "docs/publication/launch-assets/aegaeon-event-slide-deck-outline.md",
    "docs/publication/launch-assets/aegaeon-v0.1.0-asset-status.md",
    "docs/publication/launch-assets/aegaeon-v0.1.0-design-asset-brief.md",
    "docs/publication/launch-assets/aegaeon-v0.1.0-github-public-readiness.md",
    "docs/publication/launch-assets/aegaeon-v0.1.0-landing-page-copy.md",
    "docs/publication/launch-assets/aegaeon-v0.1.0-landing-page-structure.md",
    "docs/publication/launch-assets/aegaeon-v0.1.0-press-release-draft.md",
    "docs/publication/launch-assets/aegaeon-v0.1.0-preview-request-flow.md",
    "docs/publication/launch-assets/aegaeon-v0.1.0-spec-sheet-draft.md",
    "docs/publication/launch-assets/aegaeon-v0.1.0-whitepaper-outline.md",
    "docs/publication/launch-assets/oem-pricing-note-2026-05-18.md",
    "docs/publication/launch-assets/event/",
    "docs/publication/launch-assets/event",
    "docs/publication/launch-assets/partner/",
    "docs/publication/launch-assets/partner",
    "docs/publication/launch-assets/v0.1.0/aegaeon-v0.1.0-asset-status.md",
    "docs/publication/launch-assets/v0.1.0/aegaeon-v0.1.0-design-asset-brief.md",
    "docs/publication/launch-assets/v0.1.0/aegaeon-v0.1.0-github-public-readiness.md",
    "docs/publication/launch-assets/v0.1.0/aegaeon-v0.1.0-landing-page-copy.md",
    "docs/publication/launch-assets/v0.1.0/aegaeon-v0.1.0-landing-page-structure.md",
    "docs/publication/launch-assets/v0.1.0/aegaeon-v0.1.0-press-release-draft.md",
    "docs/publication/launch-assets/v0.1.0/aegaeon-v0.1.0-preview-request-flow.md",
    "docs/publication/launch-assets/v0.1.0/aegaeon-v0.1.0-spec-sheet-draft.md",
    "docs/publication/launch-assets/v0.1.0/aegaeon-v0.1.0-whitepaper-outline.md",
    "docs/investigations/",
    "docs/investigations",
    "docs/architecture/management-plane-phase1-spec.md",
    "docs/security/archive/",
    "docs/security/archive",
    "docs/security/asan-procedures.md",
    "docs/security/sbom-findings.md",
    "docs/security/unsafe-inventory.md",
    "docs/verification/ad-zero-feasibility.md",
    "docs/verification/archive/ad-zero-feasibility.md",
    "docs/verification/compliance-matrix-audit.md",
    "docs/verification/everparse-integration-status.md",
    "docs/verification/fstar/trust-assumptions.md",
    "docs/verification/archive/fstar/",
    "docs/verification/archive/fstar",
    "docs/verification/oidc/idtoken-formal-plan.md",
    "docs/verification/archive/oidc/",
    "docs/verification/archive/oidc",
    "docs/verification/tlv-utf8-decoder-summary.md",
    "docs/verification/archive/tlv-utf8-decoder-summary.md",
    "docs/verification/lemmas/",
    "docs/verification/lemmas",
    "docs/verification/workplans/blockers.md",
    "docs/verification/workplans/karamel-warning15-analysis.md",
    "docs/development/thread-handoff-2026-05-21-aegaeon-server-review.md",
    "docs/development/thread-handoff-2026-05-21-aegaeon-server-review.txt",
    "docs/releases/beta_conformance.md",
    "docs/releases/beta-deployment.md",
    "docs/releases/admin-ui-assurance-phase3-internal-evidence.md",
    "docs/releases/admin-ui-assurance-phase3-internal-bundle.json",
    "docs/releases/certification-phase2-internal-evidence.md",
    "docs/releases/certification-phase2-internal-bundle.json",
    "docs/releases/enterprise-readiness-evidence-bundle.md",
    "docs/releases/managed-provider-evidence.md",
    "docs/releases/phase1-evidence-acquisition.md",
    "docs/releases/phase4-claim-activation-preflight.md",
    "docs/releases/phase4-claim-activation-preflight.json",
    "docs/releases/phase5-pre-public-blockers.json",
    "docs/releases/publication-org-rollout.md",
    "docs/releases/release-security-evidence.md",
    "docs/releases/server-client-formal-assurance-phase5-internal-evidence.md",
    "docs/releases/server-client-formal-assurance-phase5-internal-bundle.json",
    "docs/releases/kms-hsm-classifications/",
]

STALE_VERIFICATION_ROOT_DOCS = {
    "admin-ui-assurance-case",
    "assumptions",
    "assurance-case",
    "claim-index",
    "client-rp-assurance-case",
    "crypto-allowlist",
    "crypto-claim-mapping",
    "verification-maturity-model",
    "verification-maturity-status",
    "verification-boundary-roadmap",
    "crypto-extraction-roadmap",
    "phase-d-plan",
    "lemma-hardening-plan",
    "rng-plan",
    "blockers",
    "karamel-warning15-analysis",
    "structure-guidelines",
    "extraction-status",
    "ffi-contracts",
    "hacl-integration",
    "runtime-linkage",
    "sanitizers",
    "verification-ops",
}

LOCAL_LINK_RE = re.compile(r"(?<!!)\[[^\]\n]+\]\(([^)\n]+)\)")
CODE_SPAN_MD_RE = re.compile(r"`([^`\n]+\.md(?:#[^`\n]+)?)`")
TYPE_LABEL_RE = re.compile(r"^-\s+`?\[([a-z][a-z0-9 -]*)\]`?\s+")
ARCHIVE_TITLE_RE = re.compile(r"\b(archived|moved)\b", re.IGNORECASE)
LATEST_RE = re.compile(r"\blatest\b", re.IGNORECASE)
DOC_PATH_COMPONENT_RE = re.compile(r"^[a-z0-9][a-z0-9.-]*$")
DOC_MARKDOWN_FILENAME_RE = re.compile(r"^[a-z0-9][a-z0-9.-]*\.md$")
FENCE_RE = re.compile(r"^(`{3,}|~{3,})(.*)$")
COMPATIBILITY_STUB_MARKER = "This compatibility entrypoint preserves"
RETAINED_FOR_RE = re.compile(r"^Retained for:\s+\S.*$")
REVIEW_AFTER_RE = re.compile(r"^Review after:\s+\d{4}-\d{2}-\d{2}$")
ISO_DATE_RE = re.compile(r"\b20\d{2}-\d{2}-\d{2}\b")
README_REQUIRED_HEADINGS = (
    "## Scope",
    "## Canonical Documents",
    "## Reading Rule of Thumb",
)

ALLOWED_TYPE_LABELS = {
    "analysis",
    "architecture",
    "automation",
    "brief",
    "checklist",
    "claim",
    "configuration",
    "context",
    "design",
    "development",
    "draft",
    "evidence",
    "guide",
    "handoff",
    "historical",
    "index",
    "initiative",
    "model",
    "performance",
    "plan",
    "policy",
    "publication",
    "reference",
    "release",
    "roadmap",
    "runbook",
    "sample",
    "security",
    "snapshot",
    "spec",
    "summary",
    "workplan",
}

ALLOWED_DOCS_PAYLOADS = {
    "docs/operations/monitoring/alertmanager.sample.yaml",
    "docs/operations/monitoring/grafana.dashboards.sample.json",
    "docs/operations/monitoring/prometheus.rules.sample.yaml",
    "docs/verification/claims/model-fidelity.yaml",
    "docs/releases/evidence/admin-ui-assurance-phase3-internal-bundle.json",
    "docs/releases/evidence/certification-phase2-internal-bundle.json",
    "docs/releases/evidence/phase4-claim-activation-preflight.json",
    "docs/releases/evidence/phase5-pre-public-blockers.json",
    "docs/releases/evidence/server-client-formal-assurance-phase5-internal-bundle.json",
}

DOC_TYPE_PREFIXES = (
    ("docs/verification/claims/", "claim"),
    ("docs/verification/runbooks/", "runbook"),
    ("docs/program-management/roadmaps/", "roadmap"),
    ("docs/program-management/initiatives/", "initiative"),
    ("docs/program-management/historical/", "historical"),
    ("docs/specs/", "spec"),
    ("docs/design/", "design"),
    ("docs/operations/", "runbook"),
    ("docs/publication/launch-assets/drafts/", "draft"),
    ("docs/publication/", "publication"),
    ("docs/policies/", "policy"),
    ("docs/releases/runbooks/", "runbook"),
    ("docs/releases/evidence/", "evidence"),
    ("docs/releases/", "release"),
    ("docs/configurations/", "configuration"),
    ("docs/automation/", "automation"),
    ("docs/development/", "development"),
    ("docs/performance/", "performance"),
    ("docs/security/", "security"),
    ("docs/verification/", "verification"),
    ("docs/architecture/", "architecture"),
)

DOC_TYPE_OVERRIDES = {
    "docs/program-management/initiatives/jose/status.md": "summary",
    "docs/program-management/initiatives/sdk/client-sdk-architecture.md": "design",
    "docs/program-management/initiatives/sdk/sdk-ci-plan.md": "plan",
    "docs/program-management/initiatives/sdk/sdk-implementation-guide.md": "guide",
    "docs/program-management/initiatives/sdk/sdk-repository-plan.md": "plan",
    "docs/program-management/initiatives/sdk/sdk-source-language-plan.md": "workplan",
}

SECTION_LABELS = {
    "architecture": "Architecture",
    "automation": "Automation",
    "configurations": "Configuration",
    "design": "Design",
    "development": "Development",
    "operations": "Operations",
    "performance": "Performance",
    "policies": "Policies",
    "program-management": "Program Management",
    "publication": "Publication",
    "releases": "Releases",
    "security": "Security",
    "specs": "Specifications",
    "verification": "Verification",
}

SECTION_ORDER = {
    "Overview": 0,
    "Architecture": 10,
    "Specifications": 20,
    "Design": 30,
    "Configuration": 40,
    "Policies": 50,
    "Automation": 60,
    "Program Management": 70,
    "Publication": 80,
    "Publication Drafts": 85,
    "Releases": 90,
    "Performance": 100,
    "Verification": 110,
    "Operations": 120,
    "Security": 130,
    "Development": 140,
}

PATH_STATUS_RULES = (("docs/program-management/historical/", {"historical record"}),)

COMPATIBILITY_STUB_REFERENCE_ALLOWED_PREFIXES = ("docs/program-management/historical/",)

COMPATIBILITY_STUB_REFERENCE_ALLOWED_PATHS = {
    "docs/index.md",
}


def git_tracked_text_files() -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "-z", "docs", "scripts", "spec", *ROOT_MARKDOWN],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    return [
        ROOT / item.decode("utf-8")
        for item in result.stdout.split(b"\0")
        if item and (ROOT / item.decode("utf-8")).is_file()
    ]


def markdown_files() -> list[Path]:
    files = sorted(DOCS.rglob("*.md"))
    for name in ROOT_MARKDOWN:
        path = ROOT / name
        if path.exists():
            files.append(path)
    return sorted(set(files))


def docs_markdown_files() -> list[Path]:
    return sorted(DOCS.rglob("*.md"))


def requires_metadata(path: Path) -> bool:
    return path.is_relative_to(DOCS)


def top_last_updated_metadata(path: Path) -> tuple[int, str] | None:
    lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()[:12]
    for index, line in enumerate(lines, start=1):
        if line.startswith("Last updated:"):
            return index, line.removeprefix("Last updated:").strip()
    return None


def top_status_metadata(path: Path) -> tuple[int, str] | None:
    lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()[:12]
    for index, line in enumerate(lines, start=1):
        if line.startswith("Status:"):
            return index, line.removeprefix("Status:").strip()
    return None


def top_owner_metadata(path: Path) -> tuple[int, str] | None:
    lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()[:16]
    for index, line in enumerate(lines, start=1):
        if line.startswith("Owner:"):
            return index, line.removeprefix("Owner:").strip()
    return None


def top_audience_metadata(path: Path) -> tuple[int, str] | None:
    lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()[:16]
    for index, line in enumerate(lines, start=1):
        if line.startswith("Audience:"):
            return index, line.removeprefix("Audience:").strip()
    return None


def markdown_link_target(raw: str) -> str | None:
    raw = raw.strip()
    if not raw:
        return None
    if raw.startswith(("#", "http://", "https://", "mailto:", "tel:")):
        return None
    target = raw.split()[0].strip("<>")
    target = target.split("#", 1)[0]
    if not target or target.startswith(("/", "file:", "javascript:")):
        return None
    return target


def resolve_code_span_markdown_target(path: Path, target: str) -> Path:
    if target.startswith(("./", "../")):
        return (path.parent / target).resolve()
    if target in ROOT_MARKDOWN or target.startswith(REPO_RELATIVE_MARKDOWN_PREFIXES):
        return (ROOT / target).resolve()

    relative = (path.parent / target).resolve()
    if relative.exists():
        return relative

    root_relative = (ROOT / target).resolve()
    if root_relative.exists():
        return root_relative

    return relative


def check_local_links(errors: list[str]) -> None:
    for path in markdown_files():
        text = path.read_text(encoding="utf-8", errors="ignore")
        for match in LOCAL_LINK_RE.finditer(text):
            target = markdown_link_target(match.group(1))
            if target is None:
                continue
            resolved = (path.parent / target).resolve()
            try:
                resolved.relative_to(ROOT)
            except ValueError:
                continue
            if not resolved.exists():
                rel_path = path.relative_to(ROOT)
                errors.append(f"{rel_path}: broken local link: {match.group(1)}")


def check_code_span_markdown_references(errors: list[str]) -> None:
    for path in markdown_files():
        rel_path = path.relative_to(ROOT)
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        for index, line in enumerate(lines, start=1):
            for match in CODE_SPAN_MD_RE.finditer(line):
                target = markdown_link_target(match.group(1))
                if target is None:
                    continue
                resolved = resolve_code_span_markdown_target(path, target)
                try:
                    resolved.relative_to(ROOT)
                except ValueError:
                    continue
                if not resolved.exists():
                    errors.append(
                        f"{rel_path}:{index}: broken Markdown path in code span: {target}"
                    )


def check_readmes(errors: list[str]) -> None:
    for directory in sorted(p for p in DOCS.rglob("*") if p.is_dir()):
        if any(child.suffix == ".md" for child in directory.rglob("*.md")):
            if not (directory / "README.md").exists():
                errors.append(f"{directory.relative_to(ROOT)}: missing README.md")


def check_readme_structure(errors: list[str]) -> None:
    for path in sorted(DOCS.rglob("README.md")):
        if path == DOCS / "README.md":
            continue
        lines = set(path.read_text(encoding="utf-8", errors="ignore").splitlines())
        rel_path = path.relative_to(ROOT)
        for heading in README_REQUIRED_HEADINGS:
            if heading not in lines:
                errors.append(f"{rel_path}: missing required README section: {heading}")


def check_doc_path_naming(errors: list[str]) -> None:
    for path in docs_markdown_files():
        rel_parts = path.relative_to(DOCS).parts
        rel_path = path.relative_to(ROOT)
        for directory in rel_parts[:-1]:
            if not DOC_PATH_COMPONENT_RE.fullmatch(directory):
                errors.append(
                    f"{rel_path}: directory component is not lowercase kebab-case: {directory}"
                )
        if path.name != "README.md" and not DOC_MARKDOWN_FILENAME_RE.fullmatch(path.name):
            errors.append(f"{rel_path}: Markdown filename must be lowercase kebab-case")


def check_status_metadata(errors: list[str]) -> None:
    for path in markdown_files():
        metadata = top_status_metadata(path)
        if metadata is None and requires_metadata(path):
            rel_path = path.relative_to(ROOT)
            errors.append(f"{rel_path}: missing required Status metadata")
            continue
        if metadata is None:
            continue
        index, value = metadata
        if value not in ALLOWED_STATUS:
            rel_path = path.relative_to(ROOT)
            allowed = ", ".join(sorted(ALLOWED_STATUS))
            errors.append(f"{rel_path}:{index}: unknown status '{value}' (allowed: {allowed})")
            continue
        if value in STATUS_NOTE_REQUIRED:
            check_status_note(errors, path, value)
        check_path_status_rule(errors, path, index, value)


def check_status_note(errors: list[str], path: Path, status: str) -> None:
    lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()[:40]
    if any("Status note" in line for line in lines):
        return
    rel_path = path.relative_to(ROOT)
    errors.append(f"{rel_path}: {status} document requires a top Status note")


def check_last_updated_metadata(errors: list[str]) -> None:
    for path in docs_markdown_files():
        if not requires_metadata(path):
            continue
        metadata = top_last_updated_metadata(path)
        if metadata is None:
            rel_path = path.relative_to(ROOT)
            errors.append(f"{rel_path}: missing required Last updated metadata")
            continue
        index, value = metadata
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
            rel_path = path.relative_to(ROOT)
            errors.append(f"{rel_path}:{index}: Last updated must use YYYY-MM-DD")


def check_duplicate_top_metadata(errors: list[str]) -> None:
    labels = ("Last updated:", "Status:", "Owner:", "Audience:")
    for path in docs_markdown_files():
        rel_path = path.relative_to(ROOT)
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()[:20]
        for label in labels:
            matches = [index for index, line in enumerate(lines, start=1) if line.startswith(label)]
            if len(matches) > 1:
                locations = ", ".join(str(index) for index in matches)
                errors.append(f"{rel_path}: duplicate top metadata '{label}' at lines {locations}")


def check_owner_audience_metadata(errors: list[str]) -> None:
    for path in docs_markdown_files():
        for label, reader in (
            ("Owner", top_owner_metadata),
            ("Audience", top_audience_metadata),
        ):
            metadata = reader(path)
            rel_path = path.relative_to(ROOT)
            if metadata is None:
                errors.append(f"{rel_path}: missing required {label} metadata")
                continue
            index, value = metadata
            if not value:
                errors.append(f"{rel_path}:{index}: {label} metadata must be non-empty")


def check_path_status_rule(errors: list[str], path: Path, index: int, status: str) -> None:
    rel_path = path.relative_to(ROOT).as_posix()
    for prefix, allowed in PATH_STATUS_RULES:
        if rel_path.startswith(prefix) and status not in allowed:
            allowed_values = ", ".join(sorted(allowed))
            errors.append(f"{rel_path}:{index}: status must be one of: {allowed_values}")
            return


def check_archived_title_status(errors: list[str]) -> None:
    allowed = {"archived", "historical record", "snapshot"}
    for path in docs_markdown_files():
        if path.name == "README.md":
            continue
        title = document_title(path)
        metadata = top_status_metadata(path)
        if metadata is None or not ARCHIVE_TITLE_RE.search(title):
            continue
        index, status = metadata
        if status not in allowed:
            rel_path = path.relative_to(ROOT)
            allowed_values = ", ".join(sorted(allowed))
            errors.append(f"{rel_path}:{index}: archived/moved title requires: {allowed_values}")


def check_compatibility_stub_metadata(errors: list[str]) -> None:
    for path in docs_markdown_files():
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        section_end = next(
            (index for index, line in enumerate(lines) if line.startswith("## ")),
            min(len(lines), 40),
        )
        top_lines = lines[:section_end]
        if not any(COMPATIBILITY_STUB_MARKER in line for line in top_lines):
            continue

        rel_path = path.relative_to(ROOT)

        if not any(RETAINED_FOR_RE.fullmatch(line) for line in top_lines):
            errors.append(f"{rel_path}: compatibility stub missing top Retained for metadata")

        review_after = [
            (index, line)
            for index, line in enumerate(top_lines, start=1)
            if line.startswith("Review after:")
        ]
        if not review_after:
            errors.append(f"{rel_path}: compatibility stub missing top Review after metadata")
            continue
        for index, line in review_after:
            if not REVIEW_AFTER_RE.fullmatch(line):
                errors.append(f"{rel_path}:{index}: Review after must use YYYY-MM-DD")


def compatibility_stub_paths() -> set[Path]:
    return {
        path for path in docs_markdown_files() if compatibility_stub_top_lines(path) is not None
    }


def compatibility_stub_reference_allowed(path: Path, stubs: set[Path]) -> bool:
    rel_path = path.relative_to(ROOT).as_posix()
    if path in stubs or rel_path in COMPATIBILITY_STUB_REFERENCE_ALLOWED_PATHS:
        return True
    return any(
        rel_path.startswith(prefix) for prefix in COMPATIBILITY_STUB_REFERENCE_ALLOWED_PREFIXES
    )


def check_compatibility_stub_references(errors: list[str]) -> None:
    stubs = compatibility_stub_paths()
    stub_rel_paths = {path.relative_to(ROOT).as_posix(): path for path in stubs}

    for path in git_tracked_text_files():
        if compatibility_stub_reference_allowed(path, stubs):
            continue
        rel_path = path.relative_to(ROOT)
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        for index, line in enumerate(lines, start=1):
            reported: set[str] = set()
            for stub_rel_path in stub_rel_paths:
                if stub_rel_path in line:
                    reported.add(stub_rel_path)
            for match in LOCAL_LINK_RE.finditer(line):
                target = markdown_link_target(match.group(1))
                if target is None:
                    continue
                resolved = (path.parent / target).resolve()
                if resolved in stubs:
                    reported.add(resolved.relative_to(ROOT).as_posix())
            for match in CODE_SPAN_MD_RE.finditer(line):
                target = markdown_link_target(match.group(1))
                if target is None:
                    continue
                resolved = (path.parent / target).resolve()
                if resolved in stubs:
                    reported.add(resolved.relative_to(ROOT).as_posix())
            for stub_rel_path in sorted(reported):
                errors.append(
                    f"{rel_path}:{index}: live document references compatibility "
                    f"stub path: {stub_rel_path}"
                )


def check_docs_payload_files(errors: list[str]) -> None:
    for path in sorted(p for p in DOCS.rglob("*") if p.is_file() and p.suffix != ".md"):
        rel_path = path.relative_to(ROOT).as_posix()
        if rel_path not in ALLOWED_DOCS_PAYLOADS:
            errors.append(f"{rel_path}: non-Markdown payload must move out of docs/ or be allowed")


def check_latest_wording(errors: list[str]) -> None:
    exempt_statuses = {"archived", "historical record", "snapshot"}
    for path in docs_markdown_files():
        rel_path = path.relative_to(ROOT).as_posix()
        if (
            path.name == "README.md"
            or rel_path == "docs/documentation-style-guide.md"
            or "/archive/" in rel_path
        ):
            continue
        metadata = top_status_metadata(path)
        status = "" if metadata is None else metadata[1]
        if status in exempt_statuses:
            continue
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        for index, line in enumerate(lines, start=1):
            if not LATEST_RE.search(line):
                continue
            if any(token in line for token in ("artifacts/", "latest_run", "dist_tag=latest")):
                continue
            errors.append(f"{rel_path}:{index}: avoid relative 'latest' wording")


def check_stale_paths(errors: list[str]) -> None:
    verification_re = re.compile(
        r"(?:docs/)?verification/(" + "|".join(sorted(STALE_VERIFICATION_ROOT_DOCS)) + r")\.md"
    )
    for path in git_tracked_text_files():
        if path == Path(__file__).resolve():
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        rel_path = path.relative_to(ROOT)
        for stale in STALE_PATHS:
            if stale in text:
                errors.append(f"{rel_path}: stale docs path remains: {stale}")
        for match in verification_re.finditer(text):
            errors.append(f"{rel_path}: stale verification root path remains: {match.group(0)}")


def check_canonical_type_labels(errors: list[str]) -> None:
    for path in sorted(DOCS.rglob("README.md")):
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        in_canonical = False
        for index, line in enumerate(lines, start=1):
            if line == "## Canonical Documents":
                in_canonical = True
                continue
            if in_canonical and line.startswith("## "):
                in_canonical = False
            if not in_canonical or not line.startswith("- "):
                continue
            match = TYPE_LABEL_RE.match(line)
            if match is None:
                rel_path = path.relative_to(ROOT)
                errors.append(f"{rel_path}:{index}: canonical entry missing type label")
                continue
            label = match.group(1)
            if label not in ALLOWED_TYPE_LABELS:
                rel_path = path.relative_to(ROOT)
                allowed = ", ".join(sorted(ALLOWED_TYPE_LABELS))
                errors.append(
                    f"{rel_path}:{index}: unknown canonical type label '{label}' "
                    f"(allowed: {allowed})"
                )


def canonical_entry_count(path: Path) -> int:
    lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    in_canonical = False
    count = 0
    for line in lines:
        if line == "## Canonical Documents":
            in_canonical = True
            continue
        if in_canonical and line.startswith("## "):
            in_canonical = False
        if in_canonical and line.startswith("- "):
            count += 1
    return count


def check_markdown_fences(errors: list[str]) -> None:
    for path in docs_markdown_files():
        rel_path = path.relative_to(ROOT)
        open_fence: tuple[str, int] | None = None
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        for index, line in enumerate(lines, start=1):
            match = FENCE_RE.match(line)
            if match is None:
                continue
            fence, suffix = match.groups()
            marker = fence[0]
            length = len(fence)
            if open_fence is None:
                open_fence = (marker * length, index)
                continue
            expected, start_index = open_fence
            if marker != expected[0] or length < len(expected):
                continue
            if suffix.strip():
                errors.append(
                    f"{rel_path}:{index}: closing fence for block opened at line "
                    f"{start_index} must not include an info string"
                )
            open_fence = None
        if open_fence is not None:
            _, start_index = open_fence
            errors.append(f"{rel_path}:{start_index}: unclosed fenced code block")


def document_title(path: Path) -> str:
    if path == DOCS_INDEX:
        return "Documentation Index"
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if line.startswith("# "):
            return line.removeprefix("# ").strip()
    return path.relative_to(ROOT).as_posix()


def document_type(path: Path) -> str:
    if path.name == "README.md" or path == DOCS_INDEX:
        return "index"
    rel_path = path.relative_to(ROOT).as_posix()
    if rel_path in DOC_TYPE_OVERRIDES:
        return DOC_TYPE_OVERRIDES[rel_path]
    doc_type = "doc"
    for prefix, candidate in DOC_TYPE_PREFIXES:
        if rel_path.startswith(prefix):
            doc_type = candidate
            break
    return doc_type


def table_cell(value: str) -> str:
    return value.replace("|", r"\|")


def print_document_index() -> None:
    print(render_document_index_body())


def render_document_index_table(paths: list[Path]) -> str:
    lines = ["| Path | Type | Title | Status | Last Updated | Owner | Audience |"]
    lines.append("| --- | --- | --- | --- | --- | --- | --- |")
    for path in paths:
        rel_path = path.relative_to(ROOT).as_posix()
        if path == DOCS_INDEX:
            status_value = DOCS_INDEX_STATUS
            last_updated_value = DOCS_INDEX_DATE
            owner_value = DOCS_INDEX_OWNER
            audience_value = DOCS_INDEX_AUDIENCE
        else:
            status = top_status_metadata(path)
            last_updated = top_last_updated_metadata(path)
            owner = top_owner_metadata(path)
            audience = top_audience_metadata(path)
            status_value = "" if status is None else status[1]
            last_updated_value = "" if last_updated is None else last_updated[1]
            owner_value = "" if owner is None else owner[1]
            audience_value = "" if audience is None else audience[1]
        row = [
            f"`{rel_path}`",
            document_type(path),
            table_cell(document_title(path)),
            status_value,
            last_updated_value,
            table_cell(owner_value),
            table_cell(audience_value),
        ]
        lines.append("| " + " | ".join(row) + " |")
    return "\n".join(lines)


def document_section(path: Path) -> str:
    rel_path = path.relative_to(ROOT).as_posix()
    if rel_path.startswith("docs/publication/launch-assets/drafts/"):
        return "Publication Drafts"
    rel_parts = path.relative_to(DOCS).parts
    if len(rel_parts) == 1:
        return "Overview"
    return SECTION_LABELS.get(rel_parts[0], rel_parts[0].replace("-", " ").title())


def render_document_index_body() -> str:
    grouped: dict[str, list[Path]] = {}
    for path in docs_markdown_files():
        grouped.setdefault(document_section(path), []).append(path)

    lines: list[str] = []
    for section in sorted(grouped, key=lambda value: (SECTION_ORDER.get(value, 999), value)):
        lines.append(f"## {section}")
        lines.append("")
        lines.append(render_document_index_table(grouped[section]))
        lines.append("")
    return "\n".join(lines).rstrip()


def render_document_index() -> str:
    return "\n".join(
        [
            "# Documentation Index",
            "",
            f"Last updated: {DOCS_INDEX_DATE}",
            "",
            f"Status: {DOCS_INDEX_STATUS}",
            "",
            f"Owner: {DOCS_INDEX_OWNER}",
            "",
            f"Audience: {DOCS_INDEX_AUDIENCE}",
            "",
            "<!-- AUTO-GENERATED by check_docs_structure.py -- DO NOT EDIT -->",
            "",
            render_document_index_body(),
            "",
        ]
    )


def normalized_index(text: str) -> str:
    return "\n".join(line for line in text.splitlines() if not line.startswith("Last updated:"))


def check_document_index(errors: list[str]) -> None:
    if not DOCS_INDEX.exists():
        errors.append("docs/index.md: generated documentation index is missing")
        return
    existing = DOCS_INDEX.read_text(encoding="utf-8")
    expected = render_document_index()
    if normalized_index(existing) != normalized_index(expected):
        errors.append("docs/index.md: generated documentation index is out of date")


def report_long_docs(threshold: int) -> None:
    rows: list[tuple[int, str, str]] = []
    for path in docs_markdown_files():
        line_count = len(path.read_text(encoding="utf-8", errors="ignore").splitlines())
        if line_count <= threshold:
            continue
        metadata = top_status_metadata(path)
        status = "" if metadata is None else metadata[1]
        rows.append((line_count, path.relative_to(ROOT).as_posix(), status))
    if not rows:
        print(f"No docs exceed {threshold} lines.")
        return
    print(f"Docs exceeding {threshold} lines:")
    for line_count, rel_path, status in sorted(rows, reverse=True):
        print(f"{line_count:5d}  {rel_path}  [{status}]")


def report_dense_readmes(threshold: int) -> None:
    rows: list[tuple[int, str]] = []
    for path in sorted(DOCS.rglob("README.md")):
        count = canonical_entry_count(path)
        if count > threshold:
            rows.append((count, path.relative_to(ROOT).as_posix()))

    if not rows:
        print(f"No README Canonical Documents sections exceed {threshold} entries.")
        return

    print(f"README Canonical Documents sections exceeding {threshold} entries:")
    for count, rel_path in sorted(rows, reverse=True):
        print(f"{count:5d}  {rel_path}")


def compatibility_stub_top_lines(path: Path) -> list[str] | None:
    lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    section_end = next(
        (index for index, line in enumerate(lines) if line.startswith("## ")),
        min(len(lines), 40),
    )
    top_lines = lines[:section_end]
    if not any(COMPATIBILITY_STUB_MARKER in line for line in top_lines):
        return None
    return top_lines


def report_compatibility_stubs() -> None:
    rows: list[tuple[date | None, str, str, str]] = []
    today = date.today()
    for path in docs_markdown_files():
        top_lines = compatibility_stub_top_lines(path)
        if top_lines is None:
            continue
        retained_for = next(
            (
                line.removeprefix("Retained for:").strip()
                for line in top_lines
                if line.startswith("Retained for:")
            ),
            "",
        )
        review_after = next(
            (
                line.removeprefix("Review after:").strip()
                for line in top_lines
                if line.startswith("Review after:")
            ),
            "",
        )
        try:
            review_date = datetime.strptime(review_after, "%Y-%m-%d").date()
        except ValueError:
            review_date = None

        if review_date is None:
            due = "invalid date"
        else:
            days = (review_date - today).days
            due = f"due in {days} days" if days >= 0 else f"overdue by {-days} days"
        rows.append(
            (
                review_date,
                path.relative_to(ROOT).as_posix(),
                due,
                retained_for,
            )
        )

    if not rows:
        print("No compatibility stubs found.")
        return

    print("Compatibility stubs by review date:")
    for review_date, rel_path, due, retained_for in sorted(
        rows, key=lambda row: (row[0] or date.max, row[1])
    ):
        review_text = "unknown" if review_date is None else review_date.isoformat()
        print(f"{review_text}  {due:18s}  {rel_path}  Retained for: {retained_for}")


def report_compatibility_stub_references() -> None:
    errors: list[str] = []
    check_compatibility_stub_references(errors)
    if not errors:
        print("No disallowed compatibility stub references found.")
        return
    print("Disallowed compatibility stub references:")
    for error in errors:
        print(error)


def active_plan_past_date_rows() -> list[tuple[date, str, int, str]]:
    rows: list[tuple[date, str, int, str]] = []
    today = date.today()
    for path in docs_markdown_files():
        rel_path = path.relative_to(ROOT).as_posix()
        if rel_path.startswith("docs/program-management/historical/"):
            continue
        metadata = top_status_metadata(path)
        if metadata is None or metadata[1] != "active plan":
            continue
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        for index, line in enumerate(lines, start=1):
            if line.startswith("Last updated:"):
                continue
            for match in ISO_DATE_RE.finditer(line):
                try:
                    parsed = datetime.strptime(match.group(0), "%Y-%m-%d").date()
                except ValueError:
                    continue
                if parsed < today:
                    rows.append((parsed, rel_path, index, line.strip()))
    return rows


def report_stale_active_plans() -> None:
    rows = active_plan_past_date_rows()
    if not rows:
        print("No past dated active-plan references found.")
        return
    print("Active-plan past dated references:")
    for parsed, rel_path, index, line in sorted(rows):
        print(f"{rel_path}:{index}: {parsed.isoformat()}: {line}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Audit repository documentation structure.")
    parser.add_argument(
        "--print-index",
        action="store_true",
        help="print a Markdown table index of docs/ files and exit",
    )
    parser.add_argument(
        "--write-index",
        action="store_true",
        help="write docs/index.md from the generated documentation index",
    )
    parser.add_argument(
        "--report-long-docs",
        action="store_true",
        help="report Markdown docs over the configured line threshold and exit",
    )
    parser.add_argument(
        "--long-doc-threshold",
        type=int,
        default=DEFAULT_LONG_DOC_THRESHOLD,
        help=f"line threshold for --report-long-docs (default: {DEFAULT_LONG_DOC_THRESHOLD})",
    )
    parser.add_argument(
        "--report-dense-readmes",
        action="store_true",
        help=(
            "report README Canonical Documents sections over the configured "
            "entry threshold and exit"
        ),
    )
    parser.add_argument(
        "--dense-readme-threshold",
        type=int,
        default=DEFAULT_DENSE_README_THRESHOLD,
        help=(
            "entry threshold for --report-dense-readmes "
            f"(default: {DEFAULT_DENSE_README_THRESHOLD})"
        ),
    )
    parser.add_argument(
        "--report-compatibility-stubs",
        action="store_true",
        help="report compatibility stubs and their review dates, then exit",
    )
    parser.add_argument(
        "--report-compatibility-stub-references",
        action="store_true",
        help="report live references to compatibility stubs, then exit",
    )
    parser.add_argument(
        "--report-stale-active-plans",
        action="store_true",
        help="report past dated references in active-plan docs, then exit",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.print_index:
        print_document_index()
        return 0
    if args.write_index:
        DOCS_INDEX.write_text(render_document_index(), encoding="utf-8")
        print(f"wrote {DOCS_INDEX.relative_to(ROOT)}")
        return 0
    if args.report_long_docs:
        report_long_docs(args.long_doc_threshold)
        return 0
    if args.report_dense_readmes:
        report_dense_readmes(args.dense_readme_threshold)
        return 0
    if args.report_compatibility_stubs:
        report_compatibility_stubs()
        return 0
    if args.report_compatibility_stub_references:
        report_compatibility_stub_references()
        return 0
    if args.report_stale_active_plans:
        report_stale_active_plans()
        return 0

    errors: list[str] = []
    check_local_links(errors)
    check_code_span_markdown_references(errors)
    check_readmes(errors)
    check_readme_structure(errors)
    check_doc_path_naming(errors)
    check_last_updated_metadata(errors)
    check_duplicate_top_metadata(errors)
    check_status_metadata(errors)
    check_owner_audience_metadata(errors)
    check_archived_title_status(errors)
    check_compatibility_stub_metadata(errors)
    check_compatibility_stub_references(errors)
    check_docs_payload_files(errors)
    check_latest_wording(errors)
    check_stale_paths(errors)
    check_canonical_type_labels(errors)
    check_markdown_fences(errors)
    check_document_index(errors)
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    print("docs structure check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
