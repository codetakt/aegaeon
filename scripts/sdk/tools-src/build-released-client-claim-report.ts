#!/usr/bin/env node
import { existsSync, promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import type {
  AdminSdkEvidenceFile,
  ClaimBoundaryFile,
  ClientClaimPromotionReportFile,
  ManagedProviderEvidenceFile,
  PublicationOrgRolloutReportFile,
  ReleaseAttestationFile,
  ReleasedClientClaimPolicyFile,
} from "./released-client-types.js";

const MODULE_DIR = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_POLICY_PATH = "spec/released-client-claim.current.json";
const DEFAULT_BOUNDARY_PATH = "spec/client-claim-boundary.current.json";
const DEFAULT_RELEASE_ATTESTATION_PATH = ".artifacts/release/release-attestation.json";
const DEFAULT_MANAGED_PROVIDER_EVIDENCE_PATH =
  ".artifacts/managed-provider/managed-provider-evidence.json";
const DEFAULT_ADMIN_SDK_EVIDENCE_PATH = ".artifacts/admin-sdk/admin-sdk-evidence.json";
const DEFAULT_PROMOTION_REPORT_PATH = ".artifacts/release/client-claim-promotion-report.json";
const DEFAULT_PUBLICATION_ORG_REPORT_PATH =
  ".artifacts/release/publication-org-rollout-report.json";
const DEFAULT_OUT_PATH = ".artifacts/release/released-client-claim-report.json";

type CliOptions = {
  root: string | null;
  policy: string;
  claimBoundary: string;
  releaseAttestation: string;
  managedProviderEvidence: string;
  adminSdkEvidence: string;
  promotionReport: string;
  publicationOrgReport: string;
  publicationOrgTasks: string[];
  out: string;
};

type PublicationOrgTaskStatus = "pending" | "done";

type ReleasedClientClaimReport = {
  schema_version: number;
  generated_at: string;
  claim_target: string;
  current_state: {
    claim_phase: string;
    released_client_claim_active: boolean;
    canonical_statement: string;
  };
  target_state: {
    claim_phase: string;
    canonical_statement: string;
    default_profile: string;
    promoted_client_slices: string[];
    compat_only_surfaces: string[];
  };
  evidence: {
    claim_boundary_path: string;
    release_attestation_path: string;
    promotion_report_path: string | null;
    managed_provider_evidence_path: string | null;
    managed_provider_evidence_age_hours: number | null;
    managed_provider_lane_name: string | null;
    managed_provider_source_repository: string | null;
    managed_provider_source_ref: string | null;
    managed_provider_source_workflow: string | null;
    managed_provider_source_job: string | null;
    managed_provider_github_run_id_present: boolean;
    managed_provider_github_sha_present: boolean;
    admin_sdk_evidence_path: string | null;
    admin_sdk_evidence_age_hours: number | null;
    admin_sdk_lane_name: string | null;
    admin_sdk_source_repository: string | null;
    admin_sdk_source_ref: string | null;
    admin_sdk_source_workflow: string | null;
    admin_sdk_source_job: string | null;
    admin_sdk_github_run_id_present: boolean;
    admin_sdk_github_sha_present: boolean;
    promotion_report_ready: boolean;
    managed_provider_evidence_present: boolean;
    admin_sdk_evidence_present: boolean;
    signed_release_attestation_present: boolean;
    sbom_publication_present: boolean;
  };
  publication_org_tasks: { name: string; status: PublicationOrgTaskStatus }[];
  ready: boolean;
  blockers: string[];
};

function usage(): string {
  return [
    "Usage:",
    "  node dist-tools/build-released-client-claim-report.js [options]",
    "",
    "Options:",
    "  --root <sdk-root>                    Workspace root (autodetected when omitted)",
    "  --policy <path>                     Default: spec/released-client-claim.current.json",
    "  --claim-boundary <path>             Default: spec/client-claim-boundary.current.json",
    "  --release-attestation <path>        Default: .artifacts/release/release-attestation.json",
    "  --managed-provider-evidence <path>  " +
      "Default: .artifacts/managed-provider/managed-provider-evidence.json",
    "  --admin-sdk-evidence <path>         Default: .artifacts/admin-sdk/admin-sdk-evidence.json",
    "  --promotion-report <path>           " +
      "Default: .artifacts/release/client-claim-promotion-report.json",
    "  --publication-org-report <path>     " +
      "Default: .artifacts/release/publication-org-rollout-report.json",
    "  --publication-org-task <name>=<status>  Repeat; status is pending|done",
    "  --out <path>                        " +
      "Default: .artifacts/release/released-client-claim-report.json",
  ].join("\n");
}

function parseArgs(argv: string[]): CliOptions {
  const options: CliOptions = {
    root: process.env.AEGAEON_SDK_ROOT ?? null,
    policy: process.env.AEGAEON_RELEASED_CLIENT_CLAIM_POLICY_PATH ?? DEFAULT_POLICY_PATH,
    claimBoundary: process.env.AEGAEON_CLIENT_CLAIM_BOUNDARY_PATH ?? DEFAULT_BOUNDARY_PATH,
    releaseAttestation:
      process.env.AEGAEON_RELEASE_ATTESTATION_PATH ??
      DEFAULT_RELEASE_ATTESTATION_PATH,
    managedProviderEvidence:
      process.env.AEGAEON_MANAGED_PROVIDER_EVIDENCE_PATH ??
      DEFAULT_MANAGED_PROVIDER_EVIDENCE_PATH,
    adminSdkEvidence:
      process.env.AEGAEON_ADMIN_SDK_EVIDENCE_PATH ??
      DEFAULT_ADMIN_SDK_EVIDENCE_PATH,
    promotionReport:
      process.env.AEGAEON_CLIENT_CLAIM_PROMOTION_REPORT_PATH ??
      DEFAULT_PROMOTION_REPORT_PATH,
    publicationOrgReport:
      process.env.AEGAEON_PUBLICATION_ORG_ROLLOUT_REPORT_PATH ??
      DEFAULT_PUBLICATION_ORG_REPORT_PATH,
    publicationOrgTasks: [],
    out: process.env.AEGAEON_RELEASED_CLIENT_CLAIM_REPORT_OUT ?? DEFAULT_OUT_PATH,
  };

  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (!token) {
      continue;
    }
    if (token === "--") {
      continue;
    }
    if (token === "--help" || token === "-h") {
      console.log(usage());
      process.exit(0);
    }
    if (!token.startsWith("--")) {
      continue;
    }
    if (token === "--publication-org-task") {
      const value = argv[index + 1];
      if (!value || value.startsWith("--")) {
        throw new Error("Missing value for option --publication-org-task");
      }
      options.publicationOrgTasks.push(value);
      index += 1;
      continue;
    }
    const value = argv[index + 1];
    if (!value || value.startsWith("--")) {
      throw new Error(`Missing value for option ${token}`);
    }
    switch (token) {
      case "--root":
        options.root = value;
        break;
      case "--policy":
        options.policy = value;
        break;
      case "--claim-boundary":
        options.claimBoundary = value;
        break;
      case "--release-attestation":
        options.releaseAttestation = value;
        break;
      case "--managed-provider-evidence":
        options.managedProviderEvidence = value;
        break;
      case "--admin-sdk-evidence":
        options.adminSdkEvidence = value;
        break;
      case "--promotion-report":
        options.promotionReport = value;
        break;
      case "--publication-org-report":
        options.publicationOrgReport = value;
        break;
      case "--out":
        options.out = value;
        break;
      default:
        throw new Error(`Unknown option ${token}`);
    }
    index += 1;
  }

  return options;
}

function findWorkspaceRoot(explicitRoot: string | null): string {
  if (explicitRoot) {
    return path.resolve(explicitRoot);
  }
  let current = path.resolve(MODULE_DIR);
  while (true) {
    if (
      existsSync(path.join(current, "package.json")) &&
      existsSync(path.join(current, "packages"))
    ) {
      return current;
    }
    const parent = path.dirname(current);
    if (parent === current) {
      throw new Error("Could not locate sdk workspace root");
    }
    current = parent;
  }
}

function resolveWithinRoot(rootDir: string, targetPath: string): string {
  return path.isAbsolute(targetPath) ? targetPath : path.resolve(rootDir, targetPath);
}

async function readJson<T>(filePath: string): Promise<T> {
  return JSON.parse(await fs.readFile(filePath, "utf8")) as T;
}

async function loadOptionalJson<T>(filePath: string): Promise<T | null> {
  try {
    return await readJson<T>(filePath);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return null;
    }
    throw error;
  }
}

function parsePublicationOrgTasks(entries: string[]): Map<string, PublicationOrgTaskStatus> {
  const statuses = new Map<string, PublicationOrgTaskStatus>();
  for (const entry of entries) {
    const separator = entry.indexOf("=");
    if (separator <= 0 || separator === entry.length - 1) {
      throw new Error(`Invalid --publication-org-task value: ${entry}`);
    }
    const name = entry.slice(0, separator);
    const status = entry.slice(separator + 1);
    if (status !== "pending" && status !== "done") {
      throw new Error(`Unsupported publication-org task status for ${name}: ${status}`);
    }
    statuses.set(name, status);
  }
  return statuses;
}

function parseIsoTimestamp(
  value: string | null | undefined,
  label: string,
  blockers: string[],
): Date | null {
  if (typeof value !== "string" || value.length === 0) {
    blockers.push(`${label} is missing generated_at`);
    return null;
  }
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    blockers.push(`${label} has an invalid generated_at timestamp`);
    return null;
  }
  return parsed;
}

function computeEvidenceAgeHours(
  timestamp: Date | null,
  now: Date,
  label: string,
  blockers: string[],
): number | null {
  if (!timestamp) {
    return null;
  }
  const ageMs = now.getTime() - timestamp.getTime();
  if (ageMs < -5 * 60 * 1000) {
    blockers.push(`${label} generated_at is in the future`);
    return null;
  }
  return Number((Math.max(ageMs, 0) / (60 * 60 * 1000)).toFixed(3));
}

function repositoryMatches(
  actualRepository: string | null | undefined,
  expectedRepository: string,
): boolean {
  if (typeof actualRepository !== "string" || actualRepository.length === 0) {
    return false;
  }
  if (actualRepository === expectedRepository) {
    return true;
  }
  return actualRepository.endsWith(`/${expectedRepository}`);
}

async function main(): Promise<void> {
  const options = parseArgs(process.argv.slice(2));
  const rootDir = findWorkspaceRoot(options.root);
  const policyPath = resolveWithinRoot(rootDir, options.policy);
  const claimBoundaryPath = resolveWithinRoot(rootDir, options.claimBoundary);
  const releaseAttestationPath = resolveWithinRoot(rootDir, options.releaseAttestation);
  const managedProviderEvidencePath = resolveWithinRoot(rootDir, options.managedProviderEvidence);
  const adminSdkEvidencePath = resolveWithinRoot(rootDir, options.adminSdkEvidence);
  const promotionReportPath = resolveWithinRoot(rootDir, options.promotionReport);
  const publicationOrgReportPath = resolveWithinRoot(rootDir, options.publicationOrgReport);
  const outPath = resolveWithinRoot(rootDir, options.out);

  const [
    policy,
    claimBoundary,
    releaseAttestation,
    managedProviderEvidence,
    adminSdkEvidence,
    promotionReport,
    publicationOrgReport,
  ] =
    await Promise.all([
      readJson<ReleasedClientClaimPolicyFile>(policyPath),
      readJson<ClaimBoundaryFile>(claimBoundaryPath),
      readJson<ReleaseAttestationFile>(releaseAttestationPath),
      loadOptionalJson<ManagedProviderEvidenceFile>(managedProviderEvidencePath),
      loadOptionalJson<AdminSdkEvidenceFile>(adminSdkEvidencePath),
      loadOptionalJson<ClientClaimPromotionReportFile>(promotionReportPath),
      loadOptionalJson<PublicationOrgRolloutReportFile>(publicationOrgReportPath),
    ]);

  const blockers: string[] = [];
  const now = new Date();

  if (claimBoundary.claim_phase !== policy.current_state.claim_phase) {
    blockers.push(
      `claim boundary phase mismatch: expected ` +
        `${policy.current_state.claim_phase}, got ` +
        claimBoundary.claim_phase,
    );
  }
  if (
    claimBoundary.released_client_claim_active !==
    policy.current_state.released_client_claim_active
  ) {
    blockers.push(
      "claim boundary released_client_claim_active does not match the released-claim policy",
    );
  }
  if (claimBoundary.default_profile !== policy.target_state.default_profile) {
    blockers.push(
      `claim boundary default_profile mismatch: expected ` +
        `${policy.target_state.default_profile}, got ` +
        claimBoundary.default_profile,
    );
  }
  for (const sliceName of policy.target_state.promoted_client_slices) {
    if (!claimBoundary.promoted_client_slices.some((entry) => entry.name === sliceName)) {
      blockers.push(`missing promoted client slice ${sliceName}`);
    }
  }
  for (const surfaceName of policy.target_state.compat_only_surfaces) {
    if (!claimBoundary.compat_only_surfaces.some((entry) => entry.name === surfaceName)) {
      blockers.push(`missing compat-only surface ${surfaceName}`);
    }
  }

  const promotionReportReady = Boolean(promotionReport?.ready);
  if (policy.activation_requirements.promotion_report_ready && !promotionReportReady) {
    if (
      promotionReport &&
      Array.isArray(promotionReport.failures) &&
      promotionReport.failures.length > 0
    ) {
      for (const failure of promotionReport.failures) {
        blockers.push(`promotion gate: ${failure}`);
      }
    } else {
      blockers.push("promotion gate report is missing or not ready");
    }
  }

  const managedProviderEvidencePresent = Boolean(managedProviderEvidence);
  if (
    policy.activation_requirements.managed_provider_evidence_required &&
    !managedProviderEvidencePresent
  ) {
    blockers.push("managed-provider evidence is missing");
  }
  if (managedProviderEvidencePresent && managedProviderEvidence) {
    if (managedProviderEvidence.provider?.class !== "commercial") {
      blockers.push("managed-provider evidence does not describe a commercial provider");
    }
    if (
      managedProviderEvidence.lane?.name !==
      policy.activation_requirements.managed_provider_expected_lane
    ) {
      blockers.push(
        `managed-provider evidence lane mismatch: expected ` +
          `${policy.activation_requirements.managed_provider_expected_lane}, got ` +
          (managedProviderEvidence.lane?.name ?? "missing"),
      );
    }
    if (managedProviderEvidence.lane?.hosted !== true) {
      blockers.push("managed-provider evidence does not record a hosted lane");
    }
    if (managedProviderEvidence.lane?.status !== "passed") {
      blockers.push(
        `managed-provider lane status is not passed: ` +
          (managedProviderEvidence.lane?.status ?? "missing"),
      );
    }
    if (
      policy.activation_requirements.managed_provider_hosted_provenance_required &&
      !managedProviderEvidence.source?.github_run_id
    ) {
      blockers.push("managed-provider evidence is missing hosted GitHub run provenance");
    }
    if (
      policy.activation_requirements.managed_provider_hosted_provenance_required &&
      managedProviderEvidence.source?.github_workflow !==
        policy.activation_requirements.managed_provider_expected_workflow
    ) {
      blockers.push(
        `managed-provider evidence workflow mismatch: expected ` +
          `${policy.activation_requirements.managed_provider_expected_workflow}, got ` +
          (managedProviderEvidence.source?.github_workflow ?? "missing"),
      );
    }
    if (
      policy.activation_requirements.managed_provider_hosted_provenance_required &&
      !repositoryMatches(
        managedProviderEvidence.source?.github_repository,
        policy.activation_requirements.managed_provider_expected_repository,
      )
    ) {
      blockers.push(
        `managed-provider evidence repository mismatch: expected suffix ` +
          `${policy.activation_requirements.managed_provider_expected_repository}, got ` +
          (managedProviderEvidence.source?.github_repository ?? "missing"),
      );
    }
    if (
      policy.activation_requirements.managed_provider_github_ref_required &&
      !managedProviderEvidence.source?.github_ref
    ) {
      blockers.push("managed-provider evidence is missing github_ref provenance");
    }
    if (
      policy.activation_requirements.managed_provider_github_sha_required &&
      !managedProviderEvidence.source?.github_sha
    ) {
      blockers.push("managed-provider evidence is missing github_sha provenance");
    }
    if (
      policy.activation_requirements.managed_provider_github_job_required &&
      !managedProviderEvidence.source?.github_job
    ) {
      blockers.push("managed-provider evidence is missing github_job provenance");
    }
    if (
      policy.activation_requirements.managed_provider_github_job_required &&
      managedProviderEvidence.source?.github_job !==
        policy.activation_requirements.managed_provider_expected_job
    ) {
      blockers.push(
        `managed-provider evidence job mismatch: expected ` +
          `${policy.activation_requirements.managed_provider_expected_job}, got ` +
          (managedProviderEvidence.source?.github_job ?? "missing"),
      );
    }
  }
  const managedProviderEvidenceGeneratedAt =
    managedProviderEvidencePresent && managedProviderEvidence
    ? parseIsoTimestamp(managedProviderEvidence.generated_at, "managed-provider evidence", blockers)
    : null;
  const managedProviderEvidenceAgeHours = managedProviderEvidencePresent
    ? computeEvidenceAgeHours(
        managedProviderEvidenceGeneratedAt,
        now,
        "managed-provider evidence",
        blockers,
      )
    : null;
  if (
    managedProviderEvidencePresent &&
    managedProviderEvidenceAgeHours !== null &&
    managedProviderEvidenceAgeHours >
      policy.activation_requirements.managed_provider_evidence_max_age_hours
  ) {
    blockers.push(
      `managed-provider evidence is older than ` +
        `${policy.activation_requirements.managed_provider_evidence_max_age_hours} ` +
        `hours (${managedProviderEvidenceAgeHours}h)`,
    );
  }

  const adminSdkEvidencePresent = Boolean(adminSdkEvidence);
  if (policy.activation_requirements.admin_sdk_evidence_required && !adminSdkEvidencePresent) {
    blockers.push("admin-console SDK evidence is missing");
  }
  if (adminSdkEvidencePresent && adminSdkEvidence) {
    if (
      adminSdkEvidence.lane?.name !==
      policy.activation_requirements.admin_sdk_expected_lane
    ) {
      blockers.push(
        `admin-console SDK evidence lane mismatch: expected ` +
          `${policy.activation_requirements.admin_sdk_expected_lane}, got ` +
          (adminSdkEvidence.lane?.name ?? "missing"),
      );
    }
    if (adminSdkEvidence.lane?.status !== "passed") {
      blockers.push(
        `admin-console lane status is not passed: ` +
          (adminSdkEvidence.lane?.status ?? "missing"),
      );
    }
    if (adminSdkEvidence.sdk_boundary?.management_sdk_package !== "@aegaeon/management-client") {
      blockers.push("admin-console evidence does not point at @aegaeon/management-client");
    }
    if (
      policy.activation_requirements.admin_sdk_hosted_provenance_required &&
      !adminSdkEvidence.source?.github_run_id
    ) {
      blockers.push("admin-console SDK evidence is missing hosted GitHub run provenance");
    }
    if (
      policy.activation_requirements.admin_sdk_hosted_provenance_required &&
      adminSdkEvidence.source?.github_workflow !==
        policy.activation_requirements.admin_sdk_expected_workflow
    ) {
      blockers.push(
        `admin-console SDK evidence workflow mismatch: expected ` +
          `${policy.activation_requirements.admin_sdk_expected_workflow}, got ` +
          (adminSdkEvidence.source?.github_workflow ?? "missing"),
      );
    }
    if (
      policy.activation_requirements.admin_sdk_hosted_provenance_required &&
      !repositoryMatches(
        adminSdkEvidence.source?.github_repository,
        policy.activation_requirements.admin_sdk_expected_repository,
      )
    ) {
      blockers.push(
        `admin-console SDK evidence repository mismatch: expected suffix ` +
          `${policy.activation_requirements.admin_sdk_expected_repository}, got ` +
          (adminSdkEvidence.source?.github_repository ?? "missing"),
      );
    }
    if (
      policy.activation_requirements.admin_sdk_github_ref_required &&
      !adminSdkEvidence.source?.github_ref
    ) {
      blockers.push("admin-console SDK evidence is missing github_ref provenance");
    }
    if (
      policy.activation_requirements.admin_sdk_github_sha_required &&
      !adminSdkEvidence.source?.github_sha
    ) {
      blockers.push("admin-console SDK evidence is missing github_sha provenance");
    }
    if (
      policy.activation_requirements.admin_sdk_github_job_required &&
      !adminSdkEvidence.source?.github_job
    ) {
      blockers.push("admin-console SDK evidence is missing github_job provenance");
    }
    if (
      policy.activation_requirements.admin_sdk_github_job_required &&
      adminSdkEvidence.source?.github_job !==
        policy.activation_requirements.admin_sdk_expected_job
    ) {
      blockers.push(
        `admin-console SDK evidence job mismatch: expected ` +
          `${policy.activation_requirements.admin_sdk_expected_job}, got ` +
          (adminSdkEvidence.source?.github_job ?? "missing"),
      );
    }
  }
  const adminSdkEvidenceGeneratedAt =
    adminSdkEvidencePresent && adminSdkEvidence
    ? parseIsoTimestamp(adminSdkEvidence.generated_at, "admin-console SDK evidence", blockers)
    : null;
  const adminSdkEvidenceAgeHours = adminSdkEvidencePresent
    ? computeEvidenceAgeHours(
        adminSdkEvidenceGeneratedAt,
        now,
        "admin-console SDK evidence",
        blockers,
      )
    : null;
  if (
    adminSdkEvidencePresent &&
    adminSdkEvidenceAgeHours !== null &&
    adminSdkEvidenceAgeHours > policy.activation_requirements.admin_sdk_evidence_max_age_hours
  ) {
    blockers.push(
      `admin-console SDK evidence is older than ` +
        `${policy.activation_requirements.admin_sdk_evidence_max_age_hours} ` +
        `hours (${adminSdkEvidenceAgeHours}h)`,
    );
  }

  const signedReleaseAttestationPresent = Boolean(
    releaseAttestation.publication?.signed_release_attestation_present,
  );
  if (
    policy.activation_requirements.signed_release_attestation_required &&
    !signedReleaseAttestationPresent
  ) {
    blockers.push("signed release attestation is not present");
  }

  const sbomPublicationPresent = Boolean(releaseAttestation.publication?.sbom_publication_present);
  if (policy.activation_requirements.sbom_publication_required && !sbomPublicationPresent) {
    blockers.push("release attestation does not record SBOM publication");
  }

  const publicationOrgStatuses = parsePublicationOrgTasks(options.publicationOrgTasks);
  if (publicationOrgStatuses.size === 0 && publicationOrgReport?.tasks) {
    for (const task of publicationOrgReport.tasks) {
      if (
        task &&
        typeof task.name === "string" &&
        (task.status === "pending" || task.status === "done")
      ) {
        publicationOrgStatuses.set(task.name, task.status);
      }
    }
  }
  const publicationOrgTasks = policy.required_publication_org_tasks.map((name) => ({
    name,
    status: publicationOrgStatuses.get(name) ?? "pending",
  }));
  if (policy.activation_requirements.publication_org_tasks_must_be_done) {
    for (const task of publicationOrgTasks) {
      if (task.status !== "done") {
        blockers.push(`publication-org task still pending: ${task.name}`);
      }
    }
  }

  const report: ReleasedClientClaimReport = {
    schema_version: 1,
    generated_at: new Date().toISOString(),
    claim_target: policy.claim_target,
    current_state: {
      claim_phase: policy.current_state.claim_phase,
      released_client_claim_active: policy.current_state.released_client_claim_active,
      canonical_statement: policy.current_state.canonical_statement,
    },
    target_state: {
      claim_phase: policy.target_state.claim_phase,
      canonical_statement: policy.target_state.canonical_statement,
      default_profile: policy.target_state.default_profile,
      promoted_client_slices: [...policy.target_state.promoted_client_slices],
      compat_only_surfaces: [...policy.target_state.compat_only_surfaces],
    },
    evidence: {
      claim_boundary_path: path.relative(rootDir, claimBoundaryPath),
      release_attestation_path: path.relative(rootDir, releaseAttestationPath),
      promotion_report_path: promotionReport
        ? path.relative(rootDir, promotionReportPath)
        : null,
      managed_provider_evidence_path: managedProviderEvidence
        ? path.relative(rootDir, managedProviderEvidencePath)
        : null,
      managed_provider_evidence_age_hours: managedProviderEvidenceAgeHours,
      managed_provider_lane_name: managedProviderEvidence?.lane?.name ?? null,
      managed_provider_source_repository:
        managedProviderEvidence?.source?.github_repository ?? null,
      managed_provider_source_ref: managedProviderEvidence?.source?.github_ref ?? null,
      managed_provider_source_workflow: managedProviderEvidence?.source?.github_workflow ?? null,
      managed_provider_source_job: managedProviderEvidence?.source?.github_job ?? null,
      managed_provider_github_run_id_present: Boolean(
        managedProviderEvidence?.source?.github_run_id,
      ),
      managed_provider_github_sha_present: Boolean(managedProviderEvidence?.source?.github_sha),
      admin_sdk_evidence_path: adminSdkEvidence
        ? path.relative(rootDir, adminSdkEvidencePath)
        : null,
      admin_sdk_evidence_age_hours: adminSdkEvidenceAgeHours,
      admin_sdk_lane_name: adminSdkEvidence?.lane?.name ?? null,
      admin_sdk_source_repository: adminSdkEvidence?.source?.github_repository ?? null,
      admin_sdk_source_ref: adminSdkEvidence?.source?.github_ref ?? null,
      admin_sdk_source_workflow: adminSdkEvidence?.source?.github_workflow ?? null,
      admin_sdk_source_job: adminSdkEvidence?.source?.github_job ?? null,
      admin_sdk_github_run_id_present: Boolean(adminSdkEvidence?.source?.github_run_id),
      admin_sdk_github_sha_present: Boolean(adminSdkEvidence?.source?.github_sha),
      promotion_report_ready: promotionReportReady,
      managed_provider_evidence_present: managedProviderEvidencePresent,
      admin_sdk_evidence_present: adminSdkEvidencePresent,
      signed_release_attestation_present: signedReleaseAttestationPresent,
      sbom_publication_present: sbomPublicationPresent,
    },
    publication_org_tasks: publicationOrgTasks,
    ready: blockers.length === 0,
    blockers,
  };

  await fs.mkdir(path.dirname(outPath), { recursive: true });
  await fs.writeFile(outPath, `${JSON.stringify(report, null, 2)}\n`, "utf8");
  console.log(`[build-released-client-claim-report] wrote ${path.relative(rootDir, outPath)}`);
}

main().catch((error) => {
  console.error(
    "[build-released-client-claim-report] error:",
    error instanceof Error ? error.message : error,
  );
  process.exitCode = 1;
});
