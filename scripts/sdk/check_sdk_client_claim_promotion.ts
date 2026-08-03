#!/usr/bin/env node
import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const MODULE_DIR = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_POLICY_PATH = "spec/client-claim-promotion.current.json";
const DEFAULT_BOUNDARY_PATH = "spec/client-claim-boundary.current.json";
const DEFAULT_ATTESTATION_PATH = ".artifacts/release/release-attestation.json";

function usage() {
  return [
    "Usage:",
    "  node --experimental-strip-types " +
      "scripts/sdk/check_sdk_client_claim_promotion.ts [options] " +
      "--managed-provider-evidence <path> --admin-sdk-evidence <path> " +
      "--lane <name>=<status>",
    "",
    "Options:",
    "  --policy <path>                    Promotion policy path",
    "  --claim-boundary <path>            Default: spec/client-claim-boundary.current.json",
    "  --release-attestation <path>       Default: .artifacts/release/release-attestation.json",
    "  --managed-provider-evidence <path> Managed-provider evidence JSON",
    "  --admin-sdk-evidence <path>        Admin-console SDK evidence JSON",
    "  --lane <name>=<status>             Repeat for each lane",
    "  --report <path>                    Optional JSON report output",
  ].join("\n");
}

function parseArgs(argv) {
  const options = {
    root: process.env.AEGAEON_SDK_ROOT ?? null,
    policy: process.env.AEGAEON_CLIENT_CLAIM_PROMOTION_POLICY ?? DEFAULT_POLICY_PATH,
    claimBoundary: process.env.AEGAEON_CLIENT_CLAIM_BOUNDARY_PATH ?? DEFAULT_BOUNDARY_PATH,
    releaseAttestation: process.env.AEGAEON_RELEASE_ATTESTATION_PATH ?? DEFAULT_ATTESTATION_PATH,
    managedProviderEvidence: null,
    adminSdkEvidence: null,
    lanes: [],
    report: null,
  };

  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (token === "--") {
      continue;
    }
    if (token === "--help" || token === "-h") {
      console.log(usage());
      process.exit(0);
    }
    if (token === "--lane") {
      const value = argv[index + 1];
      if (!value || value.startsWith("--")) {
        throw new Error("Missing value for option --lane");
      }
      options.lanes.push(value);
      index += 1;
      continue;
    }
    if (!token.startsWith("--")) {
      continue;
    }
    const rawKey = token.slice(2);
    const key = rawKey.replace(/-([a-z])/g, (_, c) => c.toUpperCase());
    const value = argv[index + 1];
    if (!value || value.startsWith("--")) {
      throw new Error(`Missing value for option --${rawKey}`);
    }
    if (!(key in options)) {
      throw new Error(`Unknown option --${rawKey}`);
    }
    options[key] = value;
    index += 1;
  }

  return options;
}

function findWorkspaceRoot(explicitRoot) {
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
      return null;
    }
    current = parent;
  }
}

function resolveFromRoot(rootDir, targetPath) {
  if (path.isAbsolute(targetPath)) {
    return targetPath;
  }
  return path.resolve(rootDir, targetPath);
}

async function readJson(filePath) {
  return JSON.parse(await fs.readFile(filePath, "utf8"));
}

async function shaHex(filePath) {
  const hash = createHash("sha256");
  hash.update(await fs.readFile(filePath));
  return hash.digest("hex");
}

function parseLanes(entries) {
  const lanes = new Map();
  for (const entry of entries) {
    const separator = entry.indexOf("=");
    if (separator <= 0 || separator === entry.length - 1) {
      throw new Error(`Invalid --lane value: ${entry}`);
    }
    lanes.set(entry.slice(0, separator), entry.slice(separator + 1));
  }
  return lanes;
}

function repositoryMatches(actualRepository, expectedRepository) {
  if (typeof actualRepository !== "string" || actualRepository.length === 0) {
    return false;
  }
  if (actualRepository === expectedRepository) {
    return true;
  }
  return actualRepository.endsWith(`/${expectedRepository}`);
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  const lanes = parseLanes(options.lanes);
  if (!options.managedProviderEvidence) {
    throw new Error("--managed-provider-evidence is required");
  }
  if (!options.adminSdkEvidence) {
    throw new Error("--admin-sdk-evidence is required");
  }

  const rootDir = findWorkspaceRoot(options.root) ?? process.cwd();
  const policyPath = resolveFromRoot(rootDir, options.policy);
  const claimBoundaryPath = resolveFromRoot(rootDir, options.claimBoundary);
  const releaseAttestationPath = resolveFromRoot(rootDir, options.releaseAttestation);
  const managedProviderEvidencePath = resolveFromRoot(rootDir, options.managedProviderEvidence);
  const adminSdkEvidencePath = resolveFromRoot(rootDir, options.adminSdkEvidence);

  for (const requiredPath of [
    policyPath,
    claimBoundaryPath,
    releaseAttestationPath,
    managedProviderEvidencePath,
    adminSdkEvidencePath,
  ]) {
    if (!existsSync(requiredPath)) {
      throw new Error(`File not found: ${requiredPath}`);
    }
  }

  const [
    policy,
    claimBoundary,
    releaseAttestation,
    managedProviderEvidence,
    adminSdkEvidence,
  ] = await Promise.all([
    readJson(policyPath),
    readJson(claimBoundaryPath),
    readJson(releaseAttestationPath),
    readJson(managedProviderEvidencePath),
    readJson(adminSdkEvidencePath),
  ]);

  const failures = [];
  if (claimBoundary.claim_phase !== policy.required_boundary.claim_phase) {
    failures.push(
      `claim boundary phase mismatch: expected ` +
        `${policy.required_boundary.claim_phase}, got ` +
        claimBoundary.claim_phase,
    );
  }
  if (
    claimBoundary.released_client_claim_active !==
    policy.required_boundary.released_client_claim_active
  ) {
    failures.push("claim boundary released_client_claim_active does not match policy");
  }
  if (claimBoundary.default_profile !== policy.required_boundary.default_profile) {
    failures.push(
      `claim boundary default_profile mismatch: expected ` +
        `${policy.required_boundary.default_profile}, got ` +
        claimBoundary.default_profile,
    );
  }

  for (const sliceName of policy.required_boundary.promoted_client_slices) {
    if (!claimBoundary.promoted_client_slices.some((entry) => entry.name === sliceName)) {
      failures.push(`missing promoted client slice ${sliceName}`);
    }
  }
  for (const surfaceName of policy.required_boundary.compat_only_surfaces) {
    if (!claimBoundary.compat_only_surfaces.some((entry) => entry.name === surfaceName)) {
      failures.push(`missing compat-only surface ${surfaceName}`);
    }
  }

  if (releaseAttestation.release_phase !== policy.required_release_attestation.release_phase) {
    failures.push(
      `release attestation phase mismatch: expected ` +
        `${policy.required_release_attestation.release_phase}, got ` +
        releaseAttestation.release_phase,
    );
  }
  if (
    Boolean(releaseAttestation.publication?.npm_provenance_enabled) !==
    policy.required_release_attestation.npm_provenance_enabled
  ) {
    failures.push("release attestation npm provenance flag does not match policy");
  }

  const boundarySha = await shaHex(claimBoundaryPath);
  if (releaseAttestation.client_claim_boundary?.sha256 !== boundarySha) {
    failures.push(
      "release attestation client-claim-boundary hash does not match the supplied boundary file",
    );
  }

  for (const laneName of policy.required_lanes) {
    if (lanes.get(laneName) !== "passed") {
      failures.push(`required lane ${laneName} is not marked passed`);
    }
  }

  if (managedProviderEvidence.provider?.class !== policy.required_managed_provider.provider_class) {
    failures.push(
      `managed provider class mismatch: expected ` +
        `${policy.required_managed_provider.provider_class}, got ` +
        managedProviderEvidence.provider?.class,
    );
  }
  if (managedProviderEvidence.lane?.name !== policy.required_managed_provider.lane_name) {
    failures.push(
      `managed provider lane mismatch: expected ` +
        `${policy.required_managed_provider.lane_name}, got ` +
        managedProviderEvidence.lane?.name,
    );
  }
  if (
    Boolean(managedProviderEvidence.lane?.hosted) !==
    policy.required_managed_provider.hosted
  ) {
    failures.push("managed provider hosted flag does not match policy");
  }
  if (managedProviderEvidence.lane?.status !== policy.required_managed_provider.status) {
    failures.push(
      `managed provider status mismatch: expected ` +
        `${policy.required_managed_provider.status}, got ` +
        managedProviderEvidence.lane?.status,
    );
  }
  if (
    !repositoryMatches(
      managedProviderEvidence.source?.github_repository,
      policy.required_managed_provider.repository,
    )
  ) {
    failures.push(
      `managed provider repository mismatch: expected suffix ` +
        `${policy.required_managed_provider.repository}, got ` +
        (managedProviderEvidence.source?.github_repository ?? "missing"),
    );
  }
  if (
    managedProviderEvidence.source?.github_workflow !==
    policy.required_managed_provider.expected_workflow
  ) {
    failures.push(
      `managed provider workflow mismatch: expected ` +
        `${policy.required_managed_provider.expected_workflow}, got ` +
        (managedProviderEvidence.source?.github_workflow ?? "missing"),
    );
  }
  if (
    policy.required_managed_provider.github_ref_required &&
    !managedProviderEvidence.source?.github_ref
  ) {
    failures.push("managed provider evidence is missing github_ref provenance");
  }
  if (
    policy.required_managed_provider.github_sha_required &&
    !managedProviderEvidence.source?.github_sha
  ) {
    failures.push("managed provider evidence is missing github_sha provenance");
  }
  if (
    policy.required_managed_provider.github_job_required &&
    !managedProviderEvidence.source?.github_job
  ) {
    failures.push("managed provider evidence is missing github_job provenance");
  }
  if (
    managedProviderEvidence.source?.github_job !==
    policy.required_managed_provider.expected_job
  ) {
    failures.push(
      `managed provider job mismatch: expected ` +
        `${policy.required_managed_provider.expected_job}, got ` +
        (managedProviderEvidence.source?.github_job ?? "missing"),
    );
  }

  if (adminSdkEvidence.lane?.name !== policy.required_admin_console.lane_name) {
    failures.push(
      `admin-console lane mismatch: expected ` +
        `${policy.required_admin_console.lane_name}, got ` +
        adminSdkEvidence.lane?.name,
    );
  }
  if (adminSdkEvidence.lane?.status !== policy.required_admin_console.status) {
    failures.push(
      `admin-console status mismatch: expected ` +
        `${policy.required_admin_console.status}, got ` +
        adminSdkEvidence.lane?.status,
    );
  }
  if (
    !repositoryMatches(
      adminSdkEvidence.source?.github_repository,
      policy.required_admin_console.repository,
    )
  ) {
    failures.push(
      `admin-console repository mismatch: expected suffix ` +
        `${policy.required_admin_console.repository}, got ` +
        (adminSdkEvidence.source?.github_repository ?? "missing"),
    );
  }
  if (
    adminSdkEvidence.source?.github_workflow !==
    policy.required_admin_console.expected_workflow
  ) {
    failures.push(
      `admin-console workflow mismatch: expected ` +
        `${policy.required_admin_console.expected_workflow}, got ` +
        (adminSdkEvidence.source?.github_workflow ?? "missing"),
    );
  }
  if (policy.required_admin_console.github_ref_required && !adminSdkEvidence.source?.github_ref) {
    failures.push("admin-console evidence is missing github_ref provenance");
  }
  if (policy.required_admin_console.github_sha_required && !adminSdkEvidence.source?.github_sha) {
    failures.push("admin-console evidence is missing github_sha provenance");
  }
  if (policy.required_admin_console.github_job_required && !adminSdkEvidence.source?.github_job) {
    failures.push("admin-console evidence is missing github_job provenance");
  }
  if (
    adminSdkEvidence.source?.github_job !==
    policy.required_admin_console.expected_job
  ) {
    failures.push(
      `admin-console job mismatch: expected ` +
        `${policy.required_admin_console.expected_job}, got ` +
        (adminSdkEvidence.source?.github_job ?? "missing"),
    );
  }
  if (
    adminSdkEvidence.sdk_boundary?.management_sdk_package !==
    policy.required_admin_console.management_sdk_package
  ) {
    failures.push(
      "admin-console management SDK package mismatch: expected " +
        `${policy.required_admin_console.management_sdk_package}, got ` +
        adminSdkEvidence.sdk_boundary?.management_sdk_package,
    );
  }
  for (const capability of policy.required_admin_console.required_capabilities) {
    if (!adminSdkEvidence.capabilities?.includes(capability)) {
      failures.push(`admin-console evidence missing capability ${capability}`);
    }
  }

  const report = {
    schema_version: 1,
    generated_at: new Date().toISOString(),
    policy_path: path.relative(rootDir, policyPath),
    claim_boundary_path: path.relative(rootDir, claimBoundaryPath),
    release_attestation_path: path.relative(rootDir, releaseAttestationPath),
    managed_provider_evidence_path: path.relative(rootDir, managedProviderEvidencePath),
    admin_sdk_evidence_path: path.relative(rootDir, adminSdkEvidencePath),
    lanes: Object.fromEntries(lanes),
    ready: failures.length === 0,
    failures,
  };

  if (options.report) {
    const reportPath = path.resolve(options.report);
    await fs.mkdir(path.dirname(reportPath), { recursive: true });
    await fs.writeFile(reportPath, `${JSON.stringify(report, null, 2)}\n`, "utf8");
  }

  if (failures.length > 0) {
    for (const failure of failures) {
      console.error(`[client-claim-promotion] ${failure}`);
    }
    process.exitCode = 1;
    return;
  }

  console.log(
    `[client-claim-promotion] ${path.relative(rootDir, policyPath)} ` +
      "matches the supplied evidence",
  );
}

main().catch((error) => {
  console.error("[client-claim-promotion] error:", error instanceof Error ? error.message : error);
  process.exitCode = 1;
});
