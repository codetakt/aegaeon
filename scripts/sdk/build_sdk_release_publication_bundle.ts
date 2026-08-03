#!/usr/bin/env node
import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const MODULE_DIR = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_PUBLISH_MANIFEST_PATH = ".artifacts/release/publish-manifest.json";
const DEFAULT_RELEASE_ATTESTATION_PATH = ".artifacts/release/release-attestation.json";
const DEFAULT_RELEASE_ATTESTATION_SIGNATURE_DESCRIPTOR_PATH =
  ".artifacts/release/release-attestation.signature.json";
const DEFAULT_WORKSPACE_SBOM_PATH = ".artifacts/release/sdk-workspace-sbom.cdx.json";
const DEFAULT_MANAGED_PROVIDER_EVIDENCE_PATH =
  ".artifacts/managed-provider/managed-provider-evidence.json";
const DEFAULT_ADMIN_SDK_EVIDENCE_PATH =
  ".artifacts/admin-sdk/admin-sdk-evidence.json";
const DEFAULT_CLIENT_CLAIM_PROMOTION_REPORT_PATH =
  ".artifacts/release/client-claim-promotion-report.json";
const DEFAULT_RELEASED_CLIENT_CLAIM_REPORT_PATH =
  ".artifacts/release/released-client-claim-report.json";
const DEFAULT_OUT_PATH = ".artifacts/release/release-publication-bundle.json";

function usage() {
  return [
    "Usage:",
    "  node --experimental-strip-types " +
      "scripts/sdk/build_sdk_release_publication_bundle.ts [options]",
    "",
    "Options:",
    "  --root <sdk-root>                   Workspace root (autodetected when omitted)",
    "  --publish-manifest <path>           Default: .artifacts/release/publish-manifest.json",
    "  --release-attestation <path>        Default: .artifacts/release/release-attestation.json",
    "  --release-attestation-signature <path>  " +
      "Default: .artifacts/release/release-attestation.signature.json",
    "  --workspace-sbom <path>             Default: .artifacts/release/sdk-workspace-sbom.cdx.json",
    "  --managed-provider-evidence <path>  " +
      "Default: .artifacts/managed-provider/managed-provider-evidence.json",
    "  --admin-sdk-evidence <path>         Default: .artifacts/admin-sdk/admin-sdk-evidence.json",
    "  --client-claim-promotion-report <path>  " +
      "Default: .artifacts/release/client-claim-promotion-report.json",
    "  --released-client-claim-report <path>  " +
      "Default: .artifacts/release/released-client-claim-report.json",
    "  --out <path>                        " +
      "Default: .artifacts/release/release-publication-bundle.json",
  ].join("\n");
}

function parseArgs(argv) {
  const options = {
    root: process.env.AEGAEON_SDK_ROOT ?? null,
    publishManifest: process.env.AEGAEON_PUBLISH_MANIFEST_PATH ?? DEFAULT_PUBLISH_MANIFEST_PATH,
    releaseAttestation:
      process.env.AEGAEON_RELEASE_ATTESTATION_PATH ??
      DEFAULT_RELEASE_ATTESTATION_PATH,
    releaseAttestationSignature:
      process.env.AEGAEON_RELEASE_ATTESTATION_SIGNATURE_DESCRIPTOR_OUT ??
      DEFAULT_RELEASE_ATTESTATION_SIGNATURE_DESCRIPTOR_PATH,
    workspaceSbom: process.env.AEGAEON_SDK_WORKSPACE_SBOM_PATH ?? DEFAULT_WORKSPACE_SBOM_PATH,
    managedProviderEvidence:
      process.env.AEGAEON_MANAGED_PROVIDER_EVIDENCE_PATH ??
      DEFAULT_MANAGED_PROVIDER_EVIDENCE_PATH,
    adminSdkEvidence:
      process.env.AEGAEON_ADMIN_SDK_EVIDENCE_PATH ??
      DEFAULT_ADMIN_SDK_EVIDENCE_PATH,
    clientClaimPromotionReport:
      process.env.AEGAEON_CLIENT_CLAIM_PROMOTION_REPORT_PATH ??
      DEFAULT_CLIENT_CLAIM_PROMOTION_REPORT_PATH,
    releasedClientClaimReport:
      process.env.AEGAEON_RELEASED_CLIENT_CLAIM_REPORT_PATH ??
      DEFAULT_RELEASED_CLIENT_CLAIM_REPORT_PATH,
    out: process.env.AEGAEON_RELEASE_PUBLICATION_BUNDLE_OUT ?? DEFAULT_OUT_PATH,
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
    if (!token.startsWith("--")) {
      continue;
    }
    const rawKey = token.slice(2);
    const key = rawKey.replace(/-([a-z])/g, (_, char) => char.toUpperCase());
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

function resolveWithinRoot(rootDir, targetPath) {
  return path.isAbsolute(targetPath) ? targetPath : path.resolve(rootDir, targetPath);
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
      throw new Error("Could not locate sdk workspace root");
    }
    current = parent;
  }
}

async function readJson(filePath) {
  return JSON.parse(await fs.readFile(filePath, "utf8"));
}

async function shaHex(filePath) {
  const hash = createHash("sha256");
  hash.update(await fs.readFile(filePath));
  return hash.digest("hex");
}

async function loadOptionalJson(filePath) {
  try {
    return await readJson(filePath);
  } catch (error) {
    if (error && error.code === "ENOENT") {
      return null;
    }
    throw error;
  }
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  const rootDir = findWorkspaceRoot(options.root);
  const publishManifestPath = resolveWithinRoot(rootDir, options.publishManifest);
  const releaseAttestationPath = resolveWithinRoot(rootDir, options.releaseAttestation);
  const releaseAttestationSignaturePath = resolveWithinRoot(
    rootDir,
    options.releaseAttestationSignature,
  );
  const workspaceSbomPath = resolveWithinRoot(rootDir, options.workspaceSbom);
  const managedProviderEvidencePath = resolveWithinRoot(rootDir, options.managedProviderEvidence);
  const adminSdkEvidencePath = resolveWithinRoot(rootDir, options.adminSdkEvidence);
  const clientClaimPromotionReportPath = resolveWithinRoot(
    rootDir,
    options.clientClaimPromotionReport,
  );
  const releasedClientClaimReportPath = resolveWithinRoot(
    rootDir,
    options.releasedClientClaimReport,
  );
  const outPath = resolveWithinRoot(rootDir, options.out);

  const publishManifest = await readJson(publishManifestPath);
  const releaseAttestation = await readJson(releaseAttestationPath);
  const releaseAttestationSignature = await loadOptionalJson(releaseAttestationSignaturePath);
  const workspaceSbom = await readJson(workspaceSbomPath);
  const managedProviderEvidence = await loadOptionalJson(managedProviderEvidencePath);
  const adminSdkEvidence = await loadOptionalJson(adminSdkEvidencePath);
  const clientClaimPromotionReport = await loadOptionalJson(clientClaimPromotionReportPath);
  const releasedClientClaimReport = await loadOptionalJson(releasedClientClaimReportPath);

  if (workspaceSbom.bomFormat !== "CycloneDX") {
    throw new Error("Workspace SBOM must be a CycloneDX document");
  }
  if (
    releaseAttestation.publication?.signed_release_attestation_present &&
    !releaseAttestationSignature
  ) {
    throw new Error("Release attestation is marked signed but no signature descriptor was found");
  }
  if (
    !releaseAttestation.publication?.signed_release_attestation_present &&
    releaseAttestationSignature
  ) {
    throw new Error(
      "Release attestation signature descriptor exists but " +
        "attestation is marked unsigned",
    );
  }

  const bundle = {
    schema_version: 1,
    generated_at: new Date().toISOString(),
    release_phase: releaseAttestation.release_phase,
    source: {
      github_ref: releaseAttestation.source.github_ref,
      github_sha: releaseAttestation.source.github_sha,
      github_run_id: releaseAttestation.source.github_run_id,
      github_workflow: releaseAttestation.source.github_workflow,
      npm_dist_tag: releaseAttestation.source.npm_dist_tag,
    },
    publish_manifest: {
      path: path.relative(rootDir, publishManifestPath),
      sha256: await shaHex(publishManifestPath),
      tarball_count: Array.isArray(publishManifest.tarballs) ? publishManifest.tarballs.length : 0,
    },
    release_attestation: {
      path: path.relative(rootDir, releaseAttestationPath),
      sha256: await shaHex(releaseAttestationPath),
      npm_provenance_enabled: releaseAttestation.publication.npm_provenance_enabled,
      signed_release_attestation_present:
        releaseAttestation.publication.signed_release_attestation_present,
      sbom_publication_present: releaseAttestation.publication.sbom_publication_present,
      deferred_requirements: [...releaseAttestation.deferred_requirements],
    },
    release_attestation_signature: releaseAttestationSignature
      ? {
          path: path.relative(rootDir, releaseAttestationSignaturePath),
          sha256: await shaHex(releaseAttestationSignaturePath),
          signature_path: releaseAttestationSignature.signature_path,
          signature_sha256: releaseAttestationSignature.signature_sha256,
          public_key_path: releaseAttestationSignature.public_key_path,
          public_key_sha256: releaseAttestationSignature.public_key_sha256,
          signature_algorithm: releaseAttestationSignature.signature_algorithm,
          key_type: releaseAttestationSignature.key_type,
          signer_source: releaseAttestationSignature.signer_source,
        }
      : null,
    workspace_sbom: {
      path: path.relative(rootDir, workspaceSbomPath),
      sha256: await shaHex(workspaceSbomPath),
      bom_format: workspaceSbom.bomFormat,
      spec_version: workspaceSbom.specVersion,
      component_count: Array.isArray(workspaceSbom.components)
        ? workspaceSbom.components.length
        : 0,
      serial_number: workspaceSbom.serialNumber ?? null,
    },
    verified_core: {
      manifest_path: releaseAttestation.verified_core.manifest_path,
      manifest_sha256: releaseAttestation.verified_core.manifest_sha256,
      handoff_manifest_path: releaseAttestation.verified_core.handoff_manifest_path,
      handoff_manifest_sha256: releaseAttestation.verified_core.handoff_manifest_sha256,
    },
    managed_provider_evidence: managedProviderEvidence
      ? {
          path: path.relative(rootDir, managedProviderEvidencePath),
          sha256: await shaHex(managedProviderEvidencePath),
          lane_name: managedProviderEvidence.lane?.name ?? null,
          provider_slug:
            managedProviderEvidence.provider?.slug ??
            managedProviderEvidence.provider?.name ??
            null,
          provider_class:
            managedProviderEvidence.provider?.provider_class ??
            managedProviderEvidence.provider?.class ??
            null,
          hosted:
            managedProviderEvidence.environment?.hosted ??
            managedProviderEvidence.lane?.hosted ??
            null,
          status:
            managedProviderEvidence.result?.status ??
            managedProviderEvidence.lane?.status ??
            null,
        }
      : null,
    admin_sdk_evidence: adminSdkEvidence
      ? {
          path: path.relative(rootDir, adminSdkEvidencePath),
          sha256: await shaHex(adminSdkEvidencePath),
          lane_name: adminSdkEvidence.lane?.name ?? null,
          stack_mode: adminSdkEvidence.lane?.stack_mode ?? null,
          management_sdk_package: adminSdkEvidence.sdk_boundary?.management_sdk_package ?? null,
          capability_count: Array.isArray(adminSdkEvidence.capabilities)
            ? adminSdkEvidence.capabilities.length
            : 0,
        }
      : null,
    client_claim_promotion: clientClaimPromotionReport
      ? {
          path: path.relative(rootDir, clientClaimPromotionReportPath),
          sha256: await shaHex(clientClaimPromotionReportPath),
          ready: Boolean(clientClaimPromotionReport.ready),
          failure_count: Array.isArray(clientClaimPromotionReport.failures)
            ? clientClaimPromotionReport.failures.length
            : 0,
          failures: Array.isArray(clientClaimPromotionReport.failures)
            ? clientClaimPromotionReport.failures.filter((entry) => typeof entry === "string")
            : [],
        }
      : null,
    released_client_claim_report: releasedClientClaimReport
      ? {
          path: path.relative(rootDir, releasedClientClaimReportPath),
          sha256: await shaHex(releasedClientClaimReportPath),
          ready: Boolean(releasedClientClaimReport.ready),
          blocker_count: Array.isArray(releasedClientClaimReport.blockers)
            ? releasedClientClaimReport.blockers.length
            : 0,
          current_claim_active: Boolean(
            releasedClientClaimReport.current_state
              ?.released_client_claim_active,
          ),
          target_statement: releasedClientClaimReport.target_state?.canonical_statement ?? "",
        }
      : null,
    deferred_publication_requirements: [...releaseAttestation.deferred_requirements],
  };

  await fs.mkdir(path.dirname(outPath), { recursive: true });
  await fs.writeFile(outPath, `${JSON.stringify(bundle, null, 2)}\n`, "utf8");
  console.log(`[build-release-publication-bundle] wrote ${path.relative(rootDir, outPath)}`);
}

main().catch((error) => {
  console.error(
    "[build-release-publication-bundle] error:",
    error instanceof Error ? error.message : error,
  );
  process.exitCode = 1;
});
