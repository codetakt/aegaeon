import {
  constants,
  createHash,
  createPrivateKey,
  createPublicKey,
  sign as signBuffer,
  type KeyObject,
} from "node:crypto";
import { existsSync } from "node:fs";
import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const MODULE_DIR = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_OUT_PATH = ".artifacts/release/release-attestation.json";
const DEFAULT_PUBLISH_MANIFEST_PATH = ".artifacts/release/publish-manifest.json";
const DEFAULT_CLAIM_BOUNDARY_PATH = "spec/client-claim-boundary.current.json";
const DEFAULT_SIGNATURE_PATH = ".artifacts/release/release-attestation.sig";
const DEFAULT_PUBLIC_KEY_PATH = ".artifacts/release/release-attestation.public.pem";
const DEFAULT_SIGNATURE_DESCRIPTOR_PATH = ".artifacts/release/release-attestation.signature.json";

type ReleaseAttestationOptions = {
  root: string | null;
  publishManifest: string;
  claimBoundary: string;
  out: string;
  signature: string;
  publicKey: string;
  signatureDescriptor: string;
};

type PublishManifest = {
  source?: {
    githubRef?: unknown;
    githubSha?: unknown;
    githubRunId?: unknown;
    githubWorkflow?: unknown;
    npmDistTag?: unknown;
  };
  tarballs?: unknown[];
  verifiedCore?: {
    manifestPath?: unknown;
    manifestSha256?: unknown;
    handoffManifestPath?: unknown;
    handoffManifestSha256?: unknown;
  };
};

type NamedSurface = {
  name: string;
};

type ClientClaimBoundary = {
  claim_phase: string;
  released_client_claim_active: boolean;
  default_profile: string;
  promoted_client_slices: NamedSurface[];
  compat_only_surfaces: NamedSurface[];
};

type SignatureSelection = {
  algorithm: Parameters<typeof signBuffer>[0];
  label: string;
  key: Parameters<typeof signBuffer>[2];
};

function usage(): string {
  return [
    "Usage:",
    "  node dist-tools/build-release-attestation.js [options]",
    "",
    "Options:",
    "  --root <sdk-root>                 Workspace root (autodetected when omitted)",
    "  --publish-manifest <path>         Default: .artifacts/release/publish-manifest.json",
    "  --claim-boundary <path>           Default: spec/client-claim-boundary.current.json",
    "  --out <path>                      Default: .artifacts/release/release-attestation.json",
    "  --signature <path>                Default: .artifacts/release/release-attestation.sig",
    "  --public-key <path>               Default: .artifacts/release/release-attestation.public.pem",
    "  --signature-descriptor <path>     Default: .artifacts/release/release-attestation.signature.json",
    "",
    "Environment fallbacks:",
    "  AEGAEON_SDK_ROOT",
    "  AEGAEON_PUBLISH_MANIFEST_PATH",
    "  AEGAEON_CLIENT_CLAIM_BOUNDARY_PATH",
    "  AEGAEON_RELEASE_ATTESTATION_OUT",
    "  AEGAEON_RELEASE_ATTESTATION_SIGNATURE_OUT",
    "  AEGAEON_RELEASE_ATTESTATION_PUBLIC_KEY_OUT",
    "  AEGAEON_RELEASE_ATTESTATION_SIGNATURE_DESCRIPTOR_OUT",
    "  AEGAEON_SDK_SIGNED_RELEASE_ATTESTATION",
    "  AEGAEON_SDK_SBOM_PUBLICATION",
    "  AEGAEON_COSIGN_KEY",
    "  AEGAEON_COSIGN_KEY_PATH",
    "  AEGAEON_COSIGN_PASSWORD",
  ].join("\n");
}

function parseArgs(argv: string[]): ReleaseAttestationOptions {
  const options: ReleaseAttestationOptions = {
    root: process.env.AEGAEON_SDK_ROOT ?? null,
    publishManifest: process.env.AEGAEON_PUBLISH_MANIFEST_PATH ?? DEFAULT_PUBLISH_MANIFEST_PATH,
    claimBoundary: process.env.AEGAEON_CLIENT_CLAIM_BOUNDARY_PATH ?? DEFAULT_CLAIM_BOUNDARY_PATH,
    out: process.env.AEGAEON_RELEASE_ATTESTATION_OUT ?? DEFAULT_OUT_PATH,
    signature: process.env.AEGAEON_RELEASE_ATTESTATION_SIGNATURE_OUT ?? DEFAULT_SIGNATURE_PATH,
    publicKey: process.env.AEGAEON_RELEASE_ATTESTATION_PUBLIC_KEY_OUT ?? DEFAULT_PUBLIC_KEY_PATH,
    signatureDescriptor:
      process.env.AEGAEON_RELEASE_ATTESTATION_SIGNATURE_DESCRIPTOR_OUT ?? DEFAULT_SIGNATURE_DESCRIPTOR_PATH,
  };

  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (!token || token === "--") {
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
    const camelKey = rawKey.replace(/-([a-z])/g, (_, char: string) => char.toUpperCase());
    const value = argv[index + 1];
    if (!value || value.startsWith("--")) {
      throw new Error(`Missing value for option --${rawKey}`);
    }
    if (!(camelKey in options)) {
      throw new Error(`Unknown option --${rawKey}`);
    }
    options[camelKey as keyof ReleaseAttestationOptions] = value;
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
    if (existsSync(path.join(current, "package.json")) && existsSync(path.join(current, "packages"))) {
      return current;
    }
    const parent = path.dirname(current);
    if (parent === current) {
      throw new Error("Could not locate sdk workspace root");
    }
    current = parent;
  }
}

function envBool(name: string, defaultValue = false): boolean {
  const value = process.env[name];
  if (value == null || value === "") {
    return defaultValue;
  }
  return /^(1|true|TRUE)$/.test(value);
}

async function shaHex(filePath: string): Promise<string> {
  const hash = createHash("sha256");
  hash.update(await fs.readFile(filePath));
  return hash.digest("hex");
}

async function readJson(filePath: string): Promise<unknown> {
  return JSON.parse(await fs.readFile(filePath, "utf8")) as unknown;
}

async function removeIfExists(filePath: string): Promise<void> {
  await fs.rm(filePath, { force: true });
}

async function readKeyMaterial(): Promise<string> {
  const inlineKey = process.env.AEGAEON_COSIGN_KEY;
  if (inlineKey && inlineKey.trim().length > 0) {
    return inlineKey;
  }
  const keyPath = process.env.AEGAEON_COSIGN_KEY_PATH;
  if (keyPath && keyPath.trim().length > 0) {
    return fs.readFile(path.resolve(keyPath), "utf8");
  }
  throw new Error(
    "AEGAEON_SDK_SIGNED_RELEASE_ATTESTATION=true requires AEGAEON_COSIGN_KEY or AEGAEON_COSIGN_KEY_PATH",
  );
}

function ensureRecord(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`Expected object for ${label}`);
  }
  return value as Record<string, unknown>;
}

function ensureString(value: unknown, label: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`Expected non-empty string for ${label}`);
  }
  return value;
}

function ensureBoolean(value: unknown, label: string): boolean {
  if (typeof value !== "boolean") {
    throw new Error(`Expected boolean for ${label}`);
  }
  return value;
}

function ensureNamedSurfaces(value: unknown, label: string): NamedSurface[] {
  if (!Array.isArray(value)) {
    throw new Error(`Expected array for ${label}`);
  }
  return value.map((entry, index) => {
    const record = ensureRecord(entry, `${label}[${index}]`);
    return { name: ensureString(record.name, `${label}[${index}].name`) };
  });
}

function normalizePublishManifest(value: unknown): PublishManifest {
  const record = ensureRecord(value, "publish manifest");
  const source =
    record.source && typeof record.source === "object" && !Array.isArray(record.source)
      ? (record.source as PublishManifest["source"])
      : null;
  const verifiedCore =
    record.verifiedCore && typeof record.verifiedCore === "object" && !Array.isArray(record.verifiedCore)
      ? (record.verifiedCore as PublishManifest["verifiedCore"])
      : null;
  return {
    ...(source ? { source } : {}),
    tarballs: Array.isArray(record.tarballs) ? record.tarballs : [],
    ...(verifiedCore ? { verifiedCore } : {}),
  };
}

function normalizeClaimBoundary(value: unknown): ClientClaimBoundary {
  const record = ensureRecord(value, "client claim boundary");
  return {
    claim_phase: ensureString(record.claim_phase, "claim_phase"),
    released_client_claim_active: ensureBoolean(
      record.released_client_claim_active,
      "released_client_claim_active",
    ),
    default_profile: ensureString(record.default_profile, "default_profile"),
    promoted_client_slices: ensureNamedSurfaces(record.promoted_client_slices, "promoted_client_slices"),
    compat_only_surfaces: ensureNamedSurfaces(record.compat_only_surfaces, "compat_only_surfaces"),
  };
}

function optionalString(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : null;
}

function detectSignatureAlgorithm(privateKey: KeyObject): SignatureSelection {
  switch (privateKey.asymmetricKeyType) {
    case "ed25519":
      return { algorithm: null, label: "ed25519", key: privateKey };
    case "rsa":
      return { algorithm: "sha256", label: "rsa-sha256", key: privateKey };
    case "rsa-pss":
      return {
        algorithm: "sha256",
        label: "rsa-pss-sha256",
        key: {
          key: privateKey,
          padding: constants.RSA_PKCS1_PSS_PADDING,
          saltLength: constants.RSA_PSS_SALTLEN_DIGEST,
        },
      };
    case "ec":
      return { algorithm: "sha256", label: "ecdsa-sha256", key: privateKey };
    default:
      throw new Error(`Unsupported signing key type: ${privateKey.asymmetricKeyType ?? "unknown"}`);
  }
}

async function main(): Promise<void> {
  const options = parseArgs(process.argv.slice(2));
  const rootDir = findWorkspaceRoot(options.root);
  const publishManifestPath = path.resolve(rootDir, options.publishManifest);
  const claimBoundaryPath = path.resolve(rootDir, options.claimBoundary);
  const outPath = path.resolve(rootDir, options.out);
  const signaturePath = path.resolve(rootDir, options.signature);
  const publicKeyPath = path.resolve(rootDir, options.publicKey);
  const signatureDescriptorPath = path.resolve(rootDir, options.signatureDescriptor);

  const publishManifest = normalizePublishManifest(await readJson(publishManifestPath));
  const claimBoundary = normalizeClaimBoundary(await readJson(claimBoundaryPath));

  const signedReleaseAttestationPresent = envBool("AEGAEON_SDK_SIGNED_RELEASE_ATTESTATION");
  const sbomPublicationPresent = envBool("AEGAEON_SDK_SBOM_PUBLICATION");
  const npmProvenanceEnabled = envBool("NPM_CONFIG_PROVENANCE");

  const deferredRequirements: string[] = [];
  if (!signedReleaseAttestationPresent) {
    deferredRequirements.push("signed_release_attestations");
  }
  if (!sbomPublicationPresent) {
    deferredRequirements.push("published_sdk_sboms");
  }
  if (!claimBoundary.released_client_claim_active) {
    deferredRequirements.push("released_client_claim_promotion");
  }

  const attestation = {
    schema_version: 1,
    generated_at: new Date().toISOString(),
    release_phase: claimBoundary.claim_phase,
    source: {
      github_ref: process.env.GITHUB_REF ?? optionalString(publishManifest.source?.githubRef),
      github_sha: process.env.GITHUB_SHA ?? optionalString(publishManifest.source?.githubSha),
      github_run_id: process.env.GITHUB_RUN_ID ?? optionalString(publishManifest.source?.githubRunId),
      github_workflow:
        process.env.GITHUB_WORKFLOW ?? optionalString(publishManifest.source?.githubWorkflow),
      npm_dist_tag: process.env.AEGAEON_NPM_DIST_TAG ?? optionalString(publishManifest.source?.npmDistTag),
    },
    publication: {
      npm_provenance_enabled: npmProvenanceEnabled,
      signed_release_attestation_present: signedReleaseAttestationPresent,
      sbom_publication_present: sbomPublicationPresent,
    },
    publish_manifest: {
      path: path.relative(rootDir, publishManifestPath),
      sha256: await shaHex(publishManifestPath),
      tarball_count: Array.isArray(publishManifest.tarballs) ? publishManifest.tarballs.length : 0,
    },
    client_claim_boundary: {
      path: path.relative(rootDir, claimBoundaryPath),
      sha256: await shaHex(claimBoundaryPath),
      claim_phase: claimBoundary.claim_phase,
      released_client_claim_active: claimBoundary.released_client_claim_active,
      default_profile: claimBoundary.default_profile,
      promoted_client_slices: claimBoundary.promoted_client_slices.map((slice) => slice.name),
      compat_only_surfaces: claimBoundary.compat_only_surfaces.map((surface) => surface.name),
    },
    verified_core: {
      manifest_path: optionalString(publishManifest.verifiedCore?.manifestPath),
      manifest_sha256: optionalString(publishManifest.verifiedCore?.manifestSha256),
      handoff_manifest_path: optionalString(publishManifest.verifiedCore?.handoffManifestPath),
      handoff_manifest_sha256: optionalString(publishManifest.verifiedCore?.handoffManifestSha256),
    },
    deferred_requirements: deferredRequirements,
  };

  await fs.mkdir(path.dirname(outPath), { recursive: true });
  await fs.writeFile(outPath, `${JSON.stringify(attestation, null, 2)}\n`, "utf8");
  console.log(`[build-release-attestation] wrote ${path.relative(rootDir, outPath)}`);

  if (!signedReleaseAttestationPresent) {
    await removeIfExists(signaturePath);
    await removeIfExists(publicKeyPath);
    await removeIfExists(signatureDescriptorPath);
    return;
  }

  const keyMaterial = await readKeyMaterial();
  const privateKey = createPrivateKey({
    key: keyMaterial,
    format: "pem",
    passphrase: process.env.AEGAEON_COSIGN_PASSWORD,
  });
  const publicKey = createPublicKey(privateKey);
  const { algorithm, label, key } = detectSignatureAlgorithm(privateKey);
  const attestationBytes = await fs.readFile(outPath);
  const signatureBytes = signBuffer(algorithm, attestationBytes, key);
  const signatureBase64 = signatureBytes.toString("base64");
  const exportedPublicKey = publicKey.export({ type: "spki", format: "pem" });
  const publicKeyPem =
    typeof exportedPublicKey === "string" ? exportedPublicKey : exportedPublicKey.toString("utf8");
  const signerSource = process.env.AEGAEON_COSIGN_KEY ? "cosign_key_env" : "cosign_key_path";

  await fs.mkdir(path.dirname(signaturePath), { recursive: true });
  await fs.mkdir(path.dirname(publicKeyPath), { recursive: true });
  await fs.mkdir(path.dirname(signatureDescriptorPath), { recursive: true });
  await fs.writeFile(signaturePath, `${signatureBase64}\n`, "utf8");
  await fs.writeFile(publicKeyPath, publicKeyPem, "utf8");

  const descriptor = {
    schema_version: 1,
    generated_at: new Date().toISOString(),
    attestation_path: path.relative(rootDir, outPath),
    attestation_sha256: await shaHex(outPath),
    signature_path: path.relative(rootDir, signaturePath),
    signature_sha256: await shaHex(signaturePath),
    public_key_path: path.relative(rootDir, publicKeyPath),
    public_key_sha256: await shaHex(publicKeyPath),
    signature_algorithm: label,
    key_type: privateKey.asymmetricKeyType ?? "unknown",
    signature_encoding: "base64",
    signer_source: signerSource,
    signed_release_attestation_present: true,
  };
  await fs.writeFile(signatureDescriptorPath, `${JSON.stringify(descriptor, null, 2)}\n`, "utf8");
  console.log(
    `[build-release-attestation] wrote ${path.relative(rootDir, signaturePath)} and ${path.relative(rootDir, signatureDescriptorPath)}`,
  );
}

main().catch((error) => {
  console.error("[build-release-attestation] error:", error instanceof Error ? error.message : error);
  process.exitCode = 1;
});
