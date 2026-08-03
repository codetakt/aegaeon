import { createHash, randomUUID } from "node:crypto";
import { existsSync } from "node:fs";
import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const MODULE_DIR = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_OUT_PATH = ".artifacts/release/sdk-workspace-sbom.cdx.json";
const DEFAULT_PUBLISH_MANIFEST_PATH = ".artifacts/release/publish-manifest.json";
const DEFAULT_CLAIM_BOUNDARY_PATH = "spec/client-claim-boundary.current.json";

type WorkspaceSbomOptions = {
  root: string | null;
  publishManifest: string;
  claimBoundary: string;
  out: string;
};

type DependencyBlocks = Partial<
  Record<"dependencies" | "peerDependencies" | "optionalDependencies", Record<string, unknown>>
>;

type PackageJsonLike = {
  name?: unknown;
  version?: unknown;
  private?: unknown;
};

type WorkspacePackageJson = {
  name: string;
  version: string;
  private: boolean;
};

type WorkspacePackage = {
  dirName: string;
  packageJsonPath: string;
  packageJson: WorkspacePackageJson;
};

type PublishManifestTarballEntry = {
  packageName: string;
  version: string;
  tarball: string;
  sha256: string;
  sha512: string;
  dependencyBlocks: DependencyBlocks;
};

type PublishManifest = {
  tarballs: PublishManifestTarballEntry[];
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

type DependencyEntry = {
  name: string;
  version: string;
  block: "dependencies" | "peerDependencies" | "optionalDependencies";
};

type CycloneDxComponent = {
  type: string;
  "bom-ref": string;
  name: string;
  version: string;
  purl: string;
  scope?: string;
  hashes?: { alg: string; content: string }[];
  properties?: { name: string; value: string }[];
  externalReferences?: { type: string; url: string; comment?: string }[];
};

function usage(): string {
  return [
    "Usage:",
    "  node dist-tools/build-workspace-sbom.js [options]",
    "",
    "Options:",
    "  --root <sdk-root>                 Workspace root (autodetected when omitted)",
    "  --publish-manifest <path>         Default: .artifacts/release/publish-manifest.json",
    "  --claim-boundary <path>           Default: spec/client-claim-boundary.current.json",
    "  --out <path>                      Default: .artifacts/release/sdk-workspace-sbom.cdx.json",
  ].join("\n");
}

function parseArgs(argv: string[]): WorkspaceSbomOptions {
  const options: WorkspaceSbomOptions = {
    root: process.env.AEGAEON_SDK_ROOT ?? null,
    publishManifest: process.env.AEGAEON_PUBLISH_MANIFEST_PATH ?? DEFAULT_PUBLISH_MANIFEST_PATH,
    claimBoundary: process.env.AEGAEON_CLIENT_CLAIM_BOUNDARY_PATH ?? DEFAULT_CLAIM_BOUNDARY_PATH,
    out: process.env.AEGAEON_SDK_WORKSPACE_SBOM_OUT ?? DEFAULT_OUT_PATH,
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
    options[camelKey as keyof WorkspaceSbomOptions] = value;
    index += 1;
  }

  return options;
}

function resolveWithinRoot(rootDir: string, targetPath: string): string {
  return path.isAbsolute(targetPath) ? targetPath : path.resolve(rootDir, targetPath);
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

async function readJson(filePath: string): Promise<unknown> {
  return JSON.parse(await fs.readFile(filePath, "utf8")) as unknown;
}

async function shaHex(filePath: string): Promise<string> {
  const hash = createHash("sha256");
  hash.update(await fs.readFile(filePath));
  return hash.digest("hex");
}

function normalizePackageJson(value: unknown, label: string): WorkspacePackageJson {
  const record = ensureRecord(value, label);
  return {
    name: ensureString(record.name, `${label}.name`),
    version: ensureString(record.version, `${label}.version`),
    private: record.private === true,
  };
}

async function loadWorkspacePackages(rootDir: string): Promise<WorkspacePackage[]> {
  const packagesDir = path.join(rootDir, "packages");
  const entries = await fs.readdir(packagesDir, { withFileTypes: true });
  const packages: WorkspacePackage[] = [];
  for (const entry of entries) {
    if (!entry.isDirectory()) {
      continue;
    }
    const packageJsonPath = path.join(packagesDir, entry.name, "package.json");
    const packageJson = normalizePackageJson(
      JSON.parse(await fs.readFile(packageJsonPath, "utf8")) as unknown,
      packageJsonPath,
    );
    if (packageJson.private) {
      continue;
    }
    packages.push({
      dirName: entry.name,
      packageJsonPath,
      packageJson,
    });
  }
  packages.sort((left, right) => left.packageJson.name.localeCompare(right.packageJson.name));
  return packages;
}

function bomRefForPackage(packageName: string, version: string): string {
  return `pkg:npm/${encodeURIComponent(packageName)}@${encodeURIComponent(version)}`;
}

function normalizeDependencyBlocks(value: unknown): DependencyEntry[] {
  const blocks = (value && typeof value === "object" && !Array.isArray(value) ? value : {}) as DependencyBlocks;
  const entries: DependencyEntry[] = [];
  for (const blockName of ["dependencies", "peerDependencies", "optionalDependencies"] as const) {
    const block = blocks[blockName] ?? {};
    for (const [name, version] of Object.entries(block)) {
      entries.push({
        name,
        version: String(version),
        block: blockName,
      });
    }
  }
  return entries.sort(
    (left, right) => left.name.localeCompare(right.name) || left.version.localeCompare(right.version),
  );
}

function normalizeTarballEntry(value: unknown, label: string): PublishManifestTarballEntry {
  const record = ensureRecord(value, label);
  return {
    packageName: ensureString(record.packageName, `${label}.packageName`),
    version: ensureString(record.version, `${label}.version`),
    tarball: ensureString(record.tarball, `${label}.tarball`),
    sha256: ensureString(record.sha256, `${label}.sha256`),
    sha512: ensureString(record.sha512, `${label}.sha512`),
    dependencyBlocks:
      record.dependencyBlocks && typeof record.dependencyBlocks === "object" && !Array.isArray(record.dependencyBlocks)
        ? (record.dependencyBlocks as DependencyBlocks)
        : {},
  };
}

function normalizePublishManifest(value: unknown): PublishManifest {
  const record = ensureRecord(value, "publish manifest");
  const tarballs = Array.isArray(record.tarballs)
    ? record.tarballs.map((entry, index) => normalizeTarballEntry(entry, `tarballs[${index}]`))
    : [];
  return { tarballs };
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

function buildPackageComponent(
  rootPackage: WorkspacePackageJson,
  tarballEntry: PublishManifestTarballEntry,
  claimBoundary: ClientClaimBoundary,
  verifiedCoreSbomMetadata: { path: string; sha256: string } | null,
  verifiedCoreManifestPath: string,
  verifiedCoreManifestSha256: string | null,
): CycloneDxComponent {
  const component: CycloneDxComponent = {
    type: "library",
    "bom-ref": bomRefForPackage(rootPackage.name, rootPackage.version),
    name: rootPackage.name,
    version: rootPackage.version,
    purl: bomRefForPackage(rootPackage.name, rootPackage.version),
    hashes: [
      { alg: "SHA-256", content: tarballEntry.sha256 },
      { alg: "SHA-512", content: tarballEntry.sha512 },
    ],
    properties: [
      { name: "aegaeon:tarball", value: tarballEntry.tarball },
      { name: "aegaeon:default_client_profile", value: claimBoundary.default_profile },
    ],
  };

  if (rootPackage.name === "@aegaeon/verified-core") {
    component.properties?.push(
      { name: "aegaeon:verified_core_manifest_path", value: verifiedCoreManifestPath },
      { name: "aegaeon:verified_core_manifest_sha256", value: verifiedCoreManifestSha256 ?? "" },
    );
    if (verifiedCoreSbomMetadata) {
      component.externalReferences = [
        {
          type: "bom",
          url: verifiedCoreSbomMetadata.path,
          comment: `SHA-256 ${verifiedCoreSbomMetadata.sha256}`,
        },
      ];
    }
  }

  return component;
}

function buildDependencyComponents(
  workspacePackages: WorkspacePackage[],
  publishManifest: PublishManifest,
): {
  extraComponents: CycloneDxComponent[];
  dependencyEntries: Map<string, Set<string>>;
} {
  const workspaceRefs = new Map(
    workspacePackages.map(({ packageJson }) => [
      packageJson.name,
      bomRefForPackage(packageJson.name, packageJson.version),
    ]),
  );
  const extraComponents = new Map<string, CycloneDxComponent>();
  const dependencyEntries = new Map<string, Set<string>>();

  for (const tarballEntry of publishManifest.tarballs) {
    for (const dependency of normalizeDependencyBlocks(tarballEntry.dependencyBlocks)) {
      if (!workspaceRefs.has(dependency.name)) {
        const bomRef = bomRefForPackage(dependency.name, dependency.version);
        if (!extraComponents.has(bomRef)) {
          extraComponents.set(bomRef, {
            type: "library",
            "bom-ref": bomRef,
            name: dependency.name,
            version: dependency.version,
            purl: bomRef,
            scope: "required",
            properties: [{ name: "aegaeon:dependency_block", value: dependency.block }],
          });
        }
      }
      const dependencyKey = workspaceRefs.get(tarballEntry.packageName);
      if (!dependencyKey) {
        continue;
      }
      const dependencyRef =
        workspaceRefs.get(dependency.name) ?? bomRefForPackage(dependency.name, dependency.version);
      const refs = dependencyEntries.get(dependencyKey) ?? new Set<string>();
      refs.add(dependencyRef);
      dependencyEntries.set(dependencyKey, refs);
    }
  }

  return {
    extraComponents: [...extraComponents.values()].sort((left, right) => left.name.localeCompare(right.name)),
    dependencyEntries,
  };
}

async function main(): Promise<void> {
  const options = parseArgs(process.argv.slice(2));
  const rootDir = findWorkspaceRoot(options.root);
  const publishManifestPath = resolveWithinRoot(rootDir, options.publishManifest);
  const claimBoundaryPath = resolveWithinRoot(rootDir, options.claimBoundary);
  const outPath = resolveWithinRoot(rootDir, options.out);

  const publishManifest = normalizePublishManifest(await readJson(publishManifestPath));
  const claimBoundary = normalizeClaimBoundary(await readJson(claimBoundaryPath));
  const workspacePackages = await loadWorkspacePackages(rootDir);
  const tarballsByPackage = new Map(
    publishManifest.tarballs.map((entry) => [entry.packageName, entry] as const),
  );

  for (const { packageJson } of workspacePackages) {
    if (!tarballsByPackage.has(packageJson.name)) {
      throw new Error(`Missing tarball entry for workspace package ${packageJson.name}`);
    }
  }

  const verifiedCoreManifestPath = path.join(rootDir, "packages", "verified-core", "dist", "manifest.json");
  const verifiedCoreSbomPath = path.join(rootDir, "packages", "verified-core", "dist", "verified-core-sbom.json");
  const verifiedCoreManifestSha = existsSync(verifiedCoreManifestPath)
    ? await shaHex(verifiedCoreManifestPath)
    : null;
  const verifiedCoreSbomMetadata = existsSync(verifiedCoreSbomPath)
    ? {
        path: path.relative(rootDir, verifiedCoreSbomPath),
        sha256: await shaHex(verifiedCoreSbomPath),
      }
    : null;

  const packageComponents = workspacePackages.map(({ packageJson }) =>
    buildPackageComponent(
      packageJson,
      tarballsByPackage.get(packageJson.name) as PublishManifestTarballEntry,
      claimBoundary,
      verifiedCoreSbomMetadata,
      path.relative(rootDir, verifiedCoreManifestPath),
      verifiedCoreManifestSha,
    ),
  );

  const { extraComponents, dependencyEntries } = buildDependencyComponents(workspacePackages, publishManifest);
  const rootPackageJson = normalizePackageJson(
    JSON.parse(await fs.readFile(path.join(rootDir, "package.json"), "utf8")) as unknown,
    "package.json",
  );
  const rootComponentRef = `pkg:generic/${encodeURIComponent(rootPackageJson.name)}@${encodeURIComponent(rootPackageJson.version)}`;

  const components = [...packageComponents, ...extraComponents];
  const dependencies = [
    {
      ref: rootComponentRef,
      dependsOn: packageComponents.map((component) => component["bom-ref"]),
    },
    ...packageComponents.map((component) => ({
      ref: component["bom-ref"],
      dependsOn: [...(dependencyEntries.get(component["bom-ref"]) ?? new Set<string>())].sort(),
    })),
  ];

  const sbom = {
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    serialNumber: `urn:uuid:${randomUUID()}`,
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      component: {
        type: "application",
        "bom-ref": rootComponentRef,
        name: rootPackageJson.name,
        version: rootPackageJson.version,
        purl: rootComponentRef,
        properties: [
          { name: "aegaeon:claim_phase", value: claimBoundary.claim_phase },
          {
            name: "aegaeon:released_client_claim_active",
            value: String(claimBoundary.released_client_claim_active),
          },
          { name: "aegaeon:default_client_profile", value: claimBoundary.default_profile },
          { name: "aegaeon:publish_manifest_path", value: path.relative(rootDir, publishManifestPath) },
          { name: "aegaeon:publish_manifest_sha256", value: await shaHex(publishManifestPath) },
        ],
      },
    },
    components,
    dependencies,
  };

  await fs.mkdir(path.dirname(outPath), { recursive: true });
  await fs.writeFile(outPath, `${JSON.stringify(sbom, null, 2)}\n`, "utf8");
  console.log(`[build-workspace-sbom] wrote ${path.relative(rootDir, outPath)}`);
}

main().catch((error) => {
  console.error("[build-workspace-sbom] error:", error instanceof Error ? error.message : error);
  process.exitCode = 1;
});
