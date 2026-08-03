#!/usr/bin/env node
import { createHash, randomUUID } from "node:crypto";
import { existsSync } from "node:fs";
import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const MODULE_DIR = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_OUT_PATH = ".artifacts/release/sdk-workspace-sbom.cdx.json";
const DEFAULT_PUBLISH_MANIFEST_PATH = ".artifacts/release/publish-manifest.json";
const DEFAULT_CLAIM_BOUNDARY_PATH = "spec/client-claim-boundary.current.json";

function usage() {
  return [
    "Usage:",
    "  node --experimental-strip-types scripts/sdk/build_sdk_workspace_sbom.ts [options]",
    "",
    "Options:",
    "  --root <sdk-root>                 Workspace root (autodetected when omitted)",
    "  --publish-manifest <path>         Default: .artifacts/release/publish-manifest.json",
    "  --claim-boundary <path>           Default: spec/client-claim-boundary.current.json",
    "  --out <path>                      Default: .artifacts/release/sdk-workspace-sbom.cdx.json",
  ].join("\n");
}

function parseArgs(argv) {
  const options = {
    root: process.env.AEGAEON_SDK_ROOT ?? null,
    publishManifest: process.env.AEGAEON_PUBLISH_MANIFEST_PATH ?? DEFAULT_PUBLISH_MANIFEST_PATH,
    claimBoundary: process.env.AEGAEON_CLIENT_CLAIM_BOUNDARY_PATH ?? DEFAULT_CLAIM_BOUNDARY_PATH,
    out: process.env.AEGAEON_SDK_WORKSPACE_SBOM_OUT ?? DEFAULT_OUT_PATH,
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

async function loadWorkspacePackages(rootDir) {
  const packagesDir = path.join(rootDir, "packages");
  const entries = await fs.readdir(packagesDir, { withFileTypes: true });
  const packages = [];
  for (const entry of entries) {
    if (!entry.isDirectory()) {
      continue;
    }
    const packageJsonPath = path.join(packagesDir, entry.name, "package.json");
    const packageJson = JSON.parse(await fs.readFile(packageJsonPath, "utf8"));
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

function bomRefForPackage(packageName, version) {
  return `pkg:npm/${encodeURIComponent(packageName)}@${encodeURIComponent(version)}`;
}

function normalizeDependencyBlocks(dependencyBlocks) {
  const blocks = dependencyBlocks ?? {};
  const entries = [];
  for (const blockName of ["dependencies", "peerDependencies", "optionalDependencies"]) {
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
    (left, right) =>
      left.name.localeCompare(right.name) ||
      left.version.localeCompare(right.version),
  );
}

function buildPackageComponent(rootPackage, tarballEntry, claimBoundary, verifiedCoreSbomMetadata) {
  const component = {
    type: "library",
    "bom-ref": bomRefForPackage(rootPackage.name, rootPackage.version),
    name: rootPackage.name,
    version: rootPackage.version,
    purl: bomRefForPackage(rootPackage.name, rootPackage.version),
    hashes: [
      {
        alg: "SHA-256",
        content: tarballEntry.sha256,
      },
      {
        alg: "SHA-512",
        content: tarballEntry.sha512,
      },
    ],
    properties: [
      {
        name: "aegaeon:tarball",
        value: tarballEntry.tarball,
      },
      {
        name: "aegaeon:default_client_profile",
        value: claimBoundary.default_profile,
      },
    ],
  };

  if (rootPackage.name === "@aegaeon/verified-core") {
    component.properties.push(
      {
        name: "aegaeon:verified_core_manifest_path",
        value: tarballEntry.verifiedCoreManifestPath,
      },
      {
        name: "aegaeon:verified_core_manifest_sha256",
        value: tarballEntry.verifiedCoreManifestSha256,
      },
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

function buildDependencyComponents(workspacePackages, publishManifest) {
  const workspaceRefs = new Map(
    workspacePackages.map(({ packageJson }) => [
      packageJson.name,
      bomRefForPackage(packageJson.name, packageJson.version),
    ]),
  );
  const extraComponents = new Map();
  const dependencyEntries = new Map();

  for (const tarballEntry of publishManifest.tarballs ?? []) {
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
            properties: [
              {
                name: "aegaeon:dependency_block",
                value: dependency.block,
              },
            ],
          });
        }
      }
      const dependencyKey = workspaceRefs.get(tarballEntry.packageName);
      const dependencyRef =
        workspaceRefs.get(dependency.name) ??
        bomRefForPackage(dependency.name, dependency.version);
      const refs = dependencyEntries.get(dependencyKey) ?? new Set();
      refs.add(dependencyRef);
      dependencyEntries.set(dependencyKey, refs);
    }
  }

  return {
    extraComponents: [...extraComponents.values()].sort(
      (left, right) => left.name.localeCompare(right.name),
    ),
    dependencyEntries,
  };
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  const rootDir = findWorkspaceRoot(options.root);
  const publishManifestPath = resolveWithinRoot(rootDir, options.publishManifest);
  const claimBoundaryPath = resolveWithinRoot(rootDir, options.claimBoundary);
  const outPath = resolveWithinRoot(rootDir, options.out);

  const publishManifest = await readJson(publishManifestPath);
  const claimBoundary = await readJson(claimBoundaryPath);
  const workspacePackages = await loadWorkspacePackages(rootDir);
  const workspaceByName = new Map(
    workspacePackages.map(({ packageJson }) => [packageJson.name, packageJson]),
  );
  const tarballsByPackage = new Map(
    (publishManifest.tarballs ?? []).map((entry) => [entry.packageName, entry]),
  );

  for (const { packageJson } of workspacePackages) {
    if (!tarballsByPackage.has(packageJson.name)) {
      throw new Error(`Missing tarball entry for workspace package ${packageJson.name}`);
    }
  }

  const verifiedCoreManifestPath = path.join(
    rootDir,
    "packages",
    "verified-core",
    "dist",
    "manifest.json",
  );
  const verifiedCoreSbomPath = path.join(
    rootDir,
    "packages",
    "verified-core",
    "dist",
    "verified-core-sbom.json",
  );
  const verifiedCoreManifestSha = existsSync(verifiedCoreManifestPath)
    ? await shaHex(verifiedCoreManifestPath)
    : null;
  const verifiedCoreSbomMetadata = existsSync(verifiedCoreSbomPath)
    ? {
        path: path.relative(rootDir, verifiedCoreSbomPath),
        sha256: await shaHex(verifiedCoreSbomPath),
      }
    : null;

  const tarballs = [];
  for (const { packageJson } of workspacePackages) {
    const tarballEntry = tarballsByPackage.get(packageJson.name);
    tarballs.push({
      ...tarballEntry,
      verifiedCoreManifestPath: path.relative(rootDir, verifiedCoreManifestPath),
      verifiedCoreManifestSha256: verifiedCoreManifestSha,
    });
  }

  const packageComponents = workspacePackages.map(({ packageJson }) =>
    buildPackageComponent(
      packageJson,
      tarballs.find((entry) => entry.packageName === packageJson.name),
      claimBoundary,
      verifiedCoreSbomMetadata,
    ),
  );

  const { extraComponents, dependencyEntries } = buildDependencyComponents(
    workspacePackages,
    publishManifest,
  );
  const rootPackageJson = JSON.parse(await fs.readFile(path.join(rootDir, "package.json"), "utf8"));
  const rootComponentRef =
    `pkg:generic/${encodeURIComponent(rootPackageJson.name)}` +
    `@${encodeURIComponent(rootPackageJson.version)}`;

  const components = [...packageComponents, ...extraComponents];
  const dependencies = [
    {
      ref: rootComponentRef,
      dependsOn: packageComponents.map((component) => component["bom-ref"]),
    },
    ...packageComponents.map((component) => ({
      ref: component["bom-ref"],
      dependsOn: [...(dependencyEntries.get(component["bom-ref"]) ?? new Set())].sort(),
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
          {
            name: "aegaeon:claim_phase",
            value: claimBoundary.claim_phase,
          },
          {
            name: "aegaeon:released_client_claim_active",
            value: String(claimBoundary.released_client_claim_active),
          },
          {
            name: "aegaeon:default_client_profile",
            value: claimBoundary.default_profile,
          },
          {
            name: "aegaeon:publish_manifest_path",
            value: path.relative(rootDir, publishManifestPath),
          },
          {
            name: "aegaeon:publish_manifest_sha256",
            value: await shaHex(publishManifestPath),
          },
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
