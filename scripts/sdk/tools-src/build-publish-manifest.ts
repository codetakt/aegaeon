import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const MODULE_DIR = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_OUT_PATH = ".artifacts/release/publish-manifest.json";

type PublishManifestOptions = {
  root: string | null;
  out: string;
};

type PackageJsonLike = {
  name?: unknown;
  version?: unknown;
  private?: unknown;
  dependencies?: Record<string, unknown>;
  peerDependencies?: Record<string, unknown>;
  optionalDependencies?: Record<string, unknown>;
};

type WorkspacePackage = {
  dirName: string;
  packageJsonPath: string;
  packageJson: {
    name: string;
    version: string;
    private: boolean;
    dependencies: Record<string, unknown>;
    peerDependencies: Record<string, unknown>;
    optionalDependencies: Record<string, unknown>;
  };
};

type TarballDependencyBlocks = Partial<
  Record<"dependencies" | "peerDependencies" | "optionalDependencies", Record<string, unknown>>
>;

function usage(): string {
  return [
    "Usage:",
    "  node dist-tools/build-publish-manifest.js [--root <sdk-root>] [--out <path>]",
    "",
    "Environment fallbacks:",
    "  AEGAEON_SDK_ROOT",
    "  AEGAEON_PUBLISH_MANIFEST_OUT",
  ].join("\n");
}

function parseArgs(argv: string[]): PublishManifestOptions {
  const options: PublishManifestOptions = {
    root: process.env.AEGAEON_SDK_ROOT ?? null,
    out: process.env.AEGAEON_PUBLISH_MANIFEST_OUT ?? DEFAULT_OUT_PATH,
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
    options[camelKey as keyof PublishManifestOptions] = value;
    index += 1;
  }

  return options;
}

function findWorkspaceRoot(explicitRoot: string | null): string {
  if (explicitRoot) {
    return path.resolve(explicitRoot);
  }
  let current = path.resolve(MODULE_DIR, "..");
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

async function shaHex(filePath: string, algorithm: "sha256" | "sha512"): Promise<string> {
  const hash = createHash(algorithm);
  hash.update(await fs.readFile(filePath));
  return hash.digest("hex");
}

function normalizePackageJson(value: unknown, label: string): WorkspacePackage["packageJson"] {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`Expected object for ${label}`);
  }
  const packageJson = value as PackageJsonLike;
  if (typeof packageJson.name !== "string" || packageJson.name.length === 0) {
    throw new Error(`${label} requires a package name`);
  }
  if (typeof packageJson.version !== "string" || packageJson.version.length === 0) {
    throw new Error(`${label} requires a package version`);
  }
  return {
    name: packageJson.name,
    version: packageJson.version,
    private: packageJson.private === true,
    dependencies:
      packageJson.dependencies && typeof packageJson.dependencies === "object" ? packageJson.dependencies : {},
    peerDependencies:
      packageJson.peerDependencies && typeof packageJson.peerDependencies === "object"
        ? packageJson.peerDependencies
        : {},
    optionalDependencies:
      packageJson.optionalDependencies && typeof packageJson.optionalDependencies === "object"
        ? packageJson.optionalDependencies
        : {},
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

function expectedTarballName(packageName: string, version: string): string {
  return `${packageName.replace(/^@/, "").replace(/\//g, "-")}-${version}.tgz`;
}

function extractTarballPackageJson(tarballPath: string): WorkspacePackage["packageJson"] {
  const result = spawnSync("tar", ["-xOf", tarballPath, "package/package.json"], {
    encoding: "utf8",
  });
  if (result.status !== 0) {
    throw new Error(`tar failed for ${tarballPath}: ${result.stderr || result.stdout}`);
  }
  return normalizePackageJson(JSON.parse(result.stdout) as unknown, tarballPath);
}

function collectDependencyBlocks(packageJson: WorkspacePackage["packageJson"]): TarballDependencyBlocks {
  const blocks: TarballDependencyBlocks = {};
  for (const key of ["dependencies", "peerDependencies", "optionalDependencies"] as const) {
    const value = packageJson[key] ?? {};
    for (const [name, range] of Object.entries(value)) {
      if (String(range).startsWith("workspace:")) {
        throw new Error(
          `Packed package ${packageJson.name} still contains workspace protocol for ${name}: ${String(range)}`,
        );
      }
    }
    if (Object.keys(value).length > 0) {
      blocks[key] = value;
    }
  }
  return blocks;
}

async function readOptionalJson(filePath: string): Promise<unknown | null> {
  try {
    return JSON.parse(await fs.readFile(filePath, "utf8")) as unknown;
  } catch (error) {
    if ((error as NodeJS.ErrnoException | undefined)?.code === "ENOENT") {
      return null;
    }
    throw error;
  }
}

async function main(): Promise<void> {
  const options = parseArgs(process.argv.slice(2));
  const rootDir = findWorkspaceRoot(options.root);
  const outPath = path.resolve(rootDir, options.out);
  const workspacePackages = await loadWorkspacePackages(rootDir);
  if (workspacePackages.length === 0) {
    throw new Error("No publishable workspace packages found under packages/");
  }

  const rootEntries = await fs.readdir(rootDir, { withFileTypes: true });
  const tarballEntries = rootEntries
    .filter((entry) => entry.isFile() && entry.name.endsWith(".tgz"))
    .map((entry) => entry.name)
    .sort();
  const expectedTarballs = workspacePackages
    .map(({ packageJson }) => expectedTarballName(packageJson.name, packageJson.version))
    .sort();

  if (tarballEntries.length === 0) {
    throw new Error("No tarballs found at workspace root; run pnpm run pack:workspace first");
  }
  if (tarballEntries.join("\n") !== expectedTarballs.join("\n")) {
    throw new Error(
      [
        "Workspace tarballs do not match the current package set.",
        `Expected: ${expectedTarballs.join(", ")}`,
        `Found: ${tarballEntries.join(", ")}`,
        "Clean stale *.tgz files and rerun pnpm run pack:workspace.",
      ].join("\n"),
    );
  }

  const tarballs = [];
  for (const { packageJson } of workspacePackages) {
    const tarballName = expectedTarballName(packageJson.name, packageJson.version);
    const tarballPath = path.join(rootDir, tarballName);
    const packedPackageJson = extractTarballPackageJson(tarballPath);
    if (packedPackageJson.name !== packageJson.name || packedPackageJson.version !== packageJson.version) {
      throw new Error(`Tarball metadata mismatch for ${tarballName}`);
    }
    tarballs.push({
      packageName: packageJson.name,
      version: packageJson.version,
      tarball: tarballName,
      sha256: await shaHex(tarballPath, "sha256"),
      sha512: await shaHex(tarballPath, "sha512"),
      dependencyBlocks: collectDependencyBlocks(packedPackageJson),
    });
  }

  const verifiedCoreManifestPath = path.join(rootDir, "packages", "verified-core", "dist", "manifest.json");
  const verifiedCoreHandoffPath = path.join(
    rootDir,
    "packages",
    "verified-core",
    "dist",
    "verified-core-handoff-manifest.json",
  );
  const manifest = {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    workspaceRoot: rootDir,
    source: {
      githubRef: process.env.GITHUB_REF ?? null,
      githubSha: process.env.GITHUB_SHA ?? null,
      githubRunId: process.env.GITHUB_RUN_ID ?? null,
      githubWorkflow: process.env.GITHUB_WORKFLOW ?? null,
      npmDistTag: process.env.AEGAEON_NPM_DIST_TAG ?? null,
    },
    tarballs,
    verifiedCore: {
      manifestPath: path.relative(rootDir, verifiedCoreManifestPath),
      manifestSha256: await shaHex(verifiedCoreManifestPath, "sha256"),
      manifest: JSON.parse(await fs.readFile(verifiedCoreManifestPath, "utf8")) as unknown,
      handoffManifestPath: existsSync(verifiedCoreHandoffPath)
        ? path.relative(rootDir, verifiedCoreHandoffPath)
        : null,
      handoffManifestSha256: existsSync(verifiedCoreHandoffPath)
        ? await shaHex(verifiedCoreHandoffPath, "sha256")
        : null,
      handoffManifest: await readOptionalJson(verifiedCoreHandoffPath),
    },
  };

  await fs.mkdir(path.dirname(outPath), { recursive: true });
  await fs.writeFile(outPath, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");

  console.log(`[build-publish-manifest] wrote ${path.relative(rootDir, outPath)}`);
  for (const tarball of tarballs) {
    console.log(`[build-publish-manifest] ${tarball.packageName}@${tarball.version} -> ${tarball.tarball}`);
  }
}

main().catch((error) => {
  console.error("[build-publish-manifest] error:", error instanceof Error ? error.message : error);
  process.exitCode = 1;
});
