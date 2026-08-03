#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const MODULE_DIR = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_OUT_PATH = ".artifacts/release/publish-manifest.json";

function usage() {
  return [
    "Usage:",
    "  node --experimental-strip-types scripts/sdk/build_sdk_publish_manifest.ts [--root <sdk-root>] [--out <path>]",
    "",
    "Environment fallbacks:",
    "  AEGAEON_SDK_ROOT",
    "  AEGAEON_PUBLISH_MANIFEST_OUT",
  ].join("\n");
}

function parseArgs(argv) {
  const options = {
    root: process.env.AEGAEON_SDK_ROOT ?? null,
    out: process.env.AEGAEON_PUBLISH_MANIFEST_OUT ?? DEFAULT_OUT_PATH,
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

async function shaHex(filePath, algorithm) {
  const hash = createHash(algorithm);
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

function expectedTarballName(packageName, version) {
  return `${packageName.replace(/^@/, "").replace(/\//g, "-")}-${version}.tgz`;
}

function extractTarballPackageJson(tarballPath) {
  const result = spawnSync("tar", ["-xOf", tarballPath, "package/package.json"], {
    encoding: "utf8",
  });
  if (result.status !== 0) {
    throw new Error(`tar failed for ${tarballPath}: ${result.stderr || result.stdout}`);
  }
  return JSON.parse(result.stdout);
}

function collectDependencyBlocks(packageJson) {
  const blocks = {};
  for (const key of ["dependencies", "peerDependencies", "optionalDependencies"]) {
    const value = packageJson[key] ?? {};
    for (const [name, range] of Object.entries(value)) {
      if (String(range).startsWith("workspace:")) {
        throw new Error(`Packed package ${packageJson.name} still contains workspace protocol for ${name}: ${range}`);
      }
    }
    if (Object.keys(value).length > 0) {
      blocks[key] = value;
    }
  }
  return blocks;
}

async function readOptionalJson(filePath) {
  try {
    return JSON.parse(await fs.readFile(filePath, "utf8"));
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
  const outPath = path.resolve(rootDir, options.out);
  const workspacePackages = await loadWorkspacePackages(rootDir);
  if (workspacePackages.length === 0) {
    throw new Error("No publishable workspace packages found under packages/");
  }

  const rootEntries = await fs.readdir(rootDir, { withFileTypes: true });
  const tarballEntries = rootEntries.filter((entry) => entry.isFile() && entry.name.endsWith(".tgz")).map((entry) => entry.name).sort();
  const expectedTarballs = workspacePackages.map(({ packageJson }) => expectedTarballName(packageJson.name, packageJson.version)).sort();

  if (tarballEntries.length === 0) {
    throw new Error("No tarballs found at workspace root; run pnpm run pack:workspace first");
  }
  if (tarballEntries.join("\n") !== expectedTarballs.join("\n")) {
    throw new Error([
      "Workspace tarballs do not match the current package set.",
      `Expected: ${expectedTarballs.join(", ")}`,
      `Found: ${tarballEntries.join(", ")}`,
      "Clean stale *.tgz files and rerun pnpm run pack:workspace.",
    ].join("\n"));
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
  const verifiedCoreHandoffPath = path.join(rootDir, "packages", "verified-core", "dist", "verified-core-handoff-manifest.json");
  const verifiedCore = {
    manifestPath: path.relative(rootDir, verifiedCoreManifestPath),
    manifestSha256: await shaHex(verifiedCoreManifestPath, "sha256"),
    manifest: JSON.parse(await fs.readFile(verifiedCoreManifestPath, "utf8")),
    handoffManifestPath: existsSync(verifiedCoreHandoffPath) ? path.relative(rootDir, verifiedCoreHandoffPath) : null,
    handoffManifestSha256: existsSync(verifiedCoreHandoffPath) ? await shaHex(verifiedCoreHandoffPath, "sha256") : null,
    handoffManifest: await readOptionalJson(verifiedCoreHandoffPath),
  };

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
    verifiedCore,
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
