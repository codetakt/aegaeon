import { execFile as execFileCallback } from "node:child_process";
import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const execFile = promisify(execFileCallback);
const MODULE_DIR = path.dirname(fileURLToPath(import.meta.url));
const ROOT_DIR = path.resolve(MODULE_DIR, "..");
const DEFAULT_OUT_DIR = path.join(ROOT_DIR, ".cache", "verified-core");
const REQUIRED_FILES = [
  "manifest.json",
  "verified_core.wasm",
  "verified_core.abi.json",
  "verified_core.wasm.sha256",
  "verified_core.wasm.sha512",
  "verified_core.wasm.sri",
  "verified-core-sbom.json",
  "types.d.ts",
  "integrity.txt",
] as const;
const OPTIONAL_FILES = [
  "verified-core-handoff-manifest.json",
  "verified_core.wasm.sig",
  "verified_core.wasm.cosign.sig",
] as const;

type DownloadOptions = {
  repo: string | null;
  tag: string | null;
  artifactDir: string | null;
  outDir: string;
};

type ErrnoLike = NodeJS.ErrnoException;

function usage(): string {
  return [
    "Usage:",
    "  node dist-tools/download-core-release.js --repo <owner/repo> --tag <tag> [--out-dir <dir>]",
    "  node dist-tools/download-core-release.js --artifact-dir <dir> [--out-dir <dir>]",
    "",
    "Environment fallbacks:",
    "  AEGAEON_CORE_RELEASE_REPO",
    "  AEGAEON_CORE_RELEASE_TAG",
    "  AEGAEON_CORE_RELEASE_ARTIFACT_DIR",
    "  AEGAEON_CORE_RELEASE_OUT_DIR",
  ].join("\n");
}

function parseArgs(argv: string[]): DownloadOptions {
  const options: DownloadOptions = {
    repo: process.env.AEGAEON_CORE_RELEASE_REPO ?? null,
    tag: process.env.AEGAEON_CORE_RELEASE_TAG ?? null,
    artifactDir: process.env.AEGAEON_CORE_RELEASE_ARTIFACT_DIR ?? null,
    outDir: process.env.AEGAEON_CORE_RELEASE_OUT_DIR ?? DEFAULT_OUT_DIR,
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
    options[camelKey as keyof DownloadOptions] = value;
    index += 1;
  }

  if (!options.artifactDir && (!options.repo || !options.tag)) {
    throw new Error(`Either --artifact-dir or both --repo and --tag are required.\n\n${usage()}`);
  }

  return options;
}

async function ensureDir(dirPath: string): Promise<void> {
  await fs.mkdir(dirPath, { recursive: true });
}

async function removeDir(dirPath: string): Promise<void> {
  await fs.rm(dirPath, { recursive: true, force: true });
}

async function copyNamedFiles(sourceDir: string, outDir: string): Promise<void> {
  await removeDir(outDir);
  await ensureDir(outDir);

  for (const name of REQUIRED_FILES) {
    await fs.copyFile(path.join(sourceDir, name), path.join(outDir, name));
  }
  for (const name of OPTIONAL_FILES) {
    try {
      await fs.copyFile(path.join(sourceDir, name), path.join(outDir, name));
    } catch (error) {
      if ((error as ErrnoLike | undefined)?.code !== "ENOENT") {
        throw error;
      }
    }
  }
}

async function main(): Promise<void> {
  const options = parseArgs(process.argv.slice(2));
  const outDir = path.resolve(options.outDir);

  if (options.artifactDir) {
    await copyNamedFiles(path.resolve(options.artifactDir), outDir);
  } else {
    await removeDir(outDir);
    await ensureDir(outDir);
    const args = [
      "release",
      "download",
      options.tag as string,
      "--repo",
      options.repo as string,
      "--dir",
      outDir,
    ];
    for (const pattern of [...REQUIRED_FILES, ...OPTIONAL_FILES]) {
      args.push("--pattern", pattern);
    }
    const { stdout, stderr } = await execFile("gh", args, { cwd: ROOT_DIR });
    if (stdout) {
      process.stdout.write(stdout);
    }
    if (stderr) {
      process.stderr.write(stderr);
    }
  }

  for (const name of REQUIRED_FILES) {
    await fs.access(path.join(outDir, name));
  }

  console.log("[download-core-release] prepared verified core artefacts in:", outDir);
  console.log("[download-core-release] manifest:", path.join(outDir, "manifest.json"));
  console.log("[download-core-release] wasm:", path.join(outDir, "verified_core.wasm"));
  try {
    const handoffPath = path.join(outDir, "verified-core-handoff-manifest.json");
    await fs.access(handoffPath);
    console.log("[download-core-release] handoff manifest:", handoffPath);
  } catch (error) {
    if ((error as ErrnoLike | undefined)?.code !== "ENOENT") {
      throw error;
    }
  }
}

main().catch((error) => {
  console.error("[download-core-release] error:", error instanceof Error ? error.message : error);
  process.exitCode = 1;
});
