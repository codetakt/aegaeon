import { execFile as execFileCallback } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const execFile = promisify(execFileCallback);
const MODULE_DIR = path.dirname(fileURLToPath(import.meta.url));
const ROOT_DIR = path.resolve(MODULE_DIR, "..");
const FETCH_CORE_SCRIPT = path.join(MODULE_DIR, "fetch-core.js");
const DEFAULT_OUT_DIR = path.join(ROOT_DIR, "packages", "verified-core", "dist");

type VerifyCoreOptions = {
  manifest: string | null;
  wasm: string | null;
  signature: string | null;
  publicKey: string | null;
  outDir: string;
};

function usage(): string {
  return [
    "Usage: node dist-tools/verify-core.js --manifest <path> --wasm <path> [--signature <path>] [--public-key <path>] [--out-dir <dir>]",
    "",
    "Environment fallbacks:",
    "  AEGAEON_CORE_MANIFEST_PATH",
    "  AEGAEON_CORE_WASM_PATH",
    "  AEGAEON_CORE_SIGNATURE_PATH",
    "  AEGAEON_CORE_PUBLIC_KEY_PATH",
    "  AEGAEON_CORE_OUT_DIR",
  ].join("\n");
}

function writeMaybeOutput(output: string | Buffer | undefined, writer: typeof process.stdout | typeof process.stderr): void {
  if (!output) {
    return;
  }
  writer.write(output);
}

function parseArgs(argv: string[]): VerifyCoreOptions {
  const options: VerifyCoreOptions = {
    manifest: process.env.AEGAEON_CORE_MANIFEST_PATH ?? null,
    wasm: process.env.AEGAEON_CORE_WASM_PATH ?? null,
    signature: process.env.AEGAEON_CORE_SIGNATURE_PATH ?? null,
    publicKey: process.env.AEGAEON_CORE_PUBLIC_KEY_PATH ?? null,
    outDir: process.env.AEGAEON_CORE_OUT_DIR ?? DEFAULT_OUT_DIR,
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
    const key = token!.slice(2);
    const value = argv[index + 1];
    if (!value || value.startsWith("--")) {
      throw new Error(`Missing value for option --${key}`);
    }
    switch (key) {
      case "manifest":
        options.manifest = value;
        break;
      case "wasm":
        options.wasm = value;
        break;
      case "signature":
        options.signature = value;
        break;
      case "public-key":
        options.publicKey = value;
        break;
      case "out-dir":
        options.outDir = value;
        break;
      default:
        throw new Error(`Unknown option --${key}`);
    }
    index += 1;
  }

  if (!options.manifest || !options.wasm) {
    throw new Error(`Both manifest and wasm inputs are required.\n\n${usage()}`);
  }
  if ((options.signature && !options.publicKey) || (!options.signature && options.publicKey)) {
    throw new Error("signature and public-key must be provided together");
  }

  return options;
}

async function main(): Promise<void> {
  const options = parseArgs(process.argv.slice(2));
  const args: string[] = [
    FETCH_CORE_SCRIPT,
    "--manifest", options.manifest!,
    "--wasm", options.wasm!,
    "--out-dir", options.outDir,
  ];
  if (options.signature && options.publicKey) {
    args.push("--signature", options.signature, "--public-key", options.publicKey);
  }
  const { stdout, stderr } = await execFile(process.execPath, args, { cwd: ROOT_DIR });
  writeMaybeOutput(stdout, process.stdout);
  writeMaybeOutput(stderr, process.stderr);
}

main().catch((error) => {
  console.error("[verify-core] error:", error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
