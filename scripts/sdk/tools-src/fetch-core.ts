import { createHash, createPublicKey, verify as verifySignature } from "node:crypto";
import { promises as fs } from "node:fs";
import path from "node:path";

type CliOptions = {
  manifest: string;
  wasm: string;
  outDir: string;
  signature: string | undefined;
  publicKey: string | undefined;
};

type VerifiedCoreManifest = {
  sha256?: unknown;
  sha512?: unknown;
  artifact?: unknown;
  version?: unknown;
  source_commit?: unknown;
};

function parseArgs(argv: string[]): CliOptions {
  const args = new Map<string, string>();
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (!token || !token.startsWith("--")) {
      continue;
    }
    const rawKey = token.slice(2);
    const key = rawKey.replace(/-([a-z])/g, (_, char: string) => char.toUpperCase());
    const value = argv[index + 1];
    if (!value || value.startsWith("--")) {
      throw new Error(`Missing value for option --${rawKey}`);
    }
    args.set(key, value);
    index += 1;
  }

  const manifest = args.get("manifest");
  const wasm = args.get("wasm");
  const outDir = args.get("outDir");
  if (!manifest) {
    throw new Error("Missing required option --manifest");
  }
  if (!wasm) {
    throw new Error("Missing required option --wasm");
  }
  if (!outDir) {
    throw new Error("Missing required option --out-dir");
  }

  const signature = args.get("signature");
  const publicKey = args.get("publicKey");
  if ((signature && !publicKey) || (!signature && publicKey)) {
    throw new Error("signature and publicKey must be provided together");
  }

  return {
    manifest,
    wasm,
    outDir,
    signature,
    publicKey,
  };
}

async function readJson(filePath: string): Promise<unknown> {
  const raw = await fs.readFile(filePath, "utf8");
  return JSON.parse(raw) as unknown;
}

async function ensureDir(dir: string): Promise<void> {
  await fs.mkdir(dir, { recursive: true });
}

function toIntegrity(hashHex: string): string {
  const hashBuffer = Buffer.from(hashHex, "hex");
  return `sha256-${hashBuffer.toString("base64")}`;
}

function parseSignatureBuffer(input: Buffer): Buffer {
  if (input.length === 64) {
    return input;
  }
  const asString = input.toString().trim();
  if (/^[A-Za-z0-9+/=]+$/.test(asString)) {
    return Buffer.from(asString, "base64");
  }
  throw new Error("Unsupported signature format. Expected raw 64-byte buffer or base64 string.");
}

function normalizeManifest(value: unknown): {
  sha256: string;
  sha512: string | null;
  artifact: string | null;
  version: string | null;
  sourceCommit: string | null;
} {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Manifest must be an object.");
  }
  const manifest = value as VerifiedCoreManifest;
  if (typeof manifest.sha256 !== "string" || manifest.sha256.length === 0) {
    throw new Error("Manifest is missing sha256 field.");
  }
  return {
    sha256: manifest.sha256,
    sha512: typeof manifest.sha512 === "string" && manifest.sha512.length > 0 ? manifest.sha512 : null,
    artifact: typeof manifest.artifact === "string" && manifest.artifact.length > 0 ? manifest.artifact : null,
    version: typeof manifest.version === "string" && manifest.version.length > 0 ? manifest.version : null,
    sourceCommit:
      typeof manifest.source_commit === "string" && manifest.source_commit.length > 0
        ? manifest.source_commit
        : null,
  };
}

async function main(): Promise<void> {
  const options = parseArgs(process.argv.slice(2));
  const manifest = normalizeManifest(await readJson(options.manifest));

  const wasm = await fs.readFile(options.wasm);
  const sha256 = createHash("sha256").update(wasm).digest("hex");
  if (sha256 !== manifest.sha256) {
    throw new Error(`sha256 mismatch: expected ${manifest.sha256}, actual ${sha256}`);
  }
  if (manifest.sha512 !== null) {
    const sha512 = createHash("sha512").update(wasm).digest("hex");
    if (sha512 !== manifest.sha512) {
      throw new Error(`sha512 mismatch: expected ${manifest.sha512}, actual ${sha512}`);
    }
  } else {
    console.warn("[fetch-core] manifest missing sha512, skipping verification");
  }

  const hasSignature = Boolean(options.signature && options.publicKey);
  if (hasSignature) {
    const signatureRaw = await fs.readFile(options.signature as string);
    const signature = parseSignatureBuffer(signatureRaw);
    const publicKeyPem = await fs.readFile(options.publicKey as string, "utf8");
    const publicKey = createPublicKey(publicKeyPem);
    if (!verifySignature(null, wasm, publicKey, signature)) {
      throw new Error("Ed25519 signature verification failed.");
    }
  } else {
    console.warn("[fetch-core] signature/public key not provided, skipping signature verification");
  }

  await ensureDir(options.outDir);
  const outputWasm = path.join(options.outDir, manifest.artifact ?? "verified_core.wasm");
  await fs.writeFile(outputWasm, wasm);
  await fs.copyFile(options.manifest, path.join(options.outDir, "manifest.json"));
  if (hasSignature) {
    await fs.copyFile(options.signature as string, path.join(options.outDir, "verified_core.wasm.sig"));
  }

  const integrity = toIntegrity(manifest.sha256);
  await fs.writeFile(path.join(options.outDir, "integrity.txt"), `${integrity}\n`, "utf8");

  console.log("[fetch-core] verified artefact stored in:", options.outDir);
  console.log("[fetch-core] version:", manifest.version ?? "unknown");
  if (manifest.sourceCommit) {
    console.log("[fetch-core] commit:", manifest.sourceCommit);
  }
}

main().catch((error) => {
  console.error("[fetch-core] error:", error instanceof Error ? error.message : error);
  process.exitCode = 1;
});
