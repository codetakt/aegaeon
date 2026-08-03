#!/usr/bin/env node
import assert from "node:assert/strict";
import { execFile as execFileCallback } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { mkdtemp, mkdir, readFile, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";

const execFile = promisify(execFileCallback);
const ROOT_DIR = path.resolve(new URL("../../", import.meta.url).pathname);
const scriptPath = path.join(ROOT_DIR, "scripts", "sdk", "materialize_verified_core_public_key.ts");

async function main() {
  console.log("=== Verified Core Public-Key Materialization Tests ===");

  const tempRoot = await mkdtemp(path.join(os.tmpdir(), "aegaeon-verified-core-pubkey-"));
  const directOutput = path.join(tempRoot, "verified-core-direct.pem");
  const base64Output = path.join(tempRoot, "verified-core-base64.pem");
  const opOutput = path.join(tempRoot, "verified-core-op.pem");
  const invalidOutput = path.join(tempRoot, "verified-core-invalid.pem");
  const fakeBinDir = path.join(tempRoot, "bin");
  const fakeOpPath = path.join(fakeBinDir, "op");

  const { publicKey } = generateKeyPairSync("ed25519");
  const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString("utf8");

  await execFile(process.execPath, [scriptPath], {
    cwd: ROOT_DIR,
    env: {
      ...process.env,
      AEGAEON_VERIFIED_CORE_PUBKEY: publicKeyPem,
      AEGAEON_VERIFIED_CORE_PUBKEY_OUTPUT: directOutput,
    },
  });
  assert.equal(await readFile(directOutput, "utf8"), publicKeyPem);

  await execFile(process.execPath, [
    scriptPath,
    "--public-key", Buffer.from(publicKeyPem, "utf8").toString("base64"),
    "--output", base64Output,
  ], { cwd: ROOT_DIR });
  assert.equal(await readFile(base64Output, "utf8"), publicKeyPem);

  await mkdir(fakeBinDir, { recursive: true });
  await writeFile(
    fakeOpPath,
    `#!/usr/bin/env bash
if [[ "$1" != "read" ]]; then exit 64; fi
printf '%s' "$FAKE_OP_VALUE"
`,
    { mode: 0o755 },
  );
  await execFile(process.execPath, [scriptPath], {
    cwd: ROOT_DIR,
    env: {
      ...process.env,
      PATH: `${fakeBinDir}:${process.env.PATH ?? ""}`,
      FAKE_OP_VALUE: Buffer.from(publicKeyPem, "utf8").toString("base64"),
      AEGAEON_VERIFIED_CORE_PUBKEY_OP_REF: "op://Aegaeon Dev Keys/Verified Core/public_key",
      AEGAEON_VERIFIED_CORE_PUBKEY_OUTPUT: opOutput,
      AEGAEON_OP_SERVICE_ACCOUNT_TOKEN: "test-token",
    },
  });
  assert.equal(await readFile(opOutput, "utf8"), publicKeyPem);

  await assert.rejects(
    execFile(process.execPath, [
      scriptPath,
      "--public-key", "not-a-valid-public-key",
      "--output", invalidOutput,
    ], { cwd: ROOT_DIR }),
    (error) => Number(error?.code) === 1,
  );

  console.log("=== verified core public-key materialization checks passed ===");
}

main().catch((error) => {
  console.error("[fail] verified_core_public_key_materialization_test:", error);
  process.exitCode = 1;
});
