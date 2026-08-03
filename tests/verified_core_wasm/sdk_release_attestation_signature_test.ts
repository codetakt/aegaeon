#!/usr/bin/env node
import assert from "node:assert/strict";
import { execFile as execFileCallback } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { mkdtemp, readFile, stat, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";

const execFile = promisify(execFileCallback);
const ROOT_DIR = path.resolve(new URL("../..", import.meta.url).pathname);

async function firstExistingPath(candidates) {
  for (const candidate of candidates) {
    try {
      await stat(candidate);
      return candidate;
    } catch (error) {
      if (!error || error.code !== "ENOENT") {
        throw error;
      }
    }
  }
  throw new Error(`No candidate path exists: ${candidates.join(", ")}`);
}

async function main() {
  console.log("=== sdk release attestation signature test ===");
  const scriptPath = await firstExistingPath([
    path.join(ROOT_DIR, "scripts", "sdk", "build_sdk_release_attestation.ts"),
    path.join(ROOT_DIR, "dist-tools", "build-release-attestation.js"),
  ]);
  const checkSignaturePath = await firstExistingPath([
    path.join(ROOT_DIR, "scripts", "sdk", "check_sdk_release_attestation_signature.ts"),
    path.join(ROOT_DIR, "dist-tools", "check-release-attestation-signature.js"),
  ]);
  const attestationValidatorPath = await firstExistingPath([
    path.join(ROOT_DIR, "scripts", "validation", "validate_sdk_release_attestation.py"),
  ]);
  const signatureValidatorPath = await firstExistingPath([
    path.join(ROOT_DIR, "scripts", "validation", "validate_sdk_release_attestation_signature.py"),
  ]);
  const boundaryPath = await firstExistingPath([
    path.join(ROOT_DIR, "spec", "client-claim-boundary.current.json"),
  ]);

  const tempRoot = await mkdtemp(path.join(os.tmpdir(), "aegaeon-sdk-attestation-signature-"));
  const publishManifestPath = path.join(tempRoot, "publish-manifest.json");
  const attestationPath = path.join(tempRoot, "release-attestation.json");
  const descriptorPath = path.join(tempRoot, "release-attestation.signature.json");
  const signaturePath = path.join(tempRoot, "release-attestation.sig");
  const publicKeyPath = path.join(tempRoot, "release-attestation.public.pem");

  await writeFile(
    publishManifestPath,
    `${JSON.stringify({
      schemaVersion: 1,
      generatedAt: "2026-03-12T00:00:00Z",
      source: {
        githubRef: "refs/heads/main",
        githubSha: "deadbeefcafebabe",
        githubRunId: "12345",
        githubWorkflow: "publish",
        npmDistTag: "latest",
      },
      tarballs: [
        {
          packageName: "@aegaeon/runtime-node",
          version: "1.0.0",
          tarball: "aegaeon-runtime-node-1.0.0.tgz",
          sha256: "0".repeat(64),
          sha512: "1".repeat(128),
          dependencyBlocks: {},
        },
      ],
      verifiedCore: {
        manifestPath: "packages/verified-core/dist/manifest.json",
        manifestSha256: "2".repeat(64),
        handoffManifestPath: "packages/verified-core/dist/verified-core-handoff-manifest.json",
        handoffManifestSha256: "3".repeat(64),
      },
    }, null, 2)}\n`,
    "utf8",
  );

  const { privateKey } = generateKeyPairSync("ec", {
    namedCurve: "prime256v1",
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
    publicKeyEncoding: { type: "spki", format: "pem" },
  });

  await execFile(
    process.execPath,
    [
      scriptPath,
      "--root",
      tempRoot,
      "--publish-manifest",
      publishManifestPath,
      "--claim-boundary",
      boundaryPath,
      "--out",
      attestationPath,
      "--signature",
      signaturePath,
      "--public-key",
      publicKeyPath,
      "--signature-descriptor",
      descriptorPath,
    ],
    {
      cwd: ROOT_DIR,
      env: {
        ...process.env,
        NPM_CONFIG_PROVENANCE: "true",
        AEGAEON_SDK_SIGNED_RELEASE_ATTESTATION: "true",
        AEGAEON_COSIGN_KEY: privateKey,
      },
    },
  );

  await execFile("python3", [attestationValidatorPath, attestationPath], { cwd: ROOT_DIR });
  await execFile("python3", [signatureValidatorPath, descriptorPath], { cwd: ROOT_DIR });
  await execFile(process.execPath, [
    checkSignaturePath,
    "--root",
    tempRoot,
    "--attestation",
    attestationPath,
    "--descriptor",
    descriptorPath,
    "--require-signed",
  ], { cwd: ROOT_DIR });

  const attestation = JSON.parse(await readFile(attestationPath, "utf8"));
  const descriptor = JSON.parse(await readFile(descriptorPath, "utf8"));
  const signatureBase64 = (await readFile(signaturePath, "utf8")).trim();
  const publicKey = await readFile(publicKeyPath, "utf8");

  assert.equal(attestation.publication.signed_release_attestation_present, true);
  assert.equal(descriptor.signature_algorithm, "ecdsa-sha256");
  assert.equal(descriptor.key_type, "ec");
  assert.equal(descriptor.signature_encoding, "base64");
  assert.equal(descriptor.signed_release_attestation_present, true);
  assert.match(signatureBase64, /^[A-Za-z0-9+/=]+$/);
  assert.match(publicKey, /BEGIN PUBLIC KEY/);

  console.log("sdk release attestation signature tests passed");
}

main().catch((error) => {
  console.error("[fail] sdk_release_attestation_signature_test:", error);
  process.exitCode = 1;
});
