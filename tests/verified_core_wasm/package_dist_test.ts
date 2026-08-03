#!/usr/bin/env node
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..", "..");
const NODE = process.execPath;

function runNode(script, args) {
  execFileSync(NODE, [script, ...args], {
    cwd: ROOT,
    stdio: "inherit",
  });
}

function main() {
  console.log("=== Verified Core Packaging Tests ===");

  const tmpDir = mkdtempSync(path.join(os.tmpdir(), "aegaeon-verified-core-"));
  try {
    const privateKeyPath = path.join(tmpDir, "signing.pem");
    const publicKeyPath = path.join(tmpDir, "signing.pub.pem");
    const distDir = path.join(tmpDir, "dist");
    const fetchedDir = path.join(tmpDir, "fetched");

    runNode("scripts/sdk/sign_core_artifact.js", [
      "--generate-keys",
      "--out-private", privateKeyPath,
      "--out-public", publicKeyPath,
    ]);

    runNode("scripts/sdk/package_verified_core_dist.js", [
      "--out", distDir,
      "--wasm", path.join(ROOT, "artifacts/verified-core/verified_core.wasm"),
      "--abi", path.join(ROOT, "generated/lowstar/verified-core/verified_core.abi.json"),
      "--version", "0.0.0-test",
      "--private-key", privateKeyPath,
    ]);

    const expectedFiles = [
      "verified_core.wasm",
      "verified_core.wasm.sig",
      "verified_core.wasm.sha256",
      "verified_core.wasm.sha512",
      "verified_core.wasm.sri",
      "manifest.json",
      "verified_core.abi.json",
      "verified-core-sbom.json",
      "types.d.ts",
      "integrity.txt",
    ];
    for (const file of expectedFiles) {
      assert.equal(existsSync(path.join(distDir, file)), true, `${file} should exist`);
    }

    const manifest = JSON.parse(readFileSync(path.join(distDir, "manifest.json"), "utf8"));
    assert.equal(manifest.artifact, "verified_core.wasm");
    assert.equal(manifest.version, "0.0.0-test");
    assert.equal(typeof manifest.sha256, "string");
    assert.equal(typeof manifest.sri, "string");
    assert.equal(manifest.signature.algorithm, "Ed25519");
    assert.equal(manifest.signature.file, "verified_core.wasm.sig");

    runNode("scripts/sdk/fetch_core_artifact.js", [
      "--manifest", path.join(distDir, "manifest.json"),
      "--wasm", path.join(distDir, "verified_core.wasm"),
      "--signature", path.join(distDir, "verified_core.wasm.sig"),
      "--public-key", publicKeyPath,
      "--out-dir", fetchedDir,
    ]);

    assert.equal(existsSync(path.join(fetchedDir, "verified_core.wasm")), true);
    assert.equal(existsSync(path.join(fetchedDir, "manifest.json")), true);
    assert.equal(existsSync(path.join(fetchedDir, "integrity.txt")), true);

    console.log("=== packaging checks passed ===");
  } finally {
    rmSync(tmpDir, { recursive: true, force: true });
  }
}

main();
