#!/usr/bin/env node
import assert from "node:assert/strict";
import { execFile as execFileCallback } from "node:child_process";
import { readFile, stat } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { promisify } from "node:util";

const execFile = promisify(execFileCallback);
const ROOT_DIR = path.resolve(new URL("../../", import.meta.url).pathname);

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

function algorithmsFromBitmask(bitmask, VC_ALG) {
  return ["EdDSA", "RS256", "ES256"].filter((name) => {
    switch (name) {
      case "EdDSA":
        return (bitmask & VC_ALG.EDDSA) !== 0;
      case "RS256":
        return (bitmask & VC_ALG.RS256) !== 0;
      case "ES256":
        return (bitmask & VC_ALG.ES256) !== 0;
      default:
        return false;
    }
  });
}

async function main() {
  console.log("=== client claim boundary test ===");
  const validatorPath = await firstExistingPath([
    path.join(ROOT_DIR, "scripts", "validation", "validate_client_claim_boundary.py"),
  ]);
  const schemaPath = await firstExistingPath([
    path.join(ROOT_DIR, "spec", "client-claim-boundary.schema.json"),
  ]);
  const currentPath = await firstExistingPath([
    path.join(ROOT_DIR, "spec", "client-claim-boundary.current.json"),
  ]);
  const runtimeNodePath = await firstExistingPath([
    path.join(ROOT_DIR, "scripts", "sdk", "runtime_node_reference.ts"),
    path.join(ROOT_DIR, "packages", "runtime-node", "dist", "index.js"),
  ]);
  const runtimeWebPath = await firstExistingPath([
    path.join(ROOT_DIR, "scripts", "sdk", "runtime_web_reference.ts"),
    path.join(ROOT_DIR, "packages", "runtime-web", "dist", "index.js"),
  ]);

  await execFile("python3", [validatorPath, currentPath], { cwd: ROOT_DIR });

  const boundary = /** @type {any} */ (JSON.parse(await readFile(currentPath, "utf8")));
  assert.equal(boundary.schema_version, 1);
  assert.equal(boundary.claim_phase, "pre-release-client-baseline");
  assert.equal(boundary.released_client_claim_active, false);
  assert.equal(boundary.default_profile, "aegaeon-rs256");
  assert.ok(Array.isArray(boundary.promoted_client_slices));
  assert.ok(Array.isArray(boundary.compat_only_surfaces));
  assert.match(await readFile(schemaPath, "utf8"), /released_client_claim_active/);

  const runtimeNode = await import(pathToFileURL(runtimeNodePath).href);
  const runtimeWeb = await import(pathToFileURL(runtimeWebPath).href);

  for (const runtime of [runtimeNode, runtimeWeb]) {
    assert.equal(runtime.DEFAULT_CLIENT_CRYPTO_PROFILE, boundary.default_profile);

    for (const [profile, expected] of Object.entries(
      /** @type {Record<string, any>} */ (boundary.profiles),
    )) {
      const jwtAlgorithms = algorithmsFromBitmask(
        runtime.resolveJwtAllowedAlgorithmsBitmaskForProfile(profile),
        runtime.VC_ALG,
      );
      const dpopAlgorithms = algorithmsFromBitmask(
        runtime.resolveDpopAllowedAlgorithmsBitmaskForProfile(profile),
        runtime.VC_ALG,
      );
      assert.deepEqual(jwtAlgorithms, expected.jwt_algorithms);
      assert.deepEqual(dpopAlgorithms, expected.dpop_algorithms);
    }
  }

  const rs256Slice = boundary.promoted_client_slices.find(
    (slice) => slice.name === "rs256-required-client-slice",
  );
  assert.ok(rs256Slice);
  assert.deepEqual(rs256Slice.algorithms, ["RS256"]);
  assert.equal(rs256Slice.signature_model, "adapter-preverified");

  const es256Surface = boundary.compat_only_surfaces.find(
    (surface) => surface.name === "es256-interop-surface",
  );
  assert.ok(es256Surface);
  assert.deepEqual(es256Surface.algorithms, ["ES256"]);

  console.log("client claim boundary tests passed");
}

main().catch((error) => {
  console.error("[fail] client_claim_boundary_test:", error);
  process.exitCode = 1;
});
