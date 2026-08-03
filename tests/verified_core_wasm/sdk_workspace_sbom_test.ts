#!/usr/bin/env node
import assert from "node:assert/strict";
import { execFile as execFileCallback } from "node:child_process";
import { mkdtemp, readFile, stat, writeFile, mkdir } from "node:fs/promises";
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

async function writeJson(filePath, value) {
  await mkdir(path.dirname(filePath), { recursive: true });
  await writeFile(filePath, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

async function main() {
  console.log("=== sdk workspace sbom test ===");
  const scriptPath = await firstExistingPath([
    path.join(ROOT_DIR, "scripts", "sdk", "build_sdk_workspace_sbom.ts"),
    path.join(ROOT_DIR, "dist-tools", "build-workspace-sbom.js"),
    path.join(ROOT_DIR, "scripts", "build-workspace-sbom.ts"),
  ]);
  const boundaryPath = await firstExistingPath([
    path.join(ROOT_DIR, "spec", "client-claim-boundary.current.json"),
  ]);

  const tempRoot = await mkdtemp(path.join(os.tmpdir(), "aegaeon-sdk-sbom-"));
  const outPath = path.join(tempRoot, ".artifacts", "release", "sdk-workspace-sbom.cdx.json");
  const publishManifestPath = path.join(tempRoot, ".artifacts", "release", "publish-manifest.json");
  const packageNames = [
    "@aegaeon/verified-core",
    "@aegaeon/runtime-node",
    "@aegaeon/runtime-web",
  ];

  await writeJson(path.join(tempRoot, "package.json"), {
    name: "aegaeon-sdk",
    version: "1.0.0",
  });

  for (const packageName of packageNames) {
    const dirName = packageName.split("/").pop();
    await writeJson(path.join(tempRoot, "packages", dirName, "package.json"), {
      name: packageName,
      version: "1.0.0",
    });
  }

  await writeJson(path.join(tempRoot, "packages", "verified-core", "dist", "manifest.json"), {
    generated_at: "2026-03-12T00:00:00Z",
  });
  await writeJson(
    path.join(tempRoot, "packages", "verified-core", "dist", "verified-core-sbom.json"),
    {
      bomFormat: "CycloneDX",
      specVersion: "1.5",
    },
  );

  await writeJson(publishManifestPath, {
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
        packageName: "@aegaeon/verified-core",
        version: "1.0.0",
        tarball: "aegaeon-verified-core-1.0.0.tgz",
        sha256: "0".repeat(64),
        sha512: "1".repeat(128),
        dependencyBlocks: {},
      },
      {
        packageName: "@aegaeon/runtime-node",
        version: "1.0.0",
        tarball: "aegaeon-runtime-node-1.0.0.tgz",
        sha256: "2".repeat(64),
        sha512: "3".repeat(128),
        dependencyBlocks: {
          dependencies: {
            "@aegaeon/verified-core": "^1.0.0",
            jose: "^5.0.0",
          },
        },
      },
      {
        packageName: "@aegaeon/runtime-web",
        version: "1.0.0",
        tarball: "aegaeon-runtime-web-1.0.0.tgz",
        sha256: "4".repeat(64),
        sha512: "5".repeat(128),
        dependencyBlocks: {
          dependencies: {
            "@aegaeon/verified-core": "^1.0.0",
          },
        },
      },
    ],
    verifiedCore: {
      manifestPath: "packages/verified-core/dist/manifest.json",
      manifestSha256: "6".repeat(64),
      handoffManifestPath: null,
      handoffManifestSha256: null,
    },
  });

  await execFile(process.execPath, [
    scriptPath,
    "--root",
    tempRoot,
    "--publish-manifest",
    publishManifestPath,
    "--claim-boundary",
    boundaryPath,
    "--out",
    outPath,
  ], { cwd: ROOT_DIR });

  const sbom = JSON.parse(await readFile(outPath, "utf8"));
  assert.equal(sbom.bomFormat, "CycloneDX");
  assert.equal(sbom.specVersion, "1.5");
  assert.equal(sbom.metadata.component.name, "aegaeon-sdk");
  assert.equal(
    sbom.metadata.component.properties.find(
      (entry) => entry.name === "aegaeon:default_client_profile",
    ).value,
    "aegaeon-rs256",
  );
  assert.ok(sbom.components.some((entry) => entry.name === "@aegaeon/runtime-node"));
  assert.ok(sbom.components.some((entry) => entry.name === "jose"));
  const rootDependency = sbom.dependencies.find((entry) => entry.ref.includes("aegaeon-sdk"));
  assert.equal(rootDependency.dependsOn.length, 3);
  const runtimeNode = sbom.components.find((entry) => entry.name === "@aegaeon/runtime-node");
  assert.ok(runtimeNode.hashes.some((entry) => entry.content === "2".repeat(64)));
  const verifiedCore = sbom.components.find((entry) => entry.name === "@aegaeon/verified-core");
  assert.equal(verifiedCore.externalReferences[0].type, "bom");

  console.log("sdk workspace sbom tests passed");
}

main().catch((error) => {
  console.error("[fail] sdk_workspace_sbom_test:", error);
  process.exitCode = 1;
});
