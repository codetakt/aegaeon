#!/usr/bin/env node
import { promises as fs } from "node:fs";
import path from "node:path";

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
];

const OPTIONAL_FILES = [
  "verified_core.wasm.sig",
  "verified_core.wasm.cosign.sig",
];

function usage() {
  return [
    "Usage: node --experimental-strip-types scripts/sdk/build_verified_core_handoff_manifest.ts \\",
    "  --core-repo <owner/repo> --core-release-tag <tag> " +
      "--source-commit <sha> --output <path> [options]",
    "",
    "Options:",
    "  --bundle-format <format>            Default: github-release",
    "  --source-workflow <name>            Default: Verified Core Release",
    "  --source-run-id <id>                Optional GitHub Actions run id",
    "  --release-url <url>                 Optional release URL",
    "  --release-artifact-name <name>      Optional workflow artifact name",
    "  --dispatch-artifact-name <name>     Optional dispatch artifact name",
    "  --handoff-manifest-file <name>      Default: verified-core-handoff-manifest.json",
    "  --generated-at <iso-8601>           Optional timestamp override",
  ].join("\n");
}

function parseArgs(argv) {
  const options = {
    coreRepo: null,
    coreReleaseTag: null,
    sourceCommit: null,
    bundleFormat: "github-release",
    sourceWorkflow: "Verified Core Release",
    sourceRunId: null,
    releaseUrl: null,
    releaseArtifactName: null,
    dispatchArtifactName: null,
    handoffManifestFile: "verified-core-handoff-manifest.json",
    generatedAt: null,
    output: null,
  };

  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (token === "--help" || token === "-h") {
      console.log(usage());
      process.exit(0);
    }
    if (!token.startsWith("--")) {
      continue;
    }
    const rawKey = token.slice(2);
    const key = rawKey.replace(/-([a-z])/g, (_, char) => char.toUpperCase());
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

  for (const [field, flag] of [
    ["coreRepo", "core-repo"],
    ["coreReleaseTag", "core-release-tag"],
    ["sourceCommit", "source-commit"],
    ["output", "output"],
  ]) {
    if (!options[field]) {
      throw new Error(`Missing required option --${flag}\n\n${usage()}`);
    }
  }

  if (!options.releaseArtifactName) {
    options.releaseArtifactName = `verified-core-${options.coreReleaseTag}`;
  }
  if (!options.dispatchArtifactName) {
    options.dispatchArtifactName = `verified-core-sdk-dispatch-${options.coreReleaseTag}`;
  }

  return options;
}

function buildManifest(options) {
  /** @type {Record<string, unknown>} */
  const manifest = {
    schema_version: 1,
    bundle_format: options.bundleFormat,
    handoff_manifest_file: options.handoffManifestFile,
    core_repo: options.coreRepo,
    core_release_tag: options.coreReleaseTag,
    source_commit: options.sourceCommit,
    source_workflow: options.sourceWorkflow,
    generated_at: options.generatedAt ?? new Date().toISOString(),
    release_artifact_name: options.releaseArtifactName,
    dispatch_artifact_name: options.dispatchArtifactName,
    required_files: REQUIRED_FILES,
    optional_files: OPTIONAL_FILES,
  };

  if (options.sourceRunId) {
    manifest.source_run_id = options.sourceRunId;
  }
  if (options.releaseUrl) {
    manifest.release_url = options.releaseUrl;
  }

  return manifest;
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  const manifest = buildManifest(options);
  const outputPath = path.resolve(options.output);
  await fs.mkdir(path.dirname(outputPath), { recursive: true });
  await fs.writeFile(outputPath, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
  console.log(`[verified-core-handoff] wrote ${outputPath}`);
}

main().catch((error) => {
  console.error("[verified-core-handoff] error:", error);
  process.exitCode = 1;
});
