#!/usr/bin/env node
import { existsSync, promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import type {
  ReleasedClientClaimPolicyFile,
  ReleasedClientClaimReportFile,
} from "./released-client-types.js";

const MODULE_DIR = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_POLICY_PATH = "spec/released-client-claim.current.json";
const DEFAULT_REPORT_PATH = ".artifacts/release/released-client-claim-report.json";

type CliOptions = {
  root: string | null;
  policy: string;
  report: string;
  claimActive: string | null;
};

function usage(): string {
  return [
    "Usage:",
    "  node dist-tools/check-released-client-claim-activation.js [options]",
    "",
    "Options:",
    "  --root <sdk-root>          Workspace root (autodetected when omitted)",
    "  --policy <path>           Default: spec/released-client-claim.current.json",
    "  --report <path>           Default: .artifacts/release/released-client-claim-report.json",
    "  --claim-active <bool>     Optional override for the requested released-client state",
  ].join("\n");
}

function parseArgs(argv: string[]): CliOptions {
  const options: CliOptions = {
    root: process.env.AEGAEON_SDK_ROOT ?? null,
    policy: process.env.AEGAEON_RELEASED_CLIENT_CLAIM_POLICY_PATH ?? DEFAULT_POLICY_PATH,
    report: process.env.AEGAEON_RELEASED_CLIENT_CLAIM_REPORT_PATH ?? DEFAULT_REPORT_PATH,
    claimActive: process.env.AEGAEON_RELEASED_CLIENT_CLAIM_ACTIVE ?? null,
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
    const value = argv[index + 1];
    if (!value || value.startsWith("--")) {
      throw new Error(`Missing value for option ${token}`);
    }
    switch (token) {
      case "--root":
        options.root = value;
        break;
      case "--policy":
        options.policy = value;
        break;
      case "--report":
        options.report = value;
        break;
      case "--claim-active":
        options.claimActive = value;
        break;
      default:
        throw new Error(`Unknown option ${token}`);
    }
    index += 1;
  }

  return options;
}

function findWorkspaceRoot(explicitRoot: string | null): string {
  if (explicitRoot) {
    return path.resolve(explicitRoot);
  }
  let current = path.resolve(MODULE_DIR);
  while (true) {
    if (
      existsSync(path.join(current, "package.json")) &&
      existsSync(path.join(current, "packages"))
    ) {
      return current;
    }
    const parent = path.dirname(current);
    if (parent === current) {
      throw new Error("Could not locate sdk workspace root");
    }
    current = parent;
  }
}

function resolveWithinRoot(rootDir: string, targetPath: string): string {
  return path.isAbsolute(targetPath) ? targetPath : path.resolve(rootDir, targetPath);
}

function parseBool(value: string | null | undefined, label: string): boolean | null {
  if (value === null || value === undefined || value === "") {
    return null;
  }
  if (/^(1|true|TRUE)$/.test(String(value))) {
    return true;
  }
  if (/^(0|false|FALSE)$/.test(String(value))) {
    return false;
  }
  throw new Error(`Expected boolean string for ${label}`);
}

async function readJson<T>(filePath: string): Promise<T> {
  return JSON.parse(await fs.readFile(filePath, "utf8")) as T;
}

async function main(): Promise<void> {
  const options = parseArgs(process.argv.slice(2));
  const rootDir = findWorkspaceRoot(options.root);
  const policyPath = resolveWithinRoot(rootDir, options.policy);
  const reportPath = resolveWithinRoot(rootDir, options.report);
  const requestedActive = parseBool(options.claimActive, "claimActive");

  const [policy, report] = await Promise.all([
    readJson<ReleasedClientClaimPolicyFile>(policyPath),
    readJson<ReleasedClientClaimReportFile>(reportPath),
  ]);
  const failures: string[] = [];

  if (report.claim_target !== policy.claim_target) {
    failures.push(
      `claim target mismatch: expected ${policy.claim_target}, got ${report.claim_target}`,
    );
  }
  if (report.current_state?.claim_phase !== policy.current_state.claim_phase) {
    failures.push(
      "report current_state.claim_phase mismatch: expected " +
        `${policy.current_state.claim_phase}, got ` +
        (report.current_state?.claim_phase ?? "missing"),
    );
  }
  if (
    report.current_state?.released_client_claim_active !==
    policy.current_state.released_client_claim_active
  ) {
    failures.push(
      "report current_state.released_client_claim_active " +
        "does not match the released-client policy",
    );
  }
  if (report.target_state?.claim_phase !== policy.target_state.claim_phase) {
    failures.push(
      "report target_state.claim_phase mismatch: expected " +
        `${policy.target_state.claim_phase}, got ` +
        (report.target_state?.claim_phase ?? "missing"),
    );
  }
  if (
    report.target_state?.canonical_statement !==
    policy.target_state.canonical_statement
  ) {
    failures.push(
      "report target_state.canonical_statement does not match " +
        "the released-client policy",
    );
  }

  const effectiveActive = requestedActive ?? policy.current_state.released_client_claim_active;
  if (effectiveActive && !policy.current_state.released_client_claim_active) {
    failures.push(
      "released client claim activation was requested, but the " +
        "source-managed policy still marks it inactive",
    );
  }

  if (policy.current_state.released_client_claim_active) {
    if (policy.current_state.claim_phase !== policy.target_state.claim_phase) {
      failures.push(
        `active policy must use released claim phase ` +
          `${policy.target_state.claim_phase}, got ` +
          policy.current_state.claim_phase,
      );
    }
    if (!report.ready) {
      if (Array.isArray(report.blockers) && report.blockers.length > 0) {
        for (const blocker of report.blockers) {
          failures.push(`released-client report: ${blocker}`);
        }
      } else {
        failures.push("released-client report is not ready");
      }
    }
  }

  if (failures.length > 0) {
    for (const failure of failures) {
      console.error(`[released-client-activation] ${failure}`);
    }
    process.exitCode = 1;
    return;
  }

  if (policy.current_state.released_client_claim_active) {
    console.log(
      "[released-client-activation] released client claim is active and " +
        `${path.relative(rootDir, reportPath)} is ready`,
    );
    return;
  }

  console.log(
    "[released-client-activation] released client claim remains inactive; " +
      `${path.relative(rootDir, reportPath)} is advisory`,
  );
}

main().catch((error) => {
  console.error(
    "[released-client-activation] error:",
    error instanceof Error ? error.message : error,
  );
  process.exitCode = 1;
});
