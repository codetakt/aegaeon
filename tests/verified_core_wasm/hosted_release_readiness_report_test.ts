#!/usr/bin/env node
import assert from "node:assert/strict";

function hoursAgo(hours: number): string {
  return new Date(Date.now() - hours * 60 * 60 * 1000).toISOString();
}

async function main() {
  const { buildHostedReleaseReadinessReport } = await import(
    "../../scripts/sdk/tools-src/build-hosted-release-readiness-report.ts"
  );
  console.log("=== hosted release readiness report test ===");
  const workflowPolicy = {
    required_workflows: [
      { path: ".github/workflows/verify-core.yml", name: "SDK Verify Core" },
      {
        path: ".github/workflows/managed-provider-evidence.yml",
        name: "SDK Managed Provider Evidence",
      },
    ],
  };
  const releasedClientClaimPolicy = {
    activation_requirements: {
      managed_provider_evidence_max_age_hours: 168,
      managed_provider_expected_workflow: "SDK Managed Provider Evidence",
      admin_sdk_evidence_max_age_hours: 168,
      admin_sdk_expected_workflow: "Admin Console Stack E2E",
    },
  };

  const readyReport = buildHostedReleaseReadinessReport({
    sdkRepository: "cariandrum22/aegaeon-sdk",
    adminRepository: "cariandrum22/aegaeon-admin-console",
    localSdkHead: "abc123",
    sdkState: {
      repository: "cariandrum22/aegaeon-sdk",
      defaultBranch: "main",
      remoteHead: "abc123",
      remoteHeadMessage: null,
      workflowFiles: ["verify-core.yml", "managed-provider-evidence.yml"],
      variables: {},
      secrets: [],
      runs: [
        {
          workflowName: "SDK Managed Provider Evidence",
          status: "completed",
          conclusion: "success",
          createdAt: hoursAgo(2),
          headBranch: "main",
          headSha: "abc123",
          event: "workflow_dispatch",
          jobName: "external-provider-managed",
        },
      ],
    },
    adminState: {
      repository: "cariandrum22/aegaeon-admin-console",
      defaultBranch: "main",
      remoteHead: "def456",
      remoteHeadMessage: null,
      workflowFiles: ["stack-e2e.yml"],
      variables: {},
      secrets: [],
      runs: [
        {
          workflowName: "Admin Console Stack E2E",
          status: "completed",
          conclusion: "success",
          createdAt: hoursAgo(3),
          headBranch: "main",
          headSha: "def456",
          event: "workflow_dispatch",
          jobName: "stack-e2e",
        },
      ],
    },
    sdkRepositorySettingsMismatches: [],
    sdkHostedEvidenceSourceMismatches: [],
    releasedClientClaimPolicy,
    workflowInventoryPolicy: workflowPolicy,
  });

  assert.equal(readyReport.ready, true);
  assert.deepEqual(readyReport.blockers, []);
  assert.equal(readyReport.sdk_remote_contains_local_head, true);
  assert.equal(readyReport.sdk_remote_matches_local_snapshot, false);

  const snapshotReadyReport = buildHostedReleaseReadinessReport({
    sdkRepository: "codetakt/aegaeon-sdk-ci",
    adminRepository: "codetakt/aegaeon-admin-console-ci",
    localSdkHead: "d5e42a95e323fac8b585c152d274622a25985abd",
    sdkState: {
      repository: "codetakt/aegaeon-sdk-ci",
      defaultBranch: "main",
      remoteHead: "ec71ab305ecdc17e0d9084e798311108deafdf12",
      remoteHeadMessage: "CI snapshot (d5e42a9)",
      workflowFiles: ["verify-core.yml", "managed-provider-evidence.yml"],
      variables: {},
      secrets: [],
      runs: [
        {
          workflowName: "SDK Managed Provider Evidence",
          status: "completed",
          conclusion: "success",
          createdAt: hoursAgo(1),
          headBranch: "main",
          headSha: "ec71ab305ecdc17e0d9084e798311108deafdf12",
          event: "workflow_dispatch",
          jobName: "external-provider-managed",
        },
      ],
    },
    adminState: {
      repository: "codetakt/aegaeon-admin-console-ci",
      defaultBranch: "main",
      remoteHead: "e88d81d51f967c778911337afeb0fda40db83f27",
      remoteHeadMessage: "CI snapshot (e88d81d)",
      workflowFiles: ["stack-e2e.yml"],
      variables: {},
      secrets: [],
      runs: [
        {
          workflowName: "Admin Console Stack E2E",
          status: "completed",
          conclusion: "success",
          createdAt: hoursAgo(2),
          headBranch: "main",
          headSha: "e88d81d51f967c778911337afeb0fda40db83f27",
          event: "workflow_dispatch",
          jobName: "stack-e2e",
        },
      ],
    },
    sdkRepositorySettingsMismatches: [],
    sdkHostedEvidenceSourceMismatches: [],
    releasedClientClaimPolicy,
    workflowInventoryPolicy: workflowPolicy,
  });

  assert.equal(snapshotReadyReport.ready, true);
  assert.deepEqual(snapshotReadyReport.blockers, []);
  assert.equal(snapshotReadyReport.sdk_remote_contains_local_head, false);
  assert.equal(snapshotReadyReport.sdk_remote_matches_local_snapshot, true);
  assert.equal(snapshotReadyReport.remote_sdk_snapshot_source_head, "d5e42a9");

  const blockedReport = buildHostedReleaseReadinessReport({
    sdkRepository: "cariandrum22/aegaeon-sdk",
    adminRepository: "cariandrum22/aegaeon-admin-console",
    localSdkHead: "local-head",
    sdkState: {
      repository: "cariandrum22/aegaeon-sdk",
      defaultBranch: "main",
      remoteHead: "remote-head",
      remoteHeadMessage: null,
      workflowFiles: ["verify-core.yml"],
      variables: {},
      secrets: [],
      runs: [],
    },
    adminState: {
      repository: "cariandrum22/aegaeon-admin-console",
      defaultBranch: "main",
      remoteHead: "admin-head",
      remoteHeadMessage: null,
      workflowFiles: [],
      variables: {},
      secrets: [],
      runs: [],
    },
    sdkRepositorySettingsMismatches: ["missing AEGAEON_NPM_TOKEN"],
    sdkHostedEvidenceSourceMismatches: ["missing AEGAEON_ADMIN_CONSOLE_REPOSITORY"],
    releasedClientClaimPolicy,
    workflowInventoryPolicy: workflowPolicy,
  });

  assert.equal(blockedReport.ready, false);
  assert.ok(blockedReport.blockers.includes("sdk_remote_does_not_contain_local_head"));
  assert.ok(blockedReport.blockers.includes("sdk_repository_settings_mismatch"));
  assert.ok(blockedReport.blockers.includes("sdk_hosted_evidence_source_mismatch"));
  assert.ok(blockedReport.blockers.includes("sdk_remote_missing_workflow_files"));
  assert.ok(blockedReport.blockers.includes("admin_remote_missing_workflow_files"));
  assert.ok(blockedReport.blockers.includes("managed_provider_successful_hosted_run_missing"));
  assert.ok(blockedReport.blockers.includes("admin_sdk_successful_hosted_run_missing"));
  assert.equal(blockedReport.managed_provider_evidence.latestSuccessfulRun, null);
  assert.equal(blockedReport.admin_sdk_evidence.latestSuccessfulRun, null);

  console.log("hosted release readiness report tests passed");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
