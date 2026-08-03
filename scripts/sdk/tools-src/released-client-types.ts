export type ClaimBoundaryEntry = {
  name: string;
};

export type ClaimBoundaryFile = {
  claim_phase: string;
  released_client_claim_active: boolean;
  default_profile: string;
  promoted_client_slices: ClaimBoundaryEntry[];
  compat_only_surfaces: ClaimBoundaryEntry[];
};

export type ReleaseAttestationSource = {
  github_ref?: string | null;
  github_sha?: string | null;
  github_run_id?: string | null;
  github_workflow?: string | null;
  npm_dist_tag?: string | null;
};

export type ReleaseAttestationPublication = {
  npm_provenance_enabled?: boolean;
  signed_release_attestation_present?: boolean;
  sbom_publication_present?: boolean;
};

export type ReleaseAttestationVerifiedCore = {
  manifest_path?: string | null;
  manifest_sha256?: string | null;
  handoff_manifest_path?: string | null;
  handoff_manifest_sha256?: string | null;
};

export type ReleaseAttestationFile = {
  release_phase: string;
  source: ReleaseAttestationSource;
  publication?: ReleaseAttestationPublication;
  deferred_requirements: string[];
  verified_core: ReleaseAttestationVerifiedCore;
  client_claim_boundary?: {
    sha256?: string;
    claim_phase?: string;
    released_client_claim_active?: boolean;
    default_profile?: string;
    promoted_client_slices?: string[];
    compat_only_surfaces?: string[];
  };
};

export type ManagedProviderEvidenceFile = {
  generated_at: string;
  source?: {
    github_run_id?: string | null;
    github_workflow?: string | null;
    github_repository?: string | null;
    github_ref?: string | null;
    github_sha?: string | null;
    github_job?: string | null;
    imported_evidence_path?: string | null;
    imported_evidence_sha256?: string | null;
    imported_github_run_id?: string | null;
    imported_github_workflow?: string | null;
    imported_github_repository?: string | null;
    imported_github_ref?: string | null;
    imported_github_sha?: string | null;
    imported_github_job?: string | null;
  };
  provider?: {
    name?: string | null;
    slug?: string | null;
    class?: string | null;
    provider_class?: string | null;
  };
  lane?: {
    name?: string | null;
    hosted?: boolean | null;
    status?: string | null;
  };
  environment?: {
    hosted?: boolean | null;
  };
  result?: {
    status?: string | null;
  };
};

export type AdminSdkEvidenceFile = {
  generated_at: string;
  source?: {
    github_run_id?: string | null;
    github_workflow?: string | null;
    github_repository?: string | null;
    github_ref?: string | null;
    github_sha?: string | null;
    github_job?: string | null;
  };
  lane?: {
    name?: string | null;
    status?: string | null;
    stack_mode?: string | null;
  };
  sdk_boundary?: {
    management_sdk_package?: string | null;
  };
  capabilities?: string[];
};

export type ClientClaimPromotionPolicyFile = {
  required_boundary: {
    claim_phase: string;
    released_client_claim_active: boolean;
    default_profile: string;
    promoted_client_slices: string[];
    compat_only_surfaces: string[];
  };
  required_release_attestation: {
    release_phase: string;
    npm_provenance_enabled: boolean;
  };
  required_lanes: string[];
  required_managed_provider: {
    provider_class: string;
    lane_name: string;
    hosted: boolean;
    status: string;
    repository: string;
    expected_workflow: string;
    github_ref_required: boolean;
    github_sha_required: boolean;
    github_job_required: boolean;
    expected_job: string;
  };
  required_admin_console: {
    lane_name: string;
    status: string;
    repository: string;
    expected_workflow: string;
    github_ref_required: boolean;
    github_sha_required: boolean;
    github_job_required: boolean;
    expected_job: string;
    management_sdk_package: string;
    required_capabilities: string[];
  };
};

export type ClientClaimPromotionReportFile = {
  ready?: boolean;
  failures?: string[];
};

export type ReleasedClientClaimPolicyFile = {
  claim_target: string;
  current_state: {
    claim_phase: string;
    released_client_claim_active: boolean;
    canonical_statement: string;
  };
  target_state: {
    claim_phase: string;
    canonical_statement: string;
    default_profile: string;
    promoted_client_slices: string[];
    compat_only_surfaces: string[];
  };
  activation_requirements: {
    promotion_report_ready: boolean;
    managed_provider_evidence_required: boolean;
    managed_provider_evidence_max_age_hours: number;
    managed_provider_hosted_provenance_required: boolean;
    managed_provider_expected_lane: string;
    managed_provider_expected_workflow: string;
    managed_provider_expected_repository: string;
    managed_provider_github_ref_required: boolean;
    managed_provider_github_sha_required: boolean;
    managed_provider_github_job_required: boolean;
    managed_provider_expected_job: string;
    admin_sdk_evidence_required: boolean;
    admin_sdk_evidence_max_age_hours: number;
    admin_sdk_hosted_provenance_required: boolean;
    admin_sdk_expected_lane: string;
    admin_sdk_expected_workflow: string;
    admin_sdk_expected_repository: string;
    admin_sdk_github_ref_required: boolean;
    admin_sdk_github_sha_required: boolean;
    admin_sdk_github_job_required: boolean;
    admin_sdk_expected_job: string;
    signed_release_attestation_required: boolean;
    sbom_publication_required: boolean;
    publication_org_tasks_must_be_done: boolean;
  };
  required_publication_org_tasks: string[];
};

export type PublicationOrgRolloutReportFile = {
  tasks?: Array<{
    name: string;
    status: "pending" | "done";
    detail?: string | null;
  }>;
  ready?: boolean;
  blockers?: string[];
};

export type ReleasedClientClaimReportFile = {
  claim_target: string;
  current_state?: {
    claim_phase: string;
    released_client_claim_active: boolean;
    canonical_statement?: string;
  };
  target_state?: {
    claim_phase: string;
    canonical_statement: string;
    default_profile?: string;
    promoted_client_slices?: string[];
    compat_only_surfaces?: string[];
  };
  ready?: boolean;
  blockers?: string[];
};

export type PublishManifestFile = {
  source?: {
    githubRef?: string;
    githubSha?: string;
    githubRunId?: string;
    githubWorkflow?: string;
    npmDistTag?: string;
  };
  tarballs?: unknown[];
  verifiedCore?: {
    manifestPath?: string;
    manifestSha256?: string;
    handoffManifestPath?: string | null;
    handoffManifestSha256?: string | null;
  };
};
