use serde_json::{Map, Value};
use std::time::SystemTime;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum UpstreamJitProvisioningCollisionPolicy {
    RejectExistingEmail,
    ReuseExistingEmail,
}

impl UpstreamJitProvisioningCollisionPolicy {
    /// # Errors
    ///
    /// Returns an error when the configured collision policy is not supported.
    pub fn parse(value: &str) -> Result<Self, String> {
        match value.trim() {
            "reject_existing_email" => Ok(Self::RejectExistingEmail),
            "reuse_existing_email" => Ok(Self::ReuseExistingEmail),
            other => Err(format!("invalid collisionPolicy: {other}")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum UpstreamJitProvisioningInitialStatus {
    Active,
    Blocked,
}

impl UpstreamJitProvisioningInitialStatus {
    /// # Errors
    ///
    /// Returns an error when the configured initial status is not supported.
    pub fn parse(value: &str) -> Result<Self, String> {
        match value.trim() {
            "ACTIVE" => Ok(Self::Active),
            "BLOCKED" => Ok(Self::Blocked),
            other => Err(format!("invalid initialStatus: {other}")),
        }
    }

    #[must_use]
    pub fn as_db_value(&self) -> &'static str {
        match self {
            Self::Active => "ACTIVE",
            Self::Blocked => "SUSPENDED",
        }
    }
}

const fn default_require_verified_email() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct UpstreamJitProvisioningPolicy {
    pub enabled: bool,
    #[serde(default = "default_require_verified_email")]
    pub require_verified_email: bool,
    pub domain_allowlist: Vec<String>,
    pub collision_policy: UpstreamJitProvisioningCollisionPolicy,
    pub initial_status: UpstreamJitProvisioningInitialStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct UpstreamLogoutPolicy {
    pub back_channel: bool,
    pub session_hint_claim: Option<String>,
    pub recovery_policy: UpstreamLogoutRecoveryPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum UpstreamAttributeMappingRule {
    Copy,
    Lower,
    MapGroups,
}

impl UpstreamAttributeMappingRule {
    pub(super) fn parse(value: Option<&str>) -> Result<Self, String> {
        match value.map(str::trim).filter(|candidate| !candidate.is_empty()) {
            None => Ok(Self::Copy),
            Some("lower") => Ok(Self::Lower),
            Some("mapGroups" | "map_groups") => Ok(Self::MapGroups),
            Some(_) => Err(
                "configurationDocument.federation.attributeMapping[].rule must be one of lower, mapGroups, or map_groups when present".to_string(),
            ),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum UpstreamAttributeMappingTarget {
    Email,
    EmailVerified,
    DisplayName,
    Custom(String),
}

impl UpstreamAttributeMappingTarget {
    pub(super) fn parse(value: &str) -> Result<Self, String> {
        let normalized = value.trim();
        match normalized {
            "email" => Ok(Self::Email),
            "email_verified" => Ok(Self::EmailVerified),
            "name" | "display_name" => Ok(Self::DisplayName),
            _ => {
                let mut claims = Map::new();
                claims.insert(normalized.to_string(), Value::Null);
                crate::end_user_profiles::validate_custom_claims(&Value::Object(claims))
                    .map_err(|_| {
                        "configurationDocument.federation.attributeMapping[].to must target email, email_verified, name/display_name, or a non-reserved custom claim".to_string()
                    })?;
                Ok(Self::Custom(normalized.to_string()))
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct UpstreamAttributeMapping {
    pub from: String,
    pub target: UpstreamAttributeMappingTarget,
    pub rule: UpstreamAttributeMappingRule,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub enum DownstreamClaimSurface {
    IdToken,
    Userinfo,
}

impl DownstreamClaimSurface {
    pub(super) fn parse(value: &str) -> Result<Self, String> {
        match value.trim() {
            "id_token" => Ok(Self::IdToken),
            "userinfo" => Ok(Self::Userinfo),
            _ => Err(
                "configurationDocument.federation.claimRelease[].surfaces[] must be id_token or userinfo".to_string(),
            ),
        }
    }

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::IdToken => "id_token",
            Self::Userinfo => "userinfo",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct UpstreamClaimReleasePolicy {
    pub managed_custom_claims: Vec<String>,
    pub id_token_custom_claims: Vec<String>,
    pub userinfo_custom_claims: Vec<String>,
}

impl UpstreamClaimReleasePolicy {
    #[must_use]
    pub fn manages_custom_claim(&self, claim: &str) -> bool {
        self.managed_custom_claims
            .iter()
            .any(|candidate| candidate == claim)
    }

    #[must_use]
    pub fn allows_custom_claim(&self, claim: &str, surface: DownstreamClaimSurface) -> bool {
        let allowed = match surface {
            DownstreamClaimSurface::IdToken => &self.id_token_custom_claims,
            DownstreamClaimSurface::Userinfo => &self.userinfo_custom_claims,
        };
        allowed.iter().any(|candidate| candidate == claim)
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct AppliedUpstreamAttributeMappings {
    pub email: Option<Option<String>>,
    pub email_verified: Option<bool>,
    pub display_name: Option<Option<String>>,
    pub custom_claims: Map<String, Value>,
    pub managed_custom_claim_keys: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum UpstreamLogoutRecoveryPolicy {
    ForcePromptLogin,
    DisableConnection,
}

impl UpstreamLogoutRecoveryPolicy {
    /// # Errors
    ///
    /// Returns an error when the configured recovery policy is not supported.
    pub fn parse(value: &str) -> Result<Self, String> {
        match value.trim() {
            "force_prompt_login" => Ok(Self::ForcePromptLogin),
            "disable_connection" => Ok(Self::DisableConnection),
            other => Err(format!("invalid recoveryPolicy: {other}")),
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ForcePromptLogin => "force_prompt_login",
            Self::DisableConnection => "disable_connection",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct UpstreamConnectionContext {
    pub connection_id: uuid::Uuid,
    pub team_id: uuid::Uuid,
    pub tenant_id: uuid::Uuid,
    pub environment_id: uuid::Uuid,
    pub configuration_version_id: uuid::Uuid,
}

impl UpstreamConnectionContext {
    #[must_use]
    pub fn new(
        connection_id: uuid::Uuid,
        team_id: uuid::Uuid,
        tenant_id: uuid::Uuid,
        environment_id: uuid::Uuid,
        configuration_version_id: uuid::Uuid,
    ) -> Self {
        Self {
            connection_id,
            team_id,
            tenant_id,
            environment_id,
            configuration_version_id,
        }
    }
}

#[derive(Debug, Clone)]
pub struct UpstreamAuthRequest {
    pub state: String,
    pub nonce: String,
    pub code_verifier: Option<String>,
    pub acr: Option<String>,
    pub issuer: String,
    pub client_id: String,
    /// Client secret for confidential upstream connections (plaintext, held in memory only).
    pub client_secret: Option<String>,
    /// Client authentication method (`none`, `client_secret_basic`, `client_secret_post`).
    pub client_auth_method: String,
    /// Managed connection context.
    pub context: UpstreamConnectionContext,
    pub token_endpoint: String,
    pub jwks_uri: String,
    pub redirect_uri: String,
    pub return_to: Option<String>,
    pub max_age: Option<i64>,
    pub require_iss_parameter: bool,
    pub jit_provisioning_policy: Option<UpstreamJitProvisioningPolicy>,
    pub attribute_mappings: Vec<UpstreamAttributeMapping>,
    pub claim_release_policy: Option<UpstreamClaimReleasePolicy>,
    pub logout_policy: Option<UpstreamLogoutPolicy>,
    pub issued_at: SystemTime,
    pub expires_at: SystemTime,
}

impl UpstreamAuthRequest {
    #[must_use]
    pub fn managed_connection_context(&self) -> UpstreamConnectionContext {
        self.context
    }
}
