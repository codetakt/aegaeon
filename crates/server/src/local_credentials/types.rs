use uuid::Uuid;

pub const PASSWORD_STATUS_ACTIVE: &str = "ACTIVE";
pub const PASSWORD_STATUS_REVOKED: &str = "REVOKED";
pub const RECOVERY_STATUS_ACTIVE: &str = "ACTIVE";
pub const RECOVERY_STATUS_REDEEMED: &str = "REDEEMED";
pub const RECOVERY_STATUS_REVOKED: &str = "REVOKED";
pub const RECOVERY_STATUS_EXPIRED: &str = "EXPIRED";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryTokenPurpose {
    Activation,
    PasswordReset,
}

#[derive(Clone, Debug)]
pub struct RuntimeEnvironmentContext {
    pub team_id: Uuid,
    pub tenant_id: Uuid,
    pub environment_id: Uuid,
}

#[derive(Clone, Debug)]
pub struct AuthenticatedLocalUser {
    pub end_user_id: Uuid,
    pub subject: String,
    pub email: Option<String>,
    pub environment: RuntimeEnvironmentContext,
}

#[derive(Clone, Debug)]
pub struct PasswordCredentialRecord {
    pub id: String,
    pub status: String,
    pub created_at: String,
    pub updated_at: String,
    pub last_used_at: Option<String>,
}

#[derive(Clone, Debug)]
pub struct RecoveryTokenRecord {
    pub id: String,
    pub purpose: String,
    pub status: String,
    pub expires_at: String,
    pub redeemed_at: Option<String>,
    pub revoked_at: Option<String>,
    pub created_at: String,
}

#[derive(Clone, Debug, Default)]
pub struct UserCredentialState {
    pub password: Option<PasswordCredentialRecord>,
    pub recovery_tokens: Vec<RecoveryTokenRecord>,
}

#[derive(Clone, Debug)]
pub struct IssuedRecoveryToken {
    pub id: String,
    pub token: String,
    pub expires_at: String,
    pub purpose: RecoveryTokenPurpose,
}

#[derive(Clone, Debug)]
pub struct RedeemedRecoveryToken {
    pub subject: String,
}
