use crate::policy::SenderConstraint;

#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)] // Effective profile snapshots keep independent policy toggles explicit.
pub struct ResolvedProfile {
    pub id: String,
    pub name: String,
    pub require_pkce: bool,
    pub require_state_parameter: bool,
    pub require_iss_parameter: bool,
    pub sender_constrained: SenderConstraint,
    pub enforce_refresh_sender_binding: bool,
    pub allowed_grant_types: Vec<String>,
    pub token_endpoint_auth_methods_allowed: Vec<String>,
}

#[derive(Debug)]
pub enum ProfileError {
    InvalidIssuer,
    MissingProfile,
    Database(sqlx::Error),
}

impl From<sqlx::Error> for ProfileError {
    fn from(err: sqlx::Error) -> Self {
        Self::Database(err)
    }
}
