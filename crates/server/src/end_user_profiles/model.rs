use serde_json::Value;
use std::collections::HashMap;

pub const SUBJECT_POLICY_EXPLICIT: &str = "explicit";

#[derive(Clone, Debug)]
pub struct EndUserProfileRecord {
    pub user_id: String,
    pub subject: String,
    pub subject_policy: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub display_name: Option<String>,
    pub custom_claims: Value,
    pub version: i64,
    pub updated_at: String,
    pub updated_at_epoch_seconds: i64,
}

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct OidcProfileClaims {
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub display_name: Option<String>,
    pub custom_claims: HashMap<String, Value>,
    pub updated_at_epoch_seconds: Option<i64>,
}

#[derive(Debug)]
pub enum UpdateProfileError {
    NotFound,
    VersionMismatch { current_version: i64 },
    InvalidCustomClaims(&'static str),
    Database(sqlx::Error),
}

impl From<sqlx::Error> for UpdateProfileError {
    fn from(value: sqlx::Error) -> Self {
        Self::Database(value)
    }
}
