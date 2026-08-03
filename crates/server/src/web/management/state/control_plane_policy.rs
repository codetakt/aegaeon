use sqlx::{postgres::PgRow, Executor, PgPool, Postgres, Row, Transaction};

use crate::config::ConfigError;

use super::super::host_validation::normalize_dns_name;
use super::config::normalize_management_allowed_origin;

/// Default management session TTL: 8 hours.
pub(in crate::web::management) const DEFAULT_SESSION_TTL_SECS: u64 = 8 * 3600;

/// Maximum management session TTL: 24 hours.
pub(in crate::web::management) const MAX_SESSION_TTL_SECS: u64 = 24 * 3600;

/// Default maximum number of concurrent management sessions.
pub(in crate::web::management) const DEFAULT_MAX_SESSIONS: usize = 10_000;
pub(in crate::web::management) const MAX_MANAGEMENT_MAX_SESSIONS: usize = 1_000_000;
pub(in crate::web::management) const DEFAULT_ISSUER_BASE_DOMAIN: &str = "aegaeon.cloud";
pub(in crate::web::management) const DEFAULT_MANAGEMENT_API_KEY_EXPIRATION_DAYS: u32 = 90;
pub(in crate::web::management) const MAX_MANAGEMENT_API_KEY_EXPIRATION_DAYS: u32 = 365;

pub(super) const fn valid_management_session_ttl_secs(value: u64) -> bool {
    value > 0 && value <= MAX_SESSION_TTL_SECS
}

pub(super) const fn valid_management_max_sessions(value: usize) -> bool {
    value > 0 && value <= MAX_MANAGEMENT_MAX_SESSIONS
}

pub(super) const fn valid_management_api_key_expiration_days(value: u32) -> bool {
    value > 0 && value <= MAX_MANAGEMENT_API_KEY_EXPIRATION_DAYS
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::web::management) struct ControlPlanePolicy {
    pub(in crate::web::management) session_ttl_secs: u64,
    pub(in crate::web::management) max_sessions: usize,
    pub(in crate::web::management) allowed_origins: Vec<String>,
    pub(in crate::web::management) issuer_base_domain: String,
    pub(in crate::web::management) api_key_default_expiration_days: u32,
    pub(in crate::web::management) api_key_max_expiration_days: u32,
    pub(in crate::web::management) api_key_allow_no_expiration: bool,
}

impl Default for ControlPlanePolicy {
    fn default() -> Self {
        Self {
            session_ttl_secs: DEFAULT_SESSION_TTL_SECS,
            max_sessions: DEFAULT_MAX_SESSIONS,
            allowed_origins: Vec::new(),
            issuer_base_domain: DEFAULT_ISSUER_BASE_DOMAIN.to_string(),
            api_key_default_expiration_days: DEFAULT_MANAGEMENT_API_KEY_EXPIRATION_DAYS,
            api_key_max_expiration_days: MAX_MANAGEMENT_API_KEY_EXPIRATION_DAYS,
            api_key_allow_no_expiration: false,
        }
    }
}

fn control_plane_policy_config_error(reason: impl Into<String>) -> ConfigError {
    ConfigError::InvalidValue {
        key: "aegaeon.control_plane_policies".to_string(),
        value: "[database]".to_string(),
        reason: reason.into(),
    }
}

fn control_plane_policy_seconds(row: &PgRow, column: &'static str) -> Result<u64, ConfigError> {
    let value: i32 = row
        .try_get(column)
        .map_err(|err| control_plane_policy_config_error(err.to_string()))?;
    u64::try_from(value)
        .map_err(|_| control_plane_policy_config_error(format!("{column} must be non-negative")))
}

fn control_plane_policy_sessions(row: &PgRow, column: &'static str) -> Result<usize, ConfigError> {
    let value: i32 = row
        .try_get(column)
        .map_err(|err| control_plane_policy_config_error(err.to_string()))?;
    usize::try_from(value)
        .map_err(|_| control_plane_policy_config_error(format!("{column} must be non-negative")))
}

fn control_plane_policy_days(row: &PgRow, column: &'static str) -> Result<u32, ConfigError> {
    let value: i32 = row
        .try_get(column)
        .map_err(|err| control_plane_policy_config_error(err.to_string()))?;
    u32::try_from(value)
        .map_err(|_| control_plane_policy_config_error(format!("{column} must be non-negative")))
}

pub(super) fn normalize_control_plane_allowed_origins(
    origins: Vec<String>,
) -> Result<Vec<String>, ConfigError> {
    origins
        .into_iter()
        .map(|origin| {
            normalize_management_allowed_origin(&origin).map_err(|reason| {
                ConfigError::InvalidValue {
                    key: "management_allowed_origins".to_string(),
                    value: origin,
                    reason,
                }
            })
        })
        .collect()
}

pub(super) fn normalize_control_plane_issuer_base_domain(
    domain: String,
) -> Result<String, ConfigError> {
    normalize_dns_name(domain.trim(), "issuer base domain").map_err(|reason| {
        ConfigError::InvalidValue {
            key: "management_issuer_base_domain".to_string(),
            value: domain,
            reason,
        }
    })
}

const LOAD_CONTROL_PLANE_POLICY_SQL: &str = r"
SELECT
  management_session_ttl_seconds,
  management_max_sessions,
  management_allowed_origins,
  management_issuer_base_domain,
  management_api_key_default_expiration_days,
  management_api_key_max_expiration_days,
  management_api_key_allow_no_expiration
FROM aegaeon.control_plane_policies
WHERE id = 'default'
        ";

const LOAD_CONTROL_PLANE_POLICY_FOR_UPDATE_SQL: &str = r"
SELECT
  management_session_ttl_seconds,
  management_max_sessions,
  management_allowed_origins,
  management_issuer_base_domain,
  management_api_key_default_expiration_days,
  management_api_key_max_expiration_days,
  management_api_key_allow_no_expiration
FROM aegaeon.control_plane_policies cp
WHERE cp.id = 'default'
FOR UPDATE OF cp
        ";

pub(in crate::web::management) async fn load_control_plane_policy(
    pool: &PgPool,
) -> Result<ControlPlanePolicy, ConfigError> {
    load_control_plane_policy_with_executor(pool, LOAD_CONTROL_PLANE_POLICY_SQL).await
}

pub(in crate::web::management) async fn load_control_plane_policy_in_transaction(
    tx: &mut Transaction<'_, Postgres>,
) -> Result<ControlPlanePolicy, ConfigError> {
    load_control_plane_policy_with_executor(&mut **tx, LOAD_CONTROL_PLANE_POLICY_FOR_UPDATE_SQL)
        .await
}

async fn load_control_plane_policy_with_executor<'e, E>(
    executor: E,
    sql: &str,
) -> Result<ControlPlanePolicy, ConfigError>
where
    E: Executor<'e, Database = Postgres>,
{
    let row = sqlx::query(sql)
        .fetch_optional(executor)
        .await
        .map_err(|err| control_plane_policy_config_error(err.to_string()))?
        .ok_or_else(|| {
            control_plane_policy_config_error("default control-plane policy is missing")
        })?;

    Ok(ControlPlanePolicy {
        session_ttl_secs: control_plane_policy_seconds(&row, "management_session_ttl_seconds")?,
        max_sessions: control_plane_policy_sessions(&row, "management_max_sessions")?,
        allowed_origins: row
            .try_get("management_allowed_origins")
            .map_err(|err| control_plane_policy_config_error(err.to_string()))?,
        issuer_base_domain: row
            .try_get("management_issuer_base_domain")
            .map_err(|err| control_plane_policy_config_error(err.to_string()))?,
        api_key_default_expiration_days: control_plane_policy_days(
            &row,
            "management_api_key_default_expiration_days",
        )?,
        api_key_max_expiration_days: control_plane_policy_days(
            &row,
            "management_api_key_max_expiration_days",
        )?,
        api_key_allow_no_expiration: row
            .try_get("management_api_key_allow_no_expiration")
            .map_err(|err| control_plane_policy_config_error(err.to_string()))?,
    })
}
