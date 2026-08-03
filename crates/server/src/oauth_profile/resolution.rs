use super::model::{ProfileError, ResolvedProfile};
use super::normalization::{normalize_lower_list, parse_sender_constraint};
use sqlx::{postgres::PgRow, PgPool, Row};
use uuid::Uuid;

const DOWNSTREAM_PROFILE_QUERY: &str = r"
SELECT
  c.oauth_profile_id AS requested_profile_id,
  cp.id AS bound_profile_id,
  dp.id AS default_profile_id,
  CASE WHEN c.oauth_profile_id IS NULL THEN dp.name ELSE cp.name END AS name,
  CASE WHEN c.oauth_profile_id IS NULL THEN dp.require_pkce ELSE cp.require_pkce END AS require_pkce,
  CASE WHEN c.oauth_profile_id IS NULL THEN dp.require_state_parameter ELSE cp.require_state_parameter END AS require_state_parameter,
  CASE WHEN c.oauth_profile_id IS NULL THEN dp.require_iss_parameter ELSE cp.require_iss_parameter END AS require_iss_parameter,
  (CASE WHEN c.oauth_profile_id IS NULL THEN dp.sender_constrained ELSE cp.sender_constrained END)::text AS sender_constrained,
  CASE WHEN c.oauth_profile_id IS NULL THEN dp.enforce_refresh_sender_binding ELSE cp.enforce_refresh_sender_binding END AS enforce_refresh_sender_binding,
  CASE WHEN c.oauth_profile_id IS NULL THEN dp.allowed_grant_types ELSE cp.allowed_grant_types END AS allowed_grant_types,
  CASE WHEN c.oauth_profile_id IS NULL THEN dp.token_endpoint_auth_methods_allowed ELSE cp.token_endpoint_auth_methods_allowed END AS token_endpoint_auth_methods_allowed
FROM aegaeon.active_runtime_environments rt
JOIN aegaeon.clients c
  ON c.environment_id = rt.environment_id
  AND c.configuration_version_id = rt.configuration_version_id
  AND c.client_identifier = $2
  AND c.status = 'ACTIVE'
LEFT JOIN aegaeon.oauth_profiles cp
  ON cp.id = c.oauth_profile_id
  AND cp.environment_id = rt.environment_id
  AND cp.configuration_version_id = rt.configuration_version_id
  AND cp.profile_type = 'DOWNSTREAM'
  AND cp.status = 'ACTIVE'
  AND (cp.expires_at IS NULL OR cp.expires_at > now())
LEFT JOIN aegaeon.oauth_profiles dp
  ON dp.environment_id = rt.environment_id
  AND dp.configuration_version_id = rt.configuration_version_id
  AND dp.profile_type = 'DOWNSTREAM'
  AND dp.is_default = true
  AND dp.status = 'ACTIVE'
  AND (dp.expires_at IS NULL OR dp.expires_at > now())
WHERE rt.issuer_host = $1
LIMIT 1
        ";

const UPSTREAM_PROFILE_QUERY: &str = r"
SELECT
  c.oauth_profile_id AS requested_profile_id,
  cp.id AS bound_profile_id,
  dp.id AS default_profile_id,
  CASE WHEN c.oauth_profile_id IS NULL THEN dp.name ELSE cp.name END AS name,
  CASE WHEN c.oauth_profile_id IS NULL THEN dp.require_pkce ELSE cp.require_pkce END AS require_pkce,
  CASE WHEN c.oauth_profile_id IS NULL THEN dp.require_state_parameter ELSE cp.require_state_parameter END AS require_state_parameter,
  CASE WHEN c.oauth_profile_id IS NULL THEN dp.require_iss_parameter ELSE cp.require_iss_parameter END AS require_iss_parameter,
  (CASE WHEN c.oauth_profile_id IS NULL THEN dp.sender_constrained ELSE cp.sender_constrained END)::text AS sender_constrained,
  CASE WHEN c.oauth_profile_id IS NULL THEN dp.enforce_refresh_sender_binding ELSE cp.enforce_refresh_sender_binding END AS enforce_refresh_sender_binding,
  CASE WHEN c.oauth_profile_id IS NULL THEN dp.allowed_grant_types ELSE cp.allowed_grant_types END AS allowed_grant_types,
  CASE WHEN c.oauth_profile_id IS NULL THEN dp.token_endpoint_auth_methods_allowed ELSE cp.token_endpoint_auth_methods_allowed END AS token_endpoint_auth_methods_allowed
FROM aegaeon.active_runtime_environments rt
JOIN aegaeon.connections c
  ON c.environment_id = rt.environment_id
  AND c.configuration_version_id = rt.configuration_version_id
  AND c.connection_identifier = $2
  AND c.status = 'ACTIVE'
LEFT JOIN aegaeon.oauth_profiles cp
  ON cp.id = c.oauth_profile_id
  AND cp.environment_id = rt.environment_id
  AND cp.configuration_version_id = rt.configuration_version_id
  AND cp.profile_type = 'UPSTREAM'
  AND cp.status = 'ACTIVE'
  AND (cp.expires_at IS NULL OR cp.expires_at > now())
LEFT JOIN aegaeon.oauth_profiles dp
  ON dp.environment_id = rt.environment_id
  AND dp.configuration_version_id = rt.configuration_version_id
  AND dp.profile_type = 'UPSTREAM'
  AND dp.is_default = true
  AND dp.status = 'ACTIVE'
  AND (dp.expires_at IS NULL OR dp.expires_at > now())
WHERE rt.issuer_host = $1
LIMIT 1
        ";

const DEFAULT_PROFILE_QUERY: &str = r"
SELECT
  dp.id AS profile_id,
  dp.name AS name,
  dp.require_pkce AS require_pkce,
  dp.require_state_parameter AS require_state_parameter,
  dp.require_iss_parameter AS require_iss_parameter,
  dp.sender_constrained::text AS sender_constrained,
  dp.enforce_refresh_sender_binding AS enforce_refresh_sender_binding,
  dp.allowed_grant_types AS allowed_grant_types,
  dp.token_endpoint_auth_methods_allowed AS token_endpoint_auth_methods_allowed
FROM aegaeon.active_runtime_environments rt
JOIN aegaeon.oauth_profiles dp
  ON dp.environment_id = rt.environment_id
  AND dp.configuration_version_id = rt.configuration_version_id
  AND dp.profile_type = $2::aegaeon.oauth_profile_type
  AND dp.is_default = true
  AND dp.status = 'ACTIVE'
  AND (dp.expires_at IS NULL OR dp.expires_at > now())
WHERE rt.issuer_host = $1
LIMIT 1
        ";

#[derive(Clone, Copy)]
struct EffectiveProfileIds {
    requested_profile_id: Option<Uuid>,
    bound_profile_id: Option<Uuid>,
    default_profile_id: Option<Uuid>,
}

/// # Errors
///
/// Returns [`ProfileError::InvalidIssuer`] when the issuer URL cannot be
/// normalized, [`ProfileError::MissingProfile`] when no effective profile can
/// be resolved, or [`ProfileError::Database`] when the query fails.
pub async fn resolve_downstream_profile(
    pool: &PgPool,
    issuer: &str,
    client_id: &str,
) -> Result<ResolvedProfile, ProfileError> {
    let issuer_host = issuer_host_from_url(issuer)?;

    let row = sqlx::query(DOWNSTREAM_PROFILE_QUERY)
        .bind(issuer_host)
        .bind(client_id)
        .fetch_optional(pool)
        .await?;

    let row = row.ok_or(ProfileError::MissingProfile)?;
    resolved_profile_from_effective_row(&row)
}

/// # Errors
///
/// Returns [`ProfileError::InvalidIssuer`] when the issuer URL cannot be
/// normalized, [`ProfileError::MissingProfile`] when no effective profile can
/// be resolved, or [`ProfileError::Database`] when the query fails.
pub async fn resolve_upstream_profile(
    pool: &PgPool,
    issuer: &str,
    connection_identifier: &str,
) -> Result<ResolvedProfile, ProfileError> {
    let issuer_host = issuer_host_from_url(issuer)?;

    let row = sqlx::query(UPSTREAM_PROFILE_QUERY)
        .bind(issuer_host)
        .bind(connection_identifier)
        .fetch_optional(pool)
        .await?;

    let row = row.ok_or(ProfileError::MissingProfile)?;
    resolved_profile_from_effective_row(&row)
}

/// # Errors
///
/// Returns [`ProfileError::InvalidIssuer`] when the issuer URL cannot be
/// normalized, [`ProfileError::MissingProfile`] when no default profile exists,
/// or [`ProfileError::Database`] when the query fails.
pub async fn resolve_default_profile(
    pool: &PgPool,
    issuer: &str,
    profile_type: &str,
) -> Result<ResolvedProfile, ProfileError> {
    let issuer_host = issuer_host_from_url(issuer)?;

    let row = sqlx::query(DEFAULT_PROFILE_QUERY)
        .bind(issuer_host)
        .bind(profile_type)
        .fetch_optional(pool)
        .await?;

    let row = row.ok_or(ProfileError::MissingProfile)?;
    let profile_id = required_uuid(&row, "profile_id")?;
    resolved_profile_from_row(&row, profile_id)
}

fn resolved_profile_from_effective_row(row: &PgRow) -> Result<ResolvedProfile, ProfileError> {
    let profile_id = effective_profile_id(EffectiveProfileIds {
        requested_profile_id: row.try_get("requested_profile_id")?,
        bound_profile_id: row.try_get("bound_profile_id")?,
        default_profile_id: row.try_get("default_profile_id")?,
    })?;
    resolved_profile_from_row(row, profile_id)
}

fn effective_profile_id(ids: EffectiveProfileIds) -> Result<Uuid, ProfileError> {
    match ids {
        EffectiveProfileIds {
            requested_profile_id: Some(_),
            bound_profile_id: Some(bound_profile_id),
            ..
        } => Ok(bound_profile_id),
        EffectiveProfileIds {
            requested_profile_id: None,
            default_profile_id: Some(default_profile_id),
            ..
        } => Ok(default_profile_id),
        _ => Err(ProfileError::MissingProfile),
    }
}

fn required_uuid(row: &PgRow, column: &'static str) -> Result<Uuid, ProfileError> {
    let value: Option<Uuid> = row.try_get(column)?;
    value.ok_or(ProfileError::MissingProfile)
}

fn resolved_profile_from_row(
    row: &PgRow,
    profile_id: Uuid,
) -> Result<ResolvedProfile, ProfileError> {
    let name: Option<String> = row.try_get("name")?;
    let require_pkce: Option<bool> = row.try_get("require_pkce")?;
    let require_state_parameter: Option<bool> = row.try_get("require_state_parameter")?;
    let require_iss_parameter: Option<bool> = row.try_get("require_iss_parameter")?;
    let sender_constrained_raw: Option<String> = row.try_get("sender_constrained")?;
    let enforce_refresh_sender_binding: Option<bool> =
        row.try_get("enforce_refresh_sender_binding")?;
    let allowed_grant_types: Option<Vec<String>> = row.try_get("allowed_grant_types")?;
    let token_endpoint_auth_methods_allowed: Option<Vec<String>> =
        row.try_get("token_endpoint_auth_methods_allowed")?;

    let sender_constrained_raw = sender_constrained_raw.ok_or(ProfileError::MissingProfile)?;

    let profile = ResolvedProfile {
        id: profile_id.to_string(),
        name: name.ok_or(ProfileError::MissingProfile)?,
        require_pkce: require_pkce.ok_or(ProfileError::MissingProfile)?,
        require_state_parameter: require_state_parameter.ok_or(ProfileError::MissingProfile)?,
        require_iss_parameter: require_iss_parameter.ok_or(ProfileError::MissingProfile)?,
        sender_constrained: parse_sender_constraint(&sender_constrained_raw)
            .ok_or(ProfileError::MissingProfile)?,
        enforce_refresh_sender_binding: enforce_refresh_sender_binding
            .ok_or(ProfileError::MissingProfile)?,
        allowed_grant_types: normalize_lower_list(
            allowed_grant_types.ok_or(ProfileError::MissingProfile)?,
        ),
        token_endpoint_auth_methods_allowed: normalize_lower_list(
            token_endpoint_auth_methods_allowed.ok_or(ProfileError::MissingProfile)?,
        ),
    };

    Ok(profile)
}

fn issuer_host_from_url(issuer: &str) -> Result<String, ProfileError> {
    let url = url::Url::parse(issuer).map_err(|_| ProfileError::InvalidIssuer)?;
    crate::util::canonical_url_host_port(&url).ok_or(ProfileError::InvalidIssuer)
}
