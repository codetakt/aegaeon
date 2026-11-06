//! Strict inputs for the Organizations HTTP profile, not authentication.
//! Callers must authorize the scope before disclosing precondition results.
use axum::http::{header::IF_MATCH, HeaderMap};
use serde::de::DeserializeOwned;
use uuid::Uuid;

pub mod delivery;
pub mod identity_policy;
pub mod invitations;
pub mod members;
pub mod objects;
pub mod pagination;
pub mod role_policy;
pub mod support_policy;

pub const MAX_BODY_BYTES: usize = 65_536;
pub const BODY_TIMEOUT_SECONDS: u64 = 10;
pub const MAX_PRECONDITION_BYTES: usize = 1_024;
pub const MAX_IDEMPOTENCY_BYTES: usize = 128;
pub const DEFAULT_PAGE_SIZE: usize = 50;
pub const MAX_PAGE_SIZE: usize = 100;

#[derive(serde::Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConfigurationReason {
    /// Nonblank reason, at most 1024 UTF-8 bytes, without control characters.
    pub reason: String,
}

#[derive(serde::Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegisterOrganizationTargetRequest {
    /// Exact nonblank audience, at most 2048 UTF-8 bytes, without controls.
    pub audience: String,
    pub management: bool,
    pub reason: String,
}

#[derive(serde::Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReplaceIntrospectionRecipientsRequest {
    pub audience: String,
    #[cfg_attr(feature = "openapi", schema(value_type = Vec<String>, min_items = 1, max_items = 8))]
    pub client_registration_ids: Vec<Uuid>,
    pub reason: String,
}

#[derive(serde::Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RevokeIntrospectionRecipientsRequest {
    pub audience: String,
    pub reason: String,
}

#[derive(serde::Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateOrganizationClientRequest {
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "uuid"))]
    pub client_registration_id: Uuid,
    pub active: bool,
    pub targets: Vec<super::operators::mutations::clients::ClientTarget>,
    pub reason: String,
}

#[derive(serde::Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdateOrganizationClientRequest {
    pub active: bool,
    pub targets: Vec<super::operators::mutations::clients::ClientTarget>,
    pub reason: String,
}

#[derive(serde::Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct OrganizationClientListResponse {
    pub clients: Vec<super::operators::mutations::clients::ClientBinding>,
    pub page_info: crate::management::types::PageInfo,
}

#[derive(serde::Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateOperatorRequest {
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "uuid"))]
    pub administrator_id: Uuid,
    pub active: bool,
    /// Explicit unique nonempty set; no capability implies another.
    #[cfg_attr(feature = "openapi", schema(min_items = 1, max_items = 5))]
    pub capabilities: Vec<super::operators::Capability>,
    pub reason: String,
}

#[derive(serde::Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdateOperatorRequest {
    pub active: bool,
    #[cfg_attr(feature = "openapi", schema(min_items = 1, max_items = 5))]
    pub capabilities: Vec<super::operators::Capability>,
    pub reason: String,
}

/// Management uses its existing camelCase field convention. Native receipt and
/// token authority encodings remain separate from these public representations.
#[derive(serde::Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct OperatorGrantResponse {
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "uuid"))]
    pub id: Uuid,
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "uuid"))]
    pub environment_id: Uuid,
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "uuid"))]
    pub domain_id: Uuid,
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "uuid"))]
    pub administrator_id: Uuid,
    pub active: bool,
    pub revision: i64,
    pub capabilities: std::collections::BTreeSet<super::operators::Capability>,
}

impl From<super::operators::mutations::OperatorGrant> for OperatorGrantResponse {
    fn from(grant: super::operators::mutations::OperatorGrant) -> Self {
        Self {
            id: grant.id,
            environment_id: grant.scope.environment_id,
            domain_id: grant.scope.domain_id,
            administrator_id: grant.administrator_id,
            active: grant.active,
            revision: grant.revision,
            capabilities: grant.capabilities,
        }
    }
}

#[derive(serde::Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct DefaultDomainResponse {
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "uuid"))]
    pub id: Uuid,
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "uuid"))]
    pub environment_id: Uuid,
    pub enabled: bool,
    pub revision: i64,
    pub operator: OperatorGrantResponse,
}

#[derive(serde::Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct OperatorListResponse {
    pub operators: Vec<OperatorGrantResponse>,
    pub page_info: crate::management::types::PageInfo,
}

impl From<super::operators::mutations::DefaultDomain> for DefaultDomainResponse {
    fn from(domain: super::operators::mutations::DefaultDomain) -> Self {
        Self {
            id: domain.scope.domain_id,
            environment_id: domain.scope.environment_id,
            enabled: domain.enabled,
            revision: domain.revision,
            operator: domain.operator.into(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputError {
    Invalid,
    TooLarge,
    PreconditionRequired,
    PreconditionFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VersionTag {
    object: Uuid,
    revision: i64,
}

impl VersionTag {
    pub fn new(object: Uuid, revision: i64) -> Result<Self, InputError> {
        if object.is_nil() || revision <= 0 {
            return Err(InputError::Invalid);
        }
        Ok(Self { object, revision })
    }

    #[must_use]
    pub fn header_value(self) -> String {
        format!("\"{}.{}\"", self.object, self.revision)
    }

    #[must_use]
    pub fn revision(self) -> i64 {
        self.revision
    }

    #[must_use]
    pub fn object(self) -> Uuid {
        self.object
    }

    pub fn require_current(self, object: Uuid, revision: i64) -> Result<(), InputError> {
        if self == Self::new(object, revision)? {
            Ok(())
        } else {
            Err(InputError::PreconditionFailed)
        }
    }
}

pub(crate) fn one_header<'a>(
    headers: &'a HeaderMap,
    name: &str,
) -> Result<Option<&'a str>, InputError> {
    let mut fields = headers.get_all(name).iter();
    let Some(field) = fields.next() else {
        return Ok(None);
    };
    if fields.next().is_some() {
        return Err(InputError::Invalid);
    }
    field.to_str().map(Some).map_err(|_| InputError::Invalid)
}

pub fn required_version(headers: &HeaderMap) -> Result<VersionTag, InputError> {
    let value = one_header(headers, IF_MATCH.as_str())?.ok_or(InputError::PreconditionRequired)?;
    if value.len() > MAX_PRECONDITION_BYTES {
        return Err(InputError::TooLarge);
    }
    let value = value.trim_matches([' ', '\t']);
    if value == "*" {
        return Err(InputError::PreconditionRequired);
    }
    let weak = value.starts_with("W/");
    let value = value.strip_prefix("W/").unwrap_or(value);
    let inner = value
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .ok_or(InputError::Invalid)?;
    let (id, revision) = inner.split_once('.').ok_or(InputError::Invalid)?;
    let object = Uuid::parse_str(id).map_err(|_| InputError::Invalid)?;
    let revision: i64 = revision.parse().map_err(|_| InputError::Invalid)?;
    let tag = VersionTag::new(object, revision)?;
    if tag.header_value() != value {
        return Err(InputError::Invalid);
    }
    if weak {
        return Err(InputError::PreconditionFailed);
    }
    Ok(tag)
}

pub fn idempotency_key(headers: &HeaderMap) -> Result<&str, InputError> {
    let value = one_header(headers, "idempotency-key")?.ok_or(InputError::Invalid)?;
    if value.len() > MAX_IDEMPOTENCY_BYTES {
        return Err(InputError::TooLarge);
    }
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(InputError::Invalid);
    }
    Ok(value)
}

/// Validate duplicate members before typed decoding; target types must deny
/// unknown fields. The adapter separately bounds reading time and body bytes.
pub fn decode_json<T: DeserializeOwned>(body: &[u8]) -> Result<T, InputError> {
    if body.len() > MAX_BODY_BYTES {
        return Err(InputError::TooLarge);
    }
    crate::util::validate_json_without_duplicate_object_keys(body)
        .map_err(|_| InputError::Invalid)?;
    serde_json::from_slice(body).map_err(|_| InputError::Invalid)
}

pub fn page_size(value: Option<&str>) -> Result<usize, InputError> {
    let Some(value) = value else {
        return Ok(DEFAULT_PAGE_SIZE);
    };
    let size: usize = value.parse().map_err(|_| InputError::Invalid)?;
    if size == 0 || size > MAX_PAGE_SIZE || size.to_string() != value {
        return Err(InputError::Invalid);
    }
    Ok(size)
}

#[cfg(test)]
mod tests;
