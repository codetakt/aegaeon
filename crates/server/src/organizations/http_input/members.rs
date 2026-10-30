//! Delegated member representations and pagination; neither grants authority.
use super::*;
use crate::organizations::{Binding, Membership, MembershipState, Organization, MAX_ROLES};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use std::collections::BTreeSet;

#[derive(Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum MemberUpdateState {
    Active,
    Suspended,
    Removed,
}

impl From<MemberUpdateState> for MembershipState {
    fn from(value: MemberUpdateState) -> Self {
        match value {
            MemberUpdateState::Active => Self::Active,
            MemberUpdateState::Suspended => Self::Suspended,
            MemberUpdateState::Removed => Self::Removed,
        }
    }
}

#[derive(serde::Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdateMemberRequest {
    pub state: MemberUpdateState,
    pub roles: Vec<String>,
    pub reason: String,
}

impl UpdateMemberRequest {
    pub fn validate(&self) -> Result<BTreeSet<String>, InputError> {
        let roles: BTreeSet<_> = self.roles.iter().cloned().collect();
        if roles.len() != self.roles.len()
            || roles.len() > MAX_ROLES
            || roles
                .iter()
                .any(|r| r.trim().is_empty() || r.len() > 128 || r.chars().any(char::is_control))
            || (self.state == MemberUpdateState::Removed && !roles.is_empty())
            || self.reason.trim().is_empty()
            || self.reason.len() > 1024
            || self.reason.chars().any(char::is_control)
        {
            return Err(InputError::Invalid);
        }
        Ok(roles)
    }
}

#[derive(serde::Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct MemberResponse {
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "uuid"))]
    pub organization_id: Uuid,
    pub organization_identifier: String,
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "uuid"))]
    pub user_id: Uuid,
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "uuid"))]
    pub incarnation: Uuid,
    pub state: MembershipState,
    pub roles: BTreeSet<String>,
    pub revision: i64,
}

impl MemberResponse {
    pub fn new(organization: &Organization, member: Membership) -> Result<Self, InputError> {
        if (member.scope, member.organization_id) != (organization.scope, organization.id) {
            return Err(InputError::Invalid);
        }
        Ok(Self {
            organization_id: organization.id,
            organization_identifier: organization.external_id.clone(),
            user_id: member.user_id,
            incarnation: member.incarnation,
            state: member.state,
            roles: member.roles,
            revision: member.revision,
        })
    }
}

#[derive(serde::Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct MemberListResponse {
    pub members: Vec<MemberResponse>,
    pub next_cursor: Option<String>,
}

/// Fixed tuple: version, Environment/domain/organization/actor/registration, last user.
#[derive(serde::Serialize, serde::Deserialize)]
struct Cursor(u8, [Uuid; 5], Uuid);

fn context(binding: &Binding, organization: Uuid) -> [Uuid; 5] {
    [
        binding.scope.environment_id,
        binding.scope.domain_id,
        organization,
        binding.user_id,
        binding.client_registration_id,
    ]
}

pub fn encode(binding: &Binding, organization: Uuid, after: Uuid) -> Result<String, InputError> {
    let context = context(binding, organization);
    if context.iter().any(Uuid::is_nil) || after.is_nil() {
        return Err(InputError::Invalid);
    }
    let bytes = serde_json::to_vec(&Cursor(1, context, after)).map_err(|_| InputError::Invalid)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

pub fn decode(
    binding: &Binding,
    organization: Uuid,
    token: Option<&str>,
) -> Result<Option<Uuid>, InputError> {
    let Some(token) = token else {
        return Ok(None);
    };
    if token.is_empty() || token.len() > pagination::MAX_CURSOR_BYTES {
        return Err(InputError::Invalid);
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(token)
        .map_err(|_| InputError::Invalid)?;
    let cursor: Cursor = decode_json(&bytes)?;
    if cursor.0 != 1
        || cursor.1 != context(binding, organization)
        || encode(binding, organization, cursor.2)? != token
    {
        return Err(InputError::Invalid);
    }
    Ok(Some(cursor.2))
}

pub fn query(value: Option<&str>) -> Result<(usize, Option<String>), InputError> {
    let Some(value) = value else {
        return Ok((DEFAULT_PAGE_SIZE, None));
    };
    if value.is_empty() || value.len() > 1024 {
        return Err(InputError::Invalid);
    }
    let fields: Vec<(String, String)> =
        serde_urlencoded::from_str(value).map_err(|_| InputError::Invalid)?;
    let (mut limit, mut after) = (None, None);
    for (key, value) in fields {
        match key.as_str() {
            "limit" if limit.is_none() => limit = Some(value),
            "after" if after.is_none() => after = Some(value),
            _ => return Err(InputError::Invalid),
        }
    }
    Ok((page_size(limit.as_deref())?, after))
}
