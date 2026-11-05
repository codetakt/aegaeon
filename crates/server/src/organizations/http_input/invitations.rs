use super::InputError;
use serde::Deserialize;
use std::collections::BTreeSet;

#[derive(Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct IssueInvitationRequest {
    pub recipient: String,
    pub roles: Vec<String>,
    pub lifetime_seconds: Option<i64>,
    pub reason: String,
}

impl IssueInvitationRequest {
    pub fn roles(&self) -> Result<BTreeSet<String>, InputError> {
        let roles: BTreeSet<_> = self.roles.iter().cloned().collect();
        if roles.len() != self.roles.len()
            || roles.is_empty()
            || roles.len() > crate::organizations::MAX_ROLES
            || !crate::organizations::model::valid_keys(&roles, crate::organizations::MAX_ROLES)
        {
            return Err(InputError::Invalid);
        }
        Ok(roles)
    }
}

/// Secrets are write-only inputs; never derive Debug or emit them in responses.
#[derive(Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RecipientChallengeRequest {
    pub invitation_capability: String,
}

#[derive(Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AcceptInvitationRequest {
    pub invitation_capability: String,
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "uuid"))]
    pub challenge_id: uuid::Uuid,
    pub challenge_capability: String,
}
