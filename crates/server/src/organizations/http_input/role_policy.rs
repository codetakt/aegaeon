use super::*;
#[derive(serde::Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReplaceRolePolicyRequest {
    pub roles: Vec<crate::organizations::operators::mutations::role_policy::Definition>,
    pub reason: String,
}

pub fn required_policy_version(headers: &HeaderMap) -> Result<VersionTag, InputError> {
    let value = one_header(headers, IF_MATCH.as_str())?.ok_or(InputError::PreconditionRequired)?;
    if value.len() > MAX_PRECONDITION_BYTES {
        return Err(InputError::TooLarge);
    }
    let value = value.trim_matches([' ', '\t']);
    if value == "*" {
        return Err(InputError::PreconditionRequired);
    }
    let (weak, value) = if let Some(value) = value.strip_prefix("W/") {
        ("W/", value)
    } else {
        ("", value)
    };
    let inner = value
        .strip_prefix("\"role-policy.")
        .ok_or(InputError::Invalid)?;
    let mut normalized = HeaderMap::new();
    normalized.insert(
        IF_MATCH,
        format!("{weak}\"{inner}")
            .parse()
            .map_err(|_| InputError::Invalid)?,
    );
    required_version(&normalized)
}
