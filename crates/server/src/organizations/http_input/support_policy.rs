use super::*;
#[derive(serde::Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ConfigureSupportPolicyRequest {
    pub policy: crate::organizations::operators::mutations::support_policy::Policy,
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
        .strip_prefix("\"support-policy.")
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
