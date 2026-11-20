use super::*;
use crate::organizations::operators::mutations::display::Target;
use std::collections::BTreeMap;

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub(crate) struct SetOrganizationDisplayName {
    // Omitting the property is invalid; explicit null clears an existing name.
    #[serde(deserialize_with = "serde::Deserialize::deserialize")]
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub display_name: Option<String>,
    pub reason: String,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub(crate) struct PatchRoleDisplay {
    pub labels: BTreeMap<String, Option<String>>,
    pub reason: String,
}

pub(crate) fn expected(
    headers: &HeaderMap,
    target: Target,
    object: Uuid,
) -> Result<i64, InputError> {
    let value = one_header(headers, IF_MATCH.as_str())?.ok_or(InputError::PreconditionRequired)?;
    if value.len() > MAX_PRECONDITION_BYTES {
        return Err(InputError::TooLarge);
    }
    let value = value.trim_matches([' ', '\t']);
    let inner = value
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .ok_or(InputError::Invalid)?;
    let mut fields = inner.split('.');
    if fields.next() != Some(target.tag_prefix()) {
        return Err(InputError::Invalid);
    }
    let id = Uuid::parse_str(fields.next().ok_or(InputError::Invalid)?)
        .map_err(|_| InputError::Invalid)?;
    let revision = fields
        .next()
        .ok_or(InputError::Invalid)?
        .parse()
        .map_err(|_| InputError::Invalid)?;
    let tag = VersionTag::display(id, revision)?;
    if fields.next().is_some() || tag.prefixed(target.tag_prefix()) != value {
        return Err(InputError::Invalid);
    }
    if id != object {
        return Err(InputError::PreconditionFailed);
    }
    Ok(revision)
}
