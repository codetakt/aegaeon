//! Atomic store-side restriction of original Organizations authority.
use crate::authcode::types::BearerTokenMeta;
use std::time::SystemTime;

pub(super) fn validate(
    output: &BearerTokenMeta,
    subject: &BearerTokenMeta,
    now: SystemTime,
) -> Result<(), &'static str> {
    let original = subject
        .exchange_grant
        .as_ref()
        .filter(|g| g.organization.is_some());
    let selected = output.selected_organization.as_ref();
    if subject.selected_organization.is_some() {
        return Err("selected organization tokens cannot acquire descendant authority");
    }
    if original.is_none() && selected.is_none() {
        return Ok(());
    }
    let original = original.ok_or("organization selection requires original authority")?;
    let selected = selected.ok_or("organization authority requires an explicit selection")?;
    let authority = original
        .organization
        .as_ref()
        .ok_or("original authority missing")?;
    if !original.original_details_match(subject.authorization_details.as_ref())
        || subject.application_grant.is_some()
        || subject.client_credentials_grant.is_some()
        || output.application_grant.is_some()
        || output.client_credentials_grant.is_some()
        || output.auth_time_epoch_secs != subject.auth_time_epoch_secs
        || output.acr != subject.acr
    {
        return Err("organization exchange must preserve original authority and authentication");
    }
    let epoch = |time| {
        crate::util::unix_epoch_secs(time)
            .ok()
            .and_then(|v| i64::try_from(v).ok())
    };
    let now = epoch(now).ok_or("invalid store clock")?;
    let parent = epoch(subject.expires_at).ok_or("invalid subject horizon")?;
    if selected.parent_expires_at > parent {
        return Err("organization selection exceeds subject horizon");
    }
    selected
        .token_binding(
            output,
            authority.consent.scope.environment_id,
            &authority.consent.issuer,
            now,
        )
        .map_err(|_| "organization output does not match its retained selection")?;
    Ok(())
}
