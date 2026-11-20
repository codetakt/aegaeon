use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{de::Error, Deserialize, Deserializer, Serialize};
use uuid::Uuid;

const MAX_BYTES: usize = 8192;
const DAY: i64 = 24 * 60 * 60;

#[derive(Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(in crate::web) struct MailLink {
    pub issuer: String,
    #[serde(deserialize_with = "canonical_id")]
    pub environment_id: Uuid,
    #[serde(deserialize_with = "canonical_id")]
    pub domain_id: Uuid,
    #[serde(deserialize_with = "canonical_id")]
    pub invitation_id: Uuid,
    #[serde(deserialize_with = "canonical_id")]
    pub object_id: Uuid,
    pub template: String,
    pub delivery_revision: i64,
    pub capability: String,
    pub expires_at: i64,
}

fn canonical_id<'de, D: Deserializer<'de>>(d: D) -> Result<Uuid, D::Error> {
    let value = String::deserialize(d)?;
    Uuid::parse_str(&value)
        .ok()
        .filter(|id| !id.is_nil() && id.to_string() == value)
        .ok_or_else(|| D::Error::custom("invalid invitation identifier"))
}

/// Parse only the bounded, unpadded part following `#aegaeon=`. The caller
/// must also verify the invitation, child purpose and revision in its live
/// scoped store before persisting or resuming anything.
pub(in crate::web) fn parse_fragment(
    encoded: &str,
    issuer: &str,
    environment_id: Uuid,
    now: i64,
) -> Option<MailLink> {
    if encoded.len() > (MAX_BYTES * 8).div_ceil(6) {
        return None;
    }
    let raw = URL_SAFE_NO_PAD.decode(encoded).ok()?;
    let value: MailLink = serde_json::from_slice(&raw).ok()?;
    let invitation = match value.template.as_str() {
        "organization_invitation" => true,
        "organization_recipient_challenge"
        | "organization_identity_registration"
        | "organization_identity_recovery" => false,
        _ => return None,
    };
    (raw.len() <= MAX_BYTES
        && value.issuer == issuer
        && value.environment_id == environment_id
        && (value.object_id == value.invitation_id) == invitation
        && (1..=5).contains(&value.delivery_revision)
        && value.capability.len() == 43
        && URL_SAFE_NO_PAD.decode(&value.capability).ok()?.len() == 32
        && value.expires_at > now
        && value.expires_at <= now.checked_add(DAY)?)
    .then_some(value)
}

#[cfg(test)]
mod tests;
