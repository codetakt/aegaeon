use super::model::EndUserProfileRecord;
use sqlx::{postgres::PgRow, Row};
use uuid::Uuid;

pub(in crate::end_user_profiles) fn issuer_host_from_url(issuer: &str) -> Option<String> {
    let url = url::Url::parse(issuer).ok()?;
    crate::util::canonical_url_host_port(&url)
}

pub(in crate::end_user_profiles) fn profile_from_row(
    row: &PgRow,
) -> Result<EndUserProfileRecord, sqlx::Error> {
    let user_id: Uuid = row.try_get("user_id")?;
    let subject: String = row.try_get("subject")?;
    let subject_policy: String = row.try_get("subject_policy")?;
    let email: Option<String> = row.try_get("email")?;
    let email_verified: bool = row.try_get("email_verified")?;
    let display_name: Option<String> = row.try_get("display_name")?;
    let custom_claims: serde_json::Value = row.try_get("custom_claims")?;
    let version: i64 = row.try_get("version")?;
    let updated_at: String = row.try_get("updated_at")?;
    let updated_at_epoch_seconds: i64 = row.try_get("updated_at_epoch_seconds")?;

    Ok(EndUserProfileRecord {
        user_id: user_id.to_string(),
        subject,
        subject_policy,
        email,
        email_verified,
        display_name,
        custom_claims,
        version,
        updated_at,
        updated_at_epoch_seconds,
    })
}
