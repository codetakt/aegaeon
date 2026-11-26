use sqlx::{Postgres, Transaction};
use uuid::Uuid;

/// Caller holds the Environment enrollment lock and the deleted user's row lock.
pub(super) async fn release(
    tx: &mut Transaction<'_, Postgres>,
    environment: Uuid,
    user: Uuid,
    email: Option<String>,
    administrator: Uuid,
) -> Result<bool, sqlx::Error> {
    let verified: Option<String> = sqlx::query_scalar(
        "SELECT verified_delivery_address FROM aegaeon.end_user_profiles WHERE end_user_id=$1 FOR UPDATE",
    )
    .bind(user).fetch_optional(&mut **tx).await?.flatten();
    let had_email = email.is_some();
    let mut addresses: Vec<_> = email
        .into_iter()
        .chain(verified)
        .map(|address| address.to_ascii_lowercase())
        .collect();
    addresses.sort_unstable();
    addresses.dedup();
    for address in addresses {
        crate::local_credentials::registration_generation::advance(tx, environment, &address)
            .await?;
    }
    let profile = sqlx::query("UPDATE aegaeon.end_user_profiles
        SET verified_delivery_address=NULL, email_verified=false, profile_version=profile_version+1, updated_at=now()
        WHERE end_user_id=$1 AND (verified_delivery_address IS NOT NULL OR email_verified)")
        .bind(user).execute(&mut **tx).await?;
    let password =
        crate::local_credentials::revoke_password_credential(tx, user, Some(administrator)).await?;
    let tokens = sqlx::query(
        "UPDATE aegaeon.end_user_recovery_tokens
        SET revoked_at=now(), revoked_by_administrator_id=$2
        WHERE end_user_id=$1 AND redeemed_at IS NULL AND revoked_at IS NULL",
    )
    .bind(user)
    .bind(administrator)
    .execute(&mut **tx)
    .await?;
    if had_email {
        sqlx::query("UPDATE aegaeon.end_users SET email=NULL, updated_at=now() WHERE id=$1")
            .bind(user)
            .execute(&mut **tx)
            .await?;
    }
    Ok(
        had_email
            || profile.rows_affected() > 0
            || password.is_some()
            || tokens.rows_affected() > 0,
    )
}
