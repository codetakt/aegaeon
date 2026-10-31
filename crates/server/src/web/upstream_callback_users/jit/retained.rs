//! The scoped caller owns the retained receipt and the primary transaction.
use super::*;
use crate::organizations::witness::creation::Receipt;

pub(in crate::web) async fn prepare(
    tx: &mut Transaction<'_, Postgres>,
    request: &UpstreamAuthRequest,
    token: &IdToken,
    issuer: &str,
) -> Result<(), Response> {
    let email = upstream_callback_email(token);
    authorize_upstream_user(
        tx,
        request,
        request.context.environment_id,
        UpstreamCallbackEmail {
            value: email.as_deref(),
            verified: upstream_callback_email_verified(token),
        },
        issuer,
    )
    .await?;
    if !request.jit_provisioning_policy.as_ref().is_some_and(|p| {
        p.initial_status == crate::upstream::UpstreamJitProvisioningInitialStatus::Active
    }) {
        return Err(json_error_with_iss(
            StatusCode::FORBIDDEN,
            "access_denied",
            Some("upstream JIT initial status prevents authentication"),
            issuer,
        ));
    }
    Ok(())
}

pub(in crate::web) async fn provision(
    tx: &mut Transaction<'_, Postgres>,
    request: &UpstreamAuthRequest,
    token: &IdToken,
    upstream_sub_hash: &str,
    receipt: &Receipt,
    issuer: &str,
    request_id: &str,
) -> Result<UpstreamResolvedUser, Response> {
    prepare(tx, request, token, issuer).await?;
    record_upstream_user_provision_audit(
        tx,
        request,
        receipt.subject(),
        "upstream.user.provision.authorized.v1",
        issuer,
        request_id,
    )
    .await?;
    let email = upstream_callback_email(token);
    let user = insert_upstream_end_user(
        tx,
        request.context.environment_id,
        receipt.subject(),
        email.as_deref(),
        crate::upstream::UpstreamJitProvisioningInitialStatus::Active,
        Some(receipt.owner_id()),
    )
    .await
    .map_err(|_| {
        json_error_with_iss(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            Some("upstream identity creation unavailable"),
            issuer,
        )
    })?;
    crate::end_user_profiles::ensure_profile_row(tx, user.end_user_id)
        .await
        .map_err(|_| {
            json_error_with_iss(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                Some("upstream profile creation unavailable"),
                issuer,
            )
        })?;
    record_upstream_account_link_audit(
        tx,
        request,
        &user.subject,
        upstream_sub_hash,
        "upstream.account_link.upsert.authorized.v1",
        issuer,
        request_id,
    )
    .await?;
    upsert_upstream_account_link(
        tx,
        request.context.environment_id,
        request.context.connection_id,
        &request.issuer,
        upstream_sub_hash,
        user.end_user_id,
        issuer,
    )
    .await?;
    Ok(user)
}
