use crate::local_credentials::{self, RecoveryTokenPurpose};
use crate::management::types::{InviteUserResponse, User};
use crate::organizations::witness::creation::{primary, Receipt};
use crate::web::management::{
    error_response, management_internal_error, request_support::creation,
    write_user_management_audit_event, EndUserAuditEvent, UserManagementContext,
};
use axum::{
    http::{HeaderMap, StatusCode},
    response::Response,
};
use sqlx::{Postgres, Transaction};

use crate::web::management::user_credentials::responses::issued_in_transaction as token_response;

pub(super) async fn invite(
    context: &UserManagementContext,
    headers: &HeaderMap,
    subject: &str,
    email: Option<&str>,
    expiry: Option<i64>,
    request_id: &str,
) -> Result<InviteUserResponse, Response> {
    let input = creation::input(
        context,
        headers,
        subject,
        email,
        creation::Profile::Invite(expiry),
        request_id,
    )?;
    creation::execute(
        context,
        &input,
        &Invite {
            context,
            email,
            expiry,
            request_id,
        },
        request_id,
    )
    .await
}

struct Invite<'a> {
    context: &'a UserManagementContext,
    email: Option<&'a str>,
    expiry: Option<i64>,
    request_id: &'a str,
}

impl primary::Mutation for Invite<'_> {
    type Output = InviteUserResponse;
    type Error = Response;

    fn apply<'a>(
        &'a self,
        tx: &'a mut Transaction<'_, Postgres>,
        receipt: &'a Receipt,
    ) -> primary::MutationFuture<'a, Self::Output, Response> {
        Box::pin(async move {
            self.context
                .require_lifecycle_role_in_transaction(tx, self.request_id)
                .await?;
            let issuer: String = sqlx::query_scalar("SELECT e.issuer_url FROM aegaeon.environments e JOIN aegaeon.tenants t ON t.id=e.tenant_id WHERE e.id=$1 AND t.team_id=$2 AND e.status<>'DELETED' AND t.status<>'DELETED' FOR SHARE OF e,t")
                .bind(self.context.environment_id).bind(self.context.team_id).fetch_one(&mut **tx).await
                .map_err(|_| management_internal_error(self.request_id, "Failed to load current issuer"))?;
            sqlx::query("SELECT environment_id FROM aegaeon.environment_policies WHERE environment_id=$1 FOR SHARE")
                .bind(self.context.environment_id).fetch_one(&mut **tx).await
                .map_err(|_| management_internal_error(self.request_id, "Failed to lock current recovery policy"))?;
            let policy =
                super::super::super::policy::load_recovery_token_ttl_policy_in_transaction(
                    tx,
                    self.context.environment_id,
                    self.request_id,
                )
                .await?;
            let ttl = local_credentials::sanitize_recovery_token_ttl(
                self.expiry,
                RecoveryTokenPurpose::Activation,
                policy,
            )
            .map_err(|message| {
                error_response(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    message,
                    None,
                    Some(self.request_id),
                )
            })?;
            sqlx::query("INSERT INTO aegaeon.end_users(id,environment_id,subject,email,status) VALUES($1,$2,$3,$4,'INVITED')")
                .bind(receipt.owner_id()).bind(self.context.environment_id).bind(receipt.subject()).bind(self.email)
                .execute(&mut **tx).await.map_err(|_| management_internal_error(self.request_id,"Failed to create invited user"))?;
            crate::end_user_profiles::ensure_profile_row(tx, receipt.owner_id())
                .await
                .map_err(|_| {
                    management_internal_error(self.request_id, "Failed to initialize user profile")
                })?;
            let user = self.current(tx, receipt).await?;
            let (issued, redeem_url) =
                super::super::super::recovery_issuance::issue_recovery_token_with_redeem_url(
                    tx,
                    &issuer,
                    receipt.owner_id(),
                    RecoveryTokenPurpose::Activation,
                    ttl,
                    self.context.session.administrator_id,
                    self.request_id,
                )
                .await?;
            write_user_management_audit_event(tx,self.context,self.request_id,EndUserAuditEvent {
                event_type:"management.user.invited.v1",target_id:receipt.owner_id(),
                data:serde_json::json!({"userId":user.id,"subject":user.subject,"email":user.email,"status":user.status,
                    "activationTokenId":issued.id,"activationExpiresAt":issued.expires_at}),
            }).await?;
            let activation =
                token_response::load(tx, receipt.owner_id(), issued, redeem_url, self.request_id)
                    .await?;
            Ok(InviteUserResponse { user, activation })
        })
    }

    fn recheck<'a>(
        &'a self,
        tx: &'a mut Transaction<'_, Postgres>,
    ) -> primary::MutationFuture<'a, (), Response> {
        Box::pin(
            self.context
                .require_lifecycle_role_in_transaction(tx, self.request_id),
        )
    }
    fn replay<'a>(
        &'a self,
        tx: &'a mut Transaction<'_, Postgres>,
        receipt: &'a Receipt,
    ) -> primary::MutationFuture<'a, Self::Output, Response> {
        Box::pin(async move {
            self.context
                .require_lifecycle_role_in_transaction(tx, self.request_id)
                .await?;
            self.current(tx, receipt).await?;
            Err(error_response(
                StatusCode::CONFLICT,
                "one_time_result_unavailable",
                "Invitation already committed; use explicit activation issuance if needed",
                None,
                Some(self.request_id),
            ))
        })
    }
}

impl Invite<'_> {
    async fn current(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        receipt: &Receipt,
    ) -> Result<User, Response> {
        crate::web::management::users::store::load_user_row_for_status(
            &mut **tx,
            self.context,
            receipt.owner_id(),
            "AND u.status <> 'DELETED'",
            "User not found",
            self.request_id,
        )
        .await
    }
}
