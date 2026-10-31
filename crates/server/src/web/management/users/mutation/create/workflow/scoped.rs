use super::*;
use crate::organizations::witness::creation::{primary, Receipt};
use crate::web::management::{management_internal_error, request_support::creation};
use axum::http::{HeaderMap, StatusCode};
use sqlx::{Postgres, Transaction};

pub(super) async fn create(
    context: &UserManagementContext,
    headers: &HeaderMap,
    subject: &str,
    email: Option<&str>,
    request_id: &str,
) -> Result<(User, StatusCode), Response> {
    let input = creation::input(
        context,
        headers,
        subject,
        email,
        creation::Profile::Create,
        request_id,
    )?;
    creation::execute(
        context,
        &input,
        &Create {
            context,
            email,
            request_id,
        },
        request_id,
    )
    .await
}

struct Create<'a> {
    context: &'a UserManagementContext,
    email: Option<&'a str>,
    request_id: &'a str,
}

impl primary::Mutation for Create<'_> {
    type Output = (User, StatusCode);
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
            sqlx::query("INSERT INTO aegaeon.end_users(id,environment_id,subject,email,status) VALUES($1,$2,$3,$4,'INVITED')")
                .bind(receipt.owner_id()).bind(self.context.environment_id).bind(receipt.subject()).bind(self.email)
                .execute(&mut **tx).await.map_err(|_| management_internal_error(self.request_id,"Failed to create user"))?;
            crate::end_user_profiles::ensure_profile_row(tx, receipt.owner_id())
                .await
                .map_err(|_| {
                    management_internal_error(self.request_id, "Failed to initialize user profile")
                })?;
            let user = self.current(tx, receipt).await?;
            write_user_management_audit_event(tx,self.context,self.request_id,EndUserAuditEvent {
                event_type:"management.user.created.v1",target_id:receipt.owner_id(),
                data:serde_json::json!({"userId":user.id,"subject":user.subject,"email":user.email,"status":user.status}),
            }).await?;
            Ok((user, StatusCode::CREATED))
        })
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
            Ok((self.current(tx, receipt).await?, StatusCode::OK))
        })
    }
}

impl Create<'_> {
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
