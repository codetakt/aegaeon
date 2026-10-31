use super::*;
use crate::organizations::{
    request_work::async_store,
    witness::creation::{primary, Input, Kind, Receipt},
};
use crate::web::management::{error_response, management_internal_error, request_support::owned};
use axum::http::{HeaderMap, StatusCode};
use sqlx::{Postgres, Transaction};

mod binding;

pub(super) async fn create(
    context: &UserManagementContext,
    headers: &HeaderMap,
    subject: &str,
    email: Option<&str>,
    request_id: &str,
) -> Result<(User, StatusCode), Response> {
    if !context.session.is_human_session() {
        return Err(error_response(
            StatusCode::FORBIDDEN,
            "forbidden",
            "Human lifecycle authority required",
            None,
            Some(request_id),
        ));
    }
    let input = binding::input(context, headers, subject, email, request_id)?;
    let owner = async_store::current_epoch_owner(context.environment_id)
        .map_err(|_| owned::unavailable(request_id))?;
    let receipt = owner
        .prepare_creation(context.environment_id, &input)
        .await
        .map_err(|e| witness_failure(&e, request_id))?;
    let mutation = Create {
        context,
        email,
        request_id,
    };
    primary::execute(&context.pool, &owner, &input, &receipt, &mutation)
        .await
        .map_err(|e| match e {
            primary::Failure::Mutation(response) => response,
            primary::Failure::Witness(error) => witness_failure(&error, request_id),
            primary::Failure::Storage(error) => {
                drop(error);
                owned::unavailable(request_id)
            }
            primary::Failure::Reconciliation => owned::unavailable(request_id),
        })
}

fn witness_failure(error: &crate::organizations::witness::Error, request_id: &str) -> Response {
    if matches!(error,crate::organizations::witness::Error::Storage(sqlx::Error::Database(error))
        if matches!(error.message(),"permanent owner conflict"|"permanent subject conflict"|"creation conflict"))
    {
        return error_response(
            StatusCode::CONFLICT,
            "conflict",
            "Identity creation conflict",
            None,
            Some(request_id),
        );
    }
    owned::unavailable(request_id)
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
