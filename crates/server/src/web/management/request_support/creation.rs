use super::super::{error_response, UserManagementContext};
use super::owned;
use crate::organizations::{
    request_work::async_store,
    witness::creation::{primary, Input},
};
use axum::{http::StatusCode, response::Response};
mod binding;
pub(in crate::web::management) use binding::{input, Profile};

pub(in crate::web::management) async fn execute<M: primary::Mutation<Error = Response>>(
    context: &UserManagementContext,
    input: &Input,
    mutation: &M,
    request_id: &str,
) -> Result<M::Output, Response> {
    if !context.session.is_human_session() {
        return Err(error_response(
            StatusCode::FORBIDDEN,
            "forbidden",
            "Human lifecycle authority required",
            None,
            Some(request_id),
        ));
    }
    let owner = async_store::current_epoch_owner(context.environment_id)
        .map_err(|_| owned::unavailable(request_id))?;
    let receipt = owner
        .prepare_creation(context.environment_id, input)
        .await
        .map_err(|e| witness_failure(&e, request_id))?;
    primary::execute(&context.pool, &owner, input, &receipt, mutation)
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
