use axum::response::Response;
use sqlx::{Executor, Postgres};

use crate::management::types::AccountLinkConflictCandidate;
use crate::web::management::{load_account_link_conflict_candidates, ManagementEnvironmentScope};

pub(in crate::web::management::account_link_conflict) async fn load_selected_account_link_candidate<
    'e,
    E,
>(
    executor: E,
    scope: ManagementEnvironmentScope,
    upstream_subject: &str,
    target_user_id: &str,
    moving_to_different_user: bool,
    request_id: &str,
) -> Result<Option<AccountLinkConflictCandidate>, Response>
where
    E: Executor<'e, Database = Postgres>,
{
    if moving_to_different_user {
        return load_account_link_conflict_candidates(
            executor,
            scope.team,
            scope.environment,
            upstream_subject,
            request_id,
        )
        .await
        .map(|candidates| {
            candidates
                .into_iter()
                .find(|candidate| candidate.end_user.id == target_user_id)
        });
    }

    Ok(None)
}
