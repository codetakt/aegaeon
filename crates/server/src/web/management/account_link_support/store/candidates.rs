use axum::response::Response;
use sqlx::{Executor, Postgres, Row};
use uuid::Uuid;

use crate::management::types::AccountLinkConflictCandidate;

use super::super::super::{management_internal_error, normalize_email, user_from_row_result};

pub(in crate::web::management) const LOAD_ACCOUNT_LINK_CONFLICT_CANDIDATES_SQL: &str = r#"
SELECT
  u.id,
  u.environment_id,
  u.subject,
  u.email,
  u.status::text AS status,
  to_char(u.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at,
  to_char(u.updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS updated_at,
  (u.subject = $3) AS subject_match,
  ($4::text IS NOT NULL AND lower(u.email) = $4) AS email_match
FROM aegaeon.end_users u
JOIN aegaeon.environments e ON e.id = u.environment_id
JOIN aegaeon.tenants t ON t.id = e.tenant_id
WHERE u.environment_id = $1
  AND t.team_id = $2
  AND t.status <> 'DELETED'
  AND e.status <> 'DELETED'
  AND u.status <> 'DELETED'
  AND (
    u.subject = $3
    OR ($4::text IS NOT NULL AND lower(u.email) = $4)
  )
ORDER BY
  CASE WHEN u.subject = $3 THEN 1 ELSE 0 END DESC,
  CASE WHEN $4::text IS NOT NULL AND lower(u.email) = $4 THEN 1 ELSE 0 END DESC,
  u.created_at ASC
        "#;

pub(in crate::web::management) async fn load_account_link_conflict_candidates<'e, E>(
    executor: E,
    team_id: Uuid,
    environment_id: Uuid,
    upstream_subject: &str,
    request_id: &str,
) -> Result<Vec<AccountLinkConflictCandidate>, Response>
where
    E: Executor<'e, Database = Postgres>,
{
    let normalized_upstream_email = normalize_email(upstream_subject);
    let rows = sqlx::query(LOAD_ACCOUNT_LINK_CONFLICT_CANDIDATES_SQL)
        .bind(environment_id)
        .bind(team_id)
        .bind(upstream_subject)
        .bind(normalized_upstream_email.as_deref())
        .fetch_all(executor)
        .await
        .map_err(|_| management_internal_error(request_id, "Database query failed"))?;

    let mut candidates = Vec::with_capacity(rows.len());
    let mut has_subject_match = false;
    let mut email_match_count = 0usize;

    for row in rows {
        let end_user = user_from_row_result(&row, request_id)?;
        let subject_match: bool = row
            .try_get("subject_match")
            .map_err(|_| management_internal_error(request_id, "Failed to load user"))?;
        let email_match: bool = row
            .try_get("email_match")
            .map_err(|_| management_internal_error(request_id, "Failed to load user"))?;
        if subject_match {
            has_subject_match = true;
        }
        if email_match {
            email_match_count += 1;
        }
        candidates.push((end_user, subject_match, email_match));
    }

    Ok(candidates
        .into_iter()
        .map(|(end_user, subject_match, email_match)| {
            let mut match_reasons = Vec::new();
            if subject_match {
                match_reasons.push("subject".to_string());
            }
            if email_match {
                match_reasons.push("email".to_string());
            }
            let recommended =
                subject_match || (!has_subject_match && email_match && email_match_count == 1);
            AccountLinkConflictCandidate {
                end_user,
                match_reasons,
                recommended,
            }
        })
        .collect())
}
