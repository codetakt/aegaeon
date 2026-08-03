use super::super::super::store::list_api_key_rows;
use crate::management::types::{ApiKeyCapability, ListApiKeysResponse};
use crate::web::management::state::ManagementSession;
use crate::web::management::{ensure_team_visible, forbidden};
use axum::response::Response;
use sqlx::PgPool;
use uuid::Uuid;

pub(super) async fn list_api_keys_inner(
    pool: &PgPool,
    team_id: Uuid,
    session: &ManagementSession,
    request_id: &str,
) -> Result<ListApiKeysResponse, Response> {
    require_api_key_list_permission(pool, team_id, session, request_id).await?;

    Ok(ListApiKeysResponse {
        api_keys: list_api_key_rows(pool, team_id, request_id).await?,
        page_info: None,
    })
}

async fn require_api_key_list_permission(
    pool: &PgPool,
    team_id: Uuid,
    session: &ManagementSession,
    request_id: &str,
) -> Result<(), Response> {
    if session.is_human_session() {
        return ensure_team_visible(pool, team_id, session, request_id).await;
    }

    if !api_key_can_list_api_keys_for_team(session, team_id) {
        return Err(forbidden(
            "forbidden",
            "Insufficient API key capabilities for API key operations",
            request_id,
        ));
    }

    Ok(())
}

fn api_key_can_list_api_keys_for_team(session: &ManagementSession, team_id: Uuid) -> bool {
    session.api_key_team_id() == Some(team_id)
        && session.api_key_has_capability(ApiKeyCapability::Read)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_key_list_permission_requires_same_team() {
        let team_id = Uuid::new_v4();
        let session = ManagementSession::api_key(
            Uuid::new_v4(),
            1,
            Uuid::new_v4(),
            Uuid::new_v4(),
            vec![ApiKeyCapability::Read],
        );

        assert!(!api_key_can_list_api_keys_for_team(&session, team_id));
    }

    #[test]
    fn api_key_list_permission_accepts_read_or_team_administration() {
        let team_id = Uuid::new_v4();
        for capability in [ApiKeyCapability::Read, ApiKeyCapability::TeamAdministration] {
            let session = ManagementSession::api_key(
                Uuid::new_v4(),
                1,
                Uuid::new_v4(),
                team_id,
                vec![capability],
            );

            assert!(api_key_can_list_api_keys_for_team(&session, team_id));
        }
    }

    #[test]
    fn api_key_list_permission_rejects_audit_only() {
        let team_id = Uuid::new_v4();
        let session = ManagementSession::api_key(
            Uuid::new_v4(),
            1,
            Uuid::new_v4(),
            team_id,
            vec![ApiKeyCapability::AuditRead],
        );

        assert!(!api_key_can_list_api_keys_for_team(&session, team_id));
    }
}
