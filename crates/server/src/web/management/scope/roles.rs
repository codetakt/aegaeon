use super::super::{
    error_response, forbidden, management_team_not_found, state::ManagementSession,
};
use crate::management::types::ApiKeyCapability;
use axum::{http::StatusCode, response::Response};
use sqlx::{Executor, PgPool, Postgres, Row, Transaction};
use uuid::Uuid;

#[derive(Debug, Clone)]
enum PrincipalTeamAccess {
    Human {
        role: String,
    },
    Service {
        allows_read: bool,
        allows_audit_read: bool,
    },
}

impl PrincipalTeamAccess {
    fn allows_read(&self) -> bool {
        match self {
            Self::Human { .. } => true,
            Self::Service { allows_read, .. } => *allows_read,
        }
    }

    fn allows_audit_read(&self) -> bool {
        match self {
            Self::Human { role } => role_allows_audit_read(role),
            Self::Service {
                allows_audit_read, ..
            } => *allows_audit_read,
        }
    }

    fn allows_lifecycle(&self) -> bool {
        match self {
            Self::Human { role } => role_allows_manage_lifecycle(role),
            Self::Service { .. } => false,
        }
    }
}

pub(in crate::web::management) async fn require_team_lifecycle_role(
    pool: &PgPool,
    team_id: Uuid,
    session: &ManagementSession,
    request_id: &str,
    forbidden_message: &str,
) -> Result<(), Response> {
    match load_principal_team_access(pool, team_id, session).await {
        Ok(Some(access)) => {
            if !access.allows_lifecycle() {
                return Err(forbidden("forbidden", forbidden_message, request_id));
            }
            Ok(())
        }
        Ok(None) => Err(error_response(
            StatusCode::NOT_FOUND,
            "not_found",
            "Team not found",
            None,
            Some(request_id),
        )),
        Err(_) => Err(error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "Database query failed",
            None,
            Some(request_id),
        )),
    }
}

pub(in crate::web::management) async fn require_team_lifecycle_role_in_transaction(
    tx: &mut Transaction<'_, Postgres>,
    team_id: Uuid,
    session: &ManagementSession,
    request_id: &str,
    forbidden_message: &str,
) -> Result<(), Response> {
    match load_principal_team_access_in_transaction(tx, team_id, session).await {
        Ok(Some(access)) => {
            if !access.allows_lifecycle() {
                return Err(forbidden("forbidden", forbidden_message, request_id));
            }
            Ok(())
        }
        Ok(None) => Err(error_response(
            StatusCode::NOT_FOUND,
            "not_found",
            "Team not found",
            None,
            Some(request_id),
        )),
        Err(_) => Err(error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "Database query failed",
            None,
            Some(request_id),
        )),
    }
}

pub(in crate::web::management) fn role_allows_manage_lifecycle(role: &str) -> bool {
    matches!(role, "OWNER" | "ADMINISTRATOR")
}

pub(in crate::web::management) fn role_allows_audit_read(role: &str) -> bool {
    matches!(role, "OWNER" | "ADMINISTRATOR" | "AUDITOR")
}

async fn load_principal_team_access(
    pool: &PgPool,
    team_id: Uuid,
    session: &ManagementSession,
) -> Result<Option<PrincipalTeamAccess>, sqlx::Error> {
    let Some((role, administrator_kind)) =
        load_team_role_with_administrator_kind(pool, team_id, session.administrator_id).await?
    else {
        return Ok(None);
    };

    Ok(principal_team_access_for_session(
        session,
        team_id,
        role,
        administrator_kind,
    ))
}

async fn load_principal_team_access_in_transaction(
    tx: &mut Transaction<'_, Postgres>,
    team_id: Uuid,
    session: &ManagementSession,
) -> Result<Option<PrincipalTeamAccess>, sqlx::Error> {
    let Some((role, administrator_kind)) =
        load_team_role_with_administrator_kind_for_update(tx, team_id, session.administrator_id)
            .await?
    else {
        return Ok(None);
    };

    Ok(principal_team_access_for_session(
        session,
        team_id,
        role,
        administrator_kind,
    ))
}

fn principal_team_access_for_session(
    session: &ManagementSession,
    team_id: Uuid,
    role: String,
    administrator_kind: String,
) -> Option<PrincipalTeamAccess> {
    if session.is_human_session() && administrator_kind == "HUMAN" {
        return Some(PrincipalTeamAccess::Human { role });
    }

    if administrator_kind == "SERVICE" && session.api_key_team_id() == Some(team_id) {
        return Some(PrincipalTeamAccess::Service {
            allows_read: session.api_key_has_capability(ApiKeyCapability::Read),
            allows_audit_read: session.api_key_has_capability(ApiKeyCapability::AuditRead),
        });
    }

    None
}

async fn load_team_role_with_administrator_kind(
    executor: impl Executor<'_, Database = Postgres>,
    team_id: Uuid,
    administrator_id: Uuid,
) -> Result<Option<(String, String)>, sqlx::Error> {
    let row = sqlx::query(
        r"
SELECT m.role::text AS role, a.kind::text AS administrator_kind
FROM aegaeon.team_memberships m
JOIN aegaeon.teams t
  ON t.id = m.team_id
JOIN aegaeon.administrators a
  ON a.id = m.administrator_id
WHERE m.team_id = $1
  AND m.administrator_id = $2
  AND t.status <> 'DELETED'
  AND a.status = 'ACTIVE'
        ",
    )
    .bind(team_id)
    .bind(administrator_id)
    .fetch_optional(executor)
    .await?;

    row.map(|row| {
        row.try_get::<String, _>("role").and_then(|role| {
            row.try_get::<String, _>("administrator_kind")
                .map(|kind| (role, kind))
        })
    })
    .transpose()
}

async fn load_team_role_with_administrator_kind_for_update(
    tx: &mut Transaction<'_, Postgres>,
    team_id: Uuid,
    administrator_id: Uuid,
) -> Result<Option<(String, String)>, sqlx::Error> {
    let row = sqlx::query(
        r"
SELECT m.role::text AS role, a.kind::text AS administrator_kind
FROM aegaeon.team_memberships m
JOIN aegaeon.teams t
  ON t.id = m.team_id
JOIN aegaeon.administrators a
  ON a.id = m.administrator_id
WHERE m.team_id = $1
  AND m.administrator_id = $2
  AND t.status <> 'DELETED'
  AND a.status = 'ACTIVE'
FOR UPDATE OF m, t, a
        ",
    )
    .bind(team_id)
    .bind(administrator_id)
    .fetch_optional(&mut **tx)
    .await?;

    row.map(|row| {
        row.try_get::<String, _>("role").and_then(|role| {
            row.try_get::<String, _>("administrator_kind")
                .map(|kind| (role, kind))
        })
    })
    .transpose()
}

pub(in crate::web::management) async fn require_team_audit_read_access(
    pool: &PgPool,
    team_id: Uuid,
    session: &ManagementSession,
    request_id: &str,
    forbidden_message: &str,
) -> Result<(), Response> {
    match load_principal_team_access(pool, team_id, session).await {
        Ok(Some(access)) if access.allows_audit_read() => Ok(()),
        Ok(Some(_)) => Err(forbidden("forbidden", forbidden_message, request_id)),
        Ok(None) => Err(error_response(
            StatusCode::NOT_FOUND,
            "not_found",
            "Team not found",
            None,
            Some(request_id),
        )),
        Err(_) => Err(error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "Database query failed",
            None,
            Some(request_id),
        )),
    }
}

pub(in crate::web::management) async fn ensure_team_visible(
    pool: &PgPool,
    team_id: Uuid,
    session: &ManagementSession,
    request_id: &str,
) -> Result<(), Response> {
    ensure_team_visible_as(
        pool,
        team_id,
        session,
        request_id,
        management_team_not_found,
    )
    .await
}

pub(in crate::web::management) async fn ensure_team_visible_as(
    pool: &PgPool,
    team_id: Uuid,
    session: &ManagementSession,
    request_id: &str,
    hidden_response: fn(&str) -> Response,
) -> Result<(), Response> {
    match load_principal_team_access(pool, team_id, session).await {
        Ok(Some(access)) if access.allows_read() => Ok(()),
        Ok(None) => Err(hidden_response(request_id)),
        Ok(Some(_)) => Err(hidden_response(request_id)),
        Err(_) => Err(error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "Database query failed",
            None,
            Some(request_id),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn service_access(capabilities: Vec<ApiKeyCapability>) -> PrincipalTeamAccess {
        let session = ManagementSession::api_key(
            Uuid::new_v4(),
            1,
            Uuid::new_v4(),
            Uuid::new_v4(),
            capabilities,
        );
        PrincipalTeamAccess::Service {
            allows_read: session.api_key_has_capability(ApiKeyCapability::Read),
            allows_audit_read: session.api_key_has_capability(ApiKeyCapability::AuditRead),
        }
    }

    #[test]
    fn service_principal_read_requires_read_or_team_administration_capability() {
        assert!(service_access(vec![ApiKeyCapability::Read]).allows_read());
        assert!(service_access(vec![ApiKeyCapability::TeamAdministration]).allows_read());
        assert!(!service_access(vec![ApiKeyCapability::AuditRead]).allows_read());
    }

    #[test]
    fn service_principal_audit_read_requires_audit_or_team_administration_capability() {
        assert!(service_access(vec![ApiKeyCapability::AuditRead]).allows_audit_read());
        assert!(service_access(vec![ApiKeyCapability::TeamAdministration]).allows_audit_read());
        assert!(!service_access(vec![ApiKeyCapability::Read]).allows_audit_read());
    }

    #[test]
    fn service_principal_lifecycle_is_never_promoted_from_api_key_capabilities() {
        assert!(!service_access(vec![ApiKeyCapability::TeamAdministration]).allows_lifecycle());
        assert!(!service_access(vec![
            ApiKeyCapability::Read,
            ApiKeyCapability::AuditRead,
            ApiKeyCapability::TeamAdministration,
        ])
        .allows_lifecycle());
    }
}
