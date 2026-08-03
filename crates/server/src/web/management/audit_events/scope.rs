mod access;
mod window;

use super::super::ManagementEnvironmentScope;
use uuid::Uuid;

pub(super) use access::{require_environment_audit_scope, require_team_audit_scope};
pub(super) use window::{require_audit_window, AuditWindow};

#[derive(Clone, Copy)]
pub(super) struct AuditScope {
    team_id: Uuid,
    environment_id: Option<Uuid>,
}

impl AuditScope {
    fn team(team_id: Uuid) -> Self {
        Self {
            team_id,
            environment_id: None,
        }
    }

    fn environment(scope: ManagementEnvironmentScope) -> Self {
        Self {
            team_id: scope.team,
            environment_id: Some(scope.environment),
        }
    }

    pub(super) fn team_id(self) -> Uuid {
        self.team_id
    }

    pub(super) fn environment_id(self) -> Option<Uuid> {
        self.environment_id
    }

    pub(super) fn where_clause(self) -> &'static str {
        if self.environment_id.is_some() {
            "team_id = $1 AND environment_id = $2"
        } else {
            "team_id = $1"
        }
    }

    pub(super) fn base_bind_idx(self) -> usize {
        if self.environment_id.is_some() {
            2
        } else {
            1
        }
    }
}
