use super::super::super::audit_query::AuditEventListQuery;
use super::super::scope::{AuditScope, AuditWindow};
use sqlx::{postgres::PgArguments, Postgres};

type PgQuery<'q> = sqlx::query::Query<'q, Postgres, PgArguments>;

pub(super) fn build_audit_cursor_sql(cursor_present: bool, last_idx: usize) -> (String, usize) {
    if cursor_present {
        let ts_idx = last_idx + 1;
        let id_idx = last_idx + 2;
        (
            format!(" AND (occurred_at, id) < (${ts_idx}::timestamptz, ${id_idx})"),
            last_idx + 2,
        )
    } else {
        (String::new(), last_idx)
    }
}

pub(super) fn bind_audit_scope(mut query: PgQuery<'_>, scope: AuditScope) -> PgQuery<'_> {
    query = query.bind(scope.team_id());
    if let Some(environment_id) = scope.environment_id() {
        query = query.bind(environment_id);
    }

    query
}

pub(super) fn bind_audit_filters<'q>(
    mut query_builder: PgQuery<'q>,
    query: &'q AuditEventListQuery,
    window: &'q AuditWindow,
) -> PgQuery<'q> {
    if let Some(ref value) = query.event_type {
        query_builder = query_builder.bind(value.as_str());
    }
    if let Some(ref value) = query.category {
        query_builder = query_builder.bind(value.as_str());
    }
    if let Some(ref value) = query.target_type {
        query_builder = query_builder.bind(value.as_str());
    }
    if let Some(ref value) = query.outcome {
        query_builder = query_builder.bind(value.as_str());
    }
    if let Some(ref value) = query.severity {
        query_builder = query_builder.bind(value.as_str());
    }

    query_builder
        .bind(window.from.as_str())
        .bind(window.to.as_str())
}
