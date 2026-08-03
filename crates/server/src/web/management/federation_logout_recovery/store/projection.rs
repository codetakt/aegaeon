mod row;

pub(in crate::web::management::federation_logout_recovery) use row::federation_logout_recovery_incident_from_row_result;

pub(super) struct FederationLogoutRecoveryIncidentProjection {
    select_sql: String,
    status_sql: String,
}

impl FederationLogoutRecoveryIncidentProjection {
    pub(super) fn new() -> Self {
        let alias = "fri";
        let status_sql = federation_logout_recovery_status_sql(alias);
        let failure_reason_sql = federation_logout_recovery_failure_reason_sql(alias);
        let resolved_at_sql = federation_logout_recovery_resolved_at_sql(alias);
        let select_sql = format!(
            r#"SELECT
  {alias}.id,
  {alias}.team_id,
  {alias}.tenant_id,
  {alias}.environment_id,
  {alias}.connection_id,
  c.connection_identifier,
  c.name AS connection_name,
  {alias}.downstream_client_id,
  {alias}.upstream_issuer,
  {alias}.recovery_policy,
  {status_sql} AS status,
  {alias}.session_hint_claim,
  {alias}.session_hint_value_hash IS NOT NULL AS session_hint_present,
  {alias}.downstream_redirect_uri,
  {alias}.downstream_state IS NOT NULL AS downstream_state_present,
  {failure_reason_sql} AS failure_reason,
  {alias}.request_id,
  to_char({alias}.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS created_at_cursor,
  {alias}.id::text AS id_cursor,
  to_char({alias}.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at,
  to_char({alias}.expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS expires_at,
  {resolved_at_sql} AS resolved_at"#
        );
        Self {
            select_sql,
            status_sql,
        }
    }

    pub(super) fn select_sql(&self) -> &str {
        &self.select_sql
    }

    pub(super) fn status_sql(&self) -> &str {
        &self.status_sql
    }
}

fn federation_logout_recovery_status_sql(alias: &str) -> String {
    format!(
        "CASE WHEN {alias}.status = 'pending' AND {alias}.expires_at <= now() THEN 'expired' ELSE {alias}.status END"
    )
}

fn federation_logout_recovery_resolved_at_sql(alias: &str) -> String {
    format!(
        "CASE \
            WHEN {alias}.resolved_at IS NOT NULL THEN to_char({alias}.resolved_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"') \
            WHEN {alias}.status = 'pending' AND {alias}.expires_at <= now() THEN to_char({alias}.expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"') \
            ELSE NULL \
         END"
    )
}

fn federation_logout_recovery_failure_reason_sql(alias: &str) -> String {
    format!(
        "CASE \
            WHEN {alias}.failure_reason IS NOT NULL THEN {alias}.failure_reason \
            WHEN {alias}.status = 'pending' AND {alias}.expires_at <= now() THEN 'relay timeout' \
            ELSE NULL \
         END"
    )
}

pub(super) fn federation_logout_recovery_incident_select_sql(lock_for_update: bool) -> String {
    let projection = FederationLogoutRecoveryIncidentProjection::new();
    let lock_clause = if lock_for_update {
        "\nFOR UPDATE OF fri"
    } else {
        ""
    };
    format!(
        r"
{select_sql}
FROM aegaeon.federation_logout_recovery_incidents fri
LEFT JOIN aegaeon.connections c
  ON c.id = fri.connection_id
WHERE fri.team_id = $1
  AND fri.environment_id = $2
  AND fri.id = $3
LIMIT 1{lock_clause}
        ",
        select_sql = projection.select_sql()
    )
}
