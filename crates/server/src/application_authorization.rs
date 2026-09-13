//! Optional application authorization adapters. Profile attributes are never authority.

pub mod inorii;
pub mod store;

#[derive(Clone)]
pub struct Authority {
    pub projections: sqlx::PgPool,
    pub memberships: Option<sqlx::PgPool>,
}

impl Authority {
    /// Connection credentials configure infrastructure, while all release permissions
    /// remain in privileged database state. No connection string is logged.
    pub fn from_env(projections: sqlx::PgPool) -> Result<Self, &'static str> {
        let memberships = match std::env::var("AEGAEON_INORII_AUTHORITY_DATABASE_URL") {
            Ok(url) => {
                let options = authority_options(&url)?;
                Some(
                    sqlx::postgres::PgPoolOptions::new()
                        .max_connections(4)
                        .acquire_timeout(std::time::Duration::from_secs(2))
                        .connect_lazy_with(options),
                )
            }
            Err(std::env::VarError::NotPresent) => None,
            Err(_) => return Err("invalid application authority database configuration"),
        };
        Ok(Self {
            projections,
            memberships,
        })
    }

    /// Every organization grant is checked against the OrganizationUser authority.
    /// Projection additions cannot create membership, and deletion requires no sync delay.
    pub async fn memberships_current(&self, grant: &inorii::Grant) -> Result<bool, sqlx::Error> {
        if grant.claims.organization_roles.is_empty() {
            return Ok(true);
        }
        let pool = self.memberships.as_ref().ok_or(sqlx::Error::Configuration(
            "organization authority is not configured".into(),
        ))?;
        let rows: Vec<(String, String)> = tokio::time::timeout(std::time::Duration::from_secs(2),
            sqlx::query_as("SELECT 'organization_' || o.public_id::text, ou.role::text FROM authorization_subject_bindings b JOIN organization_users ou ON ou.user_id=b.user_id JOIN organizations o ON o.id=ou.organization_id WHERE b.issuer=$1 AND b.subject=$2 AND ou.status='active' AND o.deleted_at IS NULL AND ('organization_' || o.public_id::text)=ANY($3)")
                .bind(&grant.issuer).bind(&grant.subject)
                .bind(grant.claims.organization_roles.iter().map(|g| g.organization_id.as_str()).collect::<Vec<_>>()).fetch_all(pool))
            .await.map_err(|_| sqlx::Error::PoolTimedOut)??;
        Ok(grant.claims.organization_roles.iter().all(|expected| {
            expected.roles.iter().all(|role| {
                rows.iter().any(|(org, current)| {
                    org == &expected.organization_id
                        && current
                            == match role {
                                inorii::OrganizationRole::OrganizationAdmin => "ORGANIZATION_ADMIN",
                                inorii::OrganizationRole::OrganizationStaff => "ORGANIZATION_STAFF",
                            }
                })
            })
        }))
    }
}

#[must_use]
pub fn is_restriction(output: Option<&inorii::Grant>, parent: Option<&inorii::Grant>) -> bool {
    match (output, parent) {
        (None, _) => true,
        (Some(output), Some(parent)) => output.is_restriction_of(parent),
        (Some(_), None) => false,
    }
}

fn authority_options(value: &str) -> Result<sqlx::postgres::PgConnectOptions, &'static str> {
    use sqlx::postgres::{PgConnectOptions, PgSslMode};
    let url = url::Url::parse(value).map_err(|_| "invalid authority database URL")?;
    if !matches!(url.scheme(), "postgres" | "postgresql") {
        return Err("invalid authority database URL");
    }
    let options: PgConnectOptions = value
        .parse()
        .map_err(|_| "invalid authority database URL")?;
    // Validate the effective SQLx destination/mode, including query overrides and aliases.
    let host = options.get_host();
    let loopback = options.get_socket().is_some()
        || host == "localhost"
        || host
            .trim_matches(['[', ']'])
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());
    if !loopback && !matches!(options.get_ssl_mode(), PgSslMode::VerifyFull) {
        return Err("remote authority databases require sslmode=verify-full");
    }
    Ok(options)
}

#[cfg(test)]
mod tests {
    use super::authority_options;

    #[test]
    fn authority_connection_checks_effective_destination_and_tls_mode() {
        for url in [
            "postgres://remote.invalid/db?sslmode=verify-full&ssl-mode=disable",
            "postgres://localhost/db?host=remote.invalid&sslmode=disable",
            "postgres://127.0.0.1/db?hostaddr=192.0.2.1&sslmode=prefer",
        ] {
            assert!(authority_options(url).is_err());
        }
        assert!(authority_options("postgres://remote.invalid/db?sslmode=verify-full").is_ok());
        assert!(authority_options("postgres://127.0.0.1/db?sslmode=disable").is_ok());
    }
}
