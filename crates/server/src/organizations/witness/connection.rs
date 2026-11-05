use super::{Error, Result};
use sqlx::postgres::{PgConnectOptions, PgSslMode};
use std::{path::Path, str::FromStr};

pub(in crate::organizations) fn options(endpoint: &str, ca: &Path) -> Result<PgConnectOptions> {
    if endpoint.len() > 16_384 {
        return Err(Error::Refused);
    }
    let mut url = url::Url::parse(endpoint).map_err(|_| Error::Refused)?;
    if !matches!(url.scheme(), "postgres" | "postgresql")
        || url.host_str().is_none_or(str::is_empty)
        || url.username().is_empty()
        || url.path().trim_start_matches('/').is_empty()
        || url.fragment().is_some()
    {
        return Err(Error::Refused);
    }
    // Do not let query aliases select another host/role/database, Unix socket,
    // password source, startup role or timeout. sslmode is accepted only to be
    // overridden by this contract's unconditional hostname/CA verification.
    let mut sslmode = false;
    for (key, value) in url.query_pairs() {
        if key != "sslmode" || sslmode || value.is_empty() {
            return Err(Error::Refused);
        }
        sslmode = true;
    }
    if url.password().is_none() {
        url.query_pairs_mut().append_pair("password", "");
    }
    let options = PgConnectOptions::from_str(url.as_str())?
        .ssl_mode(PgSslMode::VerifyFull)
        .ssl_root_cert(ca)
        .application_name("aegaeon-organization-witness")
        .options([
            ("statement_timeout", "5000"),
            ("synchronous_commit", "on"),
            ("default_transaction_read_only", "off"),
            ("lock_timeout", "1000"),
            ("idle_in_transaction_session_timeout", "5000"),
            ("transaction_timeout", "10000"),
        ]);
    if options.get_socket().is_some() || options.get_host().starts_with('/') {
        return Err(Error::Refused);
    }
    Ok(options)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn witness_destination_is_explicit_and_tls_cannot_be_downgraded() {
        let ca = Path::new("/explicit/ca.pem");
        let value = options("postgres://runtime@db.example/control?sslmode=disable", ca).unwrap();
        assert_eq!(value.get_host(), "db.example");
        assert!(matches!(value.get_ssl_mode(), PgSslMode::VerifyFull));
        assert_eq!(value.get_database(), Some("control"));
        for endpoint in [
            "postgres:///control",
            "postgres://db.example/control",
            "postgres://runtime@db.example/",
            "postgres://runtime@db.example/control#hidden",
            "postgres://runtime@db.example/control?host=/tmp/socket",
            "postgres://runtime@db.example/control?hostaddr=127.0.0.1",
            "postgres://runtime@db.example/control?user=owner",
            "postgres://runtime@db.example/control?dbname=other",
            "postgres://runtime@db.example/control?password=ambient",
            "postgres://runtime@db.example/control?options=-crole=owner",
            "postgres://runtime@db.example/control?sslmode=disable&sslmode=require",
            "postgres://runtime@db.example/control?sslrootcert=/other/ca.pem",
        ] {
            assert!(options(endpoint, ca).is_err());
        }
    }
}
