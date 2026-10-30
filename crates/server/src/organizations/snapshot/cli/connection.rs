//! Pin every connection destination before passing it to the SQLx URL parser.
use super::Result;
use std::collections::HashSet;
use url::Url;

pub(super) fn explicit_url(value: &str) -> Result<String> {
    if value.len() > 16384 {
        return Err("database URL byte limit".into());
    }
    let mut url = Url::parse(value).map_err(|_| "database URL syntax".to_string())?;
    if !matches!(url.scheme(), "postgres" | "postgresql")
        || url.host_str().is_none_or(|s| s.is_empty())
        || url.username().is_empty()
        || url.path().trim_start_matches('/').is_empty()
        || url.fragment().is_some()
    {
        return Err("database URL requires explicit host, role and database; no fragment".into());
    }
    let mut names = HashSet::new();
    for (key, value) in url.query_pairs() {
        if !names.insert(key.to_string()) || value.is_empty() {
            return Err("duplicate or empty database URL option".into());
        }
        match key.as_ref() {
            "host" if value.starts_with('/') && url.host_str() == Some("localhost") => (),
            "sslmode" | "sslrootcert" | "sslcert" | "sslkey" => (),
            _ => return Err("unsupported database URL option".into()),
        }
    }
    // An explicit empty password prevents SQLx from consulting an implicit
    // ~/.pgpass. Private Unix-socket authentication can still be passwordless.
    if url.password().is_none() {
        // Url canonicalization drops empty passwords; use a query parameter,
        // which was deliberately excluded from caller-supplied options above.
        url.query_pairs_mut().append_pair("password", "");
    }
    Ok(url.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_destination_and_no_implicit_password_source() {
        let local = explicit_url("postgresql://inspector@localhost/staging?host=/private/socket")
            .expect("explicit private socket");
        assert!(local.ends_with("password="));
        assert_eq!(
            explicit_url("postgres://inspector:secret@db.example:5433/staging?sslmode=disable")
                .expect("TLS policy is enforced on parsed options"),
            "postgres://inspector:secret@db.example:5433/staging?sslmode=disable"
        );
        for url in [
            "postgres:///staging",
            "postgres://localhost/staging",
            "postgres://inspector@localhost/",
            "postgres://inspector@localhost/staging#hidden",
            "postgres://inspector@localhost/staging?hostaddr=127.0.0.1",
            "postgres://inspector@db.example/staging?host=/private/socket",
            "postgres://inspector@localhost/staging?host=db.example",
            "postgres://inspector@localhost/staging?sslmode=disable&sslmode=require",
            "postgres://inspector@localhost/staging?options=-csearch_path=public",
            "postgres://inspector@localhost/staging?password=hidden",
            "postgres://inspector@localhost/staging?port=5433",
        ] {
            assert!(explicit_url(url).is_err(), "must refuse {url}");
        }
    }
}
