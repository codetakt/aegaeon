//! Explicit verified transport with immutable, bounded CA bytes.
use rustix::fs::{self, Mode, OFlags};
use std::{io::Read, path::Path};

pub(in crate::organizations) fn certificate(path: &Path) -> anyhow::Result<Vec<u8>> {
    // Check the opened descriptor without first waiting for a FIFO writer.
    // Regular-file symlinks remain supported; no second path lookup is used.
    let file = std::fs::File::from(fs::open(
        path,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC | OFlags::NOCTTY,
        Mode::empty(),
    )?);
    anyhow::ensure!(file.metadata()?.is_file());
    let mut bytes = Vec::new();
    file.take(1_048_577).read_to_end(&mut bytes)?;
    anyhow::ensure!(!bytes.is_empty() && bytes.len() <= 1_048_576);
    Ok(bytes)
}

#[cfg(test)]
mod tests;

pub(in crate::organizations) fn postgres_options(
    endpoint: &str,
    path: &Path,
    ca: Vec<u8>,
) -> anyhow::Result<sqlx::postgres::PgConnectOptions> {
    anyhow::ensure!(!ca.is_empty() && ca.len() <= 1_048_576);
    Ok(
        crate::organizations::witness::connection::options(endpoint, path)?
            .ssl_root_cert_from_pem(ca),
    )
}

#[cfg(test)]
pub(in crate::organizations) fn redis_url(endpoint: &str) -> anyhow::Result<url::Url> {
    anyhow::ensure!(endpoint.len() <= 16_384);
    let url = url::Url::parse(endpoint)?;
    anyhow::ensure!(
        url.scheme() == "rediss"
            && url.host_str().is_some_and(|host| !host.is_empty())
            && !url.username().is_empty()
            && url.password().is_some_and(|password| !password.is_empty())
            && url.query().is_none()
            && url.fragment().is_none()
    );
    let database = url
        .path()
        .strip_prefix('/')
        .ok_or_else(|| anyhow::anyhow!("database absent"))?;
    anyhow::ensure!(!database.is_empty() && database.bytes().all(|b| b.is_ascii_digit()));
    let _: u32 = database.parse()?;
    Ok(url)
}

#[cfg(test)]
pub(in crate::organizations) fn redis_client(
    endpoint: &str,
    ca: Vec<u8>,
) -> anyhow::Result<::redis::Client> {
    anyhow::ensure!(!ca.is_empty() && ca.len() <= 1_048_576);
    Ok(::redis::Client::build_with_tls(
        redis_url(endpoint)?,
        ::redis::TlsCertificates {
            client_tls: None,
            root_cert: Some(ca),
        },
    )?)
}
