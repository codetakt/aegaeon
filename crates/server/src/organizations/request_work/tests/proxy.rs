//! Connect the fault injector to the runner's actual Unix or TCP supplier.
use sqlx::{postgres::PgConnectOptions, ConnectOptions};
use std::{io, net::SocketAddr, time::Duration};
use tokio::io::{AsyncRead, AsyncWrite};

pub(super) trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}

pub(super) async fn upstream(options: &PgConnectOptions) -> io::Result<Box<dyn Stream>> {
    let directory = options.get_socket().cloned().or_else(|| {
        options
            .get_host()
            .starts_with('/')
            .then(|| options.get_host().into())
    });
    tokio::time::timeout(Duration::from_secs(3), async {
        if let Some(directory) = directory {
            let path = directory.join(format!(".s.PGSQL.{}", options.get_port()));
            Ok::<Box<dyn Stream>, io::Error>(Box::new(tokio::net::UnixStream::connect(path).await?))
        } else {
            Ok::<Box<dyn Stream>, io::Error>(Box::new(
                tokio::net::TcpStream::connect((options.get_host(), options.get_port())).await?,
            ))
        }
    })
    .await?
}

pub(super) fn client_options(
    direct: &PgConnectOptions,
    address: SocketAddr,
) -> Result<PgConnectOptions, sqlx::Error> {
    // Reparse to clear an explicit socket while preserving the runner's
    // authentication. This URL contains credentials and must never be logged.
    let mut url = direct.to_url_lossy();
    url.set_host(Some("127.0.0.1"))
        .map_err(sqlx::Error::config)?;
    url.set_port(Some(address.port()))
        .map_err(|()| sqlx::Error::Protocol("fixture proxy port".into()))?;
    let options: PgConnectOptions = url.as_str().parse()?;
    Ok(options.ssl_mode(sqlx::postgres::PgSslMode::Disable))
}
