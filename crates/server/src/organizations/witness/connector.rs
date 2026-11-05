//! Verified metadata connection construction; never supplier qualification.
use super::{Control, Error, Result, Role};
use crate::organizations::store_observation::{self, transport, Redis};
use sqlx::{postgres::PgConnectOptions, Connection, PgConnection};
use std::{path::Path, time::Duration};

const STEP: Duration = Duration::from_secs(5);

pub(crate) mod primary;

/// Explicit private endpoint and its trust roots. Do not log this value.
#[derive(Clone, Copy)]
pub struct Endpoint<'a> {
    pub url: &'a str,
    pub root_cert: &'a Path,
}

/// Independently expected namespace; a configuration value is not a permit.
#[derive(Clone, Copy)]
pub struct Primary<'a> {
    pub endpoint: Endpoint<'a>,
    pub environment_id: uuid::Uuid,
    pub issuer: &'a str,
}

/// Immutable metadata connection configuration. It confers no serving authority.
/// The caller must retain qualified supplier premises and an owned Work boundary.
pub struct Connector {
    control: PgConnectOptions,
    primary: PgConnectOptions,
    token: redis::Client,
    environment_id: uuid::Uuid,
    issuer: String,
}

impl Connector {
    pub fn new(control: Endpoint<'_>, primary: Primary<'_>, token: Endpoint<'_>) -> Result<Self> {
        no_ambient_postgres()?;
        if primary.environment_id.is_nil()
            || primary.issuer.is_empty()
            || primary.issuer.len() > 16_384
        {
            return Err(Error::Refused);
        }
        let postgres = |endpoint: Endpoint<'_>| {
            let ca = transport::certificate(endpoint.root_cert).map_err(|_| Error::Refused)?;
            transport::postgres_options(endpoint.url, endpoint.root_cert, ca)
                .map_err(|_| Error::Refused)
        };
        let ca = transport::certificate(token.root_cert).map_err(|_| Error::Refused)?;
        Ok(Self {
            control: postgres(control)?,
            primary: postgres(primary.endpoint)?,
            environment_id: primary.environment_id,
            issuer: primary.issuer.to_owned(),
            token: transport::redis_client(token.url, ca).map_err(|_| Error::Refused)?,
        })
    }

    /// Bounded diagnostic inspection only; this grants no serving authority.
    /// No link is replaced or retried on failure.
    pub async fn connect(&self) -> Result<super::work::ObservedConnections> {
        no_ambient_postgres()?;
        tokio::time::timeout(Duration::from_secs(20), self.connect_once())
            .await
            .map_err(|_| Error::Deadline)?
    }

    async fn connect_once(&self) -> Result<super::work::ObservedConnections> {
        let connection = pg_connect(&self.control).await?;
        let mut control = Control::checked(connection, Role::Runtime).await?;
        let primary = primary::checked(
            pg_connect(&self.primary).await?,
            self.environment_id,
            &self.issuer,
        )
        .await?;
        let witness =
            store_observation::primary(control.connection.as_mut().ok_or(Error::Refused)?)
                .await
                .map_err(|_| Error::Refused)?;
        if !primary.observation().different_cluster(&witness) {
            return Err(Error::Refused);
        }
        let config = redis::AsyncConnectionConfig::new()
            .set_connection_timeout(STEP)
            .set_response_timeout(STEP);
        let connection = tokio::time::timeout(
            STEP,
            self.token
                .get_multiplexed_async_connection_with_config(&config),
        )
        .await
        .map_err(|_| Error::Deadline)?
        .map_err(|_| Error::Refused)?;
        let token = Redis::observe(connection)
            .await
            .map_err(|_| Error::Refused)?;
        Ok(super::work::ObservedConnections::new(
            control, primary, token,
        ))
    }
}

pub(super) async fn pg_connect(options: &PgConnectOptions) -> Result<PgConnection> {
    tokio::time::timeout(STEP, PgConnection::connect_with(options))
        .await
        .map_err(|_| Error::Deadline)?
        .map_err(Error::Storage)
}

pub(in crate::organizations) fn no_ambient_postgres() -> Result<()> {
    if std::env::vars_os().any(|(key, _)| key.to_string_lossy().starts_with("PG")) {
        return Err(Error::Refused);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn primary(endpoint: Endpoint<'_>) -> Primary<'_> {
        Primary {
            endpoint,
            environment_id: uuid::Uuid::new_v4(),
            issuer: "https://issuer.example",
        }
    }

    struct Certificate(std::path::PathBuf);
    impl Certificate {
        fn new() -> Self {
            let path = std::env::temp_dir()
                .join(format!("aegaeon-connector-{}.pem", uuid::Uuid::new_v4()));
            let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
            std::fs::write(&path, cert.serialize_pem().unwrap()).unwrap();
            Self(path)
        }
    }
    impl Drop for Certificate {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    #[test]
    fn organization_connector_requires_explicit_verified_destinations() {
        let _environment = crate::util::SERVER_TEST_ENV_GUARD.lock().unwrap();
        let ca = Certificate::new();
        let endpoint = |url| Endpoint {
            url,
            root_cert: &ca.0,
        };
        let valid = Connector::new(
            endpoint("postgresql://runtime:fixture@control.example/control?sslmode=disable"),
            primary(endpoint(
                "postgresql://runtime:fixture@primary.example/primary",
            )),
            endpoint("rediss://runtime:fixture@token.example/0"),
        )
        .unwrap();
        assert!(matches!(
            valid.control.get_ssl_mode(),
            sqlx::postgres::PgSslMode::VerifyFull
        ));
        assert!(matches!(
            valid.primary.get_ssl_mode(),
            sqlx::postgres::PgSslMode::VerifyFull
        ));
        assert!(matches!(
            valid.token.get_connection_info().addr,
            redis::ConnectionAddr::TcpTls {
                insecure: false,
                ..
            }
        ));
        for url in [
            "postgresql:///control",
            "postgresql://runtime@control.example/control?hostaddr=127.0.0.1",
            "postgresql://runtime@control.example/control?options=-crole=owner",
        ] {
            assert!(Connector::new(
                endpoint(url),
                primary(endpoint("postgresql://runtime@primary.example/primary")),
                endpoint("rediss://runtime:fixture@token.example/0")
            )
            .is_err());
        }
        for url in [
            "redis://runtime:fixture@token.example/0",
            "rediss://token.example/0",
            "rediss://runtime:fixture@token.example/0#insecure",
        ] {
            assert!(Connector::new(
                endpoint("postgresql://runtime@control.example/control"),
                primary(endpoint("postgresql://runtime@primary.example/primary")),
                endpoint(url)
            )
            .is_err());
        }
    }

    #[test]
    fn organization_connector_rejects_missing_empty_and_oversized_ca() {
        let _environment = crate::util::SERVER_TEST_ENV_GUARD.lock().unwrap();
        let ca = Certificate::new();
        let endpoint = || Endpoint {
            url: "postgresql://runtime@control.example/control",
            root_cert: &ca.0,
        };
        let token = || Endpoint {
            url: "rediss://runtime:fixture@token.example/0",
            root_cert: &ca.0,
        };
        std::fs::write(&ca.0, []).unwrap();
        assert!(Connector::new(endpoint(), primary(endpoint()), token()).is_err());
        std::fs::write(&ca.0, vec![b'x'; 1_048_577]).unwrap();
        assert!(Connector::new(endpoint(), primary(endpoint()), token()).is_err());
        std::fs::remove_file(&ca.0).unwrap();
        assert!(Connector::new(endpoint(), primary(endpoint()), token()).is_err());
    }
}
