//! A distinct management credential belongs to the same selected generation.
use super::*;

pub(super) struct ManagementPools {
    pub(super) ordinary: PgPool,
    revocation: PgPool,
}

impl ManagementPools {
    pub(super) async fn checked(
        selection: Selection,
        options: &PgPoolOptions,
        endpoint: PgConnectOptions,
        ordinary: u32,
        reserved: u32,
    ) -> Result<Self> {
        check_endpoint(selection, options, &endpoint).await?;
        Ok(Self {
            ordinary: selection.pool(
                options.clone().min_connections(0).max_connections(ordinary),
                endpoint.clone(),
            ),
            revocation: selection.pool(
                options.clone().min_connections(0).max_connections(reserved),
                endpoint,
            ),
        })
    }

    pub(super) fn for_class(&self, class: CapacityClass) -> &PgPool {
        match class {
            CapacityClass::Revocation => &self.revocation,
            CapacityClass::Ordinary | CapacityClass::Snapshot => &self.ordinary,
        }
    }

    pub(super) fn is_closed(&self) -> bool {
        self.ordinary.is_closed() || self.revocation.is_closed()
    }

    pub(super) async fn close_optional(pools: Option<&Self>) {
        if let Some(pools) = pools {
            tokio::join!(close_pool(&pools.ordinary), close_pool(&pools.revocation));
        }
    }
}

pub(super) async fn check_endpoint(
    selection: Selection,
    options: &PgPoolOptions,
    endpoint: &PgConnectOptions,
) -> Result<()> {
    tokio::time::timeout(options.get_acquire_timeout(), async {
        let mut connection = PgConnection::connect_with(endpoint).await?;
        let selected = selection.bind(&mut connection).await;
        let closed = connection.close().await;
        selected.and(closed)
    })
    .await
    .map_err(|_| Error::Deadline)?
    .map_err(|error| match error {
        sqlx::Error::Protocol(ref reason) if reason == "runtime lifecycle selection refused" => {
            Error::SelectionRefused
        }
        other => Error::Storage(other),
    })
}
