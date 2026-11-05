use super::super::ClientBoundRevocationOutcome as Outcome;
use super::records::Capability;
use super::*;

pub(in crate::authcode::store) enum Owner<'a> {
    Client(Option<&'a str>),
    Subject { value: &'a str, kind: i16 },
}

impl Owner<'_> {
    fn matches(&self, row: &Capability, token: &str) -> Result<bool, String> {
        let (client, subject) = match row.kind {
            1 => {
                let (a, _) = row.access(token)?;
                (a.client_id, a.user_id)
            }
            2 => {
                let r = row.refresh(token)?;
                (r.client_id, r.user_id)
            }
            _ => return Err(unavailable()),
        };
        Ok(match self {
            Self::Client(requester) => *requester == Some(client.as_str()),
            Self::Subject { value, kind } => *value == subject && *kind == row.kind,
        })
    }
}

impl PostgresTokenStoreBackend {
    pub(in crate::authcode::store) async fn revoke(
        &self,
        requested: &str,
        owner: Owner<'_>,
    ) -> Result<Outcome, String> {
        let mut connection = AdmittedConnection::acquire(&self.database.pool)
            .await
            .map_err(|_| unavailable())?;
        let result=tokio::time::timeout(Duration::from_secs(5),async {
            crate::organizations::request_work::async_store::admit_current_commit().map_err(|_|unavailable())?;
            let mut tx=connection.as_mut().map_err(|_|unavailable())?.begin().await.map_err(|_|unavailable())?;
            let Some(first)=self.load_on(&mut tx,requested,false).await? else {tx.rollback().await.map_err(|_|unavailable())?;return Ok(Outcome::Unknown);};
            if !owner.matches(&first.row,requested)? {tx.rollback().await.map_err(|_|unavailable())?;return Ok(Outcome::OwnerMismatch);}
            let Some(current)=self.lock_capability(&mut tx,requested).await? else {tx.rollback().await.map_err(|_|unavailable())?;return Ok(Outcome::Revoked);};
            if !owner.matches(&current.row,requested)? {return Err(unavailable());}
            if current.row.kind==2 {
                self.revoke_family(&mut tx,current.row.family_id.as_deref().ok_or_else(unavailable)?).await?;
                if let Some(root)=&current.row.root_id {
                    sqlx::query("UPDATE aegaeon.runtime_exchange_roots SET revoked=true WHERE namespace=$1 AND id=$2").bind(self.database.namespace.as_ref()).bind(root).execute(&mut *tx).await.map_err(|_|unavailable())?;
                }
            }
            sqlx::query("UPDATE aegaeon.runtime_token_capabilities SET revoked=true WHERE namespace=$1 AND token_digest=$2").bind(self.database.namespace.as_ref()).bind(&current.row.token_digest).execute(&mut *tx).await.map_err(|_|unavailable())?;
            tx.commit().await.map_err(|_|unavailable())?;Ok(Outcome::Revoked)
        }).await.map_err(|_|unavailable()).and_then(|r|r);
        connection.release().await;
        result
    }
}
