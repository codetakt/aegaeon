use super::super::inventory::{
    TokenInventoryCursor, TokenInventoryKind, TokenInventoryPage, TokenInventoryRecord,
    TokenInventoryTarget,
};
use super::{
    reads::{observation_query, Observed},
    *,
};

// At most 200 candidate index entries and 4 MiB of serialized rows per page.
// The first row always fits (the schema bounds payload + metadata to 2 MiB).
const PAGE_BYTES: i64 = 4 * 1024 * 1024;
impl PostgresTokenStoreBackend {
    pub(in crate::authcode::store) async fn inventory_page(
        &self,
        subject: &str,
        kind: TokenInventoryKind,
        cursor: Option<&TokenInventoryCursor>,
        limit: usize,
    ) -> Result<TokenInventoryPage, String> {
        let mut connection = AdmittedConnection::acquire(&self.database.pool)
            .await
            .map_err(|_| unavailable())?;
        let result=tokio::time::timeout(Duration::from_secs(5),async {
            let after=match cursor {None=>"",Some(c) if c.group_emitted=>"AND coalesce(refresh_parent_digest,token_digest)>$5",Some(_)=>"AND (coalesce(refresh_parent_digest,token_digest),token_digest)>($5,$6)"};
            let query=format!("WITH candidates AS MATERIALIZED (
                SELECT token_digest,coalesce(refresh_parent_digest,token_digest) AS group_key,octet_length(payload)+coalesce(octet_length(metadata),0) AS bytes
                FROM aegaeon.runtime_token_capabilities WHERE namespace=$1 AND subject_digest=$2 AND kind=$3 {after}
                ORDER BY coalesce(refresh_parent_digest,token_digest),token_digest LIMIT $4
            ), budget AS MATERIALIZED (
                SELECT *,sum(bytes) OVER(ORDER BY group_key,token_digest) AS consumed FROM candidates
            ), selected AS MATERIALIZED (
                SELECT c.* FROM budget b JOIN aegaeon.runtime_token_capabilities c ON c.namespace=$1 AND c.token_digest=b.token_digest WHERE b.consumed<={PAGE_BYTES}
            ) {} ORDER BY coalesce(c.refresh_parent_digest,c.token_digest),c.token_digest",observation_query("selected"));
            let mut query=sqlx::query_as::<_,Observed>(&query).bind(self.database.namespace.as_ref()).bind(sha256_digest(subject.as_bytes()).to_vec()).bind(kind.code()).bind(i64::try_from(limit).map_err(|_|unavailable())?);
            if let Some(cursor)=cursor {query=query.bind(cursor.group.as_slice());if !cursor.group_emitted {query=query.bind(cursor.token.as_slice());}}
            let rows=query.fetch_all(connection.as_mut().map_err(|_|unavailable())?).await.map_err(|_|unavailable())?;
            let mut records=Vec::new();
            let mut emitted=None;
            let mut next=None;
            for row in rows {
                let group:[u8;32]=row.row.refresh_parent_digest.as_ref().unwrap_or(&row.row.token_digest).as_slice().try_into().map_err(|_|unavailable())?;
                let token:[u8;32]=row.row.token_digest.as_slice().try_into().map_err(|_|unavailable())?;
                if emitted!=Some(group) {
                    if let Some(record)=record(&row,subject,kind)? {records.push(record);emitted=Some(group);}
                }
                next=Some(TokenInventoryCursor{group,token,group_emitted:emitted==Some(group)});
            }
            Ok(TokenInventoryPage{records,next})
        }).await.map_err(|_|unavailable()).and_then(|r|r);
        connection.release().await;
        result
    }

    pub(in crate::authcode::store) async fn find_inventory_token(
        &self,
        subject: &str,
        kind: TokenInventoryKind,
        digest: &[u8; 32],
    ) -> Result<Option<TokenInventoryTarget>, String> {
        let mut connection = AdmittedConnection::acquire(&self.database.pool)
            .await
            .map_err(|_| unavailable())?;
        let result = tokio::time::timeout(Duration::from_secs(5), async {
            let query = format!(
                "{} WHERE c.namespace=$1 AND c.token_digest=$2 AND c.subject_digest=$3",
                observation_query("aegaeon.runtime_token_capabilities")
            );
            let Some(row) = sqlx::query_as::<_, Observed>(&query)
                .bind(self.database.namespace.as_ref())
                .bind(digest.as_slice())
                .bind(sha256_digest(subject.as_bytes()).to_vec())
                .fetch_optional(connection.as_mut().map_err(|_| unavailable())?)
                .await
                .map_err(|_| unavailable())?
            else {
                return Ok(None);
            };
            if row.row.kind == 2 {
                let raw: RefreshToken =
                    serde_json::from_str(&row.row.payload).map_err(|_| unavailable())?;
                let Some(current) = row.current_refresh(&raw.token)? else {
                    return Ok(None);
                };
                // Grants retain a rotated parent's identity for family revocation.
                if current.user_id != subject
                    || (kind == TokenInventoryKind::Refresh
                        && (current.rotated || row.row.expires_us <= row.now_us))
                {
                    return Ok(None);
                }
                return Ok(Some(TokenInventoryTarget::Refresh(current.token)));
            }
            if kind == TokenInventoryKind::Refresh {
                return Ok(None);
            }
            Ok(
                record(&row, subject, kind)?.and_then(|record| match record {
                    TokenInventoryRecord::Grant(meta) => {
                        Some(TokenInventoryTarget::Access(meta.token_id))
                    }
                    _ => None,
                }),
            )
        })
        .await
        .map_err(|_| unavailable())
        .and_then(|r| r);
        connection.release().await;
        result
    }
}
fn record(
    row: &Observed,
    subject: &str,
    kind: TokenInventoryKind,
) -> Result<Option<TokenInventoryRecord>, String> {
    match kind {
        TokenInventoryKind::Grants => {
            let raw: AccessToken =
                serde_json::from_str(&row.row.payload).map_err(|_| unavailable())?;
            let Some((_, meta)) = row.active_access(&raw.token)? else {
                return Ok(None);
            };
            if meta.user_id != subject {
                return Err(unavailable());
            }
            Ok(Some(TokenInventoryRecord::Grant(Box::new(meta))))
        }
        TokenInventoryKind::Refresh => {
            let raw: RefreshToken =
                serde_json::from_str(&row.row.payload).map_err(|_| unavailable())?;
            let Some(token) = row.current_refresh(&raw.token)? else {
                return Ok(None);
            };
            if token.user_id != subject {
                return Err(unavailable());
            }
            Ok((!token.rotated && row.row.expires_us > row.now_us)
                .then_some(TokenInventoryRecord::Refresh(Box::new(token))))
        }
    }
}
