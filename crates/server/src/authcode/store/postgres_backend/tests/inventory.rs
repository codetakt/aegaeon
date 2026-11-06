use super::*;
use crate::authcode::store::{
    TokenInventoryKind as Kind, TokenInventoryRecord as Record, TokenInventoryTarget as Target,
};

#[tokio::test]
#[ignore = "requires PostgreSQL; keyset progress through inactive siblings and direct subject-bound targets"]
async fn pg_token_inventory_bounded_progress_and_subject_lookup() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    let result=async {
        let store=f.store();
        let (a,r,m)=grant(true);
        let (access,parent)=store.store_issued_grant_async(a,r,m).await.map_err(anyhow::Error::msg)?;
        let parent=parent.ok_or_else(||anyhow::anyhow!("parent missing"))?;
        let current=store.try_get_refresh_token_async(parent.clone()).await.map_err(anyhow::Error::msg)?.ok_or_else(||anyhow::anyhow!("parent absent"))?;
        let mut children=vec![access];
        for _ in 0..5 {
            let (mut a,_,mut m)=grant(false);
            a.refresh_grant=current.refresh_grant.clone();m.refresh_grant=current.refresh_grant.clone();m.refresh_parent=Some(parent.clone());
            children.push(store.store_access_for_refresh_parent_async(a,m).await.map_err(anyhow::Error::msg)?);
        }
        children.sort_by_key(|token|sha256_digest(token.as_bytes()));
        for child in children.iter().take(2) {
            store.try_revoke_token_for_client_async(child.clone(),Some("client".into())).await.map_err(anyhow::Error::msg)?;
        }
        let (a,r,m)=grant(false);
        let standalone=store.store_issued_grant_async(a,r,m).await.map_err(anyhow::Error::msg)?.0;
        let mut cursor=None;let mut ids=std::collections::HashSet::new();let mut empty_continuations=0;let mut ended=false;
        for _ in 0..20 {
            let page=store.inventory_page("subject",Kind::Grants,cursor,1).await.map_err(anyhow::Error::msg)?;
            anyhow::ensure!(page.records.len()<=1);
            if page.records.is_empty() && page.next.is_some() {empty_continuations+=1;}
            for record in page.records {
                let Record::Grant(meta)=record else {anyhow::bail!("wrong kind");};
                anyhow::ensure!(ids.insert(meta.refresh_parent.unwrap_or(meta.token_id)),"duplicate group across pages");
            }
            cursor=page.next;
            if cursor.is_none(){ended=true;break;}
        }
        anyhow::ensure!(ended && empty_continuations==2 && ids==std::collections::HashSet::from([parent.clone(),standalone.clone()]));
        let fingerprint=aegaeon_crypto::hash::sha256_hex(parent.as_bytes());
        anyhow::ensure!(matches!(store.find_inventory_token("subject",Kind::Grants,&fingerprint).await.map_err(anyhow::Error::msg)?,Some(Target::Refresh(raw)) if raw==parent));
        anyhow::ensure!(store.find_inventory_token("other",Kind::Grants,&fingerprint).await.map_err(anyhow::Error::msg)?.is_none());
        anyhow::ensure!(store.find_inventory_token("subject",Kind::Refresh,&aegaeon_crypto::hash::sha256_hex(standalone.as_bytes())).await.map_err(anyhow::Error::msg)?.is_none());
        anyhow::ensure!(store.find_inventory_token("subject",Kind::Grants,&"FF".repeat(32)).await.map_err(anyhow::Error::msg)?.is_none());
        let page=store.inventory_page("subject",Kind::Refresh,None,200).await.map_err(anyhow::Error::msg)?;
        anyhow::ensure!(page.records.len()==1);
        store.try_revoke_token_for_client_async(parent,Some("client".into())).await.map_err(anyhow::Error::msg)?;
        anyhow::ensure!(store.inventory_page("subject",Kind::Refresh,None,200).await.map_err(anyhow::Error::msg)?.records.is_empty());
        anyhow::ensure!(store.find_inventory_token("subject",Kind::Grants,&fingerprint).await.map_err(anyhow::Error::msg)?.is_none());
        Ok(())
    }.await;
    f.finish().await?;
    result
}

#[tokio::test]
#[ignore = "requires PostgreSQL; serialized-page byte bound and index-shaped candidate limit"]
async fn pg_token_inventory_byte_bound_and_query_plan() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    let result=async {
        let store=f.store();
        for _ in 0..4 {
            let (mut a,r,mut m)=grant(false);
            let scope="a".repeat(900_000);a.scope=Some(scope.clone());m.granted_scopes=vec![scope];
            store.store_issued_grant_async(a,r,m).await.map_err(anyhow::Error::msg)?;
        }
        let mut cursor=None;let mut count=0;let mut ended=false;
        for _ in 0..5 {
            let page=store.inventory_page("subject",Kind::Grants,cursor,200).await.map_err(anyhow::Error::msg)?;
            anyhow::ensure!(page.records.len()<=2,"4 MiB serialized row budget");
            count+=page.records.len();cursor=page.next;
            if cursor.is_none(){ended=true;break;}
        }
        anyhow::ensure!(ended && count==4);
        // Force index eligibility only; this is not a production planner/performance claim.
        let mut conn=f.pool.acquire().await?;
        sqlx::query("SET enable_seqscan=off").execute(&mut *conn).await?;
        let plan:Vec<(String,)>=sqlx::query_as("EXPLAIN SELECT token_digest FROM aegaeon.runtime_token_capabilities WHERE namespace=$1 AND subject_digest=$2 AND kind=1 AND (coalesce(refresh_parent_digest,token_digest),token_digest)>($3,$4) ORDER BY coalesce(refresh_parent_digest,token_digest),token_digest LIMIT 200")
            .bind(f.database.namespace.as_ref()).bind(sha256_digest(b"subject").as_slice()).bind([0u8;32].as_slice()).bind([0u8;32].as_slice()).fetch_all(&mut *conn).await?;
        anyhow::ensure!(plan.iter().any(|(line,)|line.contains("runtime_token_capabilities_inventory_idx")));
        anyhow::ensure!(!plan.iter().any(|(line,)|line.contains("Sort")));
        drop(conn);
        Ok(())
    }.await;
    f.finish().await?;
    result
}
