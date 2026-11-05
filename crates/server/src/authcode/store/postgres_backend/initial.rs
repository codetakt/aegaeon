use super::super::grant_commit::{
    AuthorizationCodeGrantCommit, AUTHORIZATION_CODE_GRANT_CODE_MISSING,
};
use super::records::InitialGrant;
use super::*;

impl PostgresTokenStoreBackend {
    pub(in crate::authcode::store) async fn issue(
        &self,
        access: AccessToken,
        refresh: Option<RefreshToken>,
        meta: BearerTokenMeta,
    ) -> Result<(String, Option<String>), String> {
        let grant = InitialGrant::new(access, refresh, meta)?;
        let mut connection = AdmittedConnection::acquire(&self.database.pool)
            .await
            .map_err(|_| unavailable())?;
        let result = tokio::time::timeout(Duration::from_secs(5), async {
            crate::organizations::request_work::async_store::admit_current_commit()
                .map_err(|_| unavailable())?;
            let mut tx = connection
                .as_mut()
                .map_err(|_| unavailable())?
                .begin()
                .await
                .map_err(|_| unavailable())?;
            self.publish_initial(&mut tx, &grant).await?;
            self.check_initial_deadline(&mut tx, &grant).await?;
            tx.commit().await.map_err(|_| unavailable())?;
            Ok(grant.result())
        })
        .await
        .map_err(|_| unavailable())
        .and_then(|r| r);
        connection.release().await;
        result
    }

    pub(in crate::authcode::store) async fn redeem(
        &self,
        commit: AuthorizationCodeGrantCommit,
    ) -> Result<(String, Option<String>), String> {
        let Some(code_backend) = commit.code_store.backend.postgres() else {
            return Err(unavailable());
        };
        if !self.database.same_database(&code_backend.database) {
            return Err(unavailable());
        }
        if let Some(oidc) = &commit.oidc_session {
            let oidc = oidc.postgres_commit().ok_or_else(unavailable)?;
            if !self.database.same_database(&oidc.database)
                || oidc.user_id != commit.access_token.user_id
                || oidc.client_id != commit.access_token.client_id
            {
                return Err(unavailable());
            }
        }
        let grant = InitialGrant::new(commit.access_token, commit.refresh_token, commit.meta)?;
        let mut connection = AdmittedConnection::acquire(&self.database.pool)
            .await
            .map_err(|_| unavailable())?;
        let result=tokio::time::timeout(Duration::from_secs(5),async {
            crate::organizations::request_work::async_store::admit_current_commit().map_err(|_|unavailable())?;
            let mut tx=connection.as_mut().map_err(|_|unavailable())?.begin().await.map_err(|_|unavailable())?;
            let digest=sha256_digest(commit.code.as_bytes());
            let row=sqlx::query_as::<_,(String,Vec<u8>,i64)>("SELECT payload,client_digest,(extract(epoch from expires_at)*1000000)::bigint FROM aegaeon.runtime_authorization_codes WHERE namespace=$1 AND token_digest=$2 FOR UPDATE")
                .bind(self.database.namespace.as_ref()).bind(digest.as_slice()).fetch_optional(&mut *tx).await.map_err(|_|unavailable())?.ok_or_else(||AUTHORIZATION_CODE_GRANT_CODE_MISSING.to_owned())?;
            if !crate::util::constant_time_eq(row.0.as_bytes(),commit.expected_authorization_code_payload.as_bytes()) {return Err(AUTHORIZATION_CODE_GRANT_CODE_MISSING.into());}
            let stored=crate::authcode::code_store::StoredAuthorizationCode::decode(&commit.code,row.0).map_err(|_|unavailable())?.ok_or_else(||AUTHORIZATION_CODE_GRANT_CODE_MISSING.to_owned())?;
            if stored.code().client_id!=grant.access.client_id||stored.code().user_id!=grant.access.user_id||micros(stored.code().expires_at)?!=row.2||row.1!=sha256_digest(grant.access.client_id.as_bytes()) {return Err(unavailable());}
            if let Some(oidc)=&commit.oidc_session {
                let oidc=oidc.postgres_commit().ok_or_else(unavailable)?;
                if stored.code().auth_session_id.as_ref().is_none_or(|sid|sha256_digest(sid.as_bytes())!=oidc.auth_digest) {return Err(unavailable());}
            }
            self.publish_initial(&mut tx,&grant).await?;
            if let Some(oidc)=&commit.oidc_session {oidc.postgres_commit().ok_or_else(unavailable)?.bind_on(&mut tx,true).await?;}
            let now=self.check_initial_deadline(&mut tx,&grant).await?;
            if now>=row.2 {return Err(AUTHORIZATION_CODE_GRANT_CODE_MISSING.into());}
            sqlx::query("DELETE FROM aegaeon.runtime_authorization_codes WHERE namespace=$1 AND token_digest=$2").bind(self.database.namespace.as_ref()).bind(digest.as_slice()).execute(&mut *tx).await.map_err(|_|unavailable())?;
            tx.commit().await.map_err(|_|unavailable())?;Ok(grant.result())
        }).await.map_err(|_|unavailable()).and_then(|r|r);
        connection.release().await;
        result
    }

    pub(super) async fn publish_initial(
        &self,
        tx: &mut PgConnection,
        grant: &InitialGrant,
    ) -> Result<(), String> {
        let ns = self.database.namespace.as_ref();
        let client = sha256_digest(grant.access.client_id.as_bytes());
        let subject = sha256_digest(grant.access.user_id.as_bytes());
        let family = grant.family.as_ref().map(|f| f.reference.id.as_str());
        let generation = self
            .lock_subject(tx, &subject, true)
            .await?
            .ok_or_else(unavailable)?;
        // New roots precede family and capability locks. Foreign keys defer only this new-root insertion.
        if let Some(root) = &grant.access.exchange_root {
            sqlx::query("INSERT INTO aegaeon.runtime_exchange_roots(namespace,id,client_digest,subject_digest,family_id,expires_us,subject_generation) VALUES($1,$2,$3,$4,$5,$6,$7)")
                .bind(ns).bind(&root.id).bind(client.as_slice()).bind(subject.as_slice()).bind(family).bind(micros(root.expires_at)?).bind(generation).execute(&mut *tx).await.map_err(|_|unavailable())?;
        }
        if let Some(f) = &grant.family {
            sqlx::query("INSERT INTO aegaeon.runtime_refresh_families(namespace,id,version,client_digest,subject_digest,expires_us,subject_generation) VALUES($1,$2,1,$3,$4,$5,$6)")
                .bind(ns).bind(&f.reference.id).bind(client.as_slice()).bind(subject.as_slice()).bind(micros(f.retain_until)?).bind(generation).execute(&mut *tx).await.map_err(|_|unavailable())?;
        }
        if let Some(refresh) = &grant.refresh {
            self.insert_refresh(tx, refresh, generation).await?;
        }
        self.insert_access(tx, &grant.access, &grant.meta, generation)
            .await
    }

    pub(super) async fn check_initial_deadline(
        &self,
        tx: &mut PgConnection,
        grant: &InitialGrant,
    ) -> Result<i64, String> {
        let (now, _) = clock(tx).await?;
        if now >= micros(grant.meta.expires_at)?
            || now
                >= micros(
                    grant
                        .access
                        .created_at
                        .checked_add(Duration::from_secs(grant.access.expires_in))
                        .ok_or_else(unavailable)?,
                )?
            || grant
                .refresh
                .as_ref()
                .map(|r| micros(r.expires_at))
                .transpose()?
                .is_some_and(|expiry| now >= expiry)
            || grant
                .access
                .exchange_root
                .as_ref()
                .map(|r| micros(r.expires_at))
                .transpose()?
                .is_some_and(|expiry| now >= expiry)
        {
            return Err("issued grant is expired".into());
        }
        Ok(now)
    }

    pub(super) async fn insert_access(
        &self,
        tx: &mut PgConnection,
        access: &AccessToken,
        meta: &BearerTokenMeta,
        generation: uuid::Uuid,
    ) -> Result<(), String> {
        token_consistency::bearer_metadata_matches_access_token(access, meta)
            .map_err(str::to_string)?;
        let expiry = access
            .created_at
            .checked_add(Duration::from_secs(access.expires_in))
            .ok_or_else(unavailable)?
            .min(meta.expires_at);
        sqlx::query("INSERT INTO aegaeon.runtime_token_capabilities(namespace,token_digest,kind,payload,metadata,client_digest,subject_digest,family_id,root_id,refresh_parent_digest,expires_us,subject_generation) VALUES($1,$2,1,$3,$4,$5,$6,$7,$8,$9,$10,$11)")
            .bind(self.database.namespace.as_ref()).bind(sha256_digest(access.token.as_bytes()).as_slice()).bind(encode(access)?).bind(encode(meta)?)
            .bind(sha256_digest(access.client_id.as_bytes()).as_slice()).bind(sha256_digest(access.user_id.as_bytes()).as_slice())
            .bind(access.refresh_grant.as_ref().map(|r|r.id.as_str())).bind(access.exchange_root.as_ref().map(|r|r.id.as_str()))
            .bind(meta.refresh_parent.as_ref().map(|v|sha256_digest(v.as_bytes()).to_vec())).bind(micros(expiry)?).bind(generation).execute(tx).await.map_err(|_|unavailable())?;
        Ok(())
    }

    pub(super) async fn insert_refresh(
        &self,
        tx: &mut PgConnection,
        refresh: &RefreshToken,
        generation: uuid::Uuid,
    ) -> Result<(), String> {
        sqlx::query("INSERT INTO aegaeon.runtime_token_capabilities(namespace,token_digest,kind,payload,client_digest,subject_digest,family_id,root_id,rotated,expires_us,subject_generation) VALUES($1,$2,2,$3,$4,$5,$6,$7,$8,$9,$10)")
            .bind(self.database.namespace.as_ref()).bind(sha256_digest(refresh.token.as_bytes()).as_slice()).bind(encode(refresh)?)
            .bind(sha256_digest(refresh.client_id.as_bytes()).as_slice()).bind(sha256_digest(refresh.user_id.as_bytes()).as_slice())
            .bind(refresh.refresh_grant.as_ref().map(|r|r.id.as_str())).bind(refresh.exchange_grant.as_ref().and_then(|g|g.root()).map(|r|r.id.as_str()))
            .bind(refresh.rotated).bind(micros(refresh.expires_at)?).bind(generation).execute(tx).await.map_err(|_|unavailable())?;
        Ok(())
    }
}
