use super::*;
use crate::authcode::types::RefreshGrantRef;
use crate::policy::token_exchange::ExchangeRoot;

pub(super) struct InitialGrant {
    pub access: AccessToken,
    pub refresh: Option<RefreshToken>,
    pub meta: BearerTokenMeta,
    pub family: Option<RefreshGrantRecord>,
}

impl InitialGrant {
    pub(super) fn new(
        mut access: AccessToken,
        mut refresh: Option<RefreshToken>,
        mut meta: BearerTokenMeta,
    ) -> Result<Self, String> {
        let family =
            super::super::refresh_grants::prepare_initial(&mut access, refresh.as_mut(), &mut meta)
                .map_err(str::to_string)?;
        token_consistency::bearer_metadata_matches_access_token(&access, &meta)
            .map_err(str::to_string)?;
        if meta.refresh_parent.as_deref() != refresh.as_ref().map(|r| r.token.as_str()) {
            return Err(unavailable());
        }
        if let Some(refresh) = &refresh {
            token_consistency::refresh_token_matches_issued_grant(refresh, &access, &meta)
                .map_err(str::to_string)?;
        }
        if let Some(root) = &access.exchange_root {
            validate_root(root)?;
        }
        Ok(Self {
            access,
            refresh,
            meta,
            family,
        })
    }

    pub(super) fn result(&self) -> (String, Option<String>) {
        (
            self.access.token.clone(),
            self.refresh.as_ref().map(|r| r.token.clone()),
        )
    }
}

pub(super) fn validate_root(root: &ExchangeRoot) -> Result<(), String> {
    if root
        .id
        .strip_prefix("exchange-root:")
        .and_then(|v| uuid::Uuid::parse_str(v).ok())
        .is_none_or(|id| id.is_nil() || format!("exchange-root:{id}") != root.id)
    {
        return Err(unavailable());
    }
    micros(root.expires_at)?;
    Ok(())
}

pub(super) struct Capability {
    pub token_digest: Vec<u8>,
    pub kind: i16,
    pub payload: String,
    pub metadata: Option<String>,
    pub client_digest: Vec<u8>,
    pub subject_digest: Vec<u8>,
    pub subject_generation: uuid::Uuid,
    pub family_id: Option<String>,
    pub root_id: Option<String>,
    pub refresh_parent_digest: Option<Vec<u8>>,
    pub rotated: bool,
    pub revoked: bool,
    pub expires_us: i64,
}

impl Capability {
    fn identity(
        &self,
        requested: &str,
        stored: &str,
        owner: (&str, &str),
        lineage: (Option<&RefreshGrantRef>, Option<&ExchangeRoot>),
        expiry: SystemTime,
    ) -> Result<(), String> {
        let (client, subject) = owner;
        let (family, root) = lineage;
        if !crate::util::constant_time_eq(requested.as_bytes(), stored.as_bytes())
            || !crate::util::constant_time_eq(&self.token_digest, &sha256_digest(stored.as_bytes()))
            || !crate::util::constant_time_eq(
                &self.client_digest,
                &sha256_digest(client.as_bytes()),
            )
            || !crate::util::constant_time_eq(
                &self.subject_digest,
                &sha256_digest(subject.as_bytes()),
            )
            || self.family_id.as_deref() != family.map(|v| v.id.as_str())
            || family.is_some_and(|v| !v.supported())
            || self.root_id.as_deref() != root.map(|v| v.id.as_str())
            || self.expires_us != micros(expiry)?
        {
            return Err(unavailable());
        }
        if let Some(root) = root {
            validate_root(root)?;
        }
        Ok(())
    }

    pub(super) fn access(&self, requested: &str) -> Result<(AccessToken, BearerTokenMeta), String> {
        if self.kind != 1 || self.rotated {
            return Err(unavailable());
        }
        let access: AccessToken = serde_json::from_str(&self.payload).map_err(|_| unavailable())?;
        let meta: BearerTokenMeta =
            serde_json::from_str(self.metadata.as_deref().ok_or_else(unavailable)?)
                .map_err(|_| unavailable())?;
        token_consistency::bearer_metadata_matches_access_token(&access, &meta)
            .map_err(str::to_string)?;
        let expiry = access
            .created_at
            .checked_add(Duration::from_secs(access.expires_in))
            .ok_or_else(unavailable)?;
        self.identity(
            requested,
            &access.token,
            (&access.client_id, &access.user_id),
            (access.refresh_grant.as_ref(), access.exchange_root.as_ref()),
            expiry.min(meta.expires_at),
        )?;
        if self.refresh_parent_digest.as_deref()
            != meta
                .refresh_parent
                .as_ref()
                .map(|v| sha256_digest(v.as_bytes()))
                .as_ref()
                .map(|v| v.as_slice())
        {
            return Err(unavailable());
        }
        Ok((access, meta))
    }

    pub(super) fn refresh(&self, requested: &str) -> Result<RefreshToken, String> {
        if self.kind != 2 || self.metadata.is_some() || self.refresh_parent_digest.is_some() {
            return Err(unavailable());
        }
        let token: RefreshToken = serde_json::from_str(&self.payload).map_err(|_| unavailable())?;
        let root = token.exchange_grant.as_ref().and_then(|g| g.root());
        self.identity(
            requested,
            &token.token,
            (&token.client_id, &token.user_id),
            (token.refresh_grant.as_ref(), root),
            token.expires_at,
        )?;
        if self.rotated != token.rotated || token.refresh_grant.is_none() {
            return Err(unavailable());
        }
        Ok(token)
    }
}

impl sqlx::FromRow<'_, sqlx::postgres::PgRow> for Capability {
    fn from_row(row: &sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        use sqlx::Row;
        Ok(Self {
            token_digest: row.try_get("token_digest")?,
            kind: row.try_get("kind")?,
            payload: row.try_get("payload")?,
            metadata: row.try_get("metadata")?,
            client_digest: row.try_get("client_digest")?,
            subject_digest: row.try_get("subject_digest")?,
            subject_generation: row.try_get("subject_generation")?,
            family_id: row.try_get("family_id")?,
            root_id: row.try_get("root_id")?,
            refresh_parent_digest: row.try_get("refresh_parent_digest")?,
            rotated: row.try_get("rotated")?,
            revoked: row.try_get("revoked")?,
            expires_us: row.try_get("expires_us")?,
        })
    }
}
