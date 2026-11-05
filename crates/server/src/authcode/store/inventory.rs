//! Bounded current-state inventory. Cursors advance over inactive rows as well.
use super::{TokenStore, TokenStoreBackend};
use crate::authcode::types::{BearerTokenMeta, RefreshToken};
use aegaeon_crypto::hash::sha256_digest;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TokenInventoryKind {
    Grants,
    Refresh,
}
impl TokenInventoryKind {
    pub(super) fn code(self) -> i16 {
        match self {
            Self::Grants => 1,
            Self::Refresh => 2,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TokenInventoryCursor {
    pub group: [u8; 32],
    pub token: [u8; 32],
    pub group_emitted: bool,
}
#[derive(Clone)]
pub(crate) enum TokenInventoryRecord {
    Grant(Box<BearerTokenMeta>),
    Refresh(Box<RefreshToken>),
}
impl TokenInventoryRecord {
    pub(super) fn keys(&self) -> ([u8; 32], [u8; 32]) {
        match self {
            Self::Grant(meta) => (
                sha256_digest(
                    meta.refresh_parent
                        .as_deref()
                        .unwrap_or(&meta.token_id)
                        .as_bytes(),
                ),
                sha256_digest(meta.token_id.as_bytes()),
            ),
            Self::Refresh(token) => {
                let key = sha256_digest(token.token.as_bytes());
                (key, key)
            }
        }
    }
}
pub(crate) struct TokenInventoryPage {
    pub records: Vec<TokenInventoryRecord>,
    pub next: Option<TokenInventoryCursor>,
}
pub(crate) enum TokenInventoryTarget {
    Access(String),
    Refresh(String),
}

pub(super) fn digest(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    let mut result = [0; 32];
    for (index, slot) in result.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(result)
}
impl TokenStore {
    pub(crate) async fn inventory_page(
        &self,
        subject: &str,
        kind: TokenInventoryKind,
        cursor: Option<TokenInventoryCursor>,
        limit: usize,
    ) -> Result<TokenInventoryPage, String> {
        if !(1..=200).contains(&limit) {
            return Err("invalid token inventory limit".into());
        }
        #[cfg(not(kani))]
        if let TokenStoreBackend::Postgres(backend) = &self.backend {
            return backend
                .inventory_page(subject, kind, cursor.as_ref(), limit)
                .await;
        }
        // Compatibility until the coupled production stores switch together. SQL never uses this scan.
        let mut rows = match kind {
            TokenInventoryKind::Grants => self
                .try_list_bearer_meta_for_subject_async(subject.into())
                .await?
                .into_iter()
                .map(|meta| TokenInventoryRecord::Grant(Box::new(meta)))
                .collect::<Vec<_>>(),
            TokenInventoryKind::Refresh => self
                .try_list_refresh_tokens_for_subject_async(subject.into())
                .await?
                .into_iter()
                .map(|token| TokenInventoryRecord::Refresh(Box::new(token)))
                .collect(),
        };
        rows.sort_by_key(TokenInventoryRecord::keys);
        rows.retain(|row| {
            cursor.as_ref().is_none_or(|c| {
                let (group, token) = row.keys();
                if c.group_emitted {
                    group > c.group
                } else {
                    (group, token) > (c.group, c.token)
                }
            })
        });
        let mut records = Vec::new();
        let mut previous = None;
        let mut next = None;
        for row in rows.into_iter().take(limit) {
            let (group, token) = row.keys();
            if previous != Some(group) {
                records.push(row);
                previous = Some(group);
            }
            next = Some(TokenInventoryCursor {
                group,
                token,
                group_emitted: true,
            });
        }
        Ok(TokenInventoryPage { records, next })
    }

    pub(crate) async fn find_inventory_token(
        &self,
        subject: &str,
        kind: TokenInventoryKind,
        fingerprint: &str,
    ) -> Result<Option<TokenInventoryTarget>, String> {
        let Some(key) = digest(fingerprint) else {
            return Ok(None);
        };
        #[cfg(not(kani))]
        if let TokenStoreBackend::Postgres(backend) = &self.backend {
            return backend.find_inventory_token(subject, kind, &key).await;
        }
        match kind {
            TokenInventoryKind::Refresh => Ok(self
                .try_list_refresh_tokens_for_subject_async(subject.into())
                .await?
                .into_iter()
                .find_map(|r| {
                    (sha256_digest(r.token.as_bytes()) == key)
                        .then_some(TokenInventoryTarget::Refresh(r.token))
                })),
            TokenInventoryKind::Grants => Ok(self
                .try_list_bearer_meta_for_subject_async(subject.into())
                .await?
                .into_iter()
                .find_map(|r| {
                    if r.refresh_parent
                        .as_ref()
                        .is_some_and(|p| sha256_digest(p.as_bytes()) == key)
                    {
                        r.refresh_parent.map(TokenInventoryTarget::Refresh)
                    } else {
                        (sha256_digest(r.token_id.as_bytes()) == key)
                            .then_some(TokenInventoryTarget::Access(r.token_id))
                    }
                })),
        }
    }
}
