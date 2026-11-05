use super::{AuthSession, AuthSessionBackend, AuthSessionStore};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::web) struct SessionCursor {
    pub(in crate::web) auth_time: i64,
    pub(in crate::web) digest: [u8; 32],
}

pub(in crate::web) struct SessionPage {
    pub(in crate::web) sessions: Vec<(String, AuthSession)>,
    pub(in crate::web) next: Option<SessionCursor>,
}

pub(in crate::web) fn parse_session_digest(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    let mut digest = [0; 32];
    for (index, slot) in digest.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(digest)
}

impl AuthSessionStore {
    pub(in crate::web) async fn inventory_page(
        &self,
        subject: &str,
        cursor: Option<SessionCursor>,
        limit: usize,
    ) -> Result<SessionPage, String> {
        if !(1..=200).contains(&limit) || cursor.as_ref().is_some_and(|cursor| cursor.auth_time < 0)
        {
            return Err("invalid session inventory page".into());
        }
        match &self.backend {
            AuthSessionBackend::Postgres(backend) => {
                backend.page(subject, cursor.as_ref(), limit).await
            }
            #[cfg(test)]
            _ => {
                let mut sessions = self.try_list_for_user_async(subject.to_owned()).await?;
                sessions.sort_by_key(|(sid, session)| {
                    (
                        std::cmp::Reverse(session.auth_time_epoch_secs),
                        aegaeon_crypto::hash::sha256_digest(sid.as_bytes()),
                    )
                });
                sessions.retain(|(sid, session)| {
                    cursor.as_ref().is_none_or(|cursor| {
                        i64::try_from(session.auth_time_epoch_secs).is_ok_and(|time| {
                            time < cursor.auth_time
                                || (time == cursor.auth_time
                                    && aegaeon_crypto::hash::sha256_digest(sid.as_bytes())
                                        > cursor.digest)
                        })
                    })
                });
                let next = if sessions.len() > limit {
                    let (sid, session) = &sessions[limit - 1];
                    Some(SessionCursor {
                        auth_time: i64::try_from(session.auth_time_epoch_secs)
                            .map_err(|_| "invalid session time")?,
                        digest: aegaeon_crypto::hash::sha256_digest(sid.as_bytes()),
                    })
                } else {
                    None
                };
                sessions.truncate(limit);
                Ok(SessionPage { sessions, next })
            }
        }
    }

    pub(in crate::web) async fn find_inventory_session(
        &self,
        subject: &str,
        fingerprint: &str,
    ) -> Result<Option<String>, String> {
        let Some(digest) = parse_session_digest(fingerprint) else {
            return Ok(None);
        };
        match &self.backend {
            AuthSessionBackend::Postgres(backend) => backend.find(subject, &digest).await,
            #[cfg(test)]
            _ => Ok(self
                .try_list_for_user_async(subject.to_owned())
                .await?
                .into_iter()
                .find_map(|(sid, _)| {
                    (aegaeon_crypto::hash::sha256_digest(sid.as_bytes()) == digest).then_some(sid)
                })),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_inventory_digest_rejects_noncanonical_selectors() {
        assert_eq!(parse_session_digest(&"00".repeat(32)), Some([0; 32]));
        assert_eq!(parse_session_digest(&"af".repeat(32)), Some([0xaf; 32]));
        for invalid in [
            "AF".repeat(32),
            "a".repeat(63),
            "a".repeat(65),
            "é".repeat(32),
            "gg".repeat(32),
        ] {
            assert!(parse_session_digest(&invalid).is_none());
        }
    }
}
