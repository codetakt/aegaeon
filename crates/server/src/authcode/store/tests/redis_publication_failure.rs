//! Real Redis ACL failures through the Rust writer and authoritative readers.
use super::*;
use crate::authcode::types::{RefreshGrantRef, RefreshTargetContext};

struct Fixture {
    admin: redis::Connection,
    reader: TokenStore,
    writer: TokenStore,
    user: String,
    acl_helper: bool,
}

impl Fixture {
    fn new() -> Self {
        let raw = std::env::var("AEGAEON_TEST_REDIS_URL").expect("Redis URL required");
        let mut admin = redis::Client::open(raw.as_str())
            .unwrap()
            .get_connection()
            .unwrap();
        let id = uuid::Uuid::new_v4().to_string();
        let namespace =
            crate::config::RuntimeStateNamespace::for_tests(format!("publication-{id}"));
        let user = format!("publication-{id}");
        redis::cmd("ACL")
            .arg("SETUSER")
            .arg(&user)
            .arg(&["reset", "on", ">local-test-only", "~*", "+@all"])
            .query::<()>(&mut admin)
            .unwrap();
        let mut url = url::Url::parse(&raw).unwrap();
        url.set_username(&user).unwrap();
        url.set_password(Some("local-test-only")).unwrap();
        let make = |url: &str| TokenStore {
            backend: TokenStoreBackend::Redis(
                RedisTokenStoreBackend::new(url, &namespace).unwrap(),
            ),
        };
        let acl_helper: bool = redis::Script::new(
            "return type(rawget(redis, 'acl_check_cmd')) == 'function' and 1 or 0",
        )
        .invoke(&mut admin)
        .unwrap();
        Self {
            reader: make(&raw),
            writer: make(url.as_str()),
            admin,
            user,
            acl_helper,
        }
    }

    fn keys(&self) -> &redis_support::RedisTokenStoreKeyspace {
        let TokenStoreBackend::Redis(backend) = &self.reader.backend else {
            unreachable!()
        };
        backend.keyspace_for_tests()
    }

    fn deny(&mut self, command: &str) {
        redis::cmd("ACL")
            .arg("SETUSER")
            .arg(&self.user)
            .arg(format!("-{command}"))
            .query::<()>(&mut self.admin)
            .unwrap();
    }

    fn restore(&mut self) {
        redis::cmd("ACL")
            .arg("SETUSER")
            .arg(&self.user)
            .arg("+@all")
            .query::<()>(&mut self.admin)
            .unwrap();
    }

    fn assert_access(&self, id: &str, active: bool) {
        assert_eq!(
            self.reader.try_verify_access_token(id).unwrap().is_some(),
            active
        );
        let validator = crate::authcode::TokenValidator::new(
            self.reader.clone(),
            Arc::new(crate::kms::InMemoryKeyManager::new()),
        );
        assert_eq!(validator.introspect_token(id)["active"], active);
        assert_eq!(
            validator
                .validate_bearer_token_with_meta(&format!("Bearer {id}"))
                .is_ok(),
            active,
        );
    }

    fn value(&mut self, key: String) -> Option<String> {
        redis::cmd("GET").arg(key).query(&mut self.admin).unwrap()
    }

    fn exists(&mut self, key: String) -> bool {
        redis::cmd("EXISTS")
            .arg(key)
            .query(&mut self.admin)
            .unwrap()
    }

    fn member(&mut self, key: String, id: &str) -> bool {
        redis::cmd("SISMEMBER")
            .arg(key)
            .arg(id)
            .query(&mut self.admin)
            .unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = redis::cmd("ACL")
            .arg("DELUSER")
            .arg(&self.user)
            .query::<()>(&mut self.admin);
    }
}

fn assert_acl_error(error: &str) {
    assert!(
        error.contains("acl_denied")
            || error.contains("permission")
            || error.contains("NOPERM")
            || error.contains("The user executing the script can't run this command or subcommand"),
        "expected an ACL failure, got: {error}"
    );
}

fn records(parent: Option<&RefreshToken>) -> (AccessToken, BearerTokenMeta) {
    let access = AccessToken {
        refresh_grant: parent.and_then(|parent| parent.refresh_grant.clone()),
        ..AccessToken::new("client".into(), "user".into(), Some("read".into()), 300)
    };
    let mut meta = BearerTokenMeta::new(bearer_meta_input(&access.token, "client", "user"));
    meta.issued_at = access.created_at;
    meta.expires_at = access.created_at + Duration::from_secs(300);
    meta.audience = "https://resource.example".into();
    meta.refresh_parent = parent.map(|parent| parent.token.clone());
    meta.refresh_grant = access.refresh_grant.clone();
    (access, meta)
}

fn refresh() -> RefreshToken {
    let mut token = RefreshToken::new(refresh_input(
        "client",
        "user",
        Some("read"),
        Some("https://resource.example"),
    ));
    token.refresh_grant = Some(RefreshGrantRef {
        version: 1,
        id: "G".repeat(43),
    });
    token.target_context = Some(RefreshTargetContext {
        version: 1,
        audience: "https://resource.example".into(),
        token_issuer: None,
        oidc_issuer: None,
    });
    token
}

fn initial(f: &Fixture) -> RefreshToken {
    let token = refresh();
    let (access, meta) = records(Some(&token));
    f.reader
        .store_issued_grant(access, Some(token.clone()), meta)
        .unwrap();
    token
}

fn issue(
    store: &TokenStore,
    mode: u8,
    access: AccessToken,
    meta: BearerTokenMeta,
    parent: Option<&RefreshToken>,
) -> Result<(), String> {
    if mode == 2 {
        store
            .store_access_for_refresh_parent(access, meta)
            .map(|_| ())
    } else {
        store
            .store_issued_grant(access, parent.cloned(), meta)
            .map(|_| ())
    }
}

#[test]
#[ignore = "requires AEGAEON_TEST_REDIS_URL with ACL administration"]
fn redis_publication_command_failures_preserve_authoritative_denial() {
    for mode in 0..=2 {
        for denied in ["INCR", "SADD", "ZADD"] {
            let mut f = Fixture::new();
            let parent = match mode {
                1 => Some(refresh()),
                2 => Some(initial(&f)),
                _ => None,
            };
            let (access, meta) = records(parent.as_ref());
            f.deny(denied);
            assert_acl_error(
                &issue(&f.writer, mode, access.clone(), meta, parent.as_ref())
                    .expect_err("ACL denied issuance"),
            );
            f.assert_access(&access.token, false);
            if mode == 1 {
                let parent = parent.as_ref().unwrap();
                assert!(f
                    .reader
                    .try_get_refresh_token(&parent.token)
                    .unwrap()
                    .is_none());
                assert!(!f.exists(
                    f.keys()
                        .refresh_grant_key(&parent.refresh_grant.as_ref().unwrap().id)
                ));
            }
            if f.acl_helper {
                assert!(!f.exists(f.keys().access_key(&access.token)));
                assert!(!f.exists(f.keys().bearer_key(&access.token)));
            }
            f.restore();
            let (control, meta) = records(parent.as_ref());
            issue(&f.writer, mode, control.clone(), meta, parent.as_ref()).unwrap();
            f.assert_access(&control.token, true);
        }
    }
}

#[test]
#[ignore = "requires AEGAEON_TEST_REDIS_URL with ACL administration"]
fn redis_publication_sender_failure_preserves_exact_binding() {
    for denied in ["INCR", "ZADD"] {
        let mut f = Fixture::new();
        let parent = initial(&f);
        let before = f.value(f.keys().refresh_key(&parent.token)).unwrap();
        f.deny(denied);
        let binding = Some(SenderBinding::DPoP {
            jkt: "updated-binding".into(),
        });
        assert_acl_error(
            &f.writer
                .try_set_refresh_sender_binding(&parent.token, binding.clone())
                .expect_err("ACL denied sender update"),
        );
        assert_eq!(
            f.value(f.keys().refresh_key(&parent.token)).as_deref(),
            Some(before.as_str())
        );
        assert_eq!(
            f.reader
                .try_get_refresh_token(&parent.token)
                .unwrap()
                .unwrap()
                .sender_binding,
            None
        );
        f.restore();
        assert!(f
            .writer
            .try_set_refresh_sender_binding(&parent.token, binding.clone())
            .unwrap());
        assert_eq!(
            f.reader
                .try_get_refresh_token(&parent.token)
                .unwrap()
                .unwrap()
                .sender_binding,
            binding
        );
    }
}

#[test]
#[ignore = "requires Redis 7+ ACL selectors; older engines exercise command denial separately"]
fn redis_publication_key_permissions_checked_before_mutation() {
    for mode in 0..=2 {
        let mut f = Fixture::new();
        if !f.acl_helper {
            return;
        }
        let parent = match mode {
            1 => Some(refresh()),
            2 => Some(initial(&f)),
            _ => None,
        };
        let (access, meta) = records(parent.as_ref());
        let target = if mode == 1 {
            f.keys()
                .refresh_grant_key(&parent.as_ref().unwrap().refresh_grant.as_ref().unwrap().id)
        } else {
            f.keys().access_key(&access.token)
        };
        let mut allowed = vec![
            f.keys().lock_key(),
            f.keys().access_key(&access.token),
            f.keys().bearer_key(&access.token),
        ];
        if let Some(parent) = &parent {
            allowed.extend([
                f.keys().refresh_key(&parent.token),
                f.keys().refresh_children_key(&parent.token),
                f.keys()
                    .refresh_grant_key(&parent.refresh_grant.as_ref().unwrap().id),
            ]);
        }
        allowed.retain(|key| key != &target);
        let selector = format!(
            "(+SET {})",
            allowed
                .iter()
                .map(|key| format!("~{key}"))
                .collect::<Vec<_>>()
                .join(" ")
        );
        redis::cmd("ACL")
            .arg("SETUSER")
            .arg(&f.user)
            .arg("-SET")
            .arg(selector)
            .query::<()>(&mut f.admin)
            .unwrap();
        assert_acl_error(
            &issue(&f.writer, mode, access.clone(), meta, parent.as_ref())
                .expect_err("ACL denied issuance"),
        );
        f.assert_access(&access.token, false);
        assert!(!f.exists(f.keys().bearer_key(&access.token)));
        if mode == 1 {
            assert!(!f.exists(target));
        }
        f.restore();
        let (control, meta) = records(parent.as_ref());
        issue(&f.writer, mode, control.clone(), meta, parent.as_ref()).unwrap();
        f.assert_access(&control.token, true);
    }
}

fn stage_missing_access(f: &mut Fixture, access: &AccessToken, meta: &BearerTokenMeta) {
    let access_expiry = access
        .created_at
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + access.expires_in;
    let meta_expiry = meta
        .expires_at
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    redis::pipe()
        .cmd("ZADD")
        .arg(f.keys().expiry_access_key())
        .arg(access_expiry)
        .arg(&access.token)
        .ignore()
        .cmd("ZADD")
        .arg(f.keys().expiry_bearer_key())
        .arg(meta_expiry)
        .arg(&access.token)
        .ignore()
        .cmd("SET")
        .arg(f.keys().bearer_key(&access.token))
        .arg(serde_json::to_string(meta).unwrap())
        .ignore()
        .cmd("SADD")
        .arg(f.keys().subject_access_key("user"))
        .arg(&access.token)
        .ignore()
        .cmd("SADD")
        .arg(f.keys().subject_bearer_key("user"))
        .arg(&access.token)
        .ignore()
        .query::<()>(&mut f.admin)
        .unwrap();
}

#[test]
#[ignore = "requires AEGAEON_TEST_REDIS_URL"]
fn redis_publication_residue_cleanup_handles_both_lifetime_orders() {
    for metadata_first in [false, true] {
        let mut f = Fixture::new();
        let mut ids = Vec::new();
        for _ in 0..3 {
            let (mut access, mut meta) = records(None);
            if metadata_first {
                meta.expires_at = SystemTime::now() - Duration::from_secs(2);
            } else {
                access.created_at = SystemTime::now() - Duration::from_secs(400);
            }
            stage_missing_access(&mut f, &access, &meta);
            ids.push((access, meta));
        }
        f.reader.try_cleanup_expired().unwrap();
        for (access, meta) in &mut ids {
            f.assert_access(&access.token, false);
            if metadata_first {
                assert!(!f.member(f.keys().subject_access_key("user"), &access.token));
                redis::cmd("ZADD")
                    .arg(f.keys().expiry_access_key())
                    .arg(0)
                    .arg(&access.token)
                    .query::<()>(&mut f.admin)
                    .unwrap();
            } else {
                assert!(f.member(f.keys().subject_access_key("user"), &access.token));
                meta.expires_at = SystemTime::now() - Duration::from_secs(2);
                redis::cmd("SET")
                    .arg(f.keys().bearer_key(&access.token))
                    .arg(serde_json::to_string(meta).unwrap())
                    .query::<()>(&mut f.admin)
                    .unwrap();
                redis::cmd("ZADD")
                    .arg(f.keys().expiry_bearer_key())
                    .arg(0)
                    .arg(&access.token)
                    .query::<()>(&mut f.admin)
                    .unwrap();
            }
        }
        f.reader.try_cleanup_expired().unwrap();
        for (access, _) in ids {
            assert!(!f.member(f.keys().subject_access_key("user"), &access.token));
            assert!(!f.member(f.keys().subject_bearer_key("user"), &access.token));
            assert!(!f.exists(f.keys().bearer_key(&access.token)));
        }
        assert!(!f.exists(f.keys().expiry_access_key()));
        assert!(!f.exists(f.keys().expiry_bearer_key()));
    }
}

#[test]
#[ignore = "requires AEGAEON_TEST_REDIS_URL"]
fn redis_publication_subject_cleanup_preserves_live_access_membership() {
    let mut f = Fixture::new();
    let (access, meta) = records(None);
    stage_missing_access(&mut f, &access, &meta);
    f.reader.try_revoke_tokens_by_subject("user").unwrap();
    assert!(!f.member(f.keys().subject_access_key("user"), &access.token));
    assert!(!f.exists(f.keys().bearer_key(&access.token)));

    let (live, meta) = records(None);
    f.reader
        .store_issued_grant(live.clone(), None, meta.clone())
        .unwrap();
    let mut expired = meta;
    expired.expires_at = SystemTime::now() - Duration::from_secs(2);
    redis::cmd("SET")
        .arg(f.keys().bearer_key(&live.token))
        .arg(serde_json::to_string(&expired).unwrap())
        .query::<()>(&mut f.admin)
        .unwrap();
    redis::cmd("ZADD")
        .arg(f.keys().expiry_bearer_key())
        .arg(0)
        .arg(&live.token)
        .query::<()>(&mut f.admin)
        .unwrap();
    f.reader.try_cleanup_expired().unwrap();
    assert!(f.member(f.keys().subject_access_key("user"), &live.token));
    assert!(f.exists(f.keys().access_key(&live.token)));
}

#[test]
#[ignore = "requires AEGAEON_TEST_REDIS_URL"]
fn redis_publication_missing_subject_records_and_children_are_pruned() {
    let mut f = Fixture::new();
    let live = initial(&f);
    let live_children = f.value(f.keys().refresh_children_key(&live.token));
    redis::pipe()
        .cmd("SADD")
        .arg(f.keys().subject_access_key("user"))
        .arg("missing-access")
        .ignore()
        .cmd("SADD")
        .arg(f.keys().subject_bearer_key("user"))
        .arg("missing-meta")
        .ignore()
        .cmd("SADD")
        .arg(f.keys().subject_refresh_key("user"))
        .arg("missing-refresh")
        .ignore()
        .cmd("SET")
        .arg(f.keys().refresh_children_key("missing-refresh"))
        .arg("{}")
        .ignore()
        .cmd("ZADD")
        .arg(f.keys().expiry_refresh_key())
        .arg(0)
        .arg("missing-refresh")
        .ignore()
        .query::<()>(&mut f.admin)
        .unwrap();
    f.reader.try_list_bearer_meta_for_subject("user").unwrap();
    f.reader
        .try_list_refresh_tokens_for_subject("user")
        .unwrap();
    assert!(!f.member(f.keys().subject_bearer_key("user"), "missing-meta"));
    assert!(!f.member(f.keys().subject_refresh_key("user"), "missing-refresh"));
    f.reader.try_cleanup_expired().unwrap();
    assert!(!f.exists(f.keys().refresh_children_key("missing-refresh")));
    assert_eq!(
        f.value(f.keys().refresh_children_key(&live.token)),
        live_children
    );
    f.reader.try_revoke_tokens_by_subject("user").unwrap();
    assert!(!f.member(f.keys().subject_access_key("user"), "missing-access"));
}

#[test]
#[ignore = "requires AEGAEON_TEST_REDIS_URL with ACL administration"]
fn redis_publication_repeated_command_failures_are_reclaimable() {
    for mode in 0..=2 {
        let mut f = Fixture::new();
        let parent = match mode {
            1 => Some(refresh()),
            2 => Some(initial(&f)),
            _ => None,
        };
        let mut failed = Vec::new();
        f.deny("SADD");
        for _ in 0..3 {
            let (access, meta) = records(parent.as_ref());
            assert_acl_error(
                &issue(&f.writer, mode, access.clone(), meta, parent.as_ref())
                    .expect_err("ACL denied issuance"),
            );
            f.assert_access(&access.token, false);
            failed.push(access.token);
        }
        f.restore();
        for id in &failed {
            if let Some(raw) = f.value(f.keys().bearer_key(id)) {
                let mut meta: BearerTokenMeta = serde_json::from_str(&raw).unwrap();
                meta.expires_at = SystemTime::now() - Duration::from_secs(2);
                redis::cmd("SET")
                    .arg(f.keys().bearer_key(id))
                    .arg(serde_json::to_string(&meta).unwrap())
                    .query::<()>(&mut f.admin)
                    .unwrap();
            }
            redis::cmd("ZADD")
                .arg(f.keys().expiry_access_key())
                .arg(0)
                .arg(id)
                .query::<()>(&mut f.admin)
                .unwrap();
            redis::cmd("ZADD")
                .arg(f.keys().expiry_bearer_key())
                .arg(0)
                .arg(id)
                .query::<()>(&mut f.admin)
                .unwrap();
        }
        if mode == 1 {
            redis::cmd("ZADD")
                .arg(f.keys().expiry_refresh_grant_key())
                .arg(0)
                .arg(&parent.as_ref().unwrap().refresh_grant.as_ref().unwrap().id)
                .query::<()>(&mut f.admin)
                .unwrap();
        }
        f.reader.try_cleanup_expired().unwrap();
        if mode == 1 {
            assert!(!f.exists(f.keys().expiry_refresh_grant_key()));
        } else if mode == 2 {
            assert!(f
                .reader
                .try_get_refresh_token(&parent.as_ref().unwrap().token)
                .unwrap()
                .is_some());
        }
        for id in failed {
            assert!(!f.exists(f.keys().access_key(&id)));
            assert!(!f.exists(f.keys().bearer_key(&id)));
            assert!(!f.member(f.keys().subject_access_key("user"), &id));
            assert!(!f.member(f.keys().subject_bearer_key("user"), &id));
        }
    }
}

#[test]
#[ignore = "requires AEGAEON_TEST_REDIS_URL"]
fn redis_publication_cleanup_rejects_mismatched_metadata_identity() {
    let mut f = Fixture::new();
    let (access, mut meta) = records(None);
    meta.expires_at = SystemTime::now() - Duration::from_secs(2);
    stage_missing_access(&mut f, &access, &meta);
    meta.token_id = "different-token".into();
    redis::cmd("SET")
        .arg(f.keys().bearer_key(&access.token))
        .arg(serde_json::to_string(&meta).unwrap())
        .query::<()>(&mut f.admin)
        .unwrap();
    assert!(f.reader.try_cleanup_expired().is_err());
    assert!(f.member(f.keys().subject_access_key("user"), &access.token));
    assert!(f.exists(f.keys().bearer_key(&access.token)));
}
