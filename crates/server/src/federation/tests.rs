use super::fetcher::{ensure_fetch_status_success, host_matches_allowlist};
use super::raw_payload::{parse_entity_statement_payload, parse_trust_mark_claims_payload};
use super::repositories::{
    current_unix_epoch_secs, reconstruct_chain_from_cache, storage_err,
    trust_chain_cache_expires_at,
};
use super::*;
use aegaeon_jose::raw_json::RawJsonSurface;
#[cfg(feature = "verified-claim")]
use ffi::raw_json_structural as ffi_raw_json_structural;
use serde_json::json;
use sqlx::PgPool;
use std::future::Future;
use std::sync::MutexGuard;
use std::time::Duration;
use uuid::Uuid;

use crate::kms::{FederationKeyManager, InMemoryKeyManager};

// ── Test Helpers ─────────────────────────────────────────────────

fn raw_json_env_guard() -> MutexGuard<'static, ()> {
    match crate::util::RAW_JSON_ENV_GUARD.lock() {
        Ok(guard) => guard,
        Err(err) => fail_assertion(format!("raw JSON env guard should not be poisoned: {err}")),
    }
}

fn block_on_test_future<T>(future: impl Future<Output = T>) -> T {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(err) => fail_assertion(format!("test runtime should initialize: {err}")),
    };
    runtime.block_on(future)
}

struct EnvVarRestore {
    key: &'static str,
    previous: Option<String>,
}

impl Drop for EnvVarRestore {
    fn drop(&mut self) {
        if let Some(previous) = self.previous.take() {
            std::env::set_var(self.key, previous);
        } else {
            std::env::remove_var(self.key);
        }
    }
}

fn override_env_var(key: &'static str, value: Option<&str>) -> EnvVarRestore {
    let previous = std::env::var(key).ok();
    if let Some(value) = value {
        std::env::set_var(key, value);
    } else {
        std::env::remove_var(key);
    }
    EnvVarRestore { key, previous }
}

fn encode_json_value(value: &Value) -> String {
    let bytes = must_ok(serde_json::to_vec(value));
    URL_SAFE_NO_PAD.encode(bytes)
}

#[track_caller]
fn fail_assertion(message: String) -> ! {
    std::panic::panic_any(message)
}

fn must_ok<T, E>(result: Result<T, E>) -> T
where
    E: std::fmt::Debug,
{
    match result {
        Ok(value) => value,
        Err(err) => fail_assertion(format!("expected Ok(..), got Err({err:?})")),
    }
}

fn must_some<T>(value: Option<T>) -> T {
    match value {
        Some(inner) => inner,
        None => fail_assertion("expected Some(..)".to_string()),
    }
}

fn must_err<T, E>(result: Result<T, E>) -> E
where
    E: std::fmt::Debug,
{
    match result {
        Ok(_) => fail_assertion("expected Err(..), got Ok(..)".to_string()),
        Err(err) => err,
    }
}

fn make_test_jws(header: &Value, payload: &Value) -> String {
    let h = encode_json_value(header);
    let p = encode_json_value(payload);
    let s = URL_SAFE_NO_PAD.encode(b"test-signature-placeholder");
    format!("{h}.{p}.{s}")
}

fn sample_jwks_value() -> Value {
    json!({
        "keys": [{
            "kty": "EC",
            "crv": "P-256",
            "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
            "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
            "kid": "test-key-1",
            "use": "sig"
        }]
    })
}

fn sample_jwks() -> JwkSet {
    must_ok(JwkSet::from_value(sample_jwks_value()))
}

fn sample_trust_anchor(entity_id: &str) -> TrustAnchor {
    TrustAnchor {
        entity_id: entity_id.to_string(),
        jwks: sample_jwks(),
        metadata_policy: Some(json!({})),
    }
}

fn federation_jwks_value(key_manager: &InMemoryKeyManager) -> Value {
    json!({
        "keys": [must_some(FederationKeyManager::federation_public_jwk(key_manager))]
    })
}

fn sign_entity_statement_for_test(
    key_manager: &InMemoryKeyManager,
    stmt: &EntityStatement,
) -> String {
    let public_jwk = must_some(FederationKeyManager::federation_public_jwk(key_manager));
    let kid = public_jwk
        .get("kid")
        .and_then(Value::as_str)
        .unwrap_or_else(|| fail_assertion("federation public JWK missing kid".to_string()));
    let header = json!({
        "alg": FederationKeyManager::federation_alg(key_manager),
        "typ": "entity-statement+jwt",
        "kid": kid,
    });
    let header_b64 = encode_json_value(&header);
    let payload_b64 = encode_json_value(&must_ok(serde_json::to_value(stmt)));
    let signing_input = format!("{header_b64}.{payload_b64}");
    let signature = must_ok(FederationKeyManager::sign_federation(
        key_manager,
        signing_input.as_bytes(),
    ));
    format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature))
}

struct SignedDirectChain {
    anchor_jwks: Value,
    leaf_config: EntityStatement,
    leaf_jws: String,
    subordinate_statement: EntityStatement,
    subordinate_jws: String,
    anchor_config: EntityStatement,
    anchor_config_jws: String,
}

fn signed_direct_chain(ta_id: &str, leaf_id: &str, now: i64) -> SignedDirectChain {
    signed_direct_chain_with_constraints(ta_id, leaf_id, now, None)
}

fn signed_direct_chain_with_constraints(
    ta_id: &str,
    leaf_id: &str,
    now: i64,
    constraints: Option<Constraints>,
) -> SignedDirectChain {
    let leaf_key = InMemoryKeyManager::new();
    let anchor_key = InMemoryKeyManager::new();
    let leaf_jwks = federation_jwks_value(&leaf_key);
    let anchor_jwks = federation_jwks_value(&anchor_key);

    let mut leaf_config = sample_entity_config(leaf_id, now);
    leaf_config.jwks = Some(leaf_jwks.clone());
    leaf_config.authority_hints = Some(vec![ta_id.to_string()]);
    let leaf_jws = sign_entity_statement_for_test(&leaf_key, &leaf_config);

    let mut subordinate_statement = sample_subordinate_statement(ta_id, leaf_id, now);
    subordinate_statement.jwks = Some(leaf_jwks);
    subordinate_statement.constraints = constraints;
    let subordinate_jws = sign_entity_statement_for_test(&anchor_key, &subordinate_statement);

    let mut anchor_config = sample_entity_config(ta_id, now);
    anchor_config.jwks = Some(anchor_jwks.clone());
    anchor_config.authority_hints = None;
    let anchor_config_jws = sign_entity_statement_for_test(&anchor_key, &anchor_config);

    SignedDirectChain {
        anchor_jwks,
        leaf_config,
        leaf_jws,
        subordinate_statement,
        subordinate_jws,
        anchor_config,
        anchor_config_jws,
    }
}

fn signed_chain_jwts(chain: &SignedDirectChain) -> Value {
    json!([
        chain.leaf_jws.clone(),
        chain.subordinate_jws.clone(),
        chain.anchor_config_jws.clone()
    ])
}

fn current_epoch_secs() -> i64 {
    must_ok(current_unix_epoch_secs())
}

fn sample_entity_config(entity_id: &str, now: i64) -> EntityStatement {
    EntityStatement {
        iss: entity_id.to_string(),
        sub: entity_id.to_string(),
        iat: now - 100,
        exp: now + 3600,
        jwks: Some(sample_jwks_value()),
        metadata: Some(HashMap::from([(
            "openid_relying_party".to_string(),
            json!({
                "redirect_uris": ["https://rp.example.com/callback"],
                "grant_types": ["authorization_code"]
            }),
        )])),
        metadata_policy: None,
        constraints: None,
        trust_marks: None,
        authority_hints: Some(vec!["https://ta.example.com".to_string()]),
        source_endpoint: None,
    }
}

fn sample_subordinate_statement(issuer: &str, subject: &str, now: i64) -> EntityStatement {
    EntityStatement {
        iss: issuer.to_string(),
        sub: subject.to_string(),
        iat: now - 100,
        exp: now + 3600,
        jwks: Some(sample_jwks_value()),
        metadata: None,
        metadata_policy: Some(HashMap::new()),
        constraints: None,
        trust_marks: None,
        authority_hints: None,
        source_endpoint: None,
    }
}

// ── Mock Fetcher ─────────────────────────────────────────────────

struct MockFetcher {
    entity_configs: HashMap<String, EntityStatement>,
    subordinate_stmts: HashMap<(String, String), EntityStatement>,
    entity_config_jwts: HashMap<String, String>,
    subordinate_stmt_jwts: HashMap<(String, String), String>,
}

impl MockFetcher {
    fn new() -> Self {
        Self {
            entity_configs: HashMap::new(),
            subordinate_stmts: HashMap::new(),
            entity_config_jwts: HashMap::new(),
            subordinate_stmt_jwts: HashMap::new(),
        }
    }

    fn add_entity_config(&mut self, entity_id: &str, stmt: EntityStatement) {
        self.entity_configs.insert(entity_id.to_string(), stmt);
    }

    fn add_entity_config_with_jws(&mut self, entity_id: &str, stmt: EntityStatement, jws: String) {
        self.entity_configs.insert(entity_id.to_string(), stmt);
        self.entity_config_jwts.insert(entity_id.to_string(), jws);
    }

    fn add_subordinate_stmt(&mut self, authority_id: &str, sub_id: &str, stmt: EntityStatement) {
        self.subordinate_stmts
            .insert((authority_id.to_string(), sub_id.to_string()), stmt);
    }

    fn add_subordinate_stmt_with_jws(
        &mut self,
        authority_id: &str,
        sub_id: &str,
        stmt: EntityStatement,
        jws: String,
    ) {
        let key = (authority_id.to_string(), sub_id.to_string());
        self.subordinate_stmts.insert(key.clone(), stmt);
        self.subordinate_stmt_jwts.insert(key, jws);
    }

    fn add_signed_direct_chain(&mut self, ta_id: &str, leaf_id: &str, chain: &SignedDirectChain) {
        self.add_entity_config_with_jws(leaf_id, chain.leaf_config.clone(), chain.leaf_jws.clone());
        self.add_entity_config_with_jws(
            ta_id,
            chain.anchor_config.clone(),
            chain.anchor_config_jws.clone(),
        );
        self.add_subordinate_stmt_with_jws(
            ta_id,
            leaf_id,
            chain.subordinate_statement.clone(),
            chain.subordinate_jws.clone(),
        );
    }
}

impl FederationFetcher for MockFetcher {
    fn fetch_entity_configuration<'a>(
        &'a self,
        entity_id: &'a str,
    ) -> FederationFetchFuture<'a, EntityStatement> {
        Box::pin(async move {
            self.entity_configs
                .get(entity_id)
                .cloned()
                .ok_or_else(|| FederationError::Fetch(format!("not found: {entity_id}")))
        })
    }

    fn fetch_entity_configuration_with_jws<'a>(
        &'a self,
        entity_id: &'a str,
    ) -> FederationFetchFuture<'a, FetchedEntityConfiguration> {
        Box::pin(async move {
            let statement = self.fetch_entity_configuration(entity_id).await?;
            let entity_configuration_jws = self.entity_config_jwts.get(entity_id).cloned();
            Ok(FetchedEntityConfiguration {
                statement,
                entity_configuration_jws,
            })
        })
    }

    fn fetch_subordinate_statement<'a>(
        &'a self,
        authority_entity_id: &'a str,
        _authority_config: &'a EntityStatement,
        subordinate_entity_id: &'a str,
        _issuer_jwks: &'a JwkSet,
    ) -> FederationFetchFuture<'a, EntityStatement> {
        Box::pin(async move {
            let key = (
                authority_entity_id.to_string(),
                subordinate_entity_id.to_string(),
            );
            self.subordinate_stmts.get(&key).cloned().ok_or_else(|| {
                FederationError::Fetch(format!(
                    "subordinate not found: {authority_entity_id} -> {subordinate_entity_id}"
                ))
            })
        })
    }

    fn fetch_subordinate_statement_with_jws<'a>(
        &'a self,
        authority_entity_id: &'a str,
        authority_config: &'a EntityStatement,
        subordinate_entity_id: &'a str,
        issuer_jwks: &'a JwkSet,
    ) -> FederationFetchFuture<'a, FetchedSubordinateStatement> {
        Box::pin(async move {
            let statement = self
                .fetch_subordinate_statement(
                    authority_entity_id,
                    authority_config,
                    subordinate_entity_id,
                    issuer_jwks,
                )
                .await?;
            let key = (
                authority_entity_id.to_string(),
                subordinate_entity_id.to_string(),
            );
            let subordinate_statement_jws = self.subordinate_stmt_jwts.get(&key).cloned();
            Ok(FetchedSubordinateStatement {
                statement,
                subordinate_statement_jws,
            })
        })
    }
}

mod entity_statement {
    use super::*;
    include!("tests/entity_statement.rs");
}

mod raw_payload {
    use super::*;
    include!("tests/raw_payload.rs");
}

mod fetcher {
    use super::*;
    include!("tests/fetcher.rs");
}

mod jwk {
    use super::*;
    include!("tests/jwk.rs");
}

mod metadata_policy {
    use super::*;
    include!("tests/metadata_policy.rs");
}

mod trust_mark {
    use super::*;
    include!("tests/trust_mark.rs");
}

mod trust_chain {
    use super::*;
    include!("tests/trust_chain.rs");
}

mod repositories {
    use super::*;
    include!("tests/repositories.rs");
}

mod pg_repositories {
    use super::*;
    include!("tests/pg_repositories.rs");
}
