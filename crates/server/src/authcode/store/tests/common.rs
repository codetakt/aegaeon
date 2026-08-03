use super::redis_support::token_store_key_digest;
use super::*;
use crate::authcode::code_store::RedisAuthCodeBackend;
use crate::authcode::types::{
    AuthorizationCode, BearerTokenMeta, BearerTokenMetaInput, CnfClaim, RefreshToken,
    RefreshTokenInput, SenderBinding,
};
use std::io::{self, Result as IoResult, Write};
use std::sync::{Arc, Mutex};
use std::thread;
use tracing_subscriber::fmt::MakeWriter;

struct BufferWriter {
    buf: Arc<Mutex<Vec<u8>>>,
}

type StoreTestResult = Result<(), String>;

macro_rules! fail_test {
    ($($arg:tt)*) => {
        return Err(format!($($arg)*))
    };
}

macro_rules! must_ok {
    ($result:expr, $context:expr $(,)?) => {
        match $result {
            Ok(value) => value,
            Err(err) => fail_test!("{}: {:?}", $context, err),
        }
    };
}

macro_rules! must_err {
    ($result:expr, $context:expr $(,)?) => {
        match $result {
            Ok(_) => fail_test!("{}", $context),
            Err(err) => err,
        }
    };
}

macro_rules! must_some {
    ($value:expr, $context:expr $(,)?) => {
        match $value {
            Some(value) => value,
            None => fail_test!("{}", $context),
        }
    };
}

#[track_caller]
fn fail_assertion(message: String) -> ! {
    std::panic::panic_any(message)
}

fn refresh_input(
    client_id: &str,
    user_id: &str,
    scope: Option<&str>,
    resource: Option<&str>,
) -> RefreshTokenInput {
    RefreshTokenInput {
        scope: scope.map(str::to_string),
        resource: resource.map(str::to_string),
        ..RefreshTokenInput::new(client_id.to_string(), user_id.to_string())
    }
}

fn bearer_meta_input(token_id: &str, client_id: &str, user_id: &str) -> BearerTokenMetaInput {
    let now = SystemTime::now();
    BearerTokenMetaInput {
        token_id: token_id.to_string(),
        client_id: client_id.to_string(),
        user_id: user_id.to_string(),
        granted_scopes: vec!["read".to_string()],
        audience: client_id.to_string(),
        sender_binding: None,
        authorization_details: None,
        auth_time_epoch_secs: None,
        acr: None,
        issued_at: now,
        expires_at: now + Duration::from_secs(300),
        refresh_parent: None,
    }
}

impl Write for BufferWriter {
    fn write(&mut self, data: &[u8]) -> IoResult<usize> {
        self.buf
            .lock()
            .map_err(|err| io::Error::other(format!("test log buffer poisoned: {err}")))?
            .extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> IoResult<()> {
        Ok(())
    }
}

#[derive(Clone)]
struct CaptureMakeWriter {
    buf: Arc<Mutex<Vec<u8>>>,
}

impl<'a> MakeWriter<'a> for CaptureMakeWriter {
    type Writer = BufferWriter;

    fn make_writer(&'a self) -> Self::Writer {
        BufferWriter {
            buf: Arc::clone(&self.buf),
        }
    }
}

fn make_test_code(state: Option<&str>, nonce: Option<&str>) -> AuthorizationCode {
    AuthorizationCode {
        code: format!("code-{}", uuid::Uuid::new_v4()),
        client_id: "test-client".to_string(),
        redirect_uri: Some("https://example.com/callback".to_string()),
        resource: None,
        authorization_details: None,
        scope: Some("openid".to_string()),
        state: state.map(std::string::ToString::to_string),
        nonce: nonce.map(std::string::ToString::to_string),
        user_id: "user123".to_string(),
        expires_at: SystemTime::now() + Duration::from_secs(300),
        used: false,
        code_challenge: None,
        code_challenge_method: None,
        auth_time_epoch_secs: 0,
        acr: None,
        auth_session_id: None,
        local_profile: None,
        claim_release_policy: None,
    }
}

fn make_access_token(token: &str) -> AccessToken {
    AccessToken {
        token: token.to_string(),
        token_type: "Bearer".to_string(),
        client_id: "test-client".to_string(),
        user_id: "user".to_string(),
        scope: Some("read".to_string()),
        expires_in: 300,
        created_at: SystemTime::now(),
        cnf: None,
    }
}

fn make_refresh_token(token: &str) -> RefreshToken {
    let mut refresh = RefreshToken::with_ttl(
        refresh_input("test-client", "user", Some("read"), None),
        300,
    );
    refresh.token = token.to_string();
    refresh
}

fn make_bearer_meta(token: &str, refresh_parent: Option<&str>) -> BearerTokenMeta {
    BearerTokenMeta::new(BearerTokenMetaInput {
        refresh_parent: refresh_parent.map(str::to_string),
        ..bearer_meta_input(token, "test-client", "user")
    })
}

fn store_access_token(store: &TokenStore, token: AccessToken) -> String {
    match store.try_replace_access_token_record(token) {
        Ok(value) => value,
        Err(err) => fail_assertion(format!(
            "in-memory access-token store should succeed: {err:?}"
        )),
    }
}

fn store_bearer_meta(store: &TokenStore, meta: BearerTokenMeta) {
    if let Err(err) = store.try_replace_bearer_meta_record(meta) {
        fail_assertion(format!(
            "in-memory bearer metadata store should succeed: {err:?}"
        ));
    }
}

fn store_refresh_token(store: &TokenStore, token: RefreshToken) -> String {
    match store.try_replace_refresh_token_record(token) {
        Ok(value) => value,
        Err(err) => fail_assertion(format!(
            "in-memory refresh-token store should succeed: {err:?}"
        )),
    }
}

fn bind_refresh_access(store: &TokenStore, refresh_token: &str, access_token: &str) {
    if let Err(err) = store.try_bind_refresh_access(refresh_token, access_token) {
        fail_assertion(format!(
            "in-memory refresh/access binding should succeed: {err:?}"
        ));
    }
}

fn rotate_refresh_token(store: &TokenStore, token: &str) -> Option<RefreshToken> {
    match store.try_rotate_refresh_token(token) {
        Ok(value) => value,
        Err(err) => fail_assertion(format!(
            "in-memory refresh-token rotation should not fail: {err:?}"
        )),
    }
}

fn verify_access_token(store: &TokenStore, token: &str) -> Option<AccessToken> {
    match store.try_verify_access_token(token) {
        Ok(value) => value,
        Err(err) => fail_assertion(format!(
            "in-memory access-token verification should not fail: {err:?}"
        )),
    }
}

fn get_bearer_meta(store: &TokenStore, token: &str) -> Option<BearerTokenMeta> {
    match store.try_get_bearer_meta(token) {
        Ok(value) => value,
        Err(err) => fail_assertion(format!(
            "in-memory bearer metadata lookup should not fail: {err:?}"
        )),
    }
}

fn get_refresh_token(store: &TokenStore, token: &str) -> Option<RefreshToken> {
    match store.try_get_refresh_token(token) {
        Ok(value) => value,
        Err(err) => fail_assertion(format!(
            "in-memory refresh-token lookup should not fail: {err:?}"
        )),
    }
}

fn is_refresh_revoked(store: &TokenStore, token: &str) -> bool {
    match store.try_is_refresh_revoked(token) {
        Ok(value) => value,
        Err(err) => fail_assertion(format!(
            "in-memory refresh-token revocation check should not fail: {err:?}"
        )),
    }
}

fn redis_token_store_for_test(url: &str) -> TokenStore {
    TokenStore {
        backend: TokenStoreBackend::Redis(match RedisTokenStoreBackend::new_for_tests(url) {
            Ok(backend) => backend,
            Err(err) => fail_assertion(format!("redis token store backend: {err:?}")),
        }),
    }
}

fn redis_auth_code_store_for_test(url: &str) -> AuthCodeStore {
    AuthCodeStore {
        backend: Arc::new(match RedisAuthCodeBackend::new_for_tests(
            url,
            Duration::from_secs(300),
        ) {
            Ok(backend) => backend,
            Err(err) => fail_assertion(format!("redis authorization code store backend: {err:?}")),
        }),
    }
}

fn clear_redis_token_store_for_test(url: &str) {
    let backend = match RedisTokenStoreBackend::new_for_tests(url) {
        Ok(backend) => backend,
        Err(err) => fail_assertion(format!("redis token store backend: {err:?}")),
    };
    if let Err(err) = backend.clear_for_test() {
        fail_assertion(format!("clear token store state: {err:?}"));
    }
}
