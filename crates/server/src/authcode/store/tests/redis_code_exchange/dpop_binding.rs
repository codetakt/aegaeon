//! Real Redis CAS/failure tests at the trusted sender API boundary.
//! The signer barrier does not attest DPoP possession or replace the Redis adapter.
mod compatibility;
use super::*;
use crate::authcode::types::DpopKeyThumbprint;
use crate::kms::{InMemoryPublicJwtKeyManager, KeyManager, KeyManagerError};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc,
};

type Gate = (mpsc::Sender<()>, mpsc::Receiver<()>);
struct SigningGate {
    inner: InMemoryPublicJwtKeyManager,
    gate: Mutex<Option<Gate>>,
    signed: Mutex<Vec<String>>,
}
impl KeyManager for SigningGate {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, KeyManagerError> {
        let gate = self
            .gate
            .lock()
            .map_err(|_| KeyManagerError::OperationFailed)?
            .take();
        if let Some((reached, release)) = gate {
            reached
                .send(())
                .map_err(|_| KeyManagerError::OperationFailed)?;
            release
                .recv_timeout(Duration::from_secs(20))
                .map_err(|_| KeyManagerError::OperationFailed)?;
        }
        let signature = self.inner.sign(message)?;
        let input = std::str::from_utf8(message).map_err(|_| KeyManagerError::OperationFailed)?;
        self.signed
            .lock()
            .map_err(|_| KeyManagerError::OperationFailed)?
            .push(format!("{input}.{}", URL_SAFE_NO_PAD.encode(&signature)));
        Ok(signature)
    }
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool, KeyManagerError> {
        self.inner.verify(message, signature)
    }
    fn key_id(&self) -> String {
        self.inner.key_id()
    }
    fn jwt_signing_alg(&self) -> &'static str {
        self.inner.jwt_signing_alg()
    }
    fn jwt_signing_public_jwk(&self) -> Option<serde_json::Value> {
        self.inner.jwt_signing_public_jwk()
    }
    fn rotate(&self) -> Result<(), KeyManagerError> {
        self.inner.rotate()
    }
    fn revoke(&self) -> Result<(), KeyManagerError> {
        self.inner.revoke()
    }
}

struct BoundFixture {
    issuer: Arc<TokenIssuer>,
    signer: Arc<SigningGate>,
    code: String,
    code_key: String,
    key: String,
}
impl BoundFixture {
    fn new(url: &str, gate: Option<Gate>) -> Result<Self, String> {
        let namespace = crate::config::RuntimeStateNamespace::for_tests(format!(
            "dpop-code-{}",
            uuid::Uuid::new_v4()
        ));
        let codes = AuthCodeStore {
            backend: Arc::new(
                RedisAuthCodeBackend::new(url, Duration::from_secs(300), &namespace)
                    .map_err(|e| e.to_string())?,
            ),
        };
        let tokens = TokenStore {
            backend: TokenStoreBackend::Redis(
                RedisTokenStoreBackend::new(url, &namespace).map_err(|e| e.to_string())?,
            ),
        };
        let signer = Arc::new(SigningGate {
            inner: InMemoryPublicJwtKeyManager::new().map_err(|e| e.to_string())?,
            gate: Mutex::new(gate),
            signed: Mutex::new(Vec::new()),
        });
        let issuer = Arc::new(
            TokenIssuer::with_stores(signer.clone(), codes, tokens)
                .with_issuer("https://issuer.example".into())
                .with_jwt_access_tokens_enabled(true),
        );
        let key = URL_SAFE_NO_PAD.encode([71_u8; 32]);
        let mut value = make_test_code(None, None);
        value.user_id = format!("bound-user-{}", uuid::Uuid::new_v4());
        value.scope = Some("read offline_access".into());
        value.dpop_jkt = Some(DpopKeyThumbprint::parse(&key)?);
        value.code_challenge = Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".into());
        value.code_challenge_method = Some("S256".into());
        let code = issuer.code_store.store_code(value)?;
        let code_key = issuer
            .code_store
            .redis_commit_context(&code)
            .ok_or("code context")?
            .code_key;
        Ok(Self {
            issuer,
            signer,
            code,
            code_key,
            key,
        })
    }
    fn exchange(&self, key: &str) -> Result<TokenResponse, String> {
        exchange(&self.issuer, &self.code, key)
    }
    fn backend(&self) -> &RedisTokenStoreBackend {
        match &self.issuer.token_store.backend {
            TokenStoreBackend::Redis(backend) => backend,
            _ => panic!("real Redis required"),
        }
    }
    fn records(&self, conn: &mut redis::Connection) -> Result<BTreeMap<String, Vec<u8>>, String> {
        let mut keys: Vec<String> = redis::cmd("KEYS")
            .arg(self.backend().keyspace_for_tests().all_pattern())
            .query(conn)
            .map_err(|e| e.to_string())?;
        keys.sort();
        keys.into_iter()
            .map(|key| {
                let bytes: Vec<u8> = redis::cmd("DUMP")
                    .arg(&key)
                    .query(conn)
                    .map_err(|e| e.to_string())?;
                Ok((key, bytes))
            })
            .collect()
    }
    fn assert_counts(&self, count: usize) -> StoreTestResult {
        let snapshot = self.issuer.token_store.try_snapshot()?;
        assert_eq!(snapshot.access_tokens.len(), count);
        assert_eq!(snapshot.bearer_meta.len(), count);
        assert_eq!(snapshot.refresh_tokens.len(), count);
        assert_eq!(snapshot.refresh_grants.len(), count);
        Ok(())
    }
}
fn exchange(issuer: &TokenIssuer, code: &str, key: &str) -> Result<TokenResponse, String> {
    issuer.exchange_code_for_tokens_bound_with_grant_policy(
        request(code),
        Some(&CnfClaim::Jkt(key.into())),
        Some(&SenderBinding::DPoP { jkt: key.into() }),
        true,
        true,
    )
}
fn connect(url: &str) -> Result<redis::Connection, String> {
    redis::Client::open(url)
        .and_then(|client| client.get_connection())
        .map_err(|e| e.to_string())
}
fn expire_lease(conn: &mut redis::Connection, key: &str) -> StoreTestResult {
    let ttl: i64 = redis::cmd("PTTL")
        .arg(key)
        .query(conn)
        .map_err(|e| e.to_string())?;
    assert!(ttl > 0 && ttl <= 30_000);
    redis::cmd("PEXPIREAT")
        .arg(key)
        .arg(1)
        .query::<bool>(conn)
        .map_err(|e| e.to_string())?;
    assert_eq!(get(conn, key)?, None, "expire only the held staging lease");
    Ok(())
}
fn get(conn: &mut redis::Connection, key: &str) -> Result<Option<String>, String> {
    redis::cmd("GET")
        .arg(key)
        .query(conn)
        .map_err(|e| e.to_string())
}
fn set(conn: &mut redis::Connection, key: &str, value: &str) -> StoreTestResult {
    redis::cmd("SET")
        .arg(key)
        .arg(value)
        .arg("KEEPTTL")
        .query::<()>(conn)
        .map_err(|e| e.to_string())
}
fn server_error(response: TokenResponse, expected: &str) {
    assert!(
        matches!(response, TokenResponse::Error { ref error, error_description: Some(ref description) } if error == "server_error" && description.contains(expected)),
        "{response:?}"
    );
}
fn success(response: TokenResponse) -> Result<(String, String), String> {
    match response {
        TokenResponse::Success {
            access_token,
            refresh_token: Some(refresh),
            token_type,
            ..
        } => {
            assert_eq!(token_type, "DPoP");
            Ok((access_token, refresh))
        }
        other => Err(format!("expected bound grant: {other:?}")),
    }
}
fn paused(url: &str) -> Result<(BoundFixture, mpsc::Receiver<()>, mpsc::Sender<()>), String> {
    let (reached, waiting) = mpsc::channel();
    let (release, resume) = mpsc::channel();
    Ok((
        BoundFixture::new(url, Some((reached, resume)))?,
        waiting,
        release,
    ))
}
fn worker(f: &BoundFixture) -> thread::JoinHandle<Result<TokenResponse, String>> {
    let issuer = f.issuer.clone();
    let code = f.code.clone();
    let key = f.key.clone();
    thread::spawn(move || exchange(&issuer, &code, &key))
}

#[test]
#[ignore = "requires isolated AEGAEON_TEST_REDIS_URL"]
fn redis_bound_code_original_bytes_cas_rejects_key_and_format_changes() -> StoreTestResult {
    let url = redis_url()?;
    for change_key in [true, false] {
        let (f, reached, release) = paused(&url)?;
        let mut conn = connect(&url)?;
        let original = get(&mut conn, &f.code_key)?.ok_or("original code")?;
        let task = worker(&f);
        reached
            .recv_timeout(Duration::from_secs(10))
            .map_err(|e| e.to_string())?;
        let mut value: serde_json::Value =
            serde_json::from_str(&original).map_err(|e| e.to_string())?;
        let successor_key = if change_key {
            URL_SAFE_NO_PAD.encode([72_u8; 32])
        } else {
            f.key.clone()
        };
        if change_key {
            value["dpop_jkt"] = serde_json::json!(successor_key);
        }
        let changed = if change_key {
            original.replace(&f.key, &successor_key)
        } else {
            serde_json::to_string_pretty(&value).map_err(|e| e.to_string())?
        };
        assert_ne!(changed, original);
        if !change_key {
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(&changed).map_err(|e| e.to_string())?,
                serde_json::from_str::<serde_json::Value>(&original).map_err(|e| e.to_string())?
            );
        }
        set(&mut conn, &f.code_key, &changed)?;
        release.send(()).map_err(|e| e.to_string())?;
        server_error(
            task.join().map_err(|_| "exchange panic")??,
            "authorization code payload changed before grant commit",
        );
        assert_eq!(get(&mut conn, &f.code_key)?, Some(changed));
        f.assert_counts(0)?;
        assert!(
            f.records(&mut conn)?.is_empty(),
            "no loser record or index writes"
        );
        success(f.exchange(&successor_key)?)?;
        f.assert_counts(1)?;
        assert_eq!(get(&mut conn, &f.code_key)?, None);
    }
    Ok(())
}

#[test]
#[ignore = "requires isolated AEGAEON_TEST_REDIS_URL"]
fn redis_bound_code_expired_staging_lease_still_commits_only_one_sender() -> StoreTestResult {
    let url = redis_url()?;
    let (f, reached, release) = paused(&url)?;
    let mut conn = connect(&url)?;
    let first = worker(&f);
    reached
        .recv_timeout(Duration::from_secs(10))
        .map_err(|e| e.to_string())?;
    let lock = f.code_key.replace(":code:", ":exchange-lock:");
    expire_lease(&mut conn, &lock)?;
    let (winner, _) = success(f.exchange(&f.key)?)?;
    let committed = f.records(&mut conn)?;
    f.assert_counts(1)?;
    release.send(()).map_err(|e| e.to_string())?;
    assert!(invalid_code(first.join().map_err(|_| "exchange panic")?));
    assert_eq!(f.records(&mut conn)?, committed);
    let candidates = f.signer.signed.lock().map_err(|e| e.to_string())?;
    assert_eq!(
        candidates.len(),
        2,
        "both trusted matching senders reached signing"
    );
    for token in candidates.iter().filter(|token| *token != &winner) {
        assert_eq!(
            get(
                &mut conn,
                &f.backend().keyspace_for_tests().access_key(token)
            )?,
            None
        );
        assert_eq!(
            get(
                &mut conn,
                &f.backend().keyspace_for_tests().bearer_key(token)
            )?,
            None
        );
    }
    assert_eq!(get(&mut conn, &f.code_key)?, None);
    Ok(())
}

#[test]
#[ignore = "requires isolated AEGAEON_TEST_REDIS_URL"]
fn redis_bound_code_lineage_corruption_cannot_be_bypassed_by_matching_sender() -> StoreTestResult {
    let url = redis_url()?;
    for fault in ["missing", "malformed", "revoked", "client_id", "user_id"] {
        let f = BoundFixture::new(&url, None)?;
        let (access, refresh) = success(f.exchange(&f.key)?)?;
        f.assert_counts(1)?;
        let store = &f.issuer.token_store;
        let parent = store
            .try_get_refresh_token(&refresh)?
            .ok_or("issued refresh")?;
        assert_eq!(
            parent.sender_binding,
            Some(SenderBinding::DPoP { jkt: f.key.clone() })
        );
        let reference = parent.refresh_grant.as_ref().ok_or("independent lineage")?;
        let key = f
            .backend()
            .keyspace_for_tests()
            .refresh_grant_key(&reference.id);
        let mut conn = connect(&url)?;
        let original = get(&mut conn, &key)?.ok_or("lineage bytes")?;
        match fault {
            "missing" => {
                redis::cmd("DEL")
                    .arg(&key)
                    .query::<usize>(&mut conn)
                    .map_err(|e| e.to_string())?;
            }
            "malformed" => set(&mut conn, &key, "{malformed")?,
            _ => {
                let mut value: serde_json::Value =
                    serde_json::from_str(&original).map_err(|e| e.to_string())?;
                if fault == "revoked" {
                    value["revoked"] = serde_json::json!(true);
                } else {
                    value[fault] = serde_json::json!("different-original-owner");
                }
                set(
                    &mut conn,
                    &key,
                    &serde_json::to_string(&value).map_err(|e| e.to_string())?,
                )?;
            }
        }
        let before = f.records(&mut conn)?;
        assert!(store.try_verify_access_token(&access)?.is_none(), "{fault}");
        assert!(store.try_get_refresh_token(&refresh)?.is_none(), "{fault}");
        let response = f.issuer.refresh_access_token_bound(
            &refresh,
            None,
            Some(&CnfClaim::Jkt(f.key.clone())),
            Some(&SenderBinding::DPoP { jkt: f.key.clone() }),
        );
        assert_eq!(
            response.unwrap_err(),
            "Invalid or rotated refresh token",
            "{fault}"
        );
        assert_eq!(
            f.records(&mut conn)?,
            before,
            "lineage cannot be restored or new descendants written"
        );
        assert_eq!(get(&mut conn, &f.code_key)?, None);
    }
    Ok(())
}

#[test]
#[ignore = "requires isolated AEGAEON_TEST_REDIS_URL"]
fn redis_bound_code_wrong_type_preflight_preserves_exact_retry_authority() -> StoreTestResult {
    let url = redis_url()?;
    let f = BoundFixture::new(&url, None)?;
    let mut conn = connect(&url)?;
    let code = f.issuer.code_store.try_get_code(&f.code)?.ok_or("code")?;
    let index = f
        .backend()
        .keyspace_for_tests()
        .subject_bearer_key(&code.user_id);
    set(&mut conn, &index, "owned-wrong-type-fixture")?;
    let original = get(&mut conn, &f.code_key)?;
    let before = f.records(&mut conn)?;
    server_error(f.exchange(&f.key)?, "index_type");
    assert_eq!(get(&mut conn, &f.code_key)?, original);
    assert_eq!(f.records(&mut conn)?, before);
    redis::cmd("DEL")
        .arg(index)
        .query::<usize>(&mut conn)
        .map_err(|e| e.to_string())?;
    success(f.exchange(&f.key)?)?;
    f.assert_counts(1)
}

#[test]
#[ignore = "requires isolated AEGAEON_TEST_REDIS_URL with ACL administration"]
fn redis_bound_code_post_destructive_acl_failure_does_not_restore_code() -> StoreTestResult {
    let url = redis_url()?;
    let mut admin = connect(&url)?;
    let principal = format!("bound-code-{}", uuid::Uuid::new_v4());
    redis::cmd("ACL")
        .arg("SETUSER")
        .arg(&principal)
        .arg(&[
            "reset",
            "on",
            ">public-bound-code-fixture",
            "~*",
            "+@all",
            "-sadd",
        ])
        .query::<()>(&mut admin)
        .map_err(|e| e.to_string())?;
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> StoreTestResult {
        let mut restricted = url::Url::parse(&url).map_err(|e| e.to_string())?;
        restricted
            .set_username(&principal)
            .map_err(|_| "username")?;
        restricted
            .set_password(Some("public-bound-code-fixture"))
            .map_err(|_| "password")?;
        let mut connection = connect(restricted.as_str())?;
        assert_eq!(
            redis::cmd("ACL")
                .arg("WHOAMI")
                .query::<String>(&mut connection)
                .map_err(|e| e.to_string())?,
            principal
        );
        let f = BoundFixture::new(restricted.as_str(), None)?;
        let response = f.exchange(&f.key)?;
        assert!(
            matches!(response, TokenResponse::Error { ref error, error_description: Some(ref d) } if error == "server_error" && (d.contains("permission") || d.contains("NOPERM"))),
            "{response:?}"
        );
        assert_eq!(get(&mut admin, &f.code_key)?, None);
        let signed = f.signer.signed.lock().map_err(|e| e.to_string())?.clone();
        assert_eq!(signed.len(), 1);
        let key = f.backend().keyspace_for_tests().access_key(&signed[0]);
        assert!(
            get(&mut admin, &key)?.is_some(),
            "real access SET survived later SADD error"
        );
        assert!(
            f.issuer
                .token_store
                .try_verify_access_token(&signed[0])?
                .is_none(),
            "partial grant inactive"
        );
        let before = f.records(&mut admin)?;
        assert!(invalid_code(f.exchange(&f.key)));
        assert_eq!(f.records(&mut admin)?, before);
        assert_eq!(get(&mut admin, &f.code_key)?, None);
        Ok(())
    }));
    redis::cmd("ACL")
        .arg("DELUSER")
        .arg(principal)
        .query::<usize>(&mut admin)
        .map_err(|e| e.to_string())?;
    match result {
        Ok(result) => result,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

// A RESP2 transport relay, never an emulated Redis store. It forwards the final
// Lua command, reads a real successful Redis reply, and drops only that reply.
struct ReplyLoss {
    url: String,
    armed_code: Arc<Mutex<Option<String>>>,
    witnessed: Arc<AtomicBool>,
    stopped: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}
fn resp(reader: &mut impl BufRead) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    if reader.read_until(b'\n', &mut bytes)? == 0 {
        return Err(io::ErrorKind::UnexpectedEof.into());
    }
    if bytes.len() < 3 || !bytes.ends_with(b"\r\n") {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let number = || {
        std::str::from_utf8(&bytes[1..bytes.len() - 2])
            .ok()
            .and_then(|s| s.parse::<i64>().ok())
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))
    };
    match bytes[0] {
        b'$' => {
            let length = number()?;
            if length >= 0 {
                let mut value =
                    vec![0; usize::try_from(length).map_err(|_| io::ErrorKind::InvalidData)? + 2];
                reader.read_exact(&mut value)?;
                bytes.extend(value);
            }
        }
        b'*' => {
            for _ in 0..number()?.max(0) {
                bytes.extend(resp(reader)?);
            }
        }
        b'+' | b'-' | b':' => (),
        _ => return Err(io::ErrorKind::InvalidData.into()),
    }
    Ok(bytes)
}
fn relay(
    mut client: TcpStream,
    target: &str,
    armed: &Mutex<Option<String>>,
    witnessed: &AtomicBool,
) -> std::io::Result<()> {
    let mut upstream = TcpStream::connect(target)?;
    client.set_read_timeout(Some(Duration::from_secs(5)))?;
    upstream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut requests = BufReader::new(client.try_clone()?);
    let mut responses = BufReader::new(upstream.try_clone()?);
    loop {
        let request = resp(&mut requests)?;
        upstream.write_all(&request)?;
        let response = resp(&mut responses)?;
        let mut code = armed.lock().map_err(|_| io::ErrorKind::Other)?;
        let is_commit = code.as_ref().is_some_and(|key| {
            let field = format!("${}\r\n{key}\r\n", key.len());
            request
                .windows(field.len())
                .any(|window| window == field.as_bytes())
                && (request.windows(7).any(|w| w == b"EVALSHA")
                    || request.windows(4).any(|w| w == b"EVAL"))
        });
        if is_commit && (response == b"$2\r\nok\r\n" || response == b"+ok\r\n") {
            code.take();
            witnessed.store(true, Ordering::SeqCst);
            client.shutdown(Shutdown::Both)?;
            return Ok(());
        }
        drop(code);
        client.write_all(&response)?;
    }
}
impl ReplyLoss {
    fn new(redis_url: &str) -> Result<Self, String> {
        let mut url = url::Url::parse(redis_url).map_err(|e| e.to_string())?;
        if url.scheme() != "redis" {
            return Err("reply-loss fixture requires owned TCP Redis".into());
        }
        let target = format!(
            "{}:{}",
            url.host_str().ok_or("Redis host")?,
            url.port().unwrap_or(6379)
        );
        let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
        listener.set_nonblocking(true).map_err(|e| e.to_string())?;
        let port = listener.local_addr().map_err(|e| e.to_string())?.port();
        url.set_host(Some("127.0.0.1")).map_err(|e| e.to_string())?;
        url.set_port(Some(port)).map_err(|_| "proxy port")?;
        let armed_code = Arc::new(Mutex::new(None));
        let witnessed = Arc::new(AtomicBool::new(false));
        let stopped = Arc::new(AtomicBool::new(false));
        let (armed, seen, stop) = (armed_code.clone(), witnessed.clone(), stopped.clone());
        let task = thread::spawn(move || {
            let mut children = Vec::new();
            while !stop.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((client, _)) => {
                        let (target, armed, seen) = (target.clone(), armed.clone(), seen.clone());
                        children.push(thread::spawn(move || {
                            let _ = relay(client, &target, &armed, &seen);
                        }));
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2))
                    }
                    Err(_) => break,
                }
            }
            for child in children {
                let _ = child.join();
            }
        });
        Ok(Self {
            url: url.to_string(),
            armed_code,
            witnessed,
            stopped,
            thread: Some(task),
        })
    }
}
impl Drop for ReplyLoss {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::SeqCst);
        if let Some(task) = self.thread.take() {
            let _ = task.join();
        }
    }
}

fn wait_for_lock_expiry(conn: &mut redis::Connection, lock: &str) -> StoreTestResult {
    let ttl: i64 = redis::cmd("PTTL")
        .arg(lock)
        .query(conn)
        .map_err(|e| e.to_string())?;
    assert!(
        ttl > 0 && ttl <= 30_000,
        "lost-reply mutation lock has finite TTL"
    );
    let deadline = std::time::Instant::now() + Duration::from_secs(35);
    while get(conn, lock)?.is_some() {
        assert!(
            std::time::Instant::now() < deadline,
            "mutation lock must expire"
        );
        thread::sleep(Duration::from_millis(20));
    }
    Ok(())
}

#[test]
#[ignore = "requires isolated AEGAEON_TEST_REDIS_URL over TCP"]
fn redis_bound_code_lost_successful_reply_never_restores_consumed_authority() -> StoreTestResult {
    let url = redis_url()?;
    let proxy = ReplyLoss::new(&url)?;
    let f = BoundFixture::new(&proxy.url, None)?;
    *proxy.armed_code.lock().map_err(|e| e.to_string())? = Some(f.code_key.clone());
    let response = f.exchange(&f.key)?;
    assert!(
        proxy.witnessed.load(Ordering::SeqCst),
        "real final Lua success was received before dropping reply"
    );
    assert!(
        matches!(response, TokenResponse::Error { ref error, .. } if error == "server_error"),
        "{response:?}"
    );
    let mut conn = connect(&url)?;
    assert_eq!(get(&mut conn, &f.code_key)?, None);
    // The lost connection also prevents owner-safe lock release. Observe its
    // normal expiry without deleting or rewriting any server state.
    let lock = f.backend().keyspace_for_tests().lock_key();
    let mut before_expiry = f.records(&mut conn)?;
    assert!(before_expiry.remove(&lock).is_some());
    wait_for_lock_expiry(&mut conn, &lock)?;
    f.assert_counts(1)?;
    assert_eq!(f.records(&mut conn)?, before_expiry);
    let signed = f.signer.signed.lock().map_err(|e| e.to_string())?.clone();
    assert_eq!(signed.len(), 1);
    assert!(f
        .issuer
        .token_store
        .try_verify_access_token(&signed[0])?
        .is_some());
    let committed = f.records(&mut conn)?;
    assert!(invalid_code(f.exchange(&f.key)));
    assert_eq!(f.records(&mut conn)?, committed);
    assert_eq!(get(&mut conn, &f.code_key)?, None);
    Ok(())
}
