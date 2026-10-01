use super::*;
use serde_json::{json, Value as Json};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

const URI: &str = "https://example.com/ledger.json";
const PASSWORD: &str = "owned-local-fixture-only";

fn pairs() -> HashMap<String, String> {
    HashMap::from([("kid-A".to_owned(), "fp-A".to_owned())])
}

fn policy(ttl: u64) -> JwksRuntimePolicy {
    JwksRuntimePolicy {
        cache_ttl_secs: ttl,
        shared_state_max_age_secs: ttl,
        circuit_reset_secs: 1,
        ..JwksRuntimePolicy::default()
    }
}

struct Backend {
    dir: PathBuf,
    url: String,
    child: Option<Child>,
}

impl Backend {
    fn start(label: &str) -> Self {
        assert_eq!(
            std::fs::read_link("/proc/self/ns/net")
                .unwrap()
                .to_string_lossy(),
            std::env::var("JWKS_LEDGER_TEST_NETNS").unwrap()
        );
        let id = uuid::Uuid::new_v4();
        let dir = PathBuf::from(std::env::var_os("JWKS_LEDGER_TEST_DIR").unwrap())
            .join(format!("ledger-{id}"));
        std::fs::create_dir(&dir).unwrap();
        let record = PathBuf::from(std::env::var_os("JWKS_LEDGER_TEST_DIR").unwrap());
        let log = record.join(format!("ledger-{label}-{id}.log"));
        let server = std::env::var("JWKS_LEDGER_TEST_SERVER").unwrap();
        let child = Command::new(&server)
            .args(["--port", "0", "--unixsocket"])
            .arg(dir.join("redis.sock"))
            .args([
                "--unixsocketperm",
                "700",
                "--save",
                "",
                "--appendonly",
                "no",
                "--daemonize",
                "no",
                "--logfile",
            ])
            .arg(&log)
            .arg("--dir")
            .arg(&dir)
            .spawn()
            .unwrap();
        let url = format!("redis+unix://{}", dir.join("redis.sock").display());
        let fixture = Self {
            dir,
            url,
            child: Some(child),
        };
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if redis::Client::open(fixture.url.as_str())
                .unwrap()
                .get_connection()
                .is_ok()
            {
                break;
            }
            assert!(Instant::now() < deadline, "owned backend did not start");
            std::thread::sleep(Duration::from_millis(10));
        }
        let mut connection = fixture.connection();
        let info: String = redis::cmd("INFO")
            .arg("server")
            .query(&mut connection)
            .unwrap();
        fixture.note("backend", json!({"server":server,"pid":fixture.child.as_ref().unwrap().id(),
            "socket":fixture.dir.join("redis.sock"),"log":log,"info":info,
            "config":{"port":0,"unixsocketperm":"700","save":"","appendonly":"no","daemonize":"no"}}));
        fixture
    }

    fn note(&self, case: &str, value: Json) {
        eprintln!("{case}: {value}");
    }

    fn connection(&self) -> redis::Connection {
        redis::Client::open(self.url.as_str())
            .unwrap()
            .get_connection()
            .unwrap()
    }

    fn state(&self) -> RedisJwksRuntimeState {
        RedisJwksRuntimeState::new_for_tests(&self.url).unwrap()
    }

    fn user(&self, rules: &[&str], db: u8) -> RedisJwksRuntimeState {
        let mut connection = self.connection();
        let mut command = redis::cmd("ACL");
        command
            .arg("SETUSER")
            .arg("ledger-user")
            .arg("reset")
            .arg("on")
            .arg(format!(">{PASSWORD}"))
            .arg("~*")
            .arg("+@all");
        for rule in rules {
            command.arg(rule);
        }
        command.query::<()>(&mut connection).unwrap();
        self.note("ACL principal", json!({"user":"ledger-user","rules_after_reset_on_test_password_allkeys_allcommands":rules,"db":db}));
        RedisJwksRuntimeState::new_for_tests(&format!(
            "{}?user=ledger-user&pass={PASSWORD}&db={db}",
            self.url
        ))
        .unwrap()
    }

    fn reset_key(&self) {
        redis::cmd("DEL")
            .arg(self.state().key("kid-fps", URI))
            .query::<i64>(&mut self.connection())
            .unwrap();
    }

    fn snapshot(&self) -> Json {
        let key = self.state().key("kid-fps", URI);
        let mut connection = self.connection();
        let kind: String = redis::cmd("TYPE").arg(&key).query(&mut connection).unwrap();
        let fields = if kind == "hash" {
            redis::cmd("HGETALL")
                .arg(&key)
                .query::<std::collections::BTreeMap<String, String>>(&mut connection)
                .unwrap()
        } else {
            std::collections::BTreeMap::new()
        };
        let ttl: i64 = redis::cmd("PTTL").arg(&key).query(&mut connection).unwrap();
        let expiry = redis::cmd("PEXPIRETIME")
            .arg(&key)
            .query::<i64>(&mut connection)
            .ok();
        json!({"kind":kind,"fields":fields,"pttl":ttl,"absolute_expiry_if_supported":expiry})
    }

    fn capable(&self) -> bool {
        redis::cmd("EVAL")
            .arg("return type(rawget(redis, 'acl_check_cmd')) == 'function' and 1 or 0")
            .arg(0)
            .query::<i64>(&mut self.connection())
            .unwrap()
            == 1
    }

    fn finish(mut self) {
        self.stop();
        assert!(self.child.is_none());
        assert!(!self.dir.exists());
    }

    fn stop(&mut self) {
        if let Some(mut child) = self.child.take() {
            if let Ok(mut connection) = redis::Client::open(self.url.as_str())
                .unwrap()
                .get_connection()
            {
                let _ = redis::cmd("SHUTDOWN")
                    .arg("NOSAVE")
                    .query::<()>(&mut connection);
            }
            let deadline = Instant::now() + Duration::from_secs(3);
            let mut forced = false;
            let status = loop {
                if let Some(status) = child.try_wait().unwrap() {
                    break status;
                }
                if Instant::now() > deadline {
                    forced = true;
                    let _ = child.kill();
                    break child.wait().unwrap();
                }
                std::thread::sleep(Duration::from_millis(10));
            };
            let pid = child.id();
            let absent = !PathBuf::from(format!("/proc/{pid}")).exists();
            let _ = std::fs::remove_dir_all(&self.dir);
            self.note("cleanup",json!({"pid":pid,"pid_absent":absent,"forced":forced,"exit_code":status.code(),"directory_absent":!self.dir.exists()}));
        }
    }
}

impl Drop for Backend {
    fn drop(&mut self) {
        self.stop();
    }
}

#[test]
fn empty_and_ttl_policy_keep_owned_boundaries() {
    for (value, expected) in [
        (1, 60),
        (60, 60),
        (86_400, 86_400),
        (9_223_372_036_854_775, 9_223_372_036_854_775),
    ] {
        assert_eq!(
            RedisJwksRuntimeState::ttl_i64(&policy(value)).unwrap(),
            expected
        );
    }
    assert!(matches!(
        RedisJwksRuntimeState::ttl_i64(&policy(u64::MAX)),
        Err(JwksSharedStateError::RetentionOverflow)
    ));
    let unavailable = RedisJwksRuntimeState::new_for_tests(
        "redis+unix:///nonexistent-aegaeon-ledger-fixture.sock",
    )
    .unwrap();
    assert!(!unavailable
        .record_kid_fingerprints(&policy(u64::MAX), URI, &HashMap::new())
        .unwrap());
    assert!(unavailable
        .record_kid_fingerprints(&policy(60), URI, &pairs())
        .is_err());
    let runtime = super::super::JwksRuntimeState::with_shared_state(
        super::super::JwksSharedRuntimeState::Redis(unavailable),
    );
    let mut reuse = policy(u64::MAX);
    reuse.allow_kid_reuse = true;
    assert!(
        !crate::client_registry::shared_kid_reuse_changed_with_state(
            &runtime,
            &reuse,
            URI,
            &pairs(),
        )
        .unwrap()
    );
    let mut reset = policy(1);
    reset.circuit_reset_secs = 3_600;
    assert_eq!(RedisJwksRuntimeState::ttl_i64(&reset).unwrap(), 14_400);
}

#[test]
#[ignore = "requires scripts/validation/test_jwks_fingerprint_ledger.py"]
fn normal_episode_and_conflict() {
    let backend = Backend::start("normal");
    let state = backend.state();
    let capable = backend.capable();
    assert!(!state
        .record_kid_fingerprints(&policy(90), URI, &pairs())
        .unwrap());
    let first = backend.snapshot();
    assert_eq!(first["fields"]["kid-A"], "fp-A");
    assert!(first["pttl"].as_i64().unwrap() > 88_000);
    let next = HashMap::from([("kid-B".into(), "fp-B".into())]);
    assert!(!state
        .record_kid_fingerprints(&policy(60), URI, &next)
        .unwrap());
    let second = backend.snapshot();
    assert_eq!(second["fields"].as_object().unwrap().len(), 2);
    assert!(second["pttl"].as_i64().unwrap() <= 60_000);
    assert!(!state
        .record_kid_fingerprints(&policy(120), URI, &pairs())
        .unwrap());
    let renewed = backend.snapshot();
    assert!(renewed["pttl"].as_i64().unwrap() > 118_000);
    let conflict = HashMap::from([
        ("kid-A".into(), "changed".into()),
        ("new-kid".into(), "new-fp".into()),
    ]);
    assert!(state
        .record_kid_fingerprints(&policy(600), URI, &conflict)
        .unwrap());
    let refused = backend.snapshot();
    assert_eq!(renewed["fields"], refused["fields"]);
    if capable {
        assert_eq!(
            renewed["absolute_expiry_if_supported"],
            refused["absolute_expiry_if_supported"]
        );
    }
    redis::cmd("PERSIST")
        .arg(state.key("kid-fps", URI))
        .query::<i64>(&mut backend.connection())
        .unwrap();
    assert_eq!(backend.snapshot()["pttl"], -1);
    assert!(!state
        .record_kid_fingerprints(&policy(60), URI, &pairs())
        .unwrap());
    assert!(backend.snapshot()["pttl"].as_i64().unwrap() > 58_000);
    backend.note("admission renewal and conflict",json!({"capable":capable,"first":first,"union":second,"renewed":renewed,"conflict":refused,"persistent_repaired_by_success":backend.snapshot()}));
    backend.finish();
}

#[test]
#[ignore = "requires scripts/validation/test_jwks_fingerprint_ledger.py"]
fn acl_denials_and_legacy_residue() {
    let backend = Backend::start("acl");
    let key = backend.state().key("kid-fps", URI);
    let capable = backend.capable();
    for initial in ["absent", "expired", "finite", "persistent"] {
        backend.reset_key();
        if initial != "absent" {
            redis::cmd("HSET")
                .arg(&key)
                .arg("old")
                .arg("old-fp")
                .query::<i64>(&mut backend.connection())
                .unwrap();
        }
        if initial == "expired" {
            redis::cmd("PEXPIRE")
                .arg(&key)
                .arg(1)
                .query::<i64>(&mut backend.connection())
                .unwrap();
            std::thread::sleep(Duration::from_millis(5));
        } else if initial == "finite" {
            redis::cmd("PEXPIRE")
                .arg(&key)
                .arg(30_000)
                .query::<i64>(&mut backend.connection())
                .unwrap();
        }
        let before = backend.snapshot();
        let restricted = backend.user(&["-expire"], 0);
        let result = restricted.record_kid_fingerprints(&policy(60), URI, &pairs());
        assert!(result.is_err());
        let after = backend.snapshot();
        if capable {
            assert_eq!(before["kind"], after["kind"]);
            assert_eq!(before["fields"], after["fields"]);
            assert_eq!(
                before["absolute_expiry_if_supported"],
                after["absolute_expiry_if_supported"]
            );
        } else {
            assert_eq!(after["fields"]["kid-A"], "fp-A");
            if initial != "finite" {
                assert_eq!(after["pttl"], -1);
            }
        }
        backend.note("expiry ACL rejection",json!({"capable":capable,"initial":initial,"before":before,"after":after,"caller_error":result.unwrap_err().to_string(),"known_residue":!capable}));
    }
    for denied in ["-hget", "-hset", "-evalsha"] {
        backend.reset_key();
        let state = backend.user(&[denied], 0);
        let error = state
            .record_kid_fingerprints(&policy(60), URI, &pairs())
            .unwrap_err();
        assert_eq!(backend.snapshot()["kind"], "none");
        backend.note(
            "command ACL rejection",
            json!({"denied":denied,"error":error.to_string(),"after":backend.snapshot()}),
        );
    }
    backend.reset_key();
    redis::cmd("SET")
        .arg(&key)
        .arg("wrong-type")
        .query::<()>(&mut backend.connection())
        .unwrap();
    assert!(backend
        .state()
        .record_kid_fingerprints(&policy(60), URI, &pairs())
        .is_err());
    assert_eq!(backend.snapshot()["kind"], "string");
    backend.reset_key();
    assert!(!backend
        .state()
        .record_kid_fingerprints(&policy(60), URI, &pairs())
        .unwrap());
    let restricted = backend.user(&["-expire"], 0);
    assert!(restricted
        .record_kid_fingerprints(
            &policy(60),
            URI,
            &HashMap::from([("kid-A".into(), "changed".into())])
        )
        .unwrap());
    backend.note(
        "conflict precedes expiry permission",
        json!({"wrong_type_rejected":true,"conflict_before_expire_permission":true}),
    );
    backend.finish();
}

#[test]
#[ignore = "requires scripts/validation/test_jwks_fingerprint_ledger.py"]
fn exact_key_and_valkey_database_selectors() {
    let backend = Backend::start("selectors");
    backend.reset_key();
    let denied = backend.user(&["resetkeys", "~other-key"], 0);
    assert!(denied
        .record_kid_fingerprints(&policy(60), URI, &pairs())
        .is_err());
    assert_eq!(backend.snapshot()["kind"], "none");
    backend.note("key ACL rejection", json!({"exact_key_refused":true}));
    if std::env::var("JWKS_LEDGER_TEST_ENGINE").unwrap() == "valkey" {
        let state0 = backend.user(
            &[
                "resetkeys",
                "-@all",
                "resetdbs",
                "(db=0 ~* +@all)",
                "(db=1 ~* +@all -expire)",
            ],
            0,
        );
        assert!(!state0
            .record_kid_fingerprints(&policy(60), URI, &pairs())
            .unwrap());
        let state1 = RedisJwksRuntimeState::new_for_tests(&format!(
            "{}?user=ledger-user&pass={PASSWORD}&db=1",
            backend.url
        ))
        .unwrap();
        let error = state1
            .record_kid_fingerprints(&policy(60), URI, &pairs())
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("EXPIRE permission preflight failed"));
        let mut db1 = backend.connection();
        redis::cmd("SELECT").arg(1).query::<()>(&mut db1).unwrap();
        let absent: i64 = redis::cmd("EXISTS")
            .arg(state1.key("kid-fps", URI))
            .query(&mut db1)
            .unwrap();
        assert_eq!(absent, 0);
        backend.note("database ACL rejection",json!({"same_user":"ledger-user","db0_success":true,"db1_error":error.to_string(),"db1_key_exists":absent}));
    }
    backend.finish();
}

fn invoke_wire(
    backend: &Backend,
    keys: &[&str],
    args: &[&str],
) -> redis::RedisResult<redis::Value> {
    let mut command = redis::cmd("EVAL");
    command.arg(RECORD_KID_FINGERPRINTS_SCRIPT).arg(keys.len());
    for key in keys {
        command.arg(*key);
    }
    for arg in args {
        command.arg(*arg);
    }
    command.query(&mut backend.connection())
}

#[test]
#[ignore = "requires scripts/validation/test_jwks_fingerprint_ledger.py"]
fn integer_wire_and_remaining_time_overflow() {
    let backend = Backend::start("ttl");
    assert_ne!(std::env::var("JWKS_LEDGER_TEST_ENGINE").unwrap(),"redis-legacy",
        "Redis 6.2 lacks the inspected newer expiry arithmetic guards; this regression exercises newer engines");
    let state = backend.state();
    let key = state.key("kid-fps", URI);
    for bad in ["0", "01", "+1", "-1", "1.0", "nan", "9223372036854776"] {
        backend.reset_key();
        assert!(invoke_wire(&backend, &[&key], &[bad, "kid-A", "fp-A"]).is_err());
        assert_eq!(backend.snapshot()["kind"], "none");
        backend.note(
            "invalid TTL",
            json!({"ttl":bad,"rejected_before_write":true}),
        );
    }
    for (keys, args) in [
        (vec![], vec!["60", "kid-A", "fp-A"]),
        (vec![key.as_str(), "extra"], vec!["60", "kid-A", "fp-A"]),
        (vec![key.as_str()], vec!["60", "kid-A"]),
        (vec![key.as_str()], vec!["60"]),
    ] {
        assert!(invoke_wire(&backend, &keys, &args).is_err());
        assert_eq!(backend.snapshot()["kind"], "none");
    }
    for seconds in [
        9_007_199_254_740_991_u64,
        9_007_199_254_740_992,
        9_007_199_254_740_993,
    ] {
        backend.reset_key();
        assert!(!state
            .record_kid_fingerprints(&policy(seconds), URI, &pairs())
            .unwrap());
        let after = backend.snapshot();
        assert_eq!(after["fields"]["kid-A"], "fp-A");
        let remaining = after["pttl"].as_i64().unwrap();
        let exact = i64::try_from(u128::from(seconds) * 1000).unwrap();
        assert!((exact - 10_000..=exact).contains(&remaining));
        backend.note("integer precision",json!({"seconds_exact_decimal":seconds.to_string(),"milliseconds_exact_decimal":exact.to_string(),"after":after,"oracle":"u128 multiply; no float"}));
    }
    backend.reset_key();
    let biggest = 9_223_372_036_854_775;
    let result = state.record_kid_fingerprints(&policy(biggest), URI, &pairs());
    assert!(result.is_err());
    let residual = backend.snapshot();
    assert_eq!(residual["fields"]["kid-A"], "fp-A");
    assert_eq!(residual["pttl"], -1);
    backend.note("expiry addition overflow",json!({"ttl_seconds":biggest.to_string(),"expected_time_addition_residue":residual,"error":result.unwrap_err().to_string(),"clock_changed":false,"scope":"direct real Rust shared helper under arbitrary internal policy"}));
    let conflict = HashMap::from([("kid-A".into(), "changed".into())]);
    assert!(state
        .record_kid_fingerprints(&policy(biggest + 1), URI, &conflict)
        .unwrap());
    backend.note(
        "conflict precedes TTL overflow",
        json!({"conflict_before_ms_overflow":true}),
    );
    backend.reset_key();
    let binary = HashMap::from([
        ("".to_string(), "".to_string()),
        ("kid\0binary".to_string(), "fp\0value".to_string()),
    ]);
    assert!(!state
        .record_kid_fingerprints(&policy(60), URI, &binary)
        .unwrap());
    let observed: HashMap<String, String> = redis::cmd("HGETALL")
        .arg(&key)
        .query(&mut backend.connection())
        .unwrap();
    assert_eq!(observed, binary);
    backend.note("binary-safe fields", json!({"fields":observed}));
    backend.finish();
}

#[test]
#[ignore = "requires scripts/validation/test_jwks_fingerprint_ledger.py"]
fn controlled_capability_and_expiry_reply() {
    let backend = Backend::start("controlled");
    for (label, capability, expire_reply, writes, expiry_calls) in [
        ("true", "function() return true end", "1", 1, 1),
        ("false", "function() return false end", "1", 0, 0),
        (
            "raises",
            "function() error('synthetic ACL failure') end",
            "1",
            0,
            0,
        ),
        ("nonboolean", "function() return 1 end", "1", 0, 0),
        ("nil", "nil", "1", 1, 1),
        ("nonfunction", "7", "1", 0, 0),
        ("expire-zero", "function() return true end", "0", 1, 1),
        (
            "expire-noninteger",
            "function() return true end",
            "'unexpected'",
            1,
            1,
        ),
    ] {
        let controlled = format!("local base = redis; local writes=0; local expiry=0; local redis={{error_reply=base.error_reply, acl_check_cmd={capability}, call=function(cmd, ...) if cmd=='HGET' then return false elseif cmd=='HSET' then writes=writes+1; return 1 elseif cmd=='EXPIRE' then expiry=expiry+1; return {expire_reply} end end}}; local function run()\n{RECORD_KID_FINGERPRINTS_SCRIPT}\nend; local ok,value=pcall(run); local message=type(value)=='table' and value.err or tostring(value); return {{ok and 1 or 0,writes,expiry,message}}");
        let reply: (i64, i64, i64, String) = redis::cmd("EVAL")
            .arg(&controlled)
            .arg(1)
            .arg("controlled-key")
            .arg(60)
            .arg("kid")
            .arg("fp")
            .query(&mut backend.connection())
            .unwrap();
        assert_eq!(reply.1, writes);
        assert_eq!(reply.2, expiry_calls);
        if label == "true" || label == "nil" {
            assert_eq!(reply.3, "0");
        }
        if label.starts_with("expire-") {
            assert!(reply.3.contains("unexpected JWKS ledger expiry reply"));
        }
        backend.note("controlled backend API",json!({"label":label,"reply":reply,"controlled_shadow_api":true,"core_capability":backend.capable(),"script":"exact production Lua inside explicit local API wrapper"}));
    }
    backend.finish();
}

#[test]
#[ignore = "requires scripts/validation/test_jwks_fingerprint_ledger.py"]
fn cold_noscript_and_transport_reply_loss() {
    let backend = Backend::start("unknown");
    let state = backend.state();
    let script = redis::Script::new(RECORD_KID_FINGERPRINTS_SCRIPT);
    redis::cmd("SCRIPT")
        .arg("FLUSH")
        .query::<()>(&mut backend.connection())
        .unwrap();
    let missing = redis::cmd("EVALSHA")
        .arg(script.get_hash())
        .arg(1)
        .arg(state.key("kid-fps", URI))
        .arg(60)
        .arg("kid-A")
        .arg("fp-A")
        .query::<redis::Value>(&mut backend.connection())
        .unwrap_err();
    assert_eq!(missing.kind(), redis::ErrorKind::NoScriptError);
    assert!(!state
        .record_kid_fingerprints(&policy(60), URI, &pairs())
        .unwrap());
    let exists: Vec<i64> = redis::cmd("SCRIPT")
        .arg("EXISTS")
        .arg(script.get_hash())
        .query(&mut backend.connection())
        .unwrap();
    assert_eq!(exists, vec![1]);
    backend.note("cold script load",json!({"typed_missing":"NoScriptError","after_helper_script_exists":exists,"after":backend.snapshot()}));
    backend.reset_key();
    let proxy_path = backend.dir.join("reply-loss.sock");
    let listener = UnixListener::bind(&proxy_path).unwrap();
    listener.set_nonblocking(true).unwrap();
    let upstream_path = backend.dir.join("redis.sock");
    let relay = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut caller = loop {
            match listener.accept() {
                Ok((caller, _)) => break caller,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "Redis client did not connect");
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(error) => panic!("reply-loss fixture accept: {error}"),
            }
        };
        let upstream = UnixStream::connect(upstream_path).unwrap();
        upstream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut requests = caller.try_clone().unwrap();
        let mut writer = upstream.try_clone().unwrap();
        let sending = std::thread::spawn(move || std::io::copy(&mut requests, &mut writer));
        let mut responses = BufReader::new(upstream);
        let mut forwarded = Vec::new();
        // Pinned redis-rs RESP2/no-auth/db0 setup sends two CLIENT SETINFO commands.
        // These named backends answer each with one simple/error line. This is a
        // bounded fixture contract, not a general RESP parser or retry proxy.
        for _ in 0..2 {
            let mut line = Vec::new();
            responses.read_until(b'\n', &mut line).unwrap();
            assert!(matches!(line.first(), Some(b'+') | Some(b'-')));
            caller.write_all(&line).unwrap();
            forwarded.push(String::from_utf8(line).unwrap());
        }
        let mut withheld = Vec::new();
        responses.read_until(b'\n', &mut withheld).unwrap();
        assert_eq!(withheld, b":0\r\n");
        caller.shutdown(std::net::Shutdown::Both).unwrap();
        responses
            .get_ref()
            .shutdown(std::net::Shutdown::Both)
            .unwrap();
        let transferred = sending.join().unwrap();
        (
            forwarded,
            String::from_utf8(withheld).unwrap(),
            format!("{transferred:?}"),
        )
    });
    let through_proxy =
        RedisJwksRuntimeState::new_for_tests(&format!("redis+unix://{}", proxy_path.display()))
            .unwrap();
    let result = through_proxy.record_kid_fingerprints(&policy(60), URI, &pairs());
    assert!(result.is_err());
    let (forwarded, withheld, request_transfer) = relay.join().unwrap();
    let remote = backend.snapshot();
    assert_eq!(remote["fields"]["kid-A"], "fp-A");
    assert!(remote["pttl"].as_i64().unwrap() > 58_000);
    backend.note("reply loss",json!({"forwarded_setup":forwarded,"withheld_completed_reply":withheld,"request_transfer":request_transfer,"caller_error":result.unwrap_err().to_string(),"remote_completed":remote,"no_retry_added":true}));
    backend.finish();
}

#[test]
fn raw_reply_type_is_exact() {
    assert!(!decode_kid_ledger_reply(&redis::Value::Int(0)).unwrap());
    assert!(decode_kid_ledger_reply(&redis::Value::Int(1)).unwrap());
    let bad = [
        redis::Value::Int(-1),
        redis::Value::Int(2),
        redis::Value::Int(4_294_967_296),
        redis::Value::Int(4_294_967_297),
        redis::Value::SimpleString("0".into()),
        redis::Value::BulkString(b"1".to_vec()),
        redis::Value::Double(0.0),
        redis::Value::Double(1.0),
        redis::Value::Nil,
        redis::Value::Array(vec![redis::Value::Int(0)]),
        redis::Value::Attribute {
            data: Box::new(redis::Value::Int(0)),
            attributes: vec![],
        },
    ];
    for value in bad {
        let err = decode_kid_ledger_reply(&value).unwrap_err();
        assert!(
            matches!(err,JwksSharedStateError::BackendUnavailable(ref message) if message == "unexpected JWKS kid-ledger reply")
        );
    }
}
