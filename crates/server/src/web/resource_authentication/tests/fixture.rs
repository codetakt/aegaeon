use crate::authcode::types::{
    AccessToken, BearerTokenMeta, BearerTokenMetaInput, CnfClaim, SenderBinding,
};
use crate::dcr_persistence::test_database::Database;
use crate::middleware::replay_store::{
    InMemoryReplayStore, ReplayEntry, ReplayStore, ReplayStoreError,
};
use crate::web::test_support::{
    seed_test_projection, setup_test_environment, test_app_state, TestEnvironment, TestResult,
};
use crate::web::AppState;
use axum::{
    body::{to_bytes, Body},
    extract::ConnectInfo,
    http::{HeaderMap, Method, Request, StatusCode},
    response::Response,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::{json, Value};
use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tower::ServiceExt;

#[derive(Default)]
pub(super) struct ReplayObservation {
    inner: InMemoryReplayStore,
    attempts: AtomicUsize,
}
impl ReplayObservation {
    pub(super) fn attempts(&self) -> usize {
        self.attempts.load(Ordering::SeqCst)
    }
}
impl ReplayStore for ReplayObservation {
    fn check_and_store(&self, entry: ReplayEntry<'_>) -> Result<(), ReplayStoreError> {
        self.attempts.fetch_add(1, Ordering::SeqCst);
        self.inner.check_and_store(entry)
    }
}

pub(super) struct Fixture {
    pub(super) database: Database,
    pub(super) environment: TestEnvironment,
    pub(super) state: AppState,
    pub(super) replay: Arc<ReplayObservation>,
}
impl Fixture {
    pub(super) async fn new() -> TestResult<Self> {
        let database = Database::create(false).await?;
        let environment = setup_test_environment(&database.pool).await?;
        let audiences = json!([
            crate::resource_audience::protected_resource(&environment.issuer_url),
            crate::resource_audience::userinfo(&environment.issuer_url),
            crate::resource_audience::upstream_refresh(&environment.issuer_url)
        ]);
        seed_test_projection(
            &database.pool,
            &environment,
            "resource-auth-client",
            "resource-auth-subject",
            audiences,
            json!({"roles":["USER"],"organization_roles":[]}),
        )
        .await?;
        let mut state = test_app_state(database.pool.clone(), &environment).await?;
        let validator = crate::authcode::TokenValidator::with_policy(
            state.tokens.store.as_ref().clone(),
            Arc::clone(&state.keys.access_token),
            crate::policy::SecurityPolicy::default()
                .with_sender_constraint(crate::policy::SenderConstraint::None),
        );
        state.tokens.validator = Arc::new(validator.clone());
        state.oidc.userinfo_endpoint =
            Some(Arc::new(crate::oidc::userinfo::UserinfoEndpoint::new(
                validator,
                database.pool.clone(),
                environment.issuer_url.clone(),
            )));
        state.application_authority = Some(crate::application_authorization::Authority {
            projections: database.pool.clone(),
            memberships: None,
        });
        let replay = Arc::new(ReplayObservation::default());
        state.dpop = Arc::new(
            crate::middleware::DpopMiddleware::new(
                "resource-auth-fixture",
                "https://proof.example",
                replay.clone(),
                Duration::from_secs(360),
            )
            .with_native_verifier_for_tests(),
        );
        Ok(Self {
            database,
            environment,
            state,
            replay,
        })
    }

    pub(super) async fn token(
        &self,
        path: &str,
        scope: &str,
        dpop: bool,
        expired: bool,
    ) -> TestResult<String> {
        let mut access = AccessToken::new(
            "resource-auth-client".into(),
            "resource-auth-subject".into(),
            Some(scope.into()),
            300,
        );
        if expired {
            access.created_at = SystemTime::now() - Duration::from_secs(600);
        }
        let binding = if dpop {
            let proof = signed_proof("GET", path, Some(&access.token), None)?;
            let jkt = crate::util::compute_dpop_jkt_from_proof(&proof)
                .ok_or("native fixture thumbprint")?;
            access.token_type = "DPoP".into();
            access.cnf = Some(CnfClaim::Jkt(jkt.clone()));
            Some(SenderBinding::DPoP { jkt })
        } else {
            None
        };
        let audience = match path {
            "/resource" => {
                crate::resource_audience::protected_resource(&self.environment.issuer_url)
            }
            "/oauth/upstream/refresh" => {
                crate::resource_audience::upstream_refresh(&self.environment.issuer_url)
            }
            _ => crate::resource_audience::userinfo(&self.environment.issuer_url),
        };
        let mut meta = BearerTokenMeta::new(BearerTokenMetaInput {
            token_id: access.token.clone(),
            client_id: access.client_id.clone(),
            user_id: access.user_id.clone(),
            granted_scopes: scope.split_ascii_whitespace().map(str::to_owned).collect(),
            audience,
            sender_binding: binding,
            authorization_details: None,
            auth_time_epoch_secs: None,
            acr: None,
            issued_at: access.created_at,
            expires_at: access.created_at + Duration::from_secs(300),
            refresh_parent: None,
        });
        if path == "/application/authorization" {
            meta.application_grant = crate::application_authorization::store::capture(
                &self.database.pool,
                self.environment.environment_id,
                &self.environment.issuer_url,
                "resource-auth-client",
                "resource-auth-subject",
            )
            .await?;
            assert!(meta.application_grant.is_some());
        }
        let token = access.token.clone();
        self.state
            .tokens
            .store
            .store_issued_grant_async(access, None, meta)
            .await?;
        Ok(token)
    }

    pub(super) async fn finish(self) -> TestResult {
        // Drop every state holder before the owned database closes.
        drop(self.state);
        self.database.cleanup().await?;
        Ok(())
    }
}

pub(super) fn signed_proof(
    method: &str,
    path: &str,
    token: Option<&str>,
    nonce: Option<&str>,
) -> TestResult<String> {
    proof_with_algorithm(
        method,
        path,
        token,
        nonce,
        ffi::DPOP_SIGNING_ALGORITHM,
        false,
    )
}

pub(super) fn proof_with_algorithm(
    method: &str,
    path: &str,
    token: Option<&str>,
    nonce: Option<&str>,
    algorithm: &str,
    corrupt_signature: bool,
) -> TestResult<String> {
    let key = Ed25519KeyPair::from_seed_unchecked(&[42; 32]).map_err(|_| "fixture signing key")?;
    let header = json!({"typ":"dpop+jwt","alg":algorithm,"jwk":{"kty":"OKP","crv":"Ed25519","x":URL_SAFE_NO_PAD.encode(key.public_key().as_ref())}});
    let mut claims = json!({"htm":method,"htu":format!("https://proof.example{path}"),"iat":SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),"jti":uuid::Uuid::new_v4().to_string()});
    if let Some(token) = token {
        claims["ath"] =
            json!(URL_SAFE_NO_PAD.encode(aegaeon_crypto::hash::sha256_digest(token.as_bytes())));
    }
    if let Some(nonce) = nonce {
        claims["nonce"] = json!(nonce);
    }
    let signing = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims)?)
    );
    let mut signature = key.sign(signing.as_bytes()).as_ref().to_vec();
    if corrupt_signature {
        signature[0] ^= 1;
    }
    Ok(format!("{signing}.{}", URL_SAFE_NO_PAD.encode(signature)))
}

pub(super) fn headers(
    authorization: Option<&str>,
    proof: Option<&str>,
    form: bool,
) -> TestResult<HeaderMap> {
    let mut headers = HeaderMap::new();
    if let Some(value) = authorization {
        headers.insert("authorization", value.parse()?);
    }
    if let Some(value) = proof {
        headers.insert("dpop", value.parse()?);
    }
    if form {
        headers.insert("content-type", "application/x-www-form-urlencoded".parse()?);
    }
    Ok(headers)
}

pub(super) async fn request(
    state: &AppState,
    method: &str,
    uri: &str,
    headers: HeaderMap,
    body: impl Into<Body>,
) -> TestResult<Response> {
    let mut request = Request::builder()
        .method(method.parse::<Method>()?)
        .uri(uri)
        .body(body.into())?;
    *request.headers_mut() = headers;
    request.extensions_mut().insert(ConnectInfo(
        "127.0.0.1:19001".parse::<std::net::SocketAddr>()?,
    ));
    Ok(crate::web::build_router(state.clone())
        .oneshot(request)
        .await?)
}

pub(super) async fn expect(
    response: Response,
    status: StatusCode,
    scheme: Option<&str>,
    code: Option<&str>,
    nonce: bool,
) -> TestResult<Value> {
    let observed = response.status();
    assert_eq!(
        response
            .headers()
            .get_all("www-authenticate")
            .iter()
            .count(),
        usize::from(scheme.is_some())
    );
    if let Some(scheme) = scheme {
        let mut challenge = format!("{scheme} realm=\"aegaeon\"");
        if let Some(code) = code {
            challenge.push_str(&format!(", error=\"{code}\""));
        }
        if scheme == "DPoP" {
            challenge.push_str(&format!(", algs=\"{}\"", ffi::DPOP_SIGNING_ALGORITHM));
        }
        assert_eq!(response.headers()["www-authenticate"], challenge);
    }
    assert_eq!(
        response.headers().get_all("dpop-nonce").iter().count(),
        usize::from(nonce)
    );
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(response.headers()["pragma"], "no-cache");
    let bytes = to_bytes(response.into_body(), 65536).await?;
    assert_eq!(
        observed,
        status,
        "response body: {}",
        String::from_utf8_lossy(&bytes)
    );
    if let Some(code) = code {
        let body: Value = serde_json::from_slice(&bytes)?;
        assert_eq!(body["error"], code);
        Ok(body)
    } else if status == StatusCode::UNAUTHORIZED {
        assert!(bytes.is_empty());
        Ok(Value::Null)
    } else {
        Ok(serde_json::from_slice(&bytes)?)
    }
}

pub(super) const SURFACES: [(&str, &str); 5] = [
    ("GET", "/resource"),
    ("GET", "/userinfo"),
    ("POST", "/userinfo"),
    ("GET", "/application/authorization"),
    ("POST", "/oauth/upstream/refresh"),
];
