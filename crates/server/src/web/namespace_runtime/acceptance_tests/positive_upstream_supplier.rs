//! Uses the existing cfg(test) loopback HTTP supplier support; no TLS claim.
use super::{authorization_fixture::KEY, support::TestResult};
use axum::{
    extract::{Form, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

pub(super) const CLIENT: &str = "namespace-upstream-rp";
pub(super) const SUBJECT: &str = "namespace-remote-subject";
pub(super) const CODE: &str = "namespace-remote-code";

#[derive(Default)]
pub(super) struct Observations {
    pub(super) nonce: String,
    pub(super) redirect: String,
    pub(super) challenge: String,
    pub(super) code_exchanges: usize,
    pub(super) refresh_exchanges: usize,
    pub(super) jwks_requests: usize,
    pub(super) rejected: usize,
}

#[derive(Clone)]
struct SupplierState {
    issuer: String,
    observed: Arc<Mutex<Observations>>,
}

pub(super) struct Supplier {
    pub(super) issuer: String,
    pub(super) endpoint: String,
    pub(super) observed: Arc<Mutex<Observations>>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Supplier {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Supplier {
    pub(super) async fn start() -> TestResult<Self> {
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
        let endpoint = format!("http://{}", listener.local_addr()?);
        let issuer = format!("https://upstream.example/{}", uuid::Uuid::new_v4());
        let observed = Arc::new(Mutex::new(Observations::default()));
        let app = Router::new()
            .route("/token", post(token))
            .route("/jwks", get(jwks))
            .with_state(SupplierState {
                issuer: issuer.clone(),
                observed: observed.clone(),
            });
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Ok(Self {
            issuer,
            endpoint,
            observed,
            task,
        })
    }

    pub(super) fn discovery(&self) -> TestResult<crate::oidc::OidcDiscovery> {
        Ok(serde_json::from_value(json!({"issuer":self.issuer,
            "authorization_endpoint":format!("{}/authorize",self.endpoint),
            "token_endpoint":format!("{}/token",self.endpoint),"jwks_uri":format!("{}/jwks",self.endpoint),
            "response_types_supported":["code"],"subject_types_supported":["public"],
            "id_token_signing_alg_values_supported":["RS256"],"scopes_supported":["openid"],
            "grant_types_supported":["authorization_code","refresh_token"],
            "token_endpoint_auth_methods_supported":["none"],"code_challenge_methods_supported":["S256"],
            "authorization_response_iss_parameter_supported":true}))?)
    }
}

async fn jwks(State(state): State<SupplierState>) -> (StatusCode, Json<Value>) {
    let result = (|| -> TestResult<Value> {
        state
            .observed
            .lock()
            .map_err(|e| std::io::Error::other(e.to_string()))?
            .jwks_requests += 1;
        Ok(serde_json::to_value(
            crate::oidc::OidcSigningKey::from_rsa_pem("namespace-op".into(), KEY)?.jwks(),
        )?)
    })();
    response(result)
}

fn response(result: TestResult<Value>) -> (StatusCode, Json<Value>) {
    match result {
        Ok(value) => (StatusCode::OK, Json(value)),
        Err(_) => (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"invalid_request"})),
        ),
    }
}

async fn token(
    State(state): State<SupplierState>,
    Form(form): Form<HashMap<String, String>>,
) -> (StatusCode, Json<Value>) {
    response(token_response(&state, &form))
}

fn token_response(state: &SupplierState, form: &HashMap<String, String>) -> TestResult<Value> {
    let mut observed = state
        .observed
        .lock()
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    let field = |name| form.get(name).map(String::as_str).unwrap_or("");
    let code = field("grant_type") == "authorization_code";
    let valid = field("client_id") == CLIENT
        && if code {
            field("code") == CODE
                && field("redirect_uri") == observed.redirect
                && !observed.challenge.is_empty()
                && crate::upstream::pkce_challenge(field("code_verifier")) == observed.challenge
                && observed.code_exchanges == 0
        } else {
            field("grant_type") == "refresh_token"
                && field("refresh_token") == "namespace-refresh-initial"
                && observed.refresh_exchanges == 0
        };
    if !valid {
        observed.rejected += 1;
        return Err("supplier rejected OAuth request".into());
    }
    let now = crate::util::now_unix_epoch_secs()?;
    let mut claims = json!({"iss":state.issuer,"sub":SUBJECT,"aud":CLIENT,"iat":now,"exp":now+300,"auth_time":now});
    if code {
        claims["nonce"] = json!(observed.nonce);
        observed.code_exchanges += 1;
    } else {
        observed.refresh_exchanges += 1;
    }
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some("namespace-op".into());
    let signed = jsonwebtoken::encode(
        &header,
        &claims,
        &jsonwebtoken::EncodingKey::from_rsa_pem(KEY.as_bytes())?,
    )?;
    Ok(
        json!({"access_token":if code {"namespace-upstream-access-initial"} else {"namespace-upstream-access-refreshed"},
        "token_type":"Bearer","expires_in":300,"id_token":signed,
        "refresh_token":if code {"namespace-refresh-initial"} else {"namespace-refresh-rotated"}}),
    )
}
