use super::*;
use crate::web::AppState;
use axum::{extract::State, routing::post};

pub(super) const ISSUER: &str = "https://upstream.example/issuer";
const PEM: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/rsa2048-private.pk8.pem"
));

type Mutation = (AppState, ResolvedTrustChain);
#[derive(Clone, Default)]
struct TokenServer {
    response: Arc<Mutex<Value>>,
    calls: Arc<AtomicUsize>,
    mutation: Arc<Mutex<Option<Mutation>>>,
    forms: Arc<Mutex<Vec<String>>>,
}

async fn token(State(server): State<TokenServer>, body: String) -> Json<Value> {
    server.calls.fetch_add(1, Ordering::SeqCst);
    server.forms.lock().unwrap().push(body);
    let mutation = server.mutation.lock().unwrap().take();
    if let Some((state, chain)) = mutation {
        cache(&state, &chain).await.unwrap();
    }
    Json(server.response.lock().unwrap().clone())
}

pub(super) struct Fixture {
    pub state: AppState,
    pub discovery: OidcDiscovery,
    pub request: UpstreamAuthRequest,
    pub profile: crate::oauth_profile::ResolvedProfile,
    pub calls: Arc<AtomicUsize>,
    pub forms: Arc<Mutex<Vec<String>>>,
    pub jwks: Value,
    keys: Vec<InMemoryKeyManager>,
    server: TokenServer,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Fixture {
    pub async fn new(intermediates: usize) -> Result<Self, Box<dyn std::error::Error>> {
        let server = TokenServer::default();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let endpoint = format!("http://{}", listener.local_addr()?);
        let app = Router::new()
            .route("/token", post(token))
            .with_state(server.clone());
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        // The pool is deliberately never connected: these tests exercise operation
        // workflows after existing DB connection/profile/state admission.
        let pool =
            sqlx::postgres::PgPoolOptions::new().connect_lazy("postgres://localhost/unused")?;
        let mut state = test_app_state(pool, test_management_state())?;
        state.environment_id = Uuid::new_v4();
        let mut discovery = OidcDiscovery::new_with_runtime_config(
            ISSUER,
            ISSUER,
            &crate::metadata::MetadataRuntimeConfig::default(),
        );
        discovery.token_endpoint = format!("{endpoint}/token");
        discovery.jwks_uri = format!("{endpoint}/jwks");
        discovery.scopes_supported = Some(vec!["openid".into(), "email".into()]);
        discovery.acr_values_supported = Some(vec!["low".into(), "high".into()]);
        discovery.grant_types_supported =
            Some(vec!["authorization_code".into(), "refresh_token".into()]);
        discovery.token_endpoint_auth_methods_supported = Some(vec![
            "client_secret_post".into(),
            "client_secret_basic".into(),
        ]);
        discovery.authorization_response_iss_parameter_supported = Some(true);
        discovery.code_challenge_methods_supported = Some(vec!["S256".into()]);
        discovery.id_token_signing_alg_values_supported = vec!["RS256".into(), "RS384".into()];
        discovery.end_session_endpoint = Some("https://upstream.example/logout".into());
        state
            .upstream
            .discovery_cache
            .try_insert(ISSUER, discovery.clone())?;
        let signing = crate::oidc::OidcSigningKey::from_rsa_pem("op-key".into(), PEM)?;
        let mut jwks = serde_json::to_value(signing.jwks())?;
        jwks["keys"][0].as_object_mut().unwrap().remove("alg");
        state.upstream.jwks_cache.try_insert(
            &discovery.jwks_uri,
            aegaeon_jose::jwk::JwkSet::from_value(jwks.clone())?,
        )?;
        let now = SystemTime::now();
        let request = UpstreamAuthRequest {
            state: "state".into(),
            nonce: "nonce".into(),
            code_verifier: Some("verifier".into()),
            acr: Some("high".into()),
            issuer: ISSUER.into(),
            client_id: "client".into(),
            client_secret: Some("test-client-secret".into()),
            client_auth_method: "client_secret_post".into(),
            context: UpstreamConnectionContext::new(
                Uuid::new_v4(),
                Uuid::new_v4(),
                Uuid::new_v4(),
                state.environment_id,
                Uuid::new_v4(),
            ),
            token_endpoint: discovery.token_endpoint.clone(),
            jwks_uri: discovery.jwks_uri.clone(),
            redirect_uri: "https://local.example/callback".into(),
            return_to: None,
            max_age: None,
            require_iss_parameter: true,
            jit_provisioning_policy: None,
            attribute_mappings: vec![],
            claim_release_policy: None,
            logout_policy: None,
            issued_at: now,
            expires_at: now + Duration::from_secs(300),
        };
        let profile = crate::oauth_profile::ResolvedProfile {
            id: "profile".into(),
            name: "profile".into(),
            require_pkce: true,
            require_state_parameter: true,
            require_iss_parameter: true,
            sender_constrained: crate::policy::SenderConstraint::None,
            enforce_refresh_sender_binding: false,
            allowed_grant_types: vec!["authorization_code".into(), "refresh_token".into()],
            token_endpoint_auth_methods_allowed: vec!["client_secret_post".into()],
        };
        crate::web::upstream_metadata::validate_upstream_discovery(
            &discovery,
            ISSUER,
            &profile,
            "client_secret_post",
            &[],
        )?;
        let result = Self {
            state,
            discovery,
            request,
            profile,
            calls: server.calls.clone(),
            forms: server.forms.clone(),
            jwks,
            keys: (0..intermediates + 2)
                .map(|_| InMemoryKeyManager::new())
                .collect(),
            server,
            task,
        };
        result.respond(Some(jsonwebtoken::Algorithm::RS256))?;
        Ok(result)
    }

    pub fn metadata(&self) -> Value {
        let mut value = serde_json::to_value(&self.discovery).unwrap();
        value["jwks"] = self.jwks.clone();
        value
    }

    pub fn respond(&self, alg: Option<jsonwebtoken::Algorithm>) -> ManagementTestResult {
        let mut response = json!({"access_token":"access", "token_type":"Bearer"});
        if let Some(alg) = alg {
            let now = crate::util::now_unix_epoch_secs()?;
            let claims = json!({"iss":ISSUER,"sub":"subject","aud":"client","iat":now,"exp":now+300,"nonce":"nonce","acr":"high"});
            let mut header = jsonwebtoken::Header::new(alg);
            header.kid = Some("op-key".into());
            response["id_token"] = json!(jsonwebtoken::encode(
                &header,
                &claims,
                &jsonwebtoken::EncodingKey::from_rsa_pem(PEM.as_bytes())?
            )?);
        }
        *self.server.response.lock().unwrap() = response;
        Ok(())
    }

    pub fn chain(
        &self,
        metadata: Value,
        policies: &[Option<Value>],
        overlay: Option<Value>,
    ) -> ResolvedTrustChain {
        let now = crate::util::now_unix_epoch_secs().unwrap();
        let ids: Vec<_> = (0..self.keys.len())
            .map(|i| {
                if i == 0 {
                    ISSUER.into()
                } else {
                    format!("https://authority-{i}.example")
                }
            })
            .collect();
        let jwks: Vec<_> = self
            .keys
            .iter()
            .map(|key| json!({"keys":[key.federation_public_jwk().unwrap()]}))
            .collect();
        let mut values = Vec::new();
        let mut signatures = Vec::new();
        for i in 0..ids.len() {
            if i > 0 {
                let mut sub = json!({"iss":ids[i],"sub":ids[i-1],"iat":now-10,"exp":now+600,"jwks":jwks[i-1]});
                if let Some(Some(policy)) = policies.get(i - 1) {
                    sub["metadata_policy"] = policy.clone();
                }
                if i == 1 {
                    if let Some(overlay) = overlay.as_ref() {
                        sub["metadata"] = json!({"openid_provider":overlay});
                    }
                }
                signatures.push(signed(&self.keys[i], &sub));
                values.push(sub);
            }
            let mut config = json!({"iss":ids[i],"sub":ids[i],"iat":now-10,"exp":now+600,"jwks":jwks[i],"metadata":{"federation_entity":{"federation_fetch_endpoint":format!("{}/fetch",ids[i]),"federation_list_endpoint":format!("{}/list",ids[i])}}});
            if i == 0 {
                config["metadata"]["openid_provider"] = metadata.clone();
            }
            if i + 1 < ids.len() {
                config["authority_hints"] = json!([ids[i + 1]]);
            }
            signatures.push(signed(&self.keys[i], &config));
            values.push(config);
        }
        let anchor = TrustAnchor {
            entity_id: ids.last().unwrap().clone(),
            jwks: aegaeon_jose::jwk::JwkSet::from_value(jwks.last().unwrap().clone()).unwrap(),
            metadata_policy: None,
        };
        ResolvedTrustChain::new(
            TrustChain {
                chain: values
                    .into_iter()
                    .map(|v| serde_json::from_value::<EntityStatement>(v).unwrap())
                    .collect(),
                anchor,
            },
            signatures,
        )
    }

    pub async fn configure(&self, chain: &ResolvedTrustChain) -> ManagementTestResult {
        let anchor = &chain.trust_chain.anchor;
        let jwks = chain
            .trust_chain
            .chain
            .last()
            .unwrap()
            .jwks
            .as_ref()
            .unwrap();
        self.state
            .federation
            .trust_anchors
            .upsert(
                self.state.environment_id,
                &anchor.entity_id,
                jwks,
                anchor.metadata_policy.as_ref(),
            )
            .await?;
        Ok(())
    }

    pub fn mutate_during_exchange(&self, chain: ResolvedTrustChain) {
        *self.server.mutation.lock().unwrap() = Some((self.state.clone(), chain));
    }

    pub fn refresh_link(&self) -> UpstreamRefreshLink {
        UpstreamRefreshLink {
            account_link_id: Uuid::new_v4(),
            link_env_id: self.state.environment_id,
            upstream_issuer: ISSUER.into(),
            upstream_sub_hash: "subject".into(),
            upstream_refresh_token_generation: 0,
            upstream_refresh_token: "refresh-secret".into(),
            upstream_connection_id: self.request.context.connection_id,
            upstream_connection_identifier: "connection".into(),
            upstream_client_id: "client".into(),
            upstream_auth_method: "client_secret_post".into(),
            upstream_client_secret: Some("test-client-secret".into()),
        }
    }
}

fn signed(key: &InMemoryKeyManager, value: &Value) -> String {
    let jwk = key.federation_public_jwk().unwrap();
    let header = json!({"typ":"entity-statement+jwt","alg":key.federation_alg(),"kid":jwk["kid"]});
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap()),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(value).unwrap())
    );
    format!(
        "{input}.{}",
        URL_SAFE_NO_PAD.encode(key.sign_federation(input.as_bytes()).unwrap())
    )
}

pub(super) async fn cache(state: &AppState, chain: &ResolvedTrustChain) -> ManagementTestResult {
    state
        .federation
        .chain_cache
        .upsert(
            state.environment_id,
            ISSUER,
            &chain.trust_chain.anchor.entity_id,
            &json!(chain.chain_jwts),
            i64::try_from(crate::util::now_unix_epoch_secs()?)? + 500,
        )
        .await?;
    Ok(())
}

impl Fixture {
    pub fn authorize_context(&self) -> UpstreamAuthorizeContext {
        let c = self.request.context;
        UpstreamAuthorizeContext {
            connection: crate::web::upstream_authorize::UpstreamConnection {
                id: c.connection_id,
                connection_identifier: "connection".into(),
                team_id: c.team_id,
                tenant_id: c.tenant_id,
                environment_id: c.environment_id,
                configuration_version_id: c.configuration_version_id,
                connection_type: "OIDC".into(),
                issuer_url: ISSUER.into(),
                client_id: "client".into(),
                client_auth_method: "client_secret_post".into(),
                client_secret_encrypted: None,
                jit_provisioning_policy: None,
                attribute_mappings: vec![],
                claim_release_policy: None,
                logout_policy: None,
            },
            issuer: ISSUER.into(),
            auth_method: "client_secret_post".into(),
            profile: self.profile.clone(),
            active_logout_recovery_policy: None,
        }
    }
}

pub(super) fn authorize_input(scopes: &[&str], acr: Option<&str>) -> UpstreamAuthorizeInput {
    UpstreamAuthorizeInput {
        return_to: None,
        scopes: scopes.iter().map(|v| (*v).into()).collect(),
        scope: scopes.join(" "),
        acr: acr.map(str::to_owned),
        max_age: None,
    }
}

impl Fixture {
    pub fn chain_without_op(&self) -> ResolvedTrustChain {
        let mut chain = self.chain(self.metadata(), &[], None);
        chain.trust_chain.chain[0]
            .metadata
            .as_mut()
            .unwrap()
            .remove("openid_provider");
        chain.chain_jwts[0] = signed(
            &self.keys[0],
            &serde_json::to_value(&chain.trust_chain.chain[0]).unwrap(),
        );
        chain
    }
}

impl Fixture {
    pub fn reset_discovery(&self) -> ManagementTestResult {
        self.state
            .upstream
            .discovery_cache
            .try_insert(ISSUER, self.discovery.clone())?;
        Ok(())
    }
}

impl Fixture {
    pub fn set_allowed_entity_types(
        &self,
        chain: &mut ResolvedTrustChain,
        subordinate: usize,
        allowed: &[&str],
    ) {
        let index = subordinate * 2 + 1;
        chain.trust_chain.chain[index].constraints = Some(crate::federation::Constraints {
            allowed_entity_types: Some(allowed.iter().map(|value| (*value).into()).collect()),
            ..crate::federation::Constraints::default()
        });
        let value = serde_json::to_value(&chain.trust_chain.chain[index]).unwrap();
        chain.chain_jwts[index] = signed(&self.keys[subordinate + 1], &value);
    }
}

impl Fixture {
    pub fn set_critical_policy(
        &self,
        chain: &mut ResolvedTrustChain,
        subordinate: usize,
        names: &[&str],
    ) {
        let index = subordinate * 2 + 1;
        chain.trust_chain.chain[index].metadata_policy_crit =
            Some(names.iter().map(|name| (*name).into()).collect());
        let value = serde_json::to_value(&chain.trust_chain.chain[index]).unwrap();
        chain.chain_jwts[index] = signed(&self.keys[subordinate + 1], &value);
    }
}
