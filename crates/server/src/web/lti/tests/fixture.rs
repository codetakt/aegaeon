use crate::lti::{model::ToolConfiguration, store};
use crate::management::types::{PolicyDocument, PolicySenderConstraint};
use crate::web::{test_support as t, AppState, AuthSessionTimes};
use axum::{
    body::{to_bytes, Body},
    extract::ConnectInfo,
    http::{Request, StatusCode},
    response::Response,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::{json, Value};
use sqlx::postgres::PgPoolOptions;
use std::{net::SocketAddr, sync::Arc};
use tower::ServiceExt;
use uuid::Uuid;
pub(super) type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

pub(super) struct Fixture {
    pub state: AppState,
    pub user: Uuid,
    pub author: Uuid,
    pub config: ToolConfiguration,
    pub session: String,
    pub access_token: String,
}
impl Fixture {
    pub async fn new(consent: bool, secure: bool) -> Result<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .connect(&std::env::var("AEGAEON_DATABASE_URL")?)
            .await?;
        let env = t::setup_test_environment(&pool).await?;
        for id in ["tool", "context-producer"] {
            let mut client = t::sample_registered_client(id);
            client.client_secret = Some("test-lti-producer-secret".into());
            client.token_endpoint_auth_method = "client_secret_basic".into();
            client.allowed_grant_types =
                vec!["authorization_code".into(), "client_credentials".into()];
            client.allowed_scopes = vec!["openid".into(), "lti:launch".into(), "unrelated".into()];
            crate::dcr_persistence::create_dynamic_registration(
                &pool,
                &env.issuer_host,
                &client,
                &["code".into()],
                &Uuid::new_v4().to_string(),
                "lti-http-test",
            )
            .await?;
        }
        let audience = format!("{}/lti/launches", env.issuer_url);
        let policy = PolicyDocument {
            sender_constraint: PolicySenderConstraint::None,
            oidc_enabled: true,
            allowed_grant_types: vec!["authorization_code".into(), "client_credentials".into()],
            token_exchange: serde_json::from_value(
                json!({"version":1,"targets":[{"audience":audience,"resourceAliases":[]}],"rules":[]}),
            )?,
            client_credentials: serde_json::from_value(
                json!({"version":1,"resourceServers":[{"targetAudience":audience,"introspectionClients":[]}],"rules":[{"clientId":"context-producer","targetAudience":audience,"scopes":["lti:launch","unrelated"],"defaultScopes":["lti:launch"],"defaultTarget":true}]}),
            )?,
            ..PolicyDocument::default()
        };
        t::seed_oidc_configuration(&pool, &env, policy, "lti-test-key").await?;
        sqlx::query("UPDATE aegaeon.oauth_profiles SET allowed_grant_types=$1,token_endpoint_auth_methods_allowed=$2 WHERE environment_id=$3")
            .bind(vec!["authorization_code","client_credentials"]).bind(vec!["client_secret_basic"]).bind(env.environment_id).execute(&pool).await?;
        let user:Uuid=sqlx::query_scalar("INSERT INTO aegaeon.end_users(environment_id,subject,status) VALUES($1,'lti-user','ACTIVE') RETURNING id").bind(env.environment_id).fetch_one(&pool).await?;
        let author:Uuid=sqlx::query_scalar("INSERT INTO aegaeon.administrators(email,password_hash) VALUES($1,'unusable-test-password-hash') RETURNING id").bind(format!("lti-{}@example.com",Uuid::new_v4())).fetch_one(&pool).await?;
        let mut tx = pool.begin().await?;
        crate::attribute_mapping::replace_local_attributes(
            &mut tx,
            env.environment_id,
            user,
            0,
            &json!({"nickname":"Mapped local nickname"}),
            author,
        )
        .await?;
        tx.commit().await?;
        let mut state = t::test_app_state(pool, &env).await?;
        state.tokens.validator = Arc::new(
            crate::authcode::TokenValidator::with_policy(
                state.tokens.store.as_ref().clone(),
                state.keys.access_token.clone(),
                state.cfg.security_policy,
            )
            .with_issuer(Some(env.issuer_url.clone())),
        );
        let session = state
            .browser_auth
            .auth_sessions
            .try_create(
                "lti-user",
                AuthSessionTimes::local(crate::util::now_unix_epoch_secs()?),
                None,
                None,
                None,
            )?
            .ok_or("session creation")?;
        state.validate_subject_namespace().await?;
        let mut config: ToolConfiguration = serde_json::from_value(json!({
            "schemaVersion":1,"name":"Example Tool","status":"active","initiateLoginUri":"https://tool.example/login","redirectUris":["https://tool.example/launch"],
            "security":{"requireConsent":consent,"requireDpop":secure,"stagedActivation":secure},
            "deployments":[{"id":"deployment-1","status":"active","producers":["context-producer"],"allowedRoles":["http://purl.imsglobal.org/vocab/lis/v2/membership#Learner"],
                "resourceLinks":[{"id":"resource-1","status":"active","targetLinkUri":"https://tool.example/resource","context":{"id":"context-1","types":[]}}]}]
        }))?;
        use aegaeon_attribute_mapping::{AttributeKey, Expression, ValueSchema};
        let key = AttributeKey {
            source: "local".into(),
            name: "nickname".into(),
        };
        config.mapping.inputs.insert(key.clone());
        config.mapping.source_grants.insert(key.clone());
        config.mapping.released_outputs.insert("nickname".into());
        config.mapping.outputs.insert(
            "nickname".into(),
            crate::attribute_mapping::profile::ProfileRule {
                expression: Expression::Read {
                    attribute: key,
                    path: vec![],
                },
                schema: ValueSchema::String,
                required: true,
            },
        );
        let mut fixture = Self {
            state,
            user,
            author,
            config,
            session,
            access_token: String::new(),
        };
        fixture.replace(0).await?;
        let authorization = format!(
            "Basic {}",
            STANDARD.encode("context-producer:test-lti-producer-secret")
        );
        let request = Request::builder()
            .method("POST")
            .uri("/token")
            .extension(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 12454))))
            .header("authorization", authorization)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(
                "grant_type=client_credentials&scope=lti%3Alaunch",
            ))?;
        let response = body(
            crate::web::build_router(fixture.state.clone())
                .oneshot(request)
                .await?,
        )
        .await?;
        assert_eq!(response.0, StatusCode::OK, "{}", response.1);
        fixture.access_token = serde_json::from_str::<Value>(&response.1)?["access_token"]
            .as_str()
            .ok_or("access token")?
            .into();
        Ok(fixture)
    }
    pub async fn replace(&self, revision: i64) -> Result {
        let mut tx = self.state.db_pool.begin().await?;
        store::replace(
            &mut tx,
            self.state.environment_id,
            "tool",
            revision,
            &self.config,
            self.author,
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }
    pub async fn send(
        &self,
        method: &str,
        path: &str,
        session: bool,
        content_type: Option<&str>,
        data: Option<String>,
    ) -> Result<Response> {
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .extension(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 12454))));
        if session {
            request = request.header("cookie", format!("aegaeon_auth_session={}", self.session));
        }
        if let Some(content_type) = content_type {
            request = request.header("content-type", content_type);
        }
        if method == "POST" && path.starts_with("/lti/launch/") {
            request = request.header("origin", self.state.issuer.as_str());
        }
        if path == "/lti/launches" {
            request = request.header("authorization", format!("Bearer {}", self.access_token));
        }
        Ok(crate::web::build_router(self.state.clone())
            .oneshot(request.body(match data {
                Some(data) => Body::from(data),
                None => Body::empty(),
            })?)
            .await?)
    }
    pub async fn create_response(&self) -> Result<Response> {
        self.send("POST","/lti/launches",false,Some("application/json"),Some(json!({"clientId":"tool","deploymentId":"deployment-1","resourceLinkId":"resource-1","userId":self.user,"roles":["http://purl.imsglobal.org/vocab/lis/v2/membership#Learner"]}).to_string())).await
    }
    pub async fn create(&self) -> Result<String> {
        let response = body(self.create_response().await?).await?;
        assert_eq!(response.0, StatusCode::CREATED, "{}", response.1);
        let value: Value = serde_json::from_str(&response.1)?;
        Ok(
            url::Url::parse(value["launchUrl"].as_str().ok_or("launch URL")?)?
                .path()
                .into(),
        )
    }
    pub async fn initiate(&self, path: &str, consent: bool) -> Result<String> {
        let response = self.send("GET", path, true, None, None).await?;
        let response = if consent {
            let response = body(response).await?;
            assert_eq!(response.0, StatusCode::OK, "{}", response.1);
            let csrf = hidden(&response.1, "csrf")?;
            let forged = self
                .send(
                    "POST",
                    path,
                    true,
                    Some("application/x-www-form-urlencoded"),
                    Some("csrf=wrong&decision=approve".into()),
                )
                .await?;
            assert_eq!(forged.status(), StatusCode::FORBIDDEN);
            self.send(
                "POST",
                path,
                true,
                Some("application/x-www-form-urlencoded"),
                Some(form(&[("csrf", &csrf), ("decision", "approve")])),
            )
            .await?
        } else {
            response
        };
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let location = url::Url::parse(response.headers()["location"].to_str()?)?;
        let values: std::collections::BTreeMap<_, _> =
            location.query_pairs().into_owned().collect();
        assert_eq!(values["iss"], *self.state.issuer);
        Ok(form(&[
            ("client_id", "tool"),
            ("redirect_uri", "https://tool.example/launch"),
            ("login_hint", &values["login_hint"]),
            ("lti_message_hint", &values["lti_message_hint"]),
            ("nonce", " opaque + nonce "),
            ("state", "opaque-state"),
            ("scope", "openid"),
            ("response_type", "id_token"),
            ("response_mode", "form_post"),
            ("prompt", "none"),
        ]))
    }
    pub async fn verify(&self, token: &str) -> Result<Value> {
        let response = body(self.send("GET", "/jwks", false, None, None).await?).await?;
        let jwks: Value = serde_json::from_str(&response.1)?;
        let key: jsonwebtoken::jwk::Jwk = serde_json::from_value(jwks["keys"][0].clone())?;
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
        validation.set_issuer(&[self.state.issuer.as_str()]);
        validation.set_audience(&["tool"]);
        validation.leeway = 0;
        Ok(jsonwebtoken::decode::<Value>(
            token,
            &jsonwebtoken::DecodingKey::from_jwk(&key)?,
            &validation,
        )?
        .claims)
    }
}
pub(super) fn form(pairs: &[(&str, &str)]) -> String {
    url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs.iter().copied())
        .finish()
}
pub(super) async fn body(response: Response) -> Result<(StatusCode, String)> {
    Ok((
        response.status(),
        String::from_utf8(to_bytes(response.into_body(), 262144).await?.to_vec())?,
    ))
}
pub(super) fn hidden(html: &str, name: &str) -> Result<String> {
    let marker = format!("name=\"{name}\" value=\"");
    Ok(html
        .split_once(&marker)
        .ok_or_else(|| format!("missing {name}: {html}"))?
        .1
        .split_once('"')
        .ok_or("hidden field")?
        .0
        .into())
}
