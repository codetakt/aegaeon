use super::*;
use crate::client_registry::RegisteredClientJwks;
use jsonwebtoken::{Algorithm, EncodingKey, Header};

mod credentials;
mod missing;

const PUBLIC: &str = "public-introspector";
const POST: &str = "post-introspector";
const ASSERTION: &str = "assertion-introspector";
const KID: &str = "introspection-assertion";
const PEM: &str = include_str!("../../../../tests/fixtures/rsa2048-private.pk8.pem");

async fn fixture(jwt: bool, legacy: bool) -> TestResult<Fixture> {
    let mut fixture = Fixture::new(true).await?;
    let signing = crate::oidc::OidcSigningKey::from_rsa_pem(KID.into(), PEM)?;
    for (id, method) in [
        (PUBLIC, "none"),
        (POST, "client_secret_post"),
        (ASSERTION, "private_key_jwt"),
    ] {
        let mut client = sample_registered_client(id);
        client.token_endpoint_auth_method = method.into();
        client.client_secret = (id == POST).then(|| SECRET.into());
        if id == ASSERTION {
            client.inline_jwks = Some(RegisteredClientJwks::from_value(
                serde_json::to_value(signing.jwks())?,
                true,
            )?);
            client.token_endpoint_auth_signing_alg = Some("RS256".into());
        }
        crate::dcr_persistence::create_dynamic_registration(
            &fixture.pool,
            &fixture.env.issuer_host,
            &client,
            &["code".into()],
            &uuid::Uuid::new_v4().to_string(),
            "introspection-authentication-fixture",
        )
        .await?;
    }
    update_test_policy(&mut fixture.state, |policy| {
        policy.require_client_auth_token = false;
        policy.require_client_auth_introspection = legacy;
        policy.private_key_jwt_enabled = true;
        policy.jwt_introspection_enabled = jwt;
    })
    .await?;
    sqlx::query("UPDATE aegaeon.oauth_profiles SET token_endpoint_auth_methods_allowed=$1 WHERE environment_id=$2")
        .bind(vec!["none", "client_secret_basic", "client_secret_post", "private_key_jwt"])
        .bind(fixture.env.environment_id).execute(&fixture.pool).await?;
    fixture
        .state
        .runtime_authority
        .try_synchronize_client_projection_from_database(
            &fixture.pool,
            fixture.state.clients.as_ref(),
        )
        .await?;
    assert!(fixture.state.cfg.require_client_auth_introspection);
    // Direct Rust callers also cannot disable authentication. Keep database authority intact.
    Arc::make_mut(&mut fixture.state.cfg).require_client_auth_introspection = legacy;
    Ok(fixture)
}

fn token(state: &AppState, owner: &str) -> TestResult<AccessToken> {
    let (mut access, refresh, mut meta) = grant(state, false, None);
    access.client_id = owner.into();
    meta.client_id = owner.into();
    state
        .tokens
        .store
        .store_issued_grant(access.clone(), refresh, meta)?;
    Ok(access)
}

fn basic(id: &str, secret: &str) -> String {
    format!("Basic {}", STANDARD.encode(format!("{id}:{secret}")))
}

fn assertion(state: &AppState) -> TestResult<String> {
    let now = crate::util::now_unix_epoch_secs()?;
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(KID.into());
    Ok(jsonwebtoken::encode(
        &header,
        &json!({"iss":ASSERTION,"sub":ASSERTION,
        "aud":format!("{}/introspect",state.issuer),"iat":now,"exp":now+60,
        "jti":uuid::Uuid::new_v4().to_string()}),
        &EncodingKey::from_rsa_pem(PEM.as_bytes())?,
    )?)
}

fn assertion_fields(value: &str) -> Vec<(&str, &str)> {
    vec![
        ("client_id", ASSERTION),
        (
            "client_assertion_type",
            crate::web::CLIENT_ASSERTION_TYPE_JWT_BEARER,
        ),
        ("client_assertion", value),
    ]
}

async fn request(
    state: &AppState,
    token: &str,
    fields: &[(&str, &str)],
    auth: Option<&str>,
    accept: Option<&str>,
) -> TestResult<Response> {
    let mut builder = Request::post("/introspect")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    if let Some(auth) = auth {
        builder = builder.header(header::AUTHORIZATION, auth);
    }
    if let Some(accept) = accept {
        builder = builder.header(header::ACCEPT, accept);
    }
    let mut fields = fields.to_vec();
    fields.push(("token", token));
    Ok(router(state)
        .oneshot(builder.body(Body::from(serde_urlencoded::to_string(fields)?))?)
        .await?)
}

async fn error(response: Response, state: &AppState, status: StatusCode) -> TestResult {
    assert_eq!(response.status(), status);
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(response.headers()[header::PRAGMA], "no-cache");
    if status == StatusCode::UNAUTHORIZED {
        assert_eq!(
            response
                .headers()
                .get_all(header::WWW_AUTHENTICATE)
                .iter()
                .count(),
            1
        );
        assert_eq!(
            response.headers()[header::WWW_AUTHENTICATE],
            "Basic realm=\"token_introspection\", error=\"invalid_client\""
        );
    } else {
        assert!(response.headers().get(header::WWW_AUTHENTICATE).is_none());
    }
    let body: Value = serde_json::from_slice(&to_bytes(response.into_body(), 65536).await?)?;
    assert_eq!(body["error"], "invalid_client");
    if status == StatusCode::BAD_REQUEST {
        assert_eq!(body["iss"], state.issuer.as_str());
        assert_eq!(
            body["error_description"],
            "Client authentication is required for introspection"
        );
    }
    assert!(body.get("active").is_none());
    assert!(body.get("token_introspection").is_none());
    Ok(())
}

async fn success(
    response: Response,
    state: &AppState,
    caller: &str,
    jwt: bool,
    active: bool,
) -> TestResult {
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(response.headers()[header::PRAGMA], "no-cache");
    assert!(response.headers().get(header::WWW_AUTHENTICATE).is_none());
    assert_eq!(
        response.headers()[header::CONTENT_TYPE],
        if jwt {
            "application/token-introspection+jwt"
        } else {
            "application/json"
        }
    );
    let bytes = to_bytes(response.into_body(), 65536).await?;
    let body: Value = if jwt {
        verify_response(state, std::str::from_utf8(&bytes)?, caller)?
    } else {
        serde_json::from_slice(&bytes)?
    };
    if active {
        assert_eq!(body["active"], true);
    } else {
        assert_eq!(body, json!({"active":false}));
    }
    Ok(())
}
