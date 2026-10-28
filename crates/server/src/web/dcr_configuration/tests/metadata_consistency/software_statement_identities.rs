use super::*;
use crate::client_registry::ClientRegistry;
use crate::management::types::PolicyDocument;
use std::sync::Arc;

const ISSUER: &str = "https://software.example/issuer";
const AUDIENCE: &str = "https://registration.example/register";
const PUBLIC: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/rsa2048-public.pem"
));
const PRIVATE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/rsa2048-private.pk8.pem"
));

fn claims(recipient: bool) -> Value {
    let mut value = json!({"iss":ISSUER,"exp":4102444800_u64,"redirect_uris":["https://client.example/callback"]});
    if recipient {
        value["aud"] = json!(["https://other.example", AUDIENCE]);
    }
    value
}

fn body(claims: Option<&Value>) -> TestResult<Value> {
    let mut value = json!({"redirect_uris":["https://client.example/callback"],"pkce_required":true,"token_endpoint_auth_method":"client_secret_basic"});
    if let Some(claims) = claims {
        let statement = jsonwebtoken::encode(
            &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256),
            claims,
            &jsonwebtoken::EncodingKey::from_rsa_pem(PRIVATE)?,
        )?;
        let (input, signature) = statement.rsplit_once('.').ok_or("compact statement")?;
        assert!(jsonwebtoken::crypto::verify(
            signature,
            input.as_bytes(),
            &jsonwebtoken::DecodingKey::from_rsa_pem(PUBLIC.as_bytes())?,
            jsonwebtoken::Algorithm::RS256
        )?);
        value["software_statement"] = json!(statement);
    }
    Ok(value)
}

async fn fixture(
    pool: &PgPool,
    env: &TestDcrEnvironment,
    pin: bool,
    recipient: bool,
    trusted: bool,
) -> TestResult<(axum::Router, Arc<ClientRegistry>)> {
    sqlx::query("UPDATE aegaeon.oauth_profiles SET token_endpoint_auth_methods_allowed=ARRAY['client_secret_basic','none'] WHERE environment_id=$1").bind(env.environment_id).execute(pool).await?;
    let mut state = test_app_state(pool.clone(), env).await?;
    let policy = PolicyDocument {
        dcr_enabled: true,
        dcr_everparse_runtime_enabled: true,
        ssa_jwt_pem: trusted.then(|| PUBLIC.into()),
        ssa_expected_iss: pin.then(|| ISSUER.into()),
        ssa_expected_aud: recipient.then(|| AUDIENCE.into()),
        ..Default::default()
    };
    update_test_policy(&mut state, |p| *p = policy.clone()).await?;
    state.dcr_validation_config = crate::dcr::DcrValidationConfig::try_from_policy(
        &policy,
        false,
        false,
        false,
        true,
        state.cfg.jose_header_max_len,
    )?;
    let registry = Arc::clone(&state.clients);
    Ok((crate::web::router::build_router(state), registry))
}

fn runtime_digest(registry: &ClientRegistry) -> TestResult<String> {
    let mut clients = registry.try_all_clients()?;
    clients.sort_by(|a, b| a.client_id.cmp(&b.client_id));
    let mut value = format!(
        "{:?}:{clients:?}",
        registry.try_runtime_snapshot_fingerprint()?
    );
    for client in clients {
        value.push_str(&format!(
            "{:?}",
            registry.try_client_secret_credentials(&client.client_id)?
        ));
    }
    Ok(aegaeon_crypto::hash::sha256_hex(value.as_bytes()))
}

async fn snapshot(
    pool: &PgPool,
    env: &TestDcrEnvironment,
    registry: &ClientRegistry,
) -> TestResult<(String, String)> {
    Ok((digest(pool, env).await?, runtime_digest(registry)?))
}

async fn invalid(response: Response, expected: &str) -> TestResult {
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(response.headers()[header::PRAGMA], "no-cache");
    let value = response_json(response).await?;
    assert_eq!(value["error"], expected);
    assert_eq!(
        value["error_description"],
        if expected == "invalid_software_statement" {
            "software statement is invalid"
        } else {
            "software statement is not approved"
        }
    );
    Ok(())
}

async fn update(
    app: &axum::Router,
    credentials: &Value,
    claims: Option<&Value>,
) -> TestResult<Value> {
    let mut value = body(claims)?;
    let client = field(credentials, "client_id")?;
    value["client_id"] = json!(client);
    let response = app
        .clone()
        .oneshot(request(
            Method::PUT,
            &format!("/register/{client}"),
            Some(field(credentials, "registration_access_token")?),
            &value,
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let updated = response_json(response).await?;
    assert_eq!(updated["client_id"], client);
    assert_ne!(
        updated["registration_access_token"],
        credentials["registration_access_token"]
    );
    assert_eq!(read(app, &updated).await?["client_id"], client);
    Ok(updated)
}

fn rejected_claims(pin: bool, recipient: bool) -> Vec<Value> {
    let original = claims(recipient);
    let mut values = Vec::new();
    let mut missing = original.clone();
    missing.as_object_mut().expect("claims").remove("iss");
    values.push(missing);
    for issuer in [
        Value::Null,
        json!(""),
        json!(" \n\t\u{2003}"),
        json!(true),
        json!(3),
        json!([]),
        json!({}),
    ] {
        let mut value = original.clone();
        value["iss"] = issuer;
        values.push(value);
    }
    if pin {
        for issuer in [
            "https://SOFTWARE.example/issuer",
            "https://software.example/issuer/",
            " https://software.example/issuer ",
        ] {
            let mut value = original.clone();
            value["iss"] = json!(issuer);
            values.push(value);
        }
    }
    let mut audiences = vec![
        json!("https://other.example"),
        json!([]),
        json!(""),
        json!(false),
        json!({}),
        json!([AUDIENCE, 7]),
    ];
    if recipient {
        let mut missing = original.clone();
        missing.as_object_mut().expect("claims").remove("aud");
        values.push(missing);
        audiences.push(Value::Null);
    } else {
        audiences.push(json!(AUDIENCE));
        audiences.push(json!(["https://other.example", AUDIENCE]));
    }
    for audience in audiences {
        let mut value = original.clone();
        value["aud"] = audience;
        values.push(value);
    }
    values
}

async fn scenario(pool: &PgPool, env: &TestDcrEnvironment) -> TestResult {
    for pin in [false, true] {
        for recipient in [false, true] {
            let (app, registry) = fixture(pool, env, pin, recipient, true).await?;
            let valid = claims(recipient);
            let mut credentials = post(&app, &body(Some(&valid))?).await?;
            assert!(!field(&credentials, "client_secret")?.is_empty());
            credentials = update(&app, &credentials, Some(&valid)).await?;
            let mut second = valid.clone();
            second["aud"] = if recipient {
                json!(AUDIENCE)
            } else {
                Value::Null
            };
            post(&app, &body(Some(&second))?).await?;
            if !pin {
                let mut alternate = valid.clone();
                alternate["iss"] = json!("https://other-software.example");
                post(&app, &body(Some(&alternate))?).await?;
            }
            for bad in rejected_claims(pin, recipient) {
                let mut submitted = body(Some(&bad))?;
                let before = snapshot(pool, env, &registry).await?;
                invalid(
                    app.clone()
                        .oneshot(request(Method::POST, "/register", None, &submitted)?)
                        .await?,
                    "invalid_software_statement",
                )
                .await?;
                assert_eq!(snapshot(pool, env, &registry).await?, before);
                let client = field(&credentials, "client_id")?.to_owned();
                submitted["client_id"] = json!(client);
                let token = field(&credentials, "registration_access_token")?;
                let path = format!("/register/{client}");
                invalid(
                    app.clone()
                        .oneshot(request(Method::PUT, &path, Some(token), &submitted)?)
                        .await?,
                    "invalid_software_statement",
                )
                .await?;
                assert_eq!(snapshot(pool, env, &registry).await?, before);
                assert_eq!(read(&app, &credentials).await?["client_id"], client);
                let wrong = app
                    .clone()
                    .oneshot(request(Method::PUT, &path, Some("wrong-rat"), &submitted)?)
                    .await?;
                assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);
                assert_eq!(response_json(wrong).await?["error"], "invalid_token");
                assert_eq!(snapshot(pool, env, &registry).await?, before);
                // The old valid RAT still performs a successful update after refusal.
                credentials = update(&app, &credentials, Some(&valid)).await?;
            }
            let without = post(&app, &body(None)?).await?;
            update(&app, &without, None).await?;
        }
    }
    let (app, registry) = fixture(pool, env, false, false, false).await?;
    let before = snapshot(pool, env, &registry).await?;
    invalid(
        app.clone()
            .oneshot(request(
                Method::POST,
                "/register",
                None,
                &body(Some(&claims(false)))?,
            )?)
            .await?,
        "unapproved_software_statement",
    )
    .await?;
    assert_eq!(snapshot(pool, env, &registry).await?, before);
    post(&app, &body(None)?).await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires PostgreSQL CREATEDB and native parser; mounted POST/owner PUT on disposable database"]
async fn software_statement_identities_mounted_routes_preserve_state_and_owner_retry() -> TestResult
{
    let db = Database::create(false).await?;
    let result = async {
        let env = setup_test_dcr_environment(&db.pool).await?;
        scenario(&db.pool, &env).await
    }
    .await;
    let cleanup = db.cleanup().await;
    result?;
    cleanup?;
    Ok(())
}
