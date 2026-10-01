//! Actual management workflow, database loading and public-router composition.
//! Runtime reconstruction below is not an operating-system process restart.
use super::runtime_keys::{
    activate_next_runtime_key_inner, create_runtime_key_inner, revoke_runtime_key_inner,
};
use super::*;
use crate::management::types::{
    ActivateRuntimeKeyRequest, ConfigurationTransactionRequest, CreateRuntimeKeyRequest,
};
use crate::web::authorization_consent_tests::fixture;
use crate::web::authorization_consent_tests::request_objects::shared_protocol_stores;
use crate::web::authorization_consent_tests::request_objects::{
    encrypted_headers::EnvelopeFixture, signed_request,
};
use crate::web::test_support::{
    cleanup_test_environment, finish_test, reload_authorization_runtime, setup_test_environment,
    test_pg_pool, TestEnvironment, TestResult,
};
use axum::{
    body::{to_bytes, Body},
    extract::ConnectInfo,
    http::{Request, StatusCode},
    Extension,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde_json::{json, Value};
use sqlx::PgPool;
use std::net::SocketAddr;
use tower::ServiceExt;
use uuid::Uuid;

struct KeyEnvironment(Option<std::ffi::OsString>);
impl KeyEnvironment {
    fn install() -> Self {
        let old = std::env::var_os("AEGAEON_KEY_ENCRYPTION_KEY");
        std::env::set_var(
            "AEGAEON_KEY_ENCRYPTION_KEY",
            URL_SAFE_NO_PAD.encode([0x57; 32]),
        );
        Self(old)
    }
}
impl Drop for KeyEnvironment {
    fn drop(&mut self) {
        match self.0.as_ref() {
            Some(old) => std::env::set_var("AEGAEON_KEY_ENCRYPTION_KEY", old),
            None => std::env::remove_var("AEGAEON_KEY_ENCRYPTION_KEY"),
        }
    }
}

async fn create(
    pool: &PgPool,
    env: &TestEnvironment,
    admin: Uuid,
    kid: &str,
    key: &[u8],
    activate: bool,
) -> TestResult<String> {
    let config: Uuid = sqlx::query_scalar(
        "SELECT active_configuration_version_id FROM aegaeon.environments WHERE id=$1",
    )
    .bind(env.environment_id)
    .fetch_one(pool)
    .await?;
    let req = CreateRuntimeKeyRequest {
        base_configuration_version_id: config.to_string(),
        usage: "OIDC_REQUEST_OBJECT_DECRYPTION".into(),
        algorithm: Some("RSA-OAEP+A256GCM".into()),
        provider: "databaseEncrypted".into(),
        kid: Some(kid.into()),
        provider_configuration: None,
        private_key_pem: Some(pem::encode(&pem::Pem::new("PRIVATE KEY", key.to_vec()))),
        activate,
        comment: None,
    };
    let pool = pool.clone();
    let path = TeamEnvironmentPath::for_tests(env.team_id, env.environment_id);
    let id = tokio::task::spawn_blocking(move || -> anyhow::Result<String> {
        let _lock = crate::util::KEY_ENCRYPTION_KEY_ENV_GUARD
            .lock()
            .map_err(|_| anyhow::anyhow!("key fixture lock"))?;
        let _env = KeyEnvironment::install();
        let result = tokio::runtime::Handle::current()
            .block_on(create_runtime_key_inner(
                &pool,
                &path,
                &req,
                &state::ManagementSession::human(admin, 1),
                "keyring-create",
            ))
            .map_err(|response| anyhow::anyhow!("key create refused: {}", response.status()))?;
        assert_eq!(
            result.runtime_key.status,
            if activate { "ACTIVE" } else { "NEXT" }
        );
        Ok(result.runtime_key.id)
    })
    .await??;
    Ok(id)
}

async fn request(
    state: &AppState,
    sid: &str,
    token: Option<&str>,
    par: bool,
    path: &str,
) -> TestResult<(StatusCode, Value)> {
    let (builder, body) = if let Some(token) = token {
        let fields = [("client_id", "consent-client"), ("request", token)];
        if par {
            (
                Request::post("/par").header("content-type", "application/x-www-form-urlencoded"),
                serde_urlencoded::to_string(fields)?,
            )
        } else {
            (
                Request::get(format!(
                    "/authorize?{}",
                    serde_urlencoded::to_string(fields)?
                )),
                String::new(),
            )
        }
    } else {
        (Request::get(path), String::new())
    };
    let app = crate::web::router::build_router(state.clone()).layer(Extension(ConnectInfo(
        SocketAddr::from(([127, 0, 0, 1], 12345)),
    )));
    let response = app
        .oneshot(
            builder
                .header("cookie", format!("aegaeon_auth_session={sid}"))
                .body(Body::from(body))?,
        )
        .await?;
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await?;
    // Successful authorize returns a consent document, not a JSON grant.
    let body = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
    Ok((status, body))
}

async fn accepts(state: &AppState, sid: &str, token: &str, par: bool) -> TestResult {
    let (status, body) = request(state, sid, Some(token), par, "").await?;
    assert_eq!(
        status,
        if par {
            StatusCode::CREATED
        } else {
            StatusCode::OK
        }
    );
    if par {
        assert!(body["request_uri"].is_string());
    } else {
        assert!(
            body.as_str()
                .is_some_and(|html| html.contains("name=\"transaction\"")),
            "authorize must reach consent"
        );
    }
    Ok(())
}

fn seal(fixture: &EnvelopeFixture, state: &AppState, kid: &str) -> TestResult<String> {
    fixture.seal(
        &json!({"alg":"RSA-OAEP","enc":"A256GCM","cty":"JWT","kid":kid}).to_string(),
        signed_request(state, "approve")?.as_bytes(),
    )
}

async fn reload(state: &mut AppState) -> TestResult {
    // Reconstruct the runtime after observing a restart request, without bypassing
    // admission in the rebuilt state. This does not simulate a live hot reload.
    reload_authorization_runtime(state).await?;
    state.runtime_restart = crate::runtime_restart::RuntimeRestartState::new();
    shared_protocol_stores(state)?;
    assert!(state.runtime_authority.requires_runtime_request_admission());
    Ok(())
}

async fn seed_management_projection(pool: &PgPool, env: &TestEnvironment) -> TestResult {
    let (config,document): (Uuid,Value) = sqlx::query_as("SELECT id,configuration_document FROM aegaeon.configuration_versions WHERE environment_id=$1 AND status='ACTIVE'")
        .bind(env.environment_id).fetch_one(pool).await?;
    let parsed = configuration_documents::parse_activated_environment_configuration(
        document,
        &env.issuer_host,
        &env.issuer_url,
        "keyring-policy",
    )
    .map_err(|r| std::io::Error::other(format!("fixture policy refused: {}", r.status())))?;
    let mut tx = pool.begin().await?;
    configuration_version_store::persist_environment_configuration_state(
        &mut tx,
        env.environment_id,
        config,
        &parsed.state,
        "keyring-policy",
    )
    .await
    .map_err(|r| {
        std::io::Error::other(format!(
            "fixture policy persistence refused: {}",
            r.status()
        ))
    })?;
    tx.commit().await?;
    Ok(())
}

#[derive(Clone, Copy)]
enum Removal {
    Expiry,
    Revocation,
    Disable,
}

async fn scenario(removal: Removal) -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("isolated PostgreSQL required")?;
    let env = setup_test_environment(&pool).await?;
    let admin = Uuid::new_v4();
    let result = async {
        sqlx::query("INSERT INTO aegaeon.administrators(id,email,password_hash) VALUES($1,$2,'test-password-hash')")
            .bind(admin).bind(format!("keyring-{admin}@example.com")).execute(&pool).await?;
        sqlx::query("INSERT INTO aegaeon.team_memberships(team_id,administrator_id,role) VALUES($1,$2,'OWNER')")
            .bind(env.team_id).bind(admin).execute(&pool).await?;
        let (mut state,sid) = fixture(&pool,&env).await?;
        seed_management_projection(&pool,&env).await?;
        let old = EnvelopeFixture::new()?;
        let fresh = EnvelopeFixture::second_key()?;
        assert!(old.key != fresh.key, "rotation must use distinct RSA keys");
        let old_id = create(&pool,&env,admin,"old-encryption",&old.key,true).await?;
        reload(&mut state).await?;
        create(&pool,&env,admin,"fresh-encryption",&fresh.key,false).await?;
        // NEXT is excluded even after a production loader pass.
        reload(&mut state).await?;
        for par in [false,true] {
            let token = seal(&fresh,&state,"fresh-encryption")?;
            let (status,body) = request(&state,&sid,Some(&token),par,"").await?;
            assert_eq!(status,StatusCode::BAD_REQUEST);
            assert!(body["error_description"].as_str().is_some_and(|v| v.contains("failed to decrypt")));
        }
        let old_tokens = [seal(&old,&state,"old-encryption")?,seal(&old,&state,"old-encryption")?];
        let config: Uuid = sqlx::query_scalar("SELECT active_configuration_version_id FROM aegaeon.environments WHERE id=$1")
            .bind(env.environment_id).fetch_one(&pool).await?;
        let activated = activate_next_runtime_key_inner(&pool,
            &TeamEnvironmentPath::for_tests(env.team_id, env.environment_id),
            &ActivateRuntimeKeyRequest {base_configuration_version_id:config.to_string(),usage:"OIDC_REQUEST_OBJECT_DECRYPTION".into(),comment:None},
            &state::ManagementSession::human(admin,1),"keyring-activate").await
            .map_err(|r| std::io::Error::other(format!("activate refused: {}",r.status())))?;
        assert_eq!(activated.runtime_key.kid,"fresh-encryption");
        let stale = state.clone();
        assert!(!stale.runtime_restart.is_requested());
        let (status,_) = request(&stale,&sid,Some(&old_tokens[0]),false,"").await?;
        assert_eq!(status,StatusCode::SERVICE_UNAVAILABLE);
        assert!(stale.runtime_restart.is_requested(), "actual admission must request restart");
        reload(&mut state).await?;
        for path in ["/jwks","/.well-known/jwks.json"] {
            let (status,body) = request(&state,&sid,None,false,path).await?;
            assert_eq!(status,StatusCode::OK);
            let keys = body["keys"].as_array().ok_or("JWKS")?;
            assert!(keys.iter().any(|key| key["kid"]=="fresh-encryption" && key["use"]=="enc"));
            assert!(!keys.iter().any(|key| key["kid"]=="old-encryption"));
            for key in keys { for private in ["d","p","q","dp","dq","qi","k"] { assert!(key.get(private).is_none()); } }
        }
        for (index,par) in [false,true].into_iter().enumerate() {
            accepts(&state,&sid,&old_tokens[index],par).await?;
            accepts(&state,&sid,&seal(&fresh,&state,"fresh-encryption")?,par).await?;
            // Either selected key must still pass the independent inner-signature check.
            for (encryption,kid) in [(&old,"old-encryption"),(&fresh,"fresh-encryption")] {
                let header=json!({"alg":"RSA-OAEP","enc":"A256GCM","cty":"JWT","kid":kid}).to_string();
                let invalid=encryption.seal(&header,signed_request(&state,"bad-signature")?.as_bytes())?;
                let (status,body)=request(&state,&sid,Some(&invalid),par,"").await?;
                assert_eq!(status,StatusCode::BAD_REQUEST);
                assert!(body["error_description"].as_str().is_some_and(|v| v.contains("request object validation failed")));
            }
        }
        if !matches!(removal, Removal::Expiry) {
            let revoked_id = if matches!(removal, Removal::Disable) { activated.runtime_key.id.as_str() } else { old_id.as_str() };
            revoke_runtime_key_inner(&pool,&TeamEnvironmentRuntimeKeyPath::for_tests(env.team_id, env.environment_id, Uuid::parse_str(revoked_id)?),&ConfigurationTransactionRequest {base_configuration_version_id:config.to_string(),comment:None},
            &state::ManagementSession::human(admin,1),"keyring-revoke").await
                .map_err(|r| std::io::Error::other(format!("revoke refused: {}",r.status())))?;
        } else {
            // Time fixture changes only this owned row; deterministic selection
            // tests separately cover the same loaded key at deadline equality.
            sqlx::query("UPDATE aegaeon.runtime_keys SET retiring_expires_at=now()-interval '1 second' WHERE environment_id=$1 AND kid='old-encryption' AND status='RETIRING'")
                .bind(env.environment_id).execute(&pool).await?;
        }
        reload(&mut state).await?;
        if matches!(removal, Removal::Disable) {
            let live: i64 = sqlx::query_scalar("SELECT count(*) FROM aegaeon.runtime_keys WHERE environment_id=$1 AND kid='old-encryption' AND status='RETIRING' AND retiring_expires_at>now()")
                .bind(env.environment_id).fetch_one(&pool).await?;
            assert_eq!(live,1);
            for par in [false,true] {
                for token in [seal(&old,&state,"old-encryption")?,seal(&fresh,&state,"fresh-encryption")?] {
                    let (status,body)=request(&state,&sid,Some(&token),par,"").await?;
                    assert_eq!(status,StatusCode::BAD_REQUEST);
                    assert!(body["error_description"].as_str().is_some_and(|v| v.contains("encrypted Request Objects are not supported")));
                }
                accepts(&state,&sid,&signed_request(&state,"approve")?,par).await?;
            }
            for path in ["/jwks","/.well-known/jwks.json"] {
                let (status,body)=request(&state,&sid,None,false,path).await?;
                assert_eq!(status,StatusCode::OK);
                assert!(!body["keys"].as_array().ok_or("JWKS")?.iter().any(|key| key["use"]=="enc"));
            }
            return Ok(());
        }
        for (index,par) in [false,true].into_iter().enumerate() {
            // Both the exact previous input and a fresh replay identity must fail
            // in envelope selection, before replay/claim processing.
            for token in [old_tokens[index].clone(), seal(&old,&state,"old-encryption")?] {
                let (status,body) = request(&state,&sid,Some(&token),par,"").await?;
                assert_eq!(status,StatusCode::BAD_REQUEST);
                assert!(body["error_description"].as_str().is_some_and(|v| v.contains("failed to decrypt")));
                assert!(body.get("request_uri").is_none());
            }
            let token = seal(&fresh,&state,"fresh-encryption")?;
            let (status,_) = request(&state,&sid,Some(&token),par,"").await?;
            assert_eq!(status,if par {StatusCode::CREATED} else {StatusCode::OK});
        }
        Ok(())
    }.await;
    // Remove only owned fixtures. Never reset or flush shared services.
    sqlx::query("DELETE FROM aegaeon.team_memberships WHERE team_id=$1 AND administrator_id=$2")
        .bind(env.team_id)
        .bind(admin)
        .execute(&pool)
        .await?;
    for table in ["environment_key_stores", "environment_scope_allowlist"] {
        sqlx::query(&format!(
            "DELETE FROM aegaeon.{table} WHERE environment_id=$1"
        ))
        .bind(env.environment_id)
        .execute(&pool)
        .await?;
    }
    let cleaned = cleanup_test_environment(&pool, &env).await;
    sqlx::query("DELETE FROM aegaeon.administrators WHERE id=$1")
        .bind(admin)
        .execute(&pool)
        .await?;
    finish_test(result, cleaned)
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL and Redis"]
async fn request_object_keyring_rotation_expiry_through_authorize_and_par() -> TestResult {
    scenario(Removal::Expiry).await
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL and Redis"]
async fn request_object_keyring_rotation_revocation_through_authorize_and_par() -> TestResult {
    scenario(Removal::Revocation).await
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL and Redis"]
async fn request_object_keyring_without_active_key_stays_disabled() -> TestResult {
    scenario(Removal::Disable).await
}
