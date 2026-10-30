use super::*;
use crate::organizations::consent::{GrantRequest, GRANT_TYPE};
use axum::http::Method;
use sha2::{Digest, Sha256};

mod authority;
mod body_budget;
mod browser;
mod csrf_completion;
mod members;
mod par_storage;
mod proof_workers;
mod recovery;
mod refusals;
mod replay_completion;
mod store_fault;
mod support;
mod token_completion;

const PATH: &str = "/organizations/context";
const PRIVILEGE: &str = "organization.context.read";

async fn setup(f: &Fixture) -> TestResult<AppState> {
    let mut state = fixture::state(f).await?;
    let audience = format!("{}/organizations", state.issuer);
    let mut tx = f.pool.begin().await?;
    crate::organizations::repository::lock_domain(&mut tx, f.organization.scope).await?;
    sqlx::query("INSERT INTO aegaeon.authorization_domain_targets(environment_id,domain_id,audience,management) VALUES ($1,$2,$3,true)")
        .bind(state.environment_id).bind(f.organization.scope.domain_id).bind(&audience).execute(&mut *tx).await?;
    sqlx::query("UPDATE aegaeon.organization_client_bindings SET targets=targets || $1::jsonb,revision=revision+1 WHERE environment_id=$2")
        .bind(json!([{"audience":audience,"privileges":["documents.read",PRIVILEGE]}])).bind(state.environment_id).execute(&mut *tx).await?;
    sqlx::query("UPDATE aegaeon.organization_role_definitions SET privileges=privileges || $1::jsonb,version=version+1 WHERE environment_id=$2 AND role_key='reader'")
        .bind(json!([PRIVILEGE])).bind(state.environment_id).execute(&mut *tx).await?;
    tx.commit().await?;
    Arc::make_mut(&mut state.cfg).token_exchange = serde_json::from_value(json!({
        "version":1,"targets":[{"audience":audience,"resourceAliases":[]},{"audience":"management-api","resourceAliases":[]}],
        "rules":[{"clientId":OWNER,"sourceAudience":format!("{}/userinfo",state.issuer),"targetAudience":audience,
            "scopes":[{"targetScope":"documents","sourceScopes":["read"]}],"defaultScopes":["documents"]},
            {"clientId":OWNER,"sourceAudience":format!("{}/userinfo",state.issuer),"targetAudience":"management-api",
            "scopes":[{"targetScope":"documents","sourceScopes":["read"]}],"defaultScopes":["documents"]}]
    }))?;
    // use_redis constructed the issuer from the original policy. Recreate it
    // with the explicitly supplied future profile and own-resource target.
    super::super::use_redis(&mut state).await?;
    Ok(state)
}

async fn issue(
    f: &Fixture,
    state: &AppState,
    key: &aegaeon_crypto::signing::Ed25519KeyData,
    privilege: &str,
) -> TestResult<(Value, String)> {
    let audience = format!("{}/organizations", state.issuer);
    let request = GrantRequest::parse(&json!([{"type":GRANT_TYPE,"locations":[audience],
        "organizations":[{"identifier":IDENTIFIER,"privileges":[privilege]}]}]))?;
    let parent = fixture::parent_request(f, state, key, request).await?;
    let details = json!([{"type":crate::organizations::ORGANIZATION_ACCESS_TYPE,"identifier":IDENTIFIER,"privileges":[privilege]}]).to_string();
    let proof = crate::web::test_support::native_dpop::proof(state, key, json!({}))?;
    let (status, body) = http(
        state,
        "/token",
        OWNER,
        &[
            ("grant_type", TOKEN_EXCHANGE_GRANT_TYPE),
            (
                "subject_token",
                parent["access_token"].as_str().ok_or("parent")?,
            ),
            (
                "subject_token_type",
                "urn:ietf:params:oauth:token-type:access_token",
            ),
            ("audience", &audience),
            ("authorization_details", &details),
        ],
        Some(&proof),
        false,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "own-resource selection: {body}");
    Ok((
        parent,
        body["access_token"].as_str().ok_or("selected")?.into(),
    ))
}

fn proof(
    state: &AppState,
    key: &aegaeon_crypto::signing::Ed25519KeyData,
    token: &str,
    method: &str,
    overrides: Value,
) -> TestResult<String> {
    let mut claims = json!({"htm":method,"htu":format!("{}{PATH}",state.issuer),"ath":URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()))});
    for (k, v) in overrides.as_object().ok_or("overrides")? {
        claims[k] = v.clone();
    }
    crate::web::test_support::native_dpop::proof(state, key, claims)
}

async fn get(
    state: &AppState,
    method: Method,
    path: &str,
    auth: Option<&str>,
    proof: Option<&str>,
    body: &str,
) -> TestResult<(StatusCode, Value)> {
    let mut request = Request::builder().method(method.clone()).uri(path);
    if let Some(auth) = auth {
        request = request.header(header::AUTHORIZATION, auth);
    }
    if let Some(proof) = proof {
        request = request.header("DPoP", proof);
    }
    let mut request = request.body(Body::from(body.to_owned()))?;
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 12543))));
    let response = crate::web::build_router(state.clone())
        .oneshot(request)
        .await?;
    let status = response.status();
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    if matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN) {
        assert!(response.headers()[header::WWW_AUTHENTICATE]
            .to_str()?
            .starts_with("DPoP"));
    }
    let bytes = to_bytes(response.into_body(), 65536).await?;
    if method == Method::HEAD {
        assert!(bytes.is_empty());
        return Ok((status, Value::Null));
    }
    Ok((status, serde_json::from_slice(&bytes)?))
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL and Redis"]
async fn shared_redis_organizations_own_resource_currentness_privilege_and_recovery() -> TestResult
{
    let f = Fixture::with_identifier(IDENTIFIER).await?;
    let state = setup(&f).await?;
    let result = async {
        let key = aegaeon_crypto::signing::Ed25519SigningKey::generate()?;
        let (parent, token) = issue(&f, &state, &key, PRIVILEGE).await?;
        let auth = format!("DPoP {token}");
        for method in [Method::GET, Method::HEAD] {
            let signed = proof(&state, &key, &token, method.as_str(), json!({}))?;
            let (status, body) =
                get(&state, method.clone(), PATH, Some(&auth), Some(&signed), "").await?;
            assert_eq!(status, StatusCode::OK, "{body}");
            if method == Method::GET {
                assert_eq!(body["authorization_details"][0]["identifier"], IDENTIFIER);
                assert_eq!(body["sub"], format!("organization-user-{}", f.users[1]));
                assert_eq!(body.as_object().ok_or("body")?.len(), 5);
                assert_eq!(body["organization"]["id"], f.organization.id.to_string());
                assert_eq!(body["organization"]["externalId"], IDENTIFIER);
                assert_eq!(body["organization"]["revision"], f.organization.revision);
                assert_eq!(
                    body["organization"]["versionTag"],
                    crate::organizations::http_input::VersionTag::new(
                        f.organization.id,
                        f.organization.revision
                    )
                    .map_err(|_| "version")?
                    .header_value()
                );
            }
        }
        let (_, limited) = issue(&f, &state, &key, "documents.read").await?;
        let signed = proof(&state, &key, &limited, "GET", json!({}))?;
        assert_eq!(
            get(
                &state,
                Method::GET,
                PATH,
                Some(&format!("DPoP {limited}")),
                Some(&signed),
                ""
            )
            .await?
            .0,
            StatusCode::FORBIDDEN
        );
        let mut unavailable = state.clone();
        unavailable.db_pool = sqlx::postgres::PgPoolOptions::new()
            .connect_with(f.pool.connect_options().as_ref().clone())
            .await?;
        unavailable.validate_subject_namespace().await?;
        unavailable.db_pool.close().await;
        assert!(
            unavailable.require_subject_namespace().is_ok(),
            "reach actual primary failure"
        );
        let signed = proof(&state, &key, &token, "GET", json!({}))?;
        assert_eq!(
            get(
                &unavailable,
                Method::GET,
                PATH,
                Some(&auth),
                Some(&signed),
                ""
            )
            .await?
            .0,
            StatusCode::SERVICE_UNAVAILABLE
        );
        let signed = proof(&state, &key, &token, "GET", json!({}))?;
        assert_eq!(
            get(&state, Method::GET, PATH, Some(&auth), Some(&signed), "")
                .await?
                .0,
            StatusCode::OK
        );
        state
            .tokens
            .store
            .try_revoke_token(parent["refresh_token"].as_str().ok_or("root")?)?;
        let signed = proof(&state, &key, &token, "GET", json!({}))?;
        assert_eq!(
            get(&state, Method::GET, PATH, Some(&auth), Some(&signed), "")
                .await?
                .0,
            StatusCode::UNAUTHORIZED
        );
        Ok(())
    }
    .await;
    fixture::finish(&state).await?;
    f.cleanup(result).await
}
