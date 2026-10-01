//! Pin CRUD uses the real management router and PostgreSQL. Refresh uses the
//! production workflow with signed raw acquisition only injected, not HTTP.
use super::*;
use crate::federation::{PgTrustAnchorRepository, TrustAnchorRepository};
use crate::kms::{FederationKeyManager, InMemoryKeyManager};
use crate::web::management::federation::trust_chains::refresh::workflow::refresh_with;
use crate::web::management::{state::ManagementSession, TeamEnvironmentTrustChainPath};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

const ANCHOR: &str = "https://anchor.example";
const LEAF: &str = "https://leaf.example";

fn pin() -> Value {
    json!({"openid_relying_party":{"scope":{"subset_of":["read"]}}})
}

#[test]
fn federation_policy_request_preserves_explicit_null_for_validation() {
    use crate::management::types::CreateFederationTrustAnchorRequest;
    let absent: CreateFederationTrustAnchorRequest =
        serde_json::from_value(json!({"entityId":ANCHOR,"jwks":{"keys":[]}})).unwrap();
    assert!(absent.metadata_policy.is_none());
    let present: CreateFederationTrustAnchorRequest =
        serde_json::from_value(json!({"entityId":ANCHOR,"jwks":{"keys":[]},"metadataPolicy":null}))
            .unwrap();
    assert_eq!(present.metadata_policy, Some(Value::Null));
    assert!(
        crate::federation::validate_metadata_policy_pin(present.metadata_policy.as_ref()).is_err()
    );
}

async fn send(
    app: &Router,
    session: &str,
    uri: &str,
    method: Method,
    payload: Value,
) -> Result<(StatusCode, Value), Box<dyn std::error::Error>> {
    let mut req = request(uri, payload, session, "https://admin.aegaeon.test", true);
    if method == Method::GET || method == Method::DELETE {
        *req.body_mut() = Body::empty();
    }
    *req.method_mut() = method;
    let response = app.clone().oneshot(req).await?;
    let status = response.status();
    let bytes = body::to_bytes(response.into_body(), 1024 * 1024).await?;
    Ok((
        status,
        if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes)?
        },
    ))
}

async fn saved(pool: &PgPool) -> anyhow::Result<Value> {
    Ok(sqlx::query_scalar("SELECT jsonb_build_object('anchors',(SELECT jsonb_agg(to_jsonb(t) ORDER BY id) FROM aegaeon.federation_trust_anchors t),'chains',(SELECT jsonb_agg(to_jsonb(t) ORDER BY id) FROM aegaeon.federation_trust_chains t),'audits',(SELECT count(*) FROM aegaeon.audit_events WHERE event_type LIKE 'management.federation%'))").fetch_one(pool).await?)
}

#[tokio::test]
#[ignore = "requires PostgreSQL with CREATEDB; real management router in isolated database"]
async fn pg_federation_policy_pin_router_and_repository_controls() -> ManagementTestResult {
    let (control, pool, name) = database().await?;
    let result: ManagementTestResult = async {
        let initialized = initialize_management(&pool, &input()).await?;
        let (app, session) = client_credentials_policy::management_session(&pool).await?;
        let uri = format!(
            "/api/v1/teams/{}/environments/{}/federationTrustAnchors",
            initialized.team_id, initialized.environment_id
        );
        let key = InMemoryKeyManager::new();
        let jwks = json!({"keys":[key.federation_public_jwk().unwrap()]});
        let before = saved(&pool).await?;
        let invalids = [
            Value::Null,
            json!({}),
            json!(42),
            json!({"unused":{}}),
            json!({"unused":{"x":{"value":null,"essential":true}}}),
        ];
        for invalid in invalids {
            let (status, value) = send(
                &app,
                &session,
                &uri,
                Method::POST,
                json!({"entityId":ANCHOR,"jwks":jwks,"metadataPolicy":invalid}),
            )
            .await?;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{value}");
            assert_eq!(value["errorCode"], "invalid_request");
            assert_eq!(saved(&pool).await?, before);
            let repo = PgTrustAnchorRepository::new(pool.clone());
            assert!(repo
                .upsert(initialized.environment_id, ANCHOR, &jwks, Some(&invalid))
                .await
                .is_err());
            assert_eq!(saved(&pool).await?, before);
        }
        for (entity, policy) in [(ANCHOR, None), ("https://pinned.example", Some(pin()))] {
            let mut payload = json!({"entityId":entity,"jwks":jwks});
            if let Some(policy) = policy {
                payload["metadataPolicy"] = policy;
            }
            let (status, value) = send(&app, &session, &uri, Method::POST, payload).await?;
            assert_eq!(status, StatusCode::CREATED, "{value}");
        }
        pin_router_boundaries(&pool, &app, &session, &uri, &initialized, &jwks).await?;
        drop(app);
        Ok(())
    }
    .await;
    finish(result, cleanup(control, pool, &name).await)
}

async fn pin_router_boundaries(
    pool: &PgPool,
    app: &Router,
    session: &str,
    uri: &str,
    initialized: &super::super::super::initialization::InitializationOutput,
    jwks: &Value,
) -> ManagementTestResult {
    let id: Uuid =
        sqlx::query_scalar("SELECT id FROM aegaeon.federation_trust_anchors WHERE entity_id=$1")
            .bind(ANCHOR)
            .fetch_one(pool)
            .await?;
    sqlx::query("UPDATE aegaeon.federation_trust_anchors SET metadata_policy='{}' WHERE id=$1")
        .bind(id)
        .execute(pool)
        .await?;
    let repo = PgTrustAnchorRepository::new(pool.clone());
    let stored = repo.get(initialized.environment_id, ANCHOR).await?.unwrap();
    assert_eq!(stored.metadata_policy, Some(json!({})));
    assert!(stored.to_trust_anchor().is_err());
    let (status, value) = send(
        app,
        session,
        &format!("{uri}/{id}"),
        Method::GET,
        Value::Null,
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["metadataPolicy"], json!({}));
    let before = saved(pool).await?;
    sqlx::query("UPDATE aegaeon.team_memberships SET role='READONLY' WHERE team_id=$1 AND administrator_id=$2").bind(initialized.team_id).bind(initialized.administrator_id).execute(pool).await?;
    let (status, _) = send(
        app,
        session,
        uri,
        Method::POST,
        json!({"entityId":"https://denied.example","jwks":jwks}),
    )
    .await?;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(saved(pool).await?, before);
    sqlx::query(
        "UPDATE aegaeon.team_memberships SET role='OWNER' WHERE team_id=$1 AND administrator_id=$2",
    )
    .bind(initialized.team_id)
    .bind(initialized.administrator_id)
    .execute(pool)
    .await?;
    let wrong = uri.replace(
        &initialized.environment_id.to_string(),
        &Uuid::new_v4().to_string(),
    );
    let (status, _) = send(
        app,
        session,
        &wrong,
        Method::POST,
        json!({"entityId":"https://denied.example","jwks":jwks}),
    )
    .await?;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(saved(pool).await?, before);
    assert_eq!(
        send(
            app,
            session,
            &format!("{uri}/{id}"),
            Method::DELETE,
            Value::Null
        )
        .await?
        .0,
        StatusCode::NO_CONTENT
    );
    assert!(repo
        .get(initialized.environment_id, ANCHOR)
        .await?
        .is_none());
    Ok(())
}

fn signed(key: &InMemoryKeyManager, claims: &Value) -> anyhow::Result<String> {
    let jwk = key
        .federation_public_jwk()
        .ok_or_else(|| anyhow::anyhow!("test key absent"))?;
    let header = json!({"alg":key.federation_alg(),"typ":"entity-statement+jwt","kid":jwk["kid"]});
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims)?)
    );
    Ok(format!(
        "{input}.{}",
        URL_SAFE_NO_PAD.encode(key.sign_federation(input.as_bytes())?)
    ))
}

fn raw_chain(key: &InMemoryKeyManager, policy: Option<Value>) -> anyhow::Result<Vec<String>> {
    let now = crate::util::now_unix_epoch_secs()?;
    let jwks = json!({"keys":[key.federation_public_jwk().unwrap()]});
    let leaf = json!({"iss":LEAF,"sub":LEAF,"iat":now-10,"exp":now+300,"jwks":jwks,"authority_hints":[ANCHOR],"metadata":{"openid_relying_party":{"scope":"read write"}}});
    let anchor = json!({"iss":ANCHOR,"sub":ANCHOR,"iat":now-10,"exp":now+300,"jwks":jwks,"metadata":{"federation_entity":{"federation_fetch_endpoint":"https://anchor.example/fetch","federation_list_endpoint":"https://anchor.example/list"}}});
    let mut sub = json!({"iss":ANCHOR,"sub":LEAF,"iat":now-10,"exp":now+300,"jwks":jwks});
    if let Some(policy) = policy {
        sub["metadata_policy"] = policy;
    }
    Ok(vec![
        signed(key, &leaf)?,
        signed(key, &sub)?,
        signed(key, &anchor)?,
    ])
}

#[tokio::test]
#[ignore = "requires PostgreSQL with CREATEDB; refresh workflow with signed raw acquisition injection"]
async fn pg_federation_policy_refresh_admits_before_write_and_audit() -> ManagementTestResult {
    let (control, pool, name) = database().await?;
    let result:ManagementTestResult=async {
        let initialized=initialize_management(&pool,&input()).await?;
        let key=InMemoryKeyManager::new();let jwks=json!({"keys":[key.federation_public_jwk().unwrap()]});
        let repo=PgTrustAnchorRepository::new(pool.clone());repo.upsert(initialized.environment_id,ANCHOR,&jwks,None).await?;
        let row=Uuid::new_v4();
        sqlx::query("INSERT INTO aegaeon.federation_trust_chains(id,environment_id,leaf_entity_id,anchor_entity_id,chain_jwts,resolved_at,expires_at) VALUES($1,$2,$3,$4,'[\"retained invalid evidence\"]',NOW()-INTERVAL '2 hours',NOW()-INTERVAL '1 hour')").bind(row).bind(initialized.environment_id).bind(LEAF).bind(ANCHOR).execute(&pool).await?;
        let params:TeamEnvironmentTrustChainPath=serde_json::from_value(json!({"teamId":initialized.team_id.to_string(),"environmentId":initialized.environment_id.to_string(),"trustChainId":row.to_string()}))?;
        let session=ManagementSession::human(initialized.administrator_id,0);
        refresh_failures(&pool,&params,&session,&key).await?;
        let valid=raw_chain(&key,Some(pin()))?;
        let expected=valid.clone();
        let refreshed=refresh_with(&pool,&params,&session,Duration::from_secs(120),"valid-policy-refresh",|leaf,anchors,_| {
            assert_eq!(leaf,LEAF);assert_eq!(anchors.len(),1);std::future::ready(Ok(valid))
        }).await.map_err(|r|anyhow::anyhow!("valid refresh: {}",r.status()))?;
        assert_eq!(refreshed.chain_jwts,json!(expected));
        let audit:i64=sqlx::query_scalar("SELECT count(*) FROM aegaeon.audit_events WHERE request_id='valid-policy-refresh'").fetch_one(&pool).await?;assert_eq!(audit,1);
        refresh_scope_controls(&pool,&params,&session,initialized.team_id,initialized.administrator_id).await?;
        Ok(())
    }.await;
    finish(result, cleanup(control, pool, &name).await)
}

async fn refresh_failures(
    pool: &PgPool,
    params: &TeamEnvironmentTrustChainPath,
    session: &ManagementSession,
    key: &InMemoryKeyManager,
) -> ManagementTestResult {
    let before = saved(pool).await?;
    let bads = [
        json!({}),
        json!({"unused":{"x":{"add":[true]}}}),
        json!({"openid_relying_party":{"missing":{"essential":true}}}),
    ];
    for bad in bads {
        let raw = raw_chain(key, Some(bad))?;
        let result = refresh_with(
            pool,
            params,
            session,
            Duration::from_secs(120),
            "invalid-policy-refresh",
            |_, _, _| std::future::ready(Ok(raw)),
        )
        .await;
        assert_eq!(result.unwrap_err().status(), StatusCode::BAD_REQUEST);
        assert_eq!(saved(pool).await?, before);
    }
    for (from, to) in [
        (LEAF, "https://other-leaf.example"),
        (ANCHOR, "https://other-anchor.example"),
    ] {
        let raw = raw_chain(key, None)?;
        let wrong: Vec<String> = raw
            .iter()
            .map(|jwt| -> anyhow::Result<String> {
                let payload = URL_SAFE_NO_PAD.decode(jwt.split('.').nth(1).unwrap())?;
                let claims: Value =
                    serde_json::from_str(&String::from_utf8(payload)?.replace(from, to))?;
                signed(key, &claims)
            })
            .collect::<anyhow::Result<_>>()?;
        assert!(refresh_with(
            pool,
            params,
            session,
            Duration::from_secs(120),
            "wrong-signed-identity-refresh",
            |_, _, _| std::future::ready(Ok(wrong))
        )
        .await
        .is_err());
        assert_eq!(saved(pool).await?, before);
    }
    let mut invalid = raw_chain(key, None)?;
    invalid[0] = "invalid signed input".into();
    assert!(refresh_with(
        pool,
        params,
        session,
        Duration::from_secs(120),
        "invalid-raw-refresh",
        |_, _, _| std::future::ready(Ok(invalid))
    )
    .await
    .is_err());
    assert_eq!(saved(pool).await?, before);
    Ok(())
}

async fn refresh_scope_controls(
    pool: &PgPool,
    params: &TeamEnvironmentTrustChainPath,
    session: &ManagementSession,
    team: Uuid,
    administrator: Uuid,
) -> ManagementTestResult {
    let before = saved(pool).await?;
    let calls = AtomicUsize::new(0);
    sqlx::query("UPDATE aegaeon.team_memberships SET role='READONLY' WHERE team_id=$1 AND administrator_id=$2").bind(team).bind(administrator).execute(pool).await?;
    let result = refresh_with(
        pool,
        params,
        session,
        Duration::from_secs(120),
        "wrong-role-refresh",
        |_, _, _| {
            calls.fetch_add(1, Ordering::SeqCst);
            std::future::ready(Ok(vec![]))
        },
    )
    .await;
    assert_eq!(result.unwrap_err().status(), StatusCode::FORBIDDEN);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(saved(pool).await?, before);
    sqlx::query(
        "UPDATE aegaeon.team_memberships SET role='OWNER' WHERE team_id=$1 AND administrator_id=$2",
    )
    .bind(team)
    .bind(administrator)
    .execute(pool)
    .await?;
    let wrong = json!({"teamId":team.to_string(),"environmentId":Uuid::new_v4().to_string(),"trustChainId":params.trust_chain_id("test").expect("valid fixture id").to_string()});
    let wrong = serde_json::from_value(wrong)?;
    let result = refresh_with(
        pool,
        &wrong,
        session,
        Duration::from_secs(120),
        "wrong-environment-refresh",
        |_, _, _| {
            calls.fetch_add(1, Ordering::SeqCst);
            std::future::ready(Ok(vec![]))
        },
    )
    .await;
    assert_eq!(result.unwrap_err().status(), StatusCode::NOT_FOUND);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(saved(pool).await?, before);
    Ok(())
}
