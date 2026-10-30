use super::*;
use crate::organizations::http_input::VersionTag;
use crate::organizations::invitations::transport::{fixture::Fixture as Mail, Credential};
use crate::organizations::operators::mutations::delivery::{self as channel, Change, Channel};
use std::time::Duration;

mod lifecycle;
mod refusals;

const ACCEPT: &str = "organization.invitation.accept";
fn credential() -> String {
    URL_SAFE_NO_PAD.encode([71u8; 32])
}

async fn configured(f: &Fixture) -> TestResult<AppState> {
    configured_ttl(f, 300).await
}

async fn configured_ttl(f: &Fixture, ttl: u64) -> TestResult<AppState> {
    let mut state = setup_members(f).await?;
    let audience = format!("{}/organization-invitations", state.issuer);
    sqlx::query("UPDATE aegaeon.clients SET allowed_scopes=allowed_scopes || $1::text WHERE environment_id=$2 AND client_identifier=$3").bind(ACCEPT).bind(state.environment_id).bind(OWNER).execute(&f.pool).await?;
    crate::web::dcr_runtime::synchronize_dcr_database_runtime_clients(
        &state,
        &state.issuer,
        "delegated-fixture",
    )
    .await
    .map_err(|_| "client projection")?;
    sqlx::query("INSERT INTO aegaeon.authorization_domain_targets(environment_id,domain_id,audience,management) VALUES($1,$2,$3,true)").bind(state.environment_id).bind(f.organization.scope.domain_id).bind(&audience).execute(&f.pool).await?;
    sqlx::query("UPDATE aegaeon.organization_client_bindings SET targets=targets || $1::jsonb,revision=revision+1 WHERE environment_id=$2").bind(json!([{"audience":audience,"privileges":[ACCEPT]}])).bind(state.environment_id).execute(&f.pool).await?;
    let mut policy = serde_json::to_value(&state.cfg.token_exchange)?;
    policy["targets"]
        .as_array_mut()
        .ok_or("targets")?
        .push(json!({"audience":audience,"resourceAliases":[]}));
    policy["rules"].as_array_mut().ok_or("rules")?.push(json!({"clientId":OWNER,"sourceAudience":format!("{}/userinfo",state.issuer),"targetAudience":audience,"scopes":[{"targetScope":ACCEPT,"sourceScopes":["read"]}],"defaultScopes":[ACCEPT]}));
    let cfg = Arc::make_mut(&mut state.cfg);
    cfg.access_token_ttl_secs = ttl;
    cfg.token_exchange = serde_json::from_value(policy)?;
    let issuer = crate::authcode::TokenIssuer::with_stores(
        Arc::clone(&state.keys.access_token),
        state.tokens.issuer.code_store.clone(),
        state.tokens.store.as_ref().clone(),
    )
    .with_oidc(state.oidc.config.as_deref().cloned())
    .with_issuer(state.issuer.to_string())
    .with_token_exchange_policy(state.cfg.token_exchange.clone())
    .with_jwt_access_tokens_enabled(true)
    .with_runtime_ttls_for_tests(ttl, 3600, 300);
    state.tokens.issuer = Arc::new(issuer);
    state.validate_subject_namespace().await?;
    sqlx::query("UPDATE aegaeon.organization_operator_grants SET capabilities='[\"configure\",\"provision\"]',revision=revision+1 WHERE domain_id=$1").bind(f.organization.scope.domain_id).execute(&f.pool).await?;
    let mut tx = f.pool.begin().await?;
    let revision: i64 =
        sqlx::query_scalar("SELECT revision FROM aegaeon.authorization_domains WHERE id=$1")
            .bind(f.organization.scope.domain_id)
            .fetch_one(&mut *tx)
            .await?;
    channel::apply(
        &mut tx,
        f.organization.scope,
        f.env.team_id,
        &f.actor,
        "delivery",
        &Change {
            expected_revision: revision,
            channel: Some(Channel {
                endpoint: "https://delivery.example.test/envelopes".into(),
                credential_sha256: Credential::parse(credential())
                    .map_err(|()| "credential")?
                    .digest(),
            }),
        },
    )
    .await?;
    tx.commit().await?;
    Ok(state)
}

async fn recipient_token(
    state: &AppState,
    user: Uuid,
    key: &aegaeon_crypto::signing::Ed25519KeyData,
) -> TestResult<String> {
    let signed = crate::web::test_support::native_dpop::proof(state, key, json!({}))?;
    let jkt = crate::util::compute_dpop_jkt_from_proof_with_max_len(&signed, 8192).ok_or("jkt")?;
    let request = serde_json::from_value(
        json!({"response_type":"code","client_id":OWNER,"redirect_uri":"https://example.test/cb","scope":"read offline_access","resource":format!("{}/userinfo",state.issuer),"state":"recipient","code_challenge":"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM","code_challenge_method":"S256","dpop_jkt":jkt}),
    )?;
    let now = i64::try_from(crate::util::now_unix_epoch_secs()?)?;
    let mut input =
        crate::authcode::AuthorizationCodeIssueInput::new(request, user.to_string(), true, now);
    input.exchange_scope_ceiling = vec!["read".into(), "offline_access".into(), ACCEPT.into()];
    let (code, _) = state
        .tokens
        .issuer
        .issue_authorization_code_with_local_profile(input)?;
    let (status, parent) = http(
        state,
        "/token",
        OWNER,
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", "https://example.test/cb"),
            ("code_verifier", VERIFIER),
        ],
        Some(&signed),
        false,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{parent}");
    let signed = crate::web::test_support::native_dpop::proof(state, key, json!({}))?;
    let (status, selected) = http(
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
            (
                "audience",
                &format!("{}/organization-invitations", state.issuer),
            ),
            ("scope", ACCEPT),
        ],
        Some(&signed),
        false,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{selected}");
    Ok(selected["access_token"].as_str().ok_or("token")?.into())
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL and Redis"]
async fn shared_redis_organizations_delegated_invitation_actual_tls_acceptance_and_root_revocation(
) -> TestResult {
    let f = Fixture::with_identifier(IDENTIFIER).await?;
    let state = configured_ttl(&f, 10).await?;
    let result=async {
        let key=aegaeon_crypto::signing::Ed25519SigningKey::generate()?;
        let (parent,token)=issue(&f,&state,&key,MANAGE).await?;
        let client=MemberClient {state:&state,key:&key,read:token.clone(),write:token.clone(),list:String::new()};
        let (_,context_token)=issue(&f,&state,&key,PRIVILEGE).await?;
        let context=client.request(Method::GET,PATH,&context_token,None,None,"").await?;
        assert_eq!(context.0,StatusCode::OK,"{}",context.1);
        assert!(context.2.is_none(),"context is not the organization representation");
        let object=context.1["organization"]["id"].as_str().ok_or("object")?;
        assert_eq!(Uuid::parse_str(object)?,f.organization.id);
        let path=format!("/organizations/{object}/invitations");
        let tag=context.1["organization"]["versionTag"].as_str().ok_or("version")?.to_owned();
        let body=r#"{"recipient":"Member@example.test","roles":["reader"],"reason":"invite a member"}"#;
        assert_eq!(client.request(Method::POST,&path,&token,None,Some("join"),body).await?.0,StatusCode::PRECONDITION_REQUIRED);
        let created=client.request(Method::POST,&path,&token,Some(&tag),Some("join"),body).await?;
        assert_eq!(created.0,StatusCode::OK,"{}",created.1);
        assert_eq!(client.request(Method::POST,&path,&token,Some(&tag),Some("join"),body).await?,created);
        let id=Uuid::parse_str(created.1["id"].as_str().ok_or("invitation")?)?;
        assert_eq!(created.1.as_object().ok_or("metadata")?.len(),6);
        let issuing_meta=state.tokens.store.try_get_bearer_meta(&token)?.ok_or("metadata")?;
        let expires=issuing_meta.expires_at;
        let root_id=issuing_meta.exchange_grant.as_ref().and_then(|grant|grant.root()).ok_or("root")?.id.clone();
        let deadline=crate::util::unix_epoch_secs(expires)?;
        assert!(created.1["expiresAt"].as_u64().ok_or("invitation deadline")? > deadline);
        let wait=deadline.saturating_add(1).saturating_sub(crate::util::now_unix_epoch_secs()?);
        assert!(wait<=11);
        tokio::time::sleep(Duration::from_secs(wait)).await;
        assert_eq!(client.request(Method::GET,&format!("{path}/{id}"),&token,None,None,"").await?.0,StatusCode::UNAUTHORIZED);
        let user=Uuid::new_v4();
        sqlx::query("INSERT INTO aegaeon.end_users(id,environment_id,subject,status) VALUES($1,$2,$3,'ACTIVE')").bind(user).bind(state.environment_id).bind(user.to_string()).execute(&f.pool).await?;
        let mail=Mail::new(204,vec![],Duration::ZERO,false)?;
        let send=|challenge| crate::web::OrganizationDeliveryRequest { identity_request_id: None,domain_id:f.organization.scope.domain_id,invitation_id:id,challenge_id:challenge,credential:credential()};
        assert_eq!(state.deliver_organization_invitation(send(None)).await?.outcome,"acknowledged");
        let capability=mail.received.lock().unwrap()[0]["capability"].clone();
        let recipient_key=aegaeon_crypto::signing::Ed25519SigningKey::generate()?;
        let recipient=recipient_token(&state,user,&recipient_key).await?;
        let consumer=MemberClient {state:&state,key:&recipient_key,read:recipient.clone(),write:recipient.clone(),list:String::new()};
        let base=format!("/organization-invitations/{}/{id}",f.organization.scope.domain_id);
        let challenge=consumer.request(Method::POST,&format!("{base}/challenges"),&recipient,None,Some("address"),&json!({"invitationCapability":capability}).to_string()).await?;
        assert_eq!(challenge.0,StatusCode::OK,"{}",challenge.1);
        let challenge=Uuid::parse_str(challenge.1["challengeId"].as_str().ok_or("challenge")?)?;
        assert_eq!(state.deliver_organization_invitation(send(Some(challenge))).await?.outcome,"acknowledged");
        let secret=mail.received.lock().unwrap()[1]["capability"].clone();
        let body=json!({"invitationCapability":capability,"challengeId":challenge,"challengeCapability":secret}).to_string();
        let accept_path=format!("{base}/accept");
        let (mut store,fault_key)=state.tokens.store.retained_root_fault_key_for_tests(&root_id)?;
        assert_eq!(redis::cmd("GET").arg(&fault_key).query::<Option<String>>(&mut store)?,None);
        redis::cmd("SET").arg(&fault_key).arg("malformed-owned-authority").query::<()>(&mut store)?;
        assert_eq!(consumer.request(Method::POST,&accept_path,&recipient,None,None,&body).await?.0,StatusCode::SERVICE_UNAVAILABLE);
        let absent:i64=sqlx::query_scalar("SELECT count(*) FROM aegaeon.organization_memberships WHERE organization_id=$1 AND end_user_id=$2").bind(f.organization.id).bind(user).fetch_one(&f.pool).await?;assert_eq!(absent,0);
        redis::cmd("DEL").arg(&fault_key).query::<()>(&mut store)?;
        let (accepted,concurrent)=tokio::join!(
            consumer.request(Method::POST,&accept_path,&recipient,None,None,&body),
            consumer.request(Method::POST,&accept_path,&recipient,None,None,&body)
        );
        let accepted=accepted?;assert_eq!(concurrent?,accepted);
        assert_eq!(accepted.0,StatusCode::OK,"{}",accepted.1);
        assert_eq!(consumer.request(Method::POST,&format!("{base}/accept"),&recipient,None,None,&body).await?,accepted);
        let generation:i64=sqlx::query_scalar("SELECT grant_generation FROM aegaeon.application_organizations WHERE id=$1").bind(f.organization.id).fetch_one(&f.pool).await?;
        assert_eq!(generation,f.organization.grant_generation);
        let count:i64=sqlx::query_scalar("SELECT count(*) FROM aegaeon.organization_memberships WHERE organization_id=$1 AND end_user_id=$2").bind(f.organization.id).bind(user).fetch_one(&f.pool).await?;assert_eq!(count,1);
        state.tokens.store.try_revoke_token(parent["refresh_token"].as_str().ok_or("root")?)?;
        assert_eq!(consumer.request(Method::POST,&format!("{base}/accept"),&recipient,None,None,&body).await?.0,StatusCode::FORBIDDEN);
        assert!(state.deliver_organization_invitation(send(None)).await.is_err());
        drop(mail);Ok(())
    }.await;
    fixture::finish(&state).await?;
    f.cleanup(result).await
}
