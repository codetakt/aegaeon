use super::*;
use crate::organizations::consent::{capture, CaptureContext};
use crate::runtime_keys::{RuntimeKeySet, RuntimeKeyStatus, RuntimeKeyUsage};

pub(super) async fn finish(state: &AppState) -> TestResult {
    // test_app_state owns a distinct runtime pool. Await its actual cleanup
    // before ending the test runtime, including early-refusal transactions.
    tokio::time::timeout(std::time::Duration::from_secs(30), state.db_pool.close()).await?;
    crate::organizations::request_work::Admission::drain_for_test().await?;
    Ok(())
}

pub(super) async fn state(f: &Fixture) -> TestResult<AppState> {
    crate::organizations::repository_tests::consent::setup(f).await?;
    sqlx::query("UPDATE aegaeon.clients SET allowed_scopes=ARRAY['read','offline_access','documents'],allowed_grant_types=ARRAY['authorization_code','refresh_token','urn:ietf:params:oauth:grant-type:token-exchange'] WHERE environment_id=$1 AND client_identifier=$2")
        .bind(f.env.environment_id).bind(OWNER).execute(&f.pool).await?;
    let rs = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO aegaeon.clients(id,environment_id,configuration_version_id,client_identifier,name,client_type,redirect_uris,allowed_grant_types,allowed_scopes,token_endpoint_authentication_method) SELECT $1,id,active_configuration_version_id,$2,'resource server','CONFIDENTIAL',ARRAY['https://example.test/cb'],ARRAY['authorization_code'],ARRAY['openid'],'client_secret_basic' FROM aegaeon.environments WHERE id=$3")
        .bind(rs).bind(RS).bind(f.env.environment_id).execute(&f.pool).await?;
    let secret = crate::local_credentials::hash_password(SECRET)?;
    sqlx::query("INSERT INTO aegaeon.client_secrets(environment_id,client_id,configuration_version_id,secret_hash,active_slot,expires_at) SELECT environment_id,id,configuration_version_id,$1,1,statement_timestamp()+interval '1 hour' FROM aegaeon.clients WHERE environment_id=$2 AND client_identifier=ANY($3)")
        .bind(secret).bind(f.env.environment_id).bind(vec![OWNER,RS]).execute(&f.pool).await?;
    sqlx::query("UPDATE aegaeon.authorization_domain_targets SET introspection_clients=$1 WHERE environment_id=$2")
        .bind(json!([{"clientRegistrationId":rs,"clientIdentifier":RS}])).bind(f.env.environment_id).execute(&f.pool).await?;
    sqlx::query("UPDATE aegaeon.oauth_profiles SET allowed_grant_types=ARRAY['authorization_code','refresh_token','urn:ietf:params:oauth:grant-type:token-exchange'], token_endpoint_auth_methods_allowed=ARRAY['client_secret_basic'] WHERE environment_id=$1")
        .bind(f.env.environment_id).execute(&f.pool).await?;
    let mut state = test_app_state(f.pool.clone(), &f.env).await?;
    let cfg = Arc::make_mut(&mut state.cfg);
    cfg.enable_token_exchange = true;
    cfg.enable_jwt_access_tokens = true;
    cfg.enable_jwt_introspection = true;
    // Direct-issuer component fixture supplies the profile explicitly. Browser
    // integration separately uses actual database policy validation and loading.
    cfg.authorization_details_types_supported = vec![
        crate::organizations::consent::GRANT_TYPE.into(),
        crate::organizations::ORGANIZATION_ACCESS_TYPE.into(),
    ];
    cfg.security_policy.sender_constrained = crate::policy::SenderConstraint::None;
    cfg.token_exchange = serde_json::from_value(
        json!({"version":1,"targets":[{"audience":"management-api","resourceAliases":[]}],"rules":[{"clientId":OWNER,"sourceAudience":format!("{}/userinfo",f.env.issuer_url),"targetAudience":"management-api","scopes":[{"targetScope":"documents","sourceScopes":["read"]}],"defaultScopes":["documents"]}]}),
    )?;
    let der = crate::kms::managed_slot_tests::rsa_pkcs8(2048)?;
    let mut key = crate::kms::managed_slot_tests::rsa_key(
        &der,
        "organization-access",
        RuntimeKeyStatus::Active,
    )?;
    key.environment_id = state.environment_id;
    key.usage = RuntimeKeyUsage::JwtAccessTokenSigning;
    key.key_handle = crate::key_encryption::encrypt_key_handle(
        &URL_SAFE_NO_PAD.encode(der),
        &crate::key_encryption::load_key_encryption_key()
            .map_err(|_| "fixture encryption key unavailable")?,
        key.key_handle_encryption_context(),
    )?;
    state.keys.access_token = Arc::new(crate::kms::ManagedJwtKeyManager::try_from_runtime_keys(
        &RuntimeKeySet::try_new(vec![key])?,
        RuntimeKeyUsage::JwtAccessTokenSigning,
    )?);
    state.keys.jwt_introspection = Some(Arc::new(crate::kms::InMemoryPublicJwtKeyManager::new()?));
    super::super::use_redis(&mut state).await?;
    crate::web::test_support::native_dpop::install(&mut state)?;
    Ok(state)
}

pub(super) async fn parent(
    f: &Fixture,
    state: &AppState,
    key: &aegaeon_crypto::signing::Ed25519KeyData,
) -> TestResult<Value> {
    let mut request = crate::organizations::repository_tests::consent::request(f);
    request.organizations[0].identifier = IDENTIFIER.into();
    parent_request(f, state, key, request).await
}

pub(super) async fn parent_request(
    f: &Fixture,
    state: &AppState,
    key: &aegaeon_crypto::signing::Ed25519KeyData,
    request: crate::organizations::consent::GrantRequest,
) -> TestResult<Value> {
    let proof = crate::web::test_support::native_dpop::proof(state, key, json!({}))?;
    let jkt = crate::util::compute_dpop_jkt_from_proof_with_max_len(&proof, 8192).ok_or("jkt")?;
    let subject = format!("organization-user-{}", f.users[1]);
    let now = i64::try_from(crate::util::now_unix_epoch_secs()?)?;
    let mut tx = f.pool.begin().await?;
    let approval = capture(
        &mut tx,
        CaptureContext {
            original_authentication: None,
            environment_id: state.environment_id,
            issuer: &state.issuer,
            client_id: OWNER,
            subject: &subject,
            dpop_jkt: &jkt,
            auth_time: now - 10,
            captured_at: now,
        },
        &request,
    )
    .await?;
    tx.commit().await?;
    let req = serde_json::from_value(
        json!({"response_type":"code","client_id":OWNER,"redirect_uri":"https://example.test/cb","scope":"read offline_access","resource":format!("{}/userinfo",state.issuer),"state":"original","code_challenge":"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM","code_challenge_method":"S256","dpop_jkt":jkt,"authorization_details":[request]}),
    )?;
    let mut input = crate::authcode::AuthorizationCodeIssueInput::new(req, subject, true, now - 10);
    input.organization_approval = Some(approval);
    input.exchange_scope_ceiling = vec!["read".into(), "offline_access".into(), "documents".into()];
    let (code, _) = state
        .tokens
        .issuer
        .issue_authorization_code_with_local_profile(input)?;
    let (status, body) = http(
        state,
        "/token",
        OWNER,
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", "https://example.test/cb"),
            ("code_verifier", VERIFIER),
        ],
        Some(&proof),
        false,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "original HTTP issuance: {body}");
    Ok(body)
}
