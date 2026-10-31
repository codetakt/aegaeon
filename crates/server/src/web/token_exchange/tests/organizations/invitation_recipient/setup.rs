use super::*;

pub(super) async fn new() -> TestResult<RecipientFixture> {
    create(true).await
}
pub(super) async fn undelivered() -> TestResult<RecipientFixture> {
    create(false).await
}
async fn create(deliver: bool) -> TestResult<RecipientFixture> {
    let base = Fixture::with_identifier(IDENTIFIER).await?;
    let mut state = fixture::state(&base).await?;
    let audience = format!("{}/organization-invitations", state.issuer);
    sqlx::query("UPDATE aegaeon.organization_operator_grants SET capabilities='[\"configure\",\"provision\"]',revision=revision+1 WHERE domain_id=$1").bind(base.organization.scope.domain_id).execute(&base.pool).await?;
    sqlx::query("UPDATE aegaeon.clients SET allowed_scopes=allowed_scopes || $1::text WHERE environment_id=$2 AND client_identifier=$3").bind(SCOPE).bind(state.environment_id).bind(OWNER).execute(&base.pool).await?;
    crate::web::dcr_runtime::synchronize_dcr_database_runtime_clients(
        &state,
        &state.issuer,
        "recipient-fixture",
    )
    .await
    .map_err(|_| "fixture client projection")?;
    sqlx::query("INSERT INTO aegaeon.authorization_domain_targets(environment_id,domain_id,audience,management) VALUES ($1,$2,$3,true)").bind(state.environment_id).bind(base.organization.scope.domain_id).bind(&audience).execute(&base.pool).await?;
    sqlx::query("UPDATE aegaeon.organization_client_bindings SET targets=targets || $1::jsonb,revision=revision+1 WHERE environment_id=$2").bind(json!([{"audience":audience,"privileges":[SCOPE]}])).bind(state.environment_id).execute(&base.pool).await?;
    let cfg = Arc::make_mut(&mut state.cfg);
    cfg.access_token_ttl_secs = 300;
    cfg.token_exchange = serde_json::from_value(
        json!({"version":1,"targets":[{"audience":audience,"resourceAliases":[]}],"rules":[{"clientId":OWNER,"sourceAudience":format!("{}/userinfo",state.issuer),"targetAudience":audience,"scopes":[{"targetScope":SCOPE,"sourceScopes":["read"]}],"defaultScopes":[SCOPE]}]}),
    )?;
    super::super::super::use_redis(&mut state).await?;
    lifetime(&mut state, 300).await?;
    let organization = Organization {
        id: Uuid::new_v4(),
        scope: base.organization.scope,
        external_id: "recipient-http-target".into(),
        state: OrganizationState::Provisioning,
        revision: 1,
        grant_generation: 1,
    };
    let witness = Arc::new(CallerFixture::new(state.environment_id).await?);
    let (invitation, capability) = in_epoch(
        &witness,
        Box::pin(async {
            let now = i64::try_from(crate::util::now_unix_epoch_secs()?)?;
            let mut tx = base.pool.begin().await?;
            crate::organizations::repository::create_organization(
                &mut tx,
                &organization,
                &base.actor,
            )
            .await?;
            let invitation = service::issue_first_admin(
                &mut tx,
                service::Issuance {
                    scope: organization.scope,
                    team: base.env.team_id,
                    actor: &base.actor,
                    key: "recipient-http-issue",
                    request: &service::FirstAdminRequest {
                        organization_id: organization.id,
                        expected_revision: 1,
                        recipient: "Invitee@example.test".into(),
                        roles: std::collections::BTreeSet::from(["admin".into()]),
                        lifetime_seconds: Some(3600),
                    },
                    now,
                },
            )
            .await?;
            tx.commit().await?;
            let capability = if deliver {
                let mut tx = base.pool.begin().await?;
                let delivery = service::claim_invitation_delivery(
                    &mut tx,
                    organization.scope,
                    invitation.id,
                    now,
                )
                .await?;
                tx.commit().await?;
                delivery.capability.into_delivery()
            } else {
                String::new()
            };
            Ok((invitation, capability))
        }),
    )
    .await?;
    Ok(RecipientFixture {
        witness,
        base,
        state,
        organization,
        invitation: invitation.id,
        capability,
    })
}

pub(super) async fn token(
    f: &RecipientFixture,
    key: &aegaeon_crypto::signing::Ed25519KeyData,
) -> TestResult<(Value, String)> {
    let state = &f.state;
    let proof = crate::web::test_support::native_dpop::proof(state, key, json!({}))?;
    let jkt = crate::util::compute_dpop_jkt_from_proof_with_max_len(&proof, 8192).ok_or("jkt")?;
    let req = serde_json::from_value(
        json!({"response_type":"code","client_id":OWNER,"redirect_uri":"https://example.test/cb","scope":"read offline_access","resource":format!("{}/userinfo",state.issuer),"state":"recipient","code_challenge":"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM","code_challenge_method":"S256","dpop_jkt":jkt}),
    )?;
    let now = i64::try_from(crate::util::now_unix_epoch_secs()?)?;
    let mut input = crate::authcode::AuthorizationCodeIssueInput::new(
        req,
        format!("organization-user-{}", f.base.users[1]),
        true,
        now,
    );
    input.exchange_scope_ceiling = vec!["read".into(), "offline_access".into(), SCOPE.into()];
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
        Some(&proof),
        false,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{parent}");
    let proof = crate::web::test_support::native_dpop::proof(state, key, json!({}))?;
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
            ("scope", SCOPE),
        ],
        Some(&proof),
        false,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{selected}");

    Ok((
        parent,
        selected["access_token"]
            .as_str()
            .ok_or("recipient token")?
            .into(),
    ))
}

pub(crate) async fn lifetime(state: &mut AppState, seconds: u64) -> TestResult {
    let issuer = crate::authcode::TokenIssuer::with_stores(
        Arc::clone(&state.keys.access_token),
        state.tokens.issuer.code_store.clone(),
        state.tokens.store.as_ref().clone(),
    )
    .with_oidc(state.oidc.config.as_deref().cloned())
    .with_issuer(state.issuer.to_string())
    .with_token_exchange_policy(state.cfg.token_exchange.clone())
    .with_jwt_access_tokens_enabled(true)
    .with_runtime_ttls_for_tests(seconds, 3600, 300);
    state.tokens.issuer = Arc::new(issuer);
    state.validate_subject_namespace().await?;
    Ok(())
}
