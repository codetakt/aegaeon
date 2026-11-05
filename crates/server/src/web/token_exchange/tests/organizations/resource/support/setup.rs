use super::*;
use crate::organizations::{
    authentication::OriginalAuthentication,
    consent::{self, CaptureContext},
};

pub(super) async fn state(f: &Fixture) -> TestResult<(AppState, OriginalAuthentication)> {
    let mut state = super::super::setup(f).await?;
    let (mut policy, mut evidence) = support_policy::evidence(f).await?;
    let now = i64::try_from(crate::util::now_unix_epoch_secs()?)?;
    evidence.auth_time = now - 10;
    evidence.observed_at = now;
    let own = format!("{}/organizations", state.issuer);
    let support = format!("{}/organization-support", state.issuer);
    policy.entitlements[0].audience = own.clone();
    sqlx::query("INSERT INTO aegaeon.authorization_domain_targets(environment_id,domain_id,audience,management) VALUES($1,$2,$3,true)").bind(f.env.environment_id).bind(f.organization.scope.domain_id).bind(&support).execute(&f.pool).await?;
    sqlx::query("UPDATE aegaeon.organization_client_bindings SET targets=targets || $1::jsonb,revision=revision+1 WHERE environment_id=$2").bind(json!([{"audience":support,"privileges":[service::PRIVILEGE]}])).bind(f.env.environment_id).execute(&f.pool).await?;
    sqlx::query("UPDATE aegaeon.clients SET allowed_scopes=allowed_scopes || $1::text WHERE environment_id=$2 AND client_identifier=$3").bind(service::PRIVILEGE).bind(f.env.environment_id).bind(OWNER).execute(&f.pool).await?;
    let rs: Uuid = sqlx::query_scalar(
        "SELECT id FROM aegaeon.clients WHERE environment_id=$1 AND client_identifier=$2",
    )
    .bind(f.env.environment_id)
    .bind(RS)
    .fetch_one(&f.pool)
    .await?;
    sqlx::query("UPDATE aegaeon.authorization_domain_targets SET introspection_clients=$1 WHERE environment_id=$2 AND audience=$3").bind(json!([{"clientRegistrationId":rs,"clientIdentifier":RS}])).bind(f.env.environment_id).bind(&own).execute(&f.pool).await?;
    support_policy::configure(f, "support", 1, Some(policy)).await?;
    crate::web::dcr_runtime::synchronize_dcr_database_runtime_clients(
        &state,
        &state.issuer,
        "support-fixture",
    )
    .await
    .map_err(|_| "client projection")?;
    let cfg = Arc::make_mut(&mut state.cfg);
    cfg.access_token_ttl_secs = 300;
    cfg.token_exchange = serde_json::from_value(
        json!({"version":1,"targets":[{"audience":own,"resourceAliases":[]}],"rules":[{"clientId":OWNER,"sourceAudience":support,"targetAudience":own,"scopes":[{"targetScope":"documents","sourceScopes":[service::PRIVILEGE]}],"defaultScopes":["documents"]}]}),
    )?;
    crate::web::token_exchange::tests::use_redis(&mut state).await?;
    crate::web::token_exchange::tests::organizations::invitation_recipient::setup::lifetime(
        &mut state, 300,
    )
    .await?;
    Ok((state, evidence))
}

pub(super) async fn parent(
    f: &Fixture,
    state: &AppState,
    key: &aegaeon_crypto::signing::Ed25519KeyData,
    evidence: &OriginalAuthentication,
) -> TestResult<(Value, String)> {
    let signed = crate::web::test_support::native_dpop::proof(state, key, json!({}))?;
    let jkt = crate::util::compute_dpop_jkt_from_proof_with_max_len(&signed, 8192).ok_or("jkt")?;
    let now = i64::try_from(crate::util::now_unix_epoch_secs()?)?;
    let request = GrantRequest::parse(
        &json!([{"type":GRANT_TYPE,"locations":[format!("{}/organizations",state.issuer)],"organizations":[{"identifier":IDENTIFIER,"privileges":[PRIVILEGE],"administrative_access":true}]}]),
    )?;
    let mut tx = f.pool.begin().await?;
    let approval = consent::capture(
        &mut tx,
        CaptureContext {
            environment_id: state.environment_id,
            issuer: &state.issuer,
            client_id: OWNER,
            subject: &evidence.subject,
            dpop_jkt: &jkt,
            auth_time: evidence.auth_time,
            captured_at: now,
            original_authentication: Some(evidence),
        },
        &request,
    )
    .await?;
    tx.commit().await?;
    let req = serde_json::from_value(
        json!({"response_type":"code","client_id":OWNER,"redirect_uri":"https://example.test/cb","scope":format!("{} offline_access",service::PRIVILEGE),"resource":format!("{}/organization-support",state.issuer),"state":"support","code_challenge":"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM","code_challenge_method":"S256","dpop_jkt":jkt,"authorization_details":[request]}),
    )?;
    let mut input = crate::authcode::AuthorizationCodeIssueInput::new(
        req,
        evidence.subject.clone(),
        true,
        evidence.auth_time,
    );
    input.organization_approval = Some(approval);
    input.exchange_scope_ceiling = vec![
        "read".into(),
        "offline_access".into(),
        "documents".into(),
        service::PRIVILEGE.into(),
    ];
    let (code, _) = state
        .tokens
        .issuer
        .issue_authorization_code_with_local_profile_async(input)
        .await?;
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
    let activation = parent["access_token"]
        .as_str()
        .ok_or("activation")?
        .to_owned();
    let metadata = state
        .tokens
        .store
        .try_get_bearer_meta(&activation)?
        .ok_or("parent metadata")?;
    let grant = metadata
        .exchange_grant
        .as_ref()
        .ok_or("original exchange grant")?;
    assert!(grant.original_details_match(metadata.authorization_details.as_ref()));
    assert!(
        !grant.covers_output(
            &metadata.client_id,
            &metadata.user_id,
            &metadata.audience,
            &metadata.granted_scopes
        ),
        "original parent capabilities describe destinations, not its source token"
    );
    Ok((parent, activation))
}
