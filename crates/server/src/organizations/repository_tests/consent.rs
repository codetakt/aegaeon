use super::*;
use crate::organizations::consent::{self, CaptureContext, Consent, GrantRequest, GRANT_TYPE};

pub(crate) fn request(f: &Fixture) -> GrantRequest {
    GrantRequest::parse(&serde_json::json!([{
        "type":GRANT_TYPE,"locations":["management-api"],
        "organizations":[{"identifier":f.organization.external_id,"privileges":["documents.read"]}]
    }]))
    .unwrap()
}

pub(crate) async fn setup(f: &Fixture) -> TestResult {
    clients::configured(f).await?;
    let id = clients::registration(f, "consent-client").await?;
    clients::apply(f, "client", &clients::create(id, 1)).await?;
    let mut tx = f.pool.begin().await?;
    repository::update_membership(
        &mut tx,
        f.organization.scope,
        f.organization.id,
        MembershipUpdate {
            user_id: f.users[1],
            expected_revision: 1,
            state: MembershipState::Active,
            roles: BTreeSet::from(["reader".into()]),
        },
        &f.actor,
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

pub(super) async fn capture(
    f: &Fixture,
    request: &GrantRequest,
) -> Result<Consent, RepositoryError> {
    let mut tx = f.pool.begin().await?;
    let result = consent::capture(
        &mut tx,
        CaptureContext {
            original_authentication: None,
            environment_id: f.env.environment_id,
            issuer: &f.env.issuer_url,
            client_id: "consent-client",
            subject: &format!("organization-user-{}", f.users[1]),
            dpop_jkt: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            auth_time: 100,
            captured_at: 110,
        },
        request,
    )
    .await?;
    tx.commit().await?;
    Ok(result)
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL"]
async fn pg_organizations_original_consent_rechecks_membership_client_domain_and_identity(
) -> TestResult {
    let f = Fixture::new().await?;
    let result = async {
        setup(&f).await?;
        let requested = request(&f);
        let original = capture(&f, &requested).await?;
        assert_eq!(capture(&f, &requested).await?, original);
        assert_eq!(original.memberships[&f.organization.id].privileges, BTreeSet::from(["documents.read".into()]));
        let mut excessive = requested.clone();
        excessive.organizations[0].privileges.push("documents.write".into());
        assert!(matches!(capture(&f, &excessive).await, Err(RepositoryError::Authority(AuthorityError::Forbidden))));
        sqlx::query("UPDATE aegaeon.organization_role_definitions SET version=version+1,privileges='[\"documents.read\",\"documents.write\"]' WHERE environment_id=$1 AND role_key='reader'").bind(f.env.environment_id).execute(&f.pool).await?;
        assert_ne!(capture(&f, &requested).await?, original, "role expansion requires another approval");
        sqlx::query("UPDATE aegaeon.authorization_domains SET enabled=false,revision=revision+1 WHERE id=$1").bind(f.organization.scope.domain_id).execute(&f.pool).await?;
        assert!(matches!(capture(&f, &requested).await, Err(RepositoryError::Authority(AuthorityError::Forbidden))));
        sqlx::query("UPDATE aegaeon.authorization_domains SET enabled=true,revision=revision+1 WHERE id=$1").bind(f.organization.scope.domain_id).execute(&f.pool).await?;
        assert_ne!(capture(&f, &requested).await?.domain_revision, original.domain_revision);
        sqlx::query("UPDATE aegaeon.clients SET dpop_bound_access_tokens=false WHERE id=$1").bind(original.client_registration_id).execute(&f.pool).await?;
        assert!(matches!(capture(&f, &requested).await, Err(RepositoryError::Authority(AuthorityError::Forbidden))));
        sqlx::query("UPDATE aegaeon.clients SET dpop_bound_access_tokens=true WHERE id=$1").bind(original.client_registration_id).execute(&f.pool).await?;
        let mut exhausted=f.pool.begin().await?;
        sqlx::query("UPDATE aegaeon.authorization_domains SET revision=$2 WHERE id=$1").bind(f.organization.scope.domain_id).bind(i64::MAX).execute(&mut *exhausted).await?;
        exhausted.commit().await?;
        assert!(capture(&f,&requested).await.is_err(),"terminal revision cannot issue fresh authority");
        sqlx::query("UPDATE aegaeon.authorization_domains SET revision=$2 WHERE id=$1").bind(f.organization.scope.domain_id).bind(original.domain_revision+2).execute(&f.pool).await?;
        sqlx::query("UPDATE aegaeon.end_users SET status='SUSPENDED' WHERE id=$1").bind(f.users[1]).execute(&f.pool).await?;
        assert!(matches!(capture(&f, &requested).await, Err(RepositoryError::Authority(AuthorityError::Forbidden))));
        Ok(())
    }.await;
    f.cleanup(result).await
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL"]
async fn pg_organizations_original_ceiling_root_serialization_and_refresh_are_immutable(
) -> TestResult {
    use crate::policy::token_exchange::{ExchangeGrant, TokenExchangePolicy};
    let f = Fixture::new().await?;
    let result = async {
        setup(&f).await?;
        let consent = capture(&f, &request(&f)).await?;
        let policy: TokenExchangePolicy = serde_json::from_value(serde_json::json!({
            "version":1,"targets":[{"audience":"management-api","resourceAliases":[]}],
            "rules":[{"clientId":"consent-client","sourceAudience":"parent-api","targetAudience":"management-api",
                "scopes":[{"targetScope":"documents","sourceScopes":["read"]}],"defaultScopes":["documents"]}]
        }))?;
        let mut grant = policy.capture(&f.env.issuer_url,"consent-client",&consent.subject,"parent-api",&["read".into()],&["documents".into()]).ok_or("exchange capture missing")?
            .with_lineage_deadline(std::time::UNIX_EPOCH + std::time::Duration::from_secs(100000));
        let details = serde_json::json!([consent.request]);
        grant.bind_organization_approval(&consent, &details)?;
        let authority = grant.organization.as_ref().ok_or("organization missing")?;
        assert_eq!(authority.ceiling.expires_at, 86510);
        assert!(grant.original_details_match(Some(&details)));
        assert!(!grant.original_details_match(None));
        let encoded = serde_json::to_value(&grant)?;
        for path in ["root", "subject", "privilege"] {
            let mut corrupt = encoded.clone();
            match path {
                "root" => corrupt["root"]["id"] = serde_json::json!("replacement"),
                "subject" => corrupt["organization"]["ceiling"]["binding"]["subject"] = serde_json::json!("other"),
                _ => corrupt["organization"]["ceiling"]["memberships"][f.organization.id.to_string()]["privileges"] = serde_json::json!(["documents.write"]),
            }
            let corrupt: ExchangeGrant = serde_json::from_value(corrupt)?;
            assert!(!corrupt.original_details_match(Some(&details)), "{path}");
        }
        let mut refresh = crate::authcode::types::RefreshToken::new(crate::authcode::types::RefreshTokenInput::new("consent-client".into(), consent.subject.clone()));
        refresh.auth_time_epoch_secs = consent.auth_time;
        refresh.exchange_grant = Some(grant.clone());
        let restored: crate::authcode::types::RefreshToken = serde_json::from_value(serde_json::to_value(refresh.rotate())?)?;
        assert_eq!(restored.exchange_grant, Some(grant));
        assert_eq!(restored.auth_time_epoch_secs, 100);
        sqlx::query("DELETE FROM aegaeon.clients WHERE id=$1").bind(consent.client_registration_id).execute(&f.pool).await?;
        clients::registration(&f,"consent-client").await?;
        assert!(matches!(capture(&f,&request(&f)).await,Err(RepositoryError::Authority(AuthorityError::Forbidden))));
        Ok(())
    }.await;
    f.cleanup(result).await
}

#[test]
fn organizations_original_request_rejects_ambiguous_or_oversized_selection() {
    let valid = serde_json::json!([{"type":GRANT_TYPE,"locations":["api"],"organizations":[{"identifier":"学校-É","privileges":["read"]}]}]);
    assert!(GrantRequest::parse(&valid).is_ok());
    for invalid in [
        serde_json::json!([]),
        serde_json::json!([valid[0], valid[0]]),
    ] {
        assert!(GrantRequest::parse(&invalid).is_err());
    }
    for (key, value) in [
        ("unknown", serde_json::json!(true)),
        ("locations", serde_json::json!(["api", "api"])),
    ] {
        let mut invalid = valid.clone();
        invalid[0][key] = value;
        assert!(GrantRequest::parse(&invalid).is_err());
    }
    for privileges in [serde_json::json!([]), serde_json::json!(["read", "read"])] {
        let mut invalid = valid.clone();
        invalid[0]["organizations"][0]["privileges"] = privileges;
        assert!(GrantRequest::parse(&invalid).is_err());
    }
    let mut duplicate = valid.clone();
    duplicate[0]["organizations"] =
        serde_json::json!([valid[0]["organizations"][0], valid[0]["organizations"][0]]);
    assert!(GrantRequest::parse(&duplicate).is_err());
    let mut bounded = valid.clone();
    bounded[0]["organizations"] = serde_json::json!((0..16)
        .map(|i| serde_json::json!({"identifier":format!("学校-{i}"),"privileges":["read"]}))
        .collect::<Vec<_>>());
    assert!(GrantRequest::parse(&bounded).is_ok());
    bounded[0]["organizations"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!({"identifier":"overflow","privileges":["read"]}));
    assert!(GrantRequest::parse(&bounded).is_err());
    let mut privileges = valid.clone();
    privileges[0]["organizations"][0]["privileges"] =
        serde_json::json!((0..256).map(|i| format!("p{i}")).collect::<Vec<_>>());
    assert!(GrantRequest::parse(&privileges).is_ok());
    privileges[0]["organizations"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!({"identifier":"other","privileges":["new"]}));
    assert!(GrantRequest::parse(&privileges).is_err());
    let long_keys: Vec<_> = (0..128)
        .map(|i| format!("p{i:03}{}", "x".repeat(124)))
        .collect();
    let mut bytes = valid;
    bytes[0]["organizations"][0]["privileges"] = serde_json::json!(long_keys);
    assert!(serde_json::to_vec(&bytes).unwrap().len() > 16 * 1024);
    assert!(GrantRequest::parse(&bytes).is_err());
}
