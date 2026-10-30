use super::*;
use crate::organizations::{
    authentication::OriginalAuthentication,
    consent::{CaptureContext, Consent, GrantRequest},
    operators::mutations::support_policy::{self, Change, Policy},
};
use sqlx::Row;

pub(crate) async fn setup(
    f: &Fixture,
) -> Result<(Policy, OriginalAuthentication), Box<dyn std::error::Error>> {
    consent::setup(f).await?;
    evidence(f).await
}

pub(crate) async fn evidence(
    f: &Fixture,
) -> Result<(Policy, OriginalAuthentication), Box<dyn std::error::Error>> {
    sqlx::query("UPDATE aegaeon.organization_operator_grants SET capabilities='[\"configure\",\"support\"]' WHERE administrator_id=$1").bind(f.actor.id).execute(&f.pool).await?;
    // Support user has no membership. It is a distinct identity from the operator.
    let user = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO aegaeon.end_users(id,environment_id,subject,status) VALUES($1,$2,$3,'ACTIVE')",
    )
    .bind(user)
    .bind(f.env.environment_id)
    .bind(format!("support-{user}"))
    .execute(&f.pool)
    .await?;
    let configuration: Uuid = sqlx::query_scalar(
        "SELECT active_configuration_version_id FROM aegaeon.environments WHERE id=$1",
    )
    .bind(f.env.environment_id)
    .fetch_one(&f.pool)
    .await?;
    let connection:Uuid=sqlx::query_scalar("INSERT INTO aegaeon.connections(environment_id,configuration_version_id,connection_identifier,name,issuer_url,client_id,client_auth_method,status) VALUES($1,$2,'support-test','Support provider','https://upstream.example','upstream-client','none','ACTIVE') RETURNING id").bind(f.env.environment_id).bind(configuration).fetch_one(&f.pool).await?;
    let mut evidence = OriginalAuthentication::fixture(
        f.env.environment_id,
        user,
        &format!("support-{user}"),
        100,
        110,
    );
    evidence.context = crate::upstream::UpstreamConnectionContext::new(
        connection,
        f.env.team_id,
        f.env.tenant_id,
        f.env.environment_id,
        configuration,
    );
    sqlx::query("INSERT INTO aegaeon.account_links(id,environment_id,connection_id,end_user_id,upstream_issuer,upstream_sub_hash,binding_provenance,binding_revision) VALUES($1,$2,$3,$4,$5,$6,'jit_v2',1)")
        .bind(evidence.account_link_id).bind(f.env.environment_id).bind(connection).bind(user).bind(&evidence.issuer).bind(&evidence.upstream_subject_hash).execute(&f.pool).await?;
    let policy: Policy = serde_json::from_value(
        serde_json::json!({"providers":[{"connectionId":connection,"configurationVersionId":configuration,"issuer":evidence.issuer,"upstreamClientId":evidence.upstream_client_id,"acr":evidence.acr,"factors":[{"method":"pwd","class":"knowledge"},{"method":"otp","class":"possession"}]}],"entitlements":[{"administratorId":f.actor.id,"userId":user,"organizationId":f.organization.id,"audience":"management-api","roles":["reader"]}]}),
    )?;
    Ok((policy, evidence))
}

pub(crate) async fn configure(
    f: &Fixture,
    key: &str,
    expected: i64,
    policy: Option<Policy>,
) -> Result<support_policy::Configuration, RepositoryError> {
    let mut tx = f.pool.begin().await?;
    let value = support_policy::apply(
        &mut tx,
        f.organization.scope,
        f.env.team_id,
        &f.actor,
        key,
        &Change {
            expected_revision: expected,
            policy,
        },
    )
    .await?;
    tx.commit().await?;
    Ok(value)
}
pub(super) async fn capture(
    f: &Fixture,
    evidence: Option<&OriginalAuthentication>,
    now: i64,
    request: &GrantRequest,
) -> Result<Consent, RepositoryError> {
    let mut tx = f.pool.begin().await?;
    let value = crate::organizations::consent::capture(
        &mut tx,
        CaptureContext {
            environment_id: f.env.environment_id,
            issuer: &f.env.issuer_url,
            client_id: "consent-client",
            subject: evidence.map_or("missing", |e| e.subject.as_str()),
            dpop_jkt: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            auth_time: 100,
            captured_at: now,
            original_authentication: evidence,
        },
        request,
    )
    .await?;
    tx.commit().await?;
    Ok(value)
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL"]
async fn pg_organizations_support_policy_original_ceiling_has_no_membership_or_implicit_mfa(
) -> TestResult {
    let f = Fixture::new().await?;
    let result=async {
        let (policy,evidence)=setup(&f).await?;
        let mut request=consent::request(&f);request.organizations[0].administrative_access=true;
        assert!(capture(&f,Some(&evidence),110,&request).await.is_err(),"disabled by default");
        let configured=configure(&f,"configure",1,Some(policy.clone())).await?;
        assert_eq!(configured.revision,2);
        assert_eq!(configure(&f,"configure",1,Some(policy.clone())).await?,configured);
        let original=capture(&f,Some(&evidence),110,&request).await?;
        assert!(original.memberships.is_empty());
        assert_eq!(original.support[&f.organization.id].privileges,BTreeSet::from(["documents.read".into()]));
        assert_eq!(original.support[&f.organization.id].administrator_id,f.actor.id);
        let root=original.bind("root",1000)?;
        assert!(root.ceiling.memberships.is_empty());
        assert_eq!(root.consent.original_authentication.as_ref(),Some(&evidence));
        let mut ordinary=request.clone();ordinary.organizations[0].administrative_access=false;
        assert!(capture(&f,Some(&evidence),110,&ordinary).await.is_err(),"support never creates membership");
        assert!(capture(&f,None,110,&request).await.is_err());
        assert!(capture(&f,Some(&evidence),399,&request).await.is_ok());
        assert!(capture(&f,Some(&evidence),400,&request).await.is_err(),"fresh MFA expires at the original 300-second boundary");
        for case in 0..12 {
            let mut bad=evidence.clone();
            match case {
                0=>bad.acr=None,1=>bad.amr=Some(vec!["mfa".into()]),2=>bad.amr=Some(vec!["pwd".into()]),
                3=>bad.context.environment_id=Uuid::new_v4(),4=>bad.context.team_id=Uuid::new_v4(),5=>bad.context.tenant_id=Uuid::new_v4(),
                6=>bad.context.configuration_version_id=Uuid::new_v4(),7=>bad.account_link_revision+=1,8=>bad.identity_revision+=1,
                9=>bad.account_link_provenance="legacy_unreviewed".into(),10=>bad.upstream_client_id="other".into(),_=>bad.upstream_subject_hash="A".repeat(43),
            }
            assert!(capture(&f,Some(&bad),110,&request).await.is_err(),"evidence case {case}");
        }
        let mut expanded=request.clone();expanded.organizations[0].privileges.push("documents.write".into());
        assert!(capture(&f,Some(&evidence),110,&expanded).await.is_err());
        let disabled=configure(&f,"disable",2,None).await?;assert_eq!(disabled.revision,3);
        assert!(capture(&f,Some(&evidence),110,&request).await.is_err());
        configure(&f,"again",3,Some(policy)).await?;
        assert_ne!(capture(&f,Some(&evidence),110,&request).await?,original,"policy re-enable never restores original approval");
        sqlx::query("UPDATE aegaeon.organization_operator_grants SET active=false WHERE administrator_id=$1").bind(f.actor.id).execute(&f.pool).await?;
        assert!(capture(&f,Some(&evidence),110,&request).await.is_err());
        assert!(configure(&f,"configure",1,configured.policy).await.is_err(),"revoked owner cannot replay");
        Ok(())
    }.await;
    f.cleanup(result).await
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL"]
async fn pg_organizations_support_policy_current_provider_link_owner_scope_and_counters(
) -> TestResult {
    let f = Fixture::new().await?;
    let result=async {
        let (policy,evidence)=setup(&f).await?;
        let mut request=consent::request(&f);request.organizations[0].administrative_access=true;
        for case in 0..4 {
            let mut bad=policy.clone();match case {0=>bad.entitlements[0].user_id=Uuid::new_v4(),1=>bad.entitlements[0].organization_id=Uuid::new_v4(),2=>bad.entitlements[0].audience="other-domain".into(),_=>bad.entitlements[0].roles=vec!["unknown".into()]}
            assert!(configure(&f,"invalid",1,Some(bad)).await.is_err());
        }
        sqlx::query("UPDATE aegaeon.team_memberships SET role='ADMINISTRATOR' WHERE administrator_id=$1").bind(f.actor.id).execute(&f.pool).await?;
        assert!(configure(&f,"owner",1,Some(policy.clone())).await.is_err());
        sqlx::query("UPDATE aegaeon.team_memberships SET role='OWNER' WHERE administrator_id=$1").bind(f.actor.id).execute(&f.pool).await?;
        let (a,b)=tokio::join!(configure(&f,"once",1,Some(policy.clone())),configure(&f,"once",1,Some(policy.clone())));assert_eq!(a?,b?);
        let count:i64=sqlx::query_scalar("SELECT count(*) FROM aegaeon.organization_authority_events e JOIN aegaeon.organization_authority_outbox o ON o.event_id=e.id WHERE e.domain_id=$1 AND e.event_type='domain.support.configure'").bind(f.organization.scope.domain_id).fetch_one(&f.pool).await?;assert_eq!(count,1);
        assert!(sqlx::query("UPDATE aegaeon.authorization_domains SET support_policy_revision=1 WHERE id=$1").bind(f.organization.scope.domain_id).execute(&f.pool).await.is_err(),"revision rollback refused by actual store");
        sqlx::query("UPDATE aegaeon.connections SET status='DISABLED' WHERE id=$1").bind(evidence.context.connection_id).execute(&f.pool).await?;
        assert!(capture(&f,Some(&evidence),110,&request).await.is_err());
        sqlx::query("UPDATE aegaeon.connections SET status='ACTIVE' WHERE id=$1").bind(evidence.context.connection_id).execute(&f.pool).await?;
        sqlx::query("UPDATE aegaeon.account_links SET binding_revision=binding_revision+1 WHERE id=$1").bind(evidence.account_link_id).execute(&f.pool).await?;
        assert!(capture(&f,Some(&evidence),110,&request).await.is_err());
        // Direct policy changes cannot retain or roll back the generation either.
        sqlx::query("UPDATE aegaeon.authorization_domains SET support_policy=NULL WHERE id=$1").bind(f.organization.scope.domain_id).execute(&f.pool).await?;
        let row=sqlx::query("SELECT support_policy_revision FROM aegaeon.authorization_domains WHERE id=$1").bind(f.organization.scope.domain_id).fetch_one(&f.pool).await?;
        assert_eq!(row.try_get::<i64,_>("support_policy_revision")?,3);
        Ok(())
    }.await;
    f.cleanup(result).await
}

#[test]
fn organizations_support_policy_requires_explicit_independent_methods_and_unique_bindings() {
    let policy:Policy=serde_json::from_value(serde_json::json!({"providers":[{"connectionId":Uuid::new_v4(),"configurationVersionId":Uuid::new_v4(),"issuer":"https://idp.example","upstreamClientId":"client","acr":"urn:example:two","factors":[{"method":"pwd","class":"knowledge"},{"method":"otp","class":"possession"}]}],"entitlements":[{"administratorId":Uuid::new_v4(),"userId":Uuid::new_v4(),"organizationId":Uuid::new_v4(),"audience":"api","roles":["reader"]}]})).unwrap();
    assert!(policy.validate().is_ok());
    for case in 0..7 {
        let mut bad = policy.clone();
        match case {
            0 => bad.providers[0].factors[1].class = bad.providers[0].factors[0].class,
            1 => bad.providers[0].factors[1].method = "mfa".into(),
            2 => bad.providers[0].factors[1].method = "pwd".into(),
            3 => bad.providers.push(bad.providers[0].clone()),
            4 => bad.entitlements.push(bad.entitlements[0].clone()),
            5 => bad.entitlements[0].roles.push("reader".into()),
            _ => bad.providers[0].issuer = "x".repeat(2049),
        };
        assert!(bad.validate().is_err(), "{case}");
    }
}
