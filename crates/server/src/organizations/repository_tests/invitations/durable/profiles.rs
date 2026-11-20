//! Start with a queued pre-upgrade message. Exercise the actual worker
//! credential filter and second, locked admission against a changed default.
use super::*;
use configuration::{Profiles, Route, Settings};

async fn update(f: &InvitationFixture, revision: i64, settings: &Profiles) -> TestResult {
    let mut tx = f.base.pool.begin().await?;
    configuration::apply(
        &mut tx,
        f.base.organization.scope,
        f.base.env.team_id,
        &f.base.actor,
        &format!("update-profiles-{revision}"),
        &Change {
            expected_revision: revision,
            channel: Some(Settings::Profiles(settings.clone())),
        },
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

async fn registration(f: &InvitationFixture) -> Result<Uuid, Box<dyn std::error::Error>> {
    let scope = f.base.organization.scope;
    let client = format!("aegaeon-hosted-invitation-{}", scope.domain_id);
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO aegaeon.clients(id,environment_id,configuration_version_id,client_identifier,name,client_type,redirect_uris,allowed_grant_types,allowed_scopes,token_endpoint_authentication_method,dpop_bound_access_tokens) SELECT $1,id,active_configuration_version_id,$2,'Hosted invitations','CONFIDENTIAL',ARRAY['https://'||issuer_host||'/organization-invitations/hosted/callback'], ARRAY['authorization_code','refresh_token','urn:ietf:params:oauth:grant-type:token-exchange'], ARRAY['openid','read','offline_access','organization.invitation.accept'],'client_secret_basic',true FROM aegaeon.environments WHERE id=$3")
        .bind(id).bind(&client).bind(scope.environment_id).execute(&f.base.pool).await?;
    // A policy activation moves the client to the active configuration. The
    // issuer retains an already issued secret's original version as provenance.
    let secret_version = Uuid::new_v4();
    sqlx::query("INSERT INTO aegaeon.configuration_versions (id,environment_id,version_number,configuration_hash,status,configuration_document) SELECT $2,environment_id,version_number+1,configuration_hash,'ARCHIVED',configuration_document FROM aegaeon.configuration_versions WHERE environment_id=$1 AND status='ACTIVE'")
        .bind(scope.environment_id).bind(secret_version).execute(&f.base.pool).await?;
    sqlx::query("INSERT INTO aegaeon.client_secrets(environment_id,client_id,configuration_version_id,status,active_slot,secret_hash,expires_at) SELECT environment_id,id,$3,'ACTIVE',1,$2,now()+interval '1 hour' FROM aegaeon.clients WHERE id=$1")
        .bind(id).bind(crate::local_credentials::hash_password(&Uuid::new_v4().to_string())?).bind(secret_version).execute(&f.base.pool).await?;
    let target = format!("{}/organization-invitations", f.base.env.issuer_url);
    let exchange = serde_json::json!({"version":1,"targets":[{"audience":target,"resourceAliases":[]}],
        "rules":[{"clientId":client,"sourceAudience":format!("{}/userinfo",f.base.env.issuer_url),
            "targetAudience":target,"scopes":[{"targetScope":"organization.invitation.accept","sourceScopes":["read"]}],
            "defaultScopes":["organization.invitation.accept"]}]});
    sqlx::query("INSERT INTO aegaeon.environment_policies(environment_id,configuration_version_id,pkce_required,dcr_enabled,allowed_signing_algorithms,allowed_grant_types,access_token_time_to_live_seconds,refresh_token_time_to_live_seconds,authorization_code_time_to_live_seconds,id_token_time_to_live_seconds,oidc_enabled,token_exchange) SELECT id,active_configuration_version_id,true,false,ARRAY['RS256'],ARRAY['authorization_code','refresh_token','urn:ietf:params:oauth:grant-type:token-exchange'],300,1800,60,300,true,$2 FROM aegaeon.environments WHERE id=$1 ON CONFLICT(environment_id) DO UPDATE SET oidc_enabled=true,token_exchange=EXCLUDED.token_exchange")
        .bind(scope.environment_id).bind(exchange).execute(&f.base.pool).await?;
    sqlx::query("INSERT INTO aegaeon.authorization_domain_targets(environment_id,domain_id,audience,management) VALUES ($1,$2,$3,true)")
        .bind(scope.environment_id).bind(scope.domain_id).bind(&target).execute(&f.base.pool).await?;
    sqlx::query("INSERT INTO aegaeon.organization_client_bindings(id,environment_id,domain_id,client_registration_id,client_identifier,targets,active) VALUES ($1,$2,$3,$4,$5,$6,true)")
        .bind(Uuid::new_v4()).bind(scope.environment_id).bind(scope.domain_id).bind(id).bind(client)
        .bind(serde_json::json!([{"audience":target,"privileges":["organization.invitation.accept"]}])).execute(&f.base.pool).await?;
    sqlx::query("UPDATE aegaeon.application_organizations SET display_name='University', display_revision=1 WHERE id=$1")
        .bind(f.request.organization_id).execute(&f.base.pool).await?;
    sqlx::query("UPDATE aegaeon.organization_role_definitions SET display_label='Administrator',display_revision=1 WHERE domain_id=$1 AND role_key='admin'")
        .bind(scope.domain_id).execute(&f.base.pool).await?;
    Ok(id)
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL supplier"]
async fn pg_organizations_invitation_profile_pins_survive_default_changes_and_refuse_disabled_clients(
) -> TestResult {
    let current = CurrentFixture::new().await?;
    let f = &current.fixture;
    let result = current
        .run(async {
            let scope = f.base.organization.scope;
            let mut tx = f.base.pool.begin().await?;
            let old = invite::issue_first_admin(&mut tx, f.issuance()).await?;
            tx.commit().await?;
            let (ring, selection) = configure(f).await?;
            let mut tx = f.base.pool.begin().await?;
            invite::durable::reissue(
                &mut tx,
                &invite::durable::Reissue {
                    scope,
                    invitation: old.id,
                    challenge: None,
                    identity_request: None,
                    expected_delivery_revision: 0,
                    operation: Uuid::new_v4(),
                },
                &"a".repeat(64),
                100,
                None,
            )
            .await?;
            let flat = invite::issue_first_admin(&mut tx, Issuance { key: "configured-flat", ..f.issuance() }).await?;
            let legacy_pin: bool = sqlx::query_scalar("SELECT authority ? 'custom_delivery_pin' OR authority ? 'delivery_profile_revision' FROM aegaeon.organization_invitations WHERE id=$1")
                .bind(old.id).fetch_one(&mut *tx).await?;
            assert!(!legacy_pin);
            let flat_pin: Option<i64> = sqlx::query_scalar("SELECT (authority->'custom_delivery_pin'->>'revision')::bigint FROM aegaeon.organization_invitations WHERE id=$1")
                .bind(flat.id).fetch_one(&mut *tx).await?;
            let config = configuration::read_locked(&mut tx, scope).await?;
            assert_eq!(flat_pin, Some(config.revision));
            tx.commit().await?;
            let Some(Settings::Custom(custom)) = config.channel else {
                return Err("fixture channel".into());
            };
            let id = registration(f).await?;
            let mut hosted_channel = Channel {
                endpoint: "https://mail.example.test/hosted".into(),
                credential_sha256: "b".repeat(64),
                ..custom.clone()
            };
            let tested_at = i64::try_from(crate::util::now_unix_epoch_secs()?)?;
            let key = hosted_channel
                .encryption
                .as_mut()
                .ok_or("hosted wrapping key")?;
            key.seal_until = tested_at + 3_600;
            key.open_until = tested_at + 86_400;
            let old_revision = config.revision;
            let hosted_revision = old_revision + 1;
            let mut profiles = Profiles {
                default_revision: Some(hosted_revision),
                legacy_revision: Some(old_revision),
                routes: vec![
                    Route {
                        transport_revision: None,
                        revision: old_revision,
                        enabled: true,
                        hosted_client_registration_id: None,
                        channel: custom.clone(),
                    },
                    Route {
                        transport_revision: None,
                        revision: hosted_revision,
                        enabled: true,
                        hosted_client_registration_id: Some(id),
                        channel: hosted_channel.clone(),
                    },
                ],
                return_url: Some("https://course.example.test/done".into()),
            };
            update(f, old_revision, &profiles).await?;
            let mut tx = f.base.pool.begin().await?;
            let active = configuration::hosted_current(&mut tx, scope).await?;
            assert_eq!(active.client_registration_id, id);
            assert_eq!(active.return_url, profiles.return_url);
            let hosted = invite::issue_first_admin(
                &mut tx,
                Issuance {
                    key: "hosted",
                    ..f.issuance()
                },
            )
            .await?;
            tx.commit().await?;
            profiles.default_revision = Some(old_revision);
            update(f, hosted_revision, &profiles).await?;
            let mut tx = f.base.pool.begin().await?;
            let custom_after = invite::issue_first_admin(
                &mut tx,
                Issuance {
                    key: "custom",
                    ..f.issuance()
                },
            )
            .await?;
            let legacy_claims = queue::claim_delivery(
                &mut tx,
                scope.environment_id,
                selection,
                Uuid::new_v4(),
                &custom.credential_sha256,
                8,
                100,
            )
            .await?;
            assert_eq!(
                legacy_claims
                    .iter()
                    .map(|c| c.object_id)
                    .collect::<BTreeSet<_>>(),
                BTreeSet::from([old.id, flat.id, custom_after.id])
            );
            let mut hosted_claims = queue::claim_delivery(
                &mut tx,
                scope.environment_id,
                selection,
                Uuid::new_v4(),
                &hosted_channel.credential_sha256,
                8,
                100,
            )
            .await?;
            assert_eq!(hosted_claims.len(), 1);
            let claim = hosted_claims.remove(0);
            assert_eq!(claim.object_id, hosted.id);
            tx.commit().await?;
            for c in &legacy_claims {
                let mut tx = f.base.pool.begin().await?;
                let authorized = invite::durable::admit_current(
                    &mut tx,
                    scope,
                    c,
                    selection,
                    &custom.credential_sha256,
                    101,
                    None,
                )
                .await?;
                assert_eq!(authorized.endpoint, custom.endpoint);
                assert!(authorized.open(&ring, 101).is_ok());
                tx.commit().await?;
            }
            let mut tx = f.base.pool.begin().await?;
            let authorized = invite::durable::admit_current(
                &mut tx,
                scope,
                &claim,
                selection,
                &hosted_channel.credential_sha256,
                101,
                None,
            )
            .await?;
            assert_eq!(authorized.endpoint, hosted_channel.endpoint);
            let payload: serde_json::Value = serde_json::from_slice(&authorized.open(&ring, 101)?)?;
            let mut recipient = f.recipient.clone();
            recipient.binding.client_registration_id = id;
            recipient.binding.client_id = active.client_id;
            let mut input = f.acceptance(
                hosted.id,
                payload["capability"].as_str().ok_or("proof")?,
                Uuid::nil(),
                "",
            );
            input.recipient = &recipient;
            input.now = 102;
            let challenge = invite::request_challenge(&mut tx, &input, "recipient-send").await?;
            tx.commit().await?;
            let mut tx = f.base.pool.begin().await?;
            assert!(queue::claim_delivery(
                &mut tx,
                scope.environment_id,
                selection,
                Uuid::new_v4(),
                &custom.credential_sha256,
                8,
                103
            )
            .await?
            .is_empty());
            let claims = queue::claim_delivery(
                &mut tx,
                scope.environment_id,
                selection,
                Uuid::new_v4(),
                &hosted_channel.credential_sha256,
                8,
                103,
            )
            .await?;
            assert_eq!(claims.len(), 1);
            assert_eq!(claims[0].object_id, challenge);
            tx.commit().await?;
            sqlx::query("UPDATE aegaeon.clients SET status='DELETED',deleted_at=now() WHERE id=$1")
                .bind(id)
                .execute(&f.base.pool)
                .await?;
            let mut tx = f.base.pool.begin().await?;
            assert!(configuration::hosted_current(&mut tx, scope).await.is_err());
            assert!(invite::durable::admit_current(
                &mut tx,
                scope,
                &claims[0],
                selection,
                &hosted_channel.credential_sha256,
                104,
                None
            )
            .await
            .is_err());
            assert!(queue::claim_delivery(
                &mut tx,
                scope.environment_id,
                selection,
                Uuid::new_v4(),
                &hosted_channel.credential_sha256,
                8,
                190
            )
            .await?
            .is_empty());
            tx.rollback().await?;
            profiles.default_revision = Some(hosted_revision);
            assert!(update(f, hosted_revision + 1, &profiles).await.is_err());
            profiles.default_revision = Some(old_revision);
            profiles.routes[1].enabled = false;
            rotate_custom(
                f,
                &mut profiles,
                hosted_revision + 1,
                custom_after.id,
                selection,
                &ring,
            )
            .await
        })
        .await;
    current.finish(result).await
}

async fn rotate_custom(
    f: &InvitationFixture,
    profiles: &mut Profiles,
    revision: i64,
    invitation: Uuid,
    selection: Selection,
    ring: &PrivateKeyRing,
) -> TestResult {
    let scope = f.base.organization.scope;
    let replacement = "c".repeat(64);
    profiles.routes[0].channel.credential_sha256 = replacement.clone();
    assert!(update(f, revision, profiles).await.is_err());
    profiles.routes[0].transport_revision = Some(revision + 1);
    update(f, revision, profiles).await?;
    let mut tx = f.base.pool.begin().await?;
    let command = invite::durable::Reissue {
        scope,
        invitation,
        challenge: None,
        identity_request: None,
        expected_delivery_revision: 1,
        operation: Uuid::new_v4(),
    };
    let new = invite::durable::reissue(&mut tx, &command, &replacement, 162, None).await?;
    assert_eq!(new.delivery_revision, 2);
    tx.commit().await?;
    let mut tx = f.base.pool.begin().await?;
    let claims = queue::claim_delivery(
        &mut tx,
        scope.environment_id,
        selection,
        Uuid::new_v4(),
        &replacement,
        8,
        163,
    )
    .await?;
    let claim = claims
        .iter()
        .find(|c| c.message_id == new.message_id)
        .ok_or("reissued message")?;
    tx.commit().await?;
    let mut tx = f.base.pool.begin().await?;
    let admitted =
        invite::durable::admit_current(&mut tx, scope, claim, selection, &replacement, 164, None)
            .await?;
    assert_eq!(admitted.endpoint, profiles.routes[0].channel.endpoint);
    tx.commit().await?;
    let payload: serde_json::Value = serde_json::from_slice(&admitted.open(ring, 164)?)?;
    assert_eq!(payload["invitationId"], invitation.to_string());
    assert_eq!(payload["deliveryRevision"], 2);
    Ok(())
}
