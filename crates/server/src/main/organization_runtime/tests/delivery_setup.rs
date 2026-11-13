//! Explicit fixture policy/keys before activation; production domain mutations after it.
use super::*;
use crate::management::types::PolicyDocument;
use crate::organizations::{
    commands::{self, Command, CommandResult},
    invitations::{self, transport::Credential, FirstAdminRequest, Issuance},
    operators::{mutations as config, Capability},
    repository::{ActorKind, AuditActor},
};
use crate::web::management::initialization::InitializationOutput;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use sqlx::{Postgres, Transaction};
use std::collections::BTreeSet;

pub(super) fn credential() -> String {
    URL_SAFE_NO_PAD.encode([37u8; 32])
}

pub(super) async fn enable_policy(pool: &PgPool, initialized: &InitializationOutput) -> Result<()> {
    let mut tx = pool.begin().await?;
    let mut document: serde_json::Value = sqlx::query_scalar(
        "SELECT configuration_document FROM aegaeon.configuration_versions WHERE id=$1",
    )
    .bind(initialized.configuration_version_id)
    .fetch_one(&mut *tx)
    .await?;
    let mut policy: PolicyDocument = serde_json::from_value(document["policy"].clone())?;
    policy.authorization_details_types_supported = vec![
        crate::organizations::consent::GRANT_TYPE.into(),
        crate::organizations::ORGANIZATION_ACCESS_TYPE.into(),
    ];
    policy.allowed_grant_types = vec![
        "authorization_code".into(),
        "refresh_token".into(),
        crate::policy::TOKEN_EXCHANGE_GRANT_TYPE.into(),
    ];
    policy.jwt_access_tokens_enabled = true;
    policy.jwt_introspection_enabled = true;
    policy.retain_refresh_chain = true;
    policy.enforce_refresh_sender_binding = true;
    policy.access_token_time_to_live_seconds = 300;
    policy.cleanup_interval_seconds = 3600;
    policy.runtime_config_monitor_interval_seconds = 3600;
    ServerConfig::default().apply_management_policy(&policy)?;
    document["policy"] = serde_json::to_value(policy)?;
    crate::web::management::initialization::synchronize_fixture_configuration(
        &mut tx,
        initialized,
        &document,
    )
    .await?;
    sqlx::query("UPDATE aegaeon.configuration_versions SET configuration_document=$1 WHERE id=$2")
        .bind(document)
        .bind(initialized.configuration_version_id)
        .execute(&mut *tx)
        .await?;
    let pem = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/rsa2048-private.pk8.pem"
    ));
    let der = pem::parse(pem)?;
    let kek = crate::key_encryption::load_key_encryption_key()
        .map_err(|_| anyhow::anyhow!("fixture key-encryption key"))?;
    for usage in ["JWT_ACCESS_TOKEN_SIGNING"] {
        let kid = format!("fixture-{usage}");
        let signing = crate::oidc::OidcSigningKey::from_rsa_pem(kid.clone(), pem)?;
        let handle = crate::key_encryption::encrypt_key_handle(
            &URL_SAFE_NO_PAD.encode(der.contents()),
            &kek,
            crate::key_encryption::KeyHandleEncryptionContext::new(
                initialized.environment_id,
                usage,
                "databaseEncrypted",
                "RS256",
                &kid,
            ),
        )?;
        sqlx::query("INSERT INTO aegaeon.runtime_keys(environment_id,configuration_version_id,usage,kid,algorithm,provider,status,public_jwk,key_handle) VALUES($1,$2,$3::aegaeon.runtime_key_usage,$4,'RS256','databaseEncrypted','ACTIVE',$5,$6)")
            .bind(initialized.environment_id).bind(initialized.configuration_version_id).bind(usage).bind(kid)
            .bind(serde_json::to_value(&signing.jwks().keys[0])?).bind(handle).execute(&mut *tx).await?;
    }
    // Introspection currently selects its EdDSA slot independently of the access signer.
    let ed = aegaeon_crypto::signing::Ed25519SigningKey::generate()?;
    let usage = "JWT_INTROSPECTION_SIGNING";
    let kid = "fixture-introspection";
    let handle = crate::key_encryption::encrypt_key_handle(
        &URL_SAFE_NO_PAD.encode(&ed.pkcs8),
        &kek,
        crate::key_encryption::KeyHandleEncryptionContext::new(
            initialized.environment_id,
            usage,
            "databaseEncrypted",
            "EdDSA",
            kid,
        ),
    )?;
    sqlx::query("INSERT INTO aegaeon.runtime_keys(environment_id,configuration_version_id,usage,kid,algorithm,provider,status,public_jwk,key_handle) VALUES($1,$2,'JWT_INTROSPECTION_SIGNING',$3,'EdDSA','databaseEncrypted','ACTIVE',$4,$5)")
        .bind(initialized.environment_id).bind(initialized.configuration_version_id).bind(kid)
        .bind(serde_json::json!({"kty":"OKP","crv":"Ed25519","alg":"EdDSA","kid":kid,"use":"sig","x":URL_SAFE_NO_PAD.encode(ed.public_key)}))
        .bind(handle).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(())
}

pub(super) async fn issue(
    pool: &PgPool,
    initialized: &InitializationOutput,
) -> Result<(Uuid, Uuid)> {
    let owner = crate::organizations::request_work::async_store::current_epoch_owner(
        initialized.environment_id,
    )?;
    let mut connection = owner.connection(pool).await?;
    let mut tx = connection.begin().await?;
    let actor = AuditActor {
        id: initialized.administrator_id,
        kind: ActorKind::Operator,
        basis: None,
        client_id: "operator-console".into(),
        client_registration_id: None,
        request_id: "production-delivery-fixture".into(),
        reason: "explicit fixture provisioning".into(),
    };
    let default = config::bootstrap_default(
        &mut tx,
        initialized.team_id,
        initialized.environment_id,
        &actor,
        "bootstrap",
    )
    .await?;
    let scope = default.scope;
    config::apply_grant_command(
        &mut tx,
        scope,
        initialized.team_id,
        &actor,
        "grant",
        &config::GrantCommand::Update {
            id: default.operator.id,
            expected_revision: 1,
            active: true,
            capabilities: vec![Capability::Configure, Capability::Provision],
        },
    )
    .await?;
    configure_domain(&mut tx, scope, initialized.team_id, &actor).await?;
    let created = commands::apply_operator_command(
        &mut tx,
        scope,
        initialized.team_id,
        &actor,
        "create",
        &Command::Create {
            external_id: "School/学校-CaseSensitive".into(),
        },
    )
    .await?;
    let CommandResult::Organization(organization) = created else {
        anyhow::bail!("expected organization")
    };
    let invitation = invitations::issue_first_admin(
        &mut tx,
        Issuance {
            scope,
            team: initialized.team_id,
            actor: &actor,
            key: "invite",
            request: &FirstAdminRequest {
                organization_id: organization.id,
                expected_revision: organization.revision,
                recipient: "Invitee@example.test".into(),
                roles: BTreeSet::from(["admin".into()]),
                lifetime_seconds: Some(3600),
            },
            now: i64::try_from(crate::util::now_unix_epoch_secs()?)?,
        },
    )
    .await?;
    owner.admit_commit()?;
    tx.commit().await?;
    connection.release().await;
    Ok((scope.domain_id, invitation.id))
}

async fn configure_domain(
    tx: &mut Transaction<'_, Postgres>,
    scope: crate::organizations::Scope,
    team: Uuid,
    actor: &AuditActor,
) -> Result<()> {
    use config::{clients, delivery, lifecycle, role_policy, targets};
    let target = targets::register(
        tx,
        scope,
        team,
        actor,
        "target",
        &targets::RegisterTarget {
            expected_revision: 1,
            target: targets::Target {
                audience: "management-api".into(),
                management: true,
                membership_discovery: false,
                introspection_clients: vec![],
            },
        },
    )
    .await?;
    let registration = Uuid::new_v4();
    // A test client row is an input fixture, not evidence of authenticated client registration.
    sqlx::query("INSERT INTO aegaeon.clients(id,environment_id,configuration_version_id,client_identifier,name,client_type,redirect_uris,allowed_grant_types,allowed_scopes,token_endpoint_authentication_method,dpop_bound_access_tokens) SELECT $1,id,active_configuration_version_id,'delivery-fixture','delivery fixture','CONFIDENTIAL',ARRAY['https://example.test/cb'],ARRAY['authorization_code','urn:ietf:params:oauth:grant-type:token-exchange'],ARRAY['openid'],'client_secret_basic',true FROM aegaeon.environments WHERE id=$2")
        .bind(registration).bind(scope.environment_id).execute(&mut **tx).await?;
    clients::apply(
        tx,
        scope,
        team,
        actor,
        "client",
        &clients::ClientCommand::Create {
            client_registration_id: registration,
            expected_revision: target.revision,
            active: true,
            targets: vec![clients::ClientTarget {
                audience: "management-api".into(),
                privileges: vec!["organization.members.manage".into()],
            }],
        },
    )
    .await?;
    role_policy::apply(
        tx,
        scope,
        team,
        actor,
        "roles",
        1,
        &[role_policy::Definition {
            key: "admin".into(),
            privileges: vec!["organization.members.manage".into()],
            manages_members: true,
            assignable_roles: vec!["admin".into()],
        }],
    )
    .await?;
    let revision: i64 =
        sqlx::query_scalar("SELECT revision FROM aegaeon.authorization_domains WHERE id=$1")
            .bind(scope.domain_id)
            .fetch_one(&mut **tx)
            .await?;
    let enabled = lifecycle::apply(tx, scope, team, actor, "enable", revision, true).await?;
    delivery::apply(
        tx,
        scope,
        team,
        actor,
        "delivery",
        &delivery::Change {
            expected_revision: enabled.revision,
            channel: Some(delivery::Channel {
                endpoint: "https://delivery.example.test/envelopes".into(),
                credential_sha256: Credential::parse(credential())
                    .map_err(|()| anyhow::anyhow!("fixture credential"))?
                    .digest(),
            }),
        },
    )
    .await?;
    Ok(())
}
