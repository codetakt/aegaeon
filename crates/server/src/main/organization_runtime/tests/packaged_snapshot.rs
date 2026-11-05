//! Real packaged HTTP export through current-generation PostgreSQL admission.
use super::*;
use crate::organizations::{
    operators::{mutations, Capability},
    repository::{ActorKind, AuditActor},
};
use crate::web::management::initialization::InitializationOutput;

pub(super) async fn prepare(pool: &PgPool, initialized: &InitializationOutput) -> Result<Uuid> {
    let mut tx = pool.begin().await?;
    let actor = AuditActor {
        id: initialized.administrator_id,
        kind: ActorKind::Operator,
        basis: None,
        client_id: "operator-console".into(),
        client_registration_id: None,
        request_id: "packaged-snapshot-fixture".into(),
        reason: "explicit fixture provisioning before activation".into(),
    };
    let domain = mutations::bootstrap_default(
        &mut tx,
        initialized.team_id,
        initialized.environment_id,
        &actor,
        "snapshot-bootstrap",
    )
    .await?;
    mutations::apply_grant_command(
        &mut tx,
        domain.scope,
        initialized.team_id,
        &actor,
        "snapshot-grant",
        &mutations::GrantCommand::Update {
            id: domain.operator.id,
            expected_revision: 1,
            active: true,
            capabilities: vec![Capability::Configure, Capability::Export],
        },
    )
    .await?;
    sqlx::query(
        "UPDATE aegaeon.authorization_domains SET enabled=true,revision=revision+1 WHERE id=$1",
    )
    .bind(domain.scope.domain_id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(domain.scope.domain_id)
}

pub(super) async fn check(
    client: &reqwest::Client,
    base: &str,
    initialized: &InitializationOutput,
    domain: Uuid,
    password: &str,
    admin: &PgPool,
) -> Result<()> {
    let login = client
        .post(format!("{base}/api/v1/authentication/sessions"))
        .header("x-forwarded-proto", "https")
        .header("origin", "https://admin.example.test")
        .header("cookie", "csrf_token=fixture-csrf")
        .header("x-csrf-token", "fixture-csrf")
        .json(&serde_json::json!({"email":"owner@example.test","password":password}))
        .send()
        .await?;
    anyhow::ensure!(
        login.status() == StatusCode::NO_CONTENT,
        "packaged snapshot login: {}",
        login.status()
    );
    let cookie = login
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|v| v.starts_with("aegaeon_admin_session="))
        .and_then(|v| v.split(';').next())
        .ok_or_else(|| anyhow::anyhow!("missing management session"))?
        .to_string();
    let _ = login.bytes().await?;
    let url = format!(
        "{base}/api/v1/teams/{}/environments/{}/organization-domains/{domain}/snapshot",
        initialized.team_id, initialized.environment_id
    );
    for method in [reqwest::Method::HEAD, reqwest::Method::GET] {
        let head = method == reqwest::Method::HEAD;
        let response = client
            .request(method, &url)
            .header("x-forwarded-proto", "https")
            .header("cookie", &cookie)
            .send()
            .await?;
        anyhow::ensure!(
            response.status() == StatusCode::OK,
            "packaged snapshot: {}",
            response.status()
        );
        anyhow::ensure!(response.headers()["cache-control"] == "no-store");
        let bytes = response.bytes().await?;
        if head {
            anyhow::ensure!(bytes.is_empty());
        } else {
            let rows = std::str::from_utf8(&bytes)?
                .lines()
                .map(serde_json::from_str::<serde_json::Value>)
                .collect::<std::result::Result<Vec<_>, _>>()?;
            anyhow::ensure!(rows.first().is_some_and(|r| r["record"] == "header"));
            anyhow::ensure!(rows.last().is_some_and(|r| r["record"] == "manifest"));
        }
    }
    super::audit::check(client, base, initialized, domain, &cookie, admin).await?;
    // This write changes current durable authority after a completed export.
    sqlx::query("UPDATE aegaeon.organization_operator_grants SET active=false,revision=revision+1 WHERE domain_id=$1")
        .bind(domain).execute(admin).await?;
    let response = client
        .get(&url)
        .header("x-forwarded-proto", "https")
        .header("cookie", &cookie)
        .send()
        .await?;
    anyhow::ensure!(
        response.status() == StatusCode::FORBIDDEN,
        "revoked packaged snapshot: {}",
        response.status()
    );
    let _ = response.bytes().await?;
    // The next ordinary-restart case deliberately restores this fixture grant.
    sqlx::query("UPDATE aegaeon.organization_operator_grants SET active=true,revision=revision+1 WHERE domain_id=$1")
        .bind(domain).execute(admin).await?;
    Ok(())
}
