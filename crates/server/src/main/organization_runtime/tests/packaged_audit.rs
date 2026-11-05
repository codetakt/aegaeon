//! Machine Export traverses the real outer dispatcher, API-key authentication,
//! domain grants and receipt replay in the packaged process.
use super::*;
use serde_json::{json, Value};

fn human(client: &reqwest::Client, url: &str, cookie: &str) -> reqwest::RequestBuilder {
    client
        .post(url)
        .header("x-forwarded-proto", "https")
        .header("origin", "https://admin.example.test")
        .header("cookie", format!("{cookie}; csrf_token=fixture-csrf"))
        .header("x-csrf-token", "fixture-csrf")
        .header("idempotency-key", Uuid::new_v4().to_string())
}

async fn status(response: reqwest::Response, expected: StatusCode) -> Result<()> {
    anyhow::ensure!(
        response.status() == expected,
        "machine audit status {} expected {expected}",
        response.status()
    );
    let _ = response.bytes().await?;
    Ok(())
}

pub(super) async fn check(
    client: &reqwest::Client,
    base: &str,
    initialized: &crate::web::management::initialization::InitializationOutput,
    domain: Uuid,
    cookie: &str,
    admin: &PgPool,
) -> Result<()> {
    let key_url = format!("{base}/api/v1/teams/{}/apiKeys", initialized.team_id);
    let created = human(client, &key_url, cookie)
        .json(
            &json!({"name":"unattended audit fixture", "capabilities":["organizationAuditExport"]}),
        )
        .send()
        .await?;
    anyhow::ensure!(
        created.status().is_success(),
        "create machine API key: {}",
        created.status()
    );
    let created: Value = created.json().await?;
    let raw = created["apiKeyValue"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("API key value"))?;
    let service = created["apiKey"]["serviceAdministratorId"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("service principal"))?;
    let key = Uuid::parse_str(
        created["apiKey"]["id"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("key ID"))?,
    )?;
    let domain_url = format!(
        "{base}/api/v1/teams/{}/environments/{}/organization-domains/{domain}",
        initialized.team_id, initialized.environment_id
    );
    let pending = format!("{domain_url}/audit-events/pending");
    let read = |url: &str| {
        client
            .get(url)
            .header("x-forwarded-proto", "https")
            .bearer_auth(raw)
    };
    // A credential alone and a general Team owner role do not confer Export.
    status(read(&pending).send().await?, StatusCode::FORBIDDEN).await?;
    let grant_url = format!("{domain_url}/operators");
    for capabilities in [json!(["configure"]), json!(["export", "provision"])] {
        status(human(client, &grant_url, cookie).json(&json!({"administratorId":service,"active":true,"capabilities":capabilities,"reason":"refuse machine escalation"})).send().await?, StatusCode::FORBIDDEN).await?;
    }
    let granted = human(client, &grant_url, cookie).json(&json!({"administratorId":service,"active":true,"capabilities":["export"],"reason":"explicit machine custody"})).send().await?;
    anyhow::ensure!(
        granted.status() == StatusCode::OK,
        "machine Export grant: {}",
        granted.status()
    );
    let grant_tag = granted.headers()["etag"].to_str()?.to_owned();
    let grant: Value = granted.json().await?;
    let grant_id = grant["id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("grant ID"))?;
    for path in [
        format!("{domain_url}/snapshot"),
        format!("{domain_url}/organizations"),
    ] {
        anyhow::ensure!(
            read(&path).send().await?.status().is_client_error(),
            "machine capability escaped audit delivery"
        );
    }
    status(
        read(&pending.replace(&domain.to_string(), &Uuid::new_v4().to_string()))
            .send()
            .await?,
        StatusCode::FORBIDDEN,
    )
    .await?;
    status(
        read(&pending).header("cookie", cookie).send().await?,
        StatusCode::BAD_REQUEST,
    )
    .await?;
    status(
        client
            .get(&pending)
            .header("x-forwarded-proto", "https")
            .bearer_auth("invalid")
            .send()
            .await?,
        StatusCode::UNAUTHORIZED,
    )
    .await?;
    let batch = read(&pending).send().await?;
    anyhow::ensure!(
        batch.status() == StatusCode::OK,
        "machine fetch: {}",
        batch.status()
    );
    let tag = batch.headers()["etag"].to_str()?.to_owned();
    let batch: Value = batch.json().await?;
    let events: Vec<Value> = batch["deliveries"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("deliveries"))?
        .iter()
        .map(|entry| json!({"id":entry["event"]["id"],"sha256":entry["sha256"]}))
        .collect();
    anyhow::ensure!(!events.is_empty());
    let operation = Uuid::new_v4().to_string();
    let ack = || {
        client
            .post(format!("{domain_url}/audit-events/acknowledgments"))
            .header("x-forwarded-proto", "https")
            .bearer_auth(raw)
            .header("if-match", &tag)
            .header("idempotency-key", &operation)
            .json(&json!({"events":events,"reason":"machine durable custody fixture"}))
    };
    // Discard a committed reply, then recover its exact retained receipt.
    status(ack().send().await?, StatusCode::OK).await?;
    let replay = ack().send().await?;
    anyhow::ensure!(replay.status() == StatusCode::OK);
    let replay: Value = replay.json().await?;
    anyhow::ensure!(replay["actorId"] == service && replay["events"] == json!(events));
    let receipts: i64 = sqlx::query_scalar("SELECT count(*) FROM aegaeon.organization_authority_receipts WHERE domain_id=$1 AND idempotency_key=$2 AND client_id=$3")
        .bind(domain).bind(&operation).bind(format!("management-api-key:{key}")).fetch_one(admin).await?;
    anyhow::ensure!(receipts == 1);
    // Neither broad legacy capabilities nor an expired key may replay ACK.
    sqlx::query("UPDATE aegaeon.api_key_capabilities SET capability='TEAM_ADMINISTRATION' WHERE api_key_id=$1").bind(key).execute(admin).await?;
    status(ack().send().await?, StatusCode::FORBIDDEN).await?;
    sqlx::query("UPDATE aegaeon.api_key_capabilities SET capability='ORGANIZATION_AUDIT_EXPORT' WHERE api_key_id=$1").bind(key).execute(admin).await?;
    sqlx::query(
        "UPDATE aegaeon.api_keys SET created_at=clock_timestamp()-interval '2 days',expires_at=clock_timestamp()-interval '1 second' WHERE id=$1",
    )
    .bind(key)
    .execute(admin)
    .await?;
    status(ack().send().await?, StatusCode::UNAUTHORIZED).await?;
    sqlx::query("UPDATE aegaeon.api_keys SET expires_at=NULL WHERE id=$1")
        .bind(key)
        .execute(admin)
        .await?;
    status(
        human(client, &format!("{grant_url}/{grant_id}/revoke"), cookie)
            .header("if-match", grant_tag)
            .json(&json!({"reason":"stop unattended custody"}))
            .send()
            .await?,
        StatusCode::OK,
    )
    .await?;
    status(ack().send().await?, StatusCode::FORBIDDEN).await?;
    sqlx::query("UPDATE aegaeon.api_keys SET status='REVOKED',revoked_at=now(),revoked_by_administrator_id=$2 WHERE id=$1")
        .bind(key).bind(initialized.administrator_id).execute(admin).await?;
    status(read(&pending).send().await?, StatusCode::UNAUTHORIZED).await?;
    Ok(())
}
