use super::*;
use crate::organizations::{
    lifecycle::{
        tests::{wait_runtime_release, Fixture},
        Limits, Runtime, Selection,
    },
    request_work::CapacityClass,
};
use crate::web::hosted::pending_authorization;
use sqlx::ConnectOptions;
use std::io::Write;
use std::path::PathBuf;

const ISSUER: &str = "https://issuer.example";

struct PrivateFile(PathBuf);
impl PrivateFile {
    fn new(document: &serde_json::Value) -> anyhow::Result<Self> {
        let path = std::env::temp_dir().join(format!("hosted-config-{}", Uuid::new_v4()));
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&path)?;
        let private = Self(path);
        file.write_all(&serde_json::to_vec(document)?)?;
        Ok(private)
    }
}
impl Drop for PrivateFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[tokio::test]
async fn hosted_store_startup_refuses_missing_or_invalid_flow_key() -> anyhow::Result<()> {
    let env = Uuid::new_v4();
    let mut document = serde_json::json!({
        "database_url": "invalid endpoint",
        "clients": {Uuid::new_v4().to_string(): "fixture-client"}
    });
    let missing_key = PrivateFile::new(&document)?;
    let error = Store::from_file(&missing_key.0, ISSUER, env).await.err();
    anyhow::ensure!(error.is_some_and(|e| e.to_string() == "invalid hosted configuration"));
    for (key, diagnostic) in [
        ("=".into(), "invalid hosted key"),
        (
            URL_SAFE_NO_PAD.encode([1; 31]),
            "invalid hosted credentials",
        ),
    ] {
        document["key"] = key.into();
        let file = PrivateFile::new(&document)?;
        let error = Store::from_file(&file.0, ISSUER, env).await.err();
        anyhow::ensure!(error.is_some_and(|e| e.to_string() == diagnostic));
    }
    std::fs::remove_file(&missing_key.0)?;
    let error = Store::from_file(&missing_key.0, ISSUER, env).await.err();
    anyhow::ensure!(error
        .and_then(|e| e.downcast::<std::io::Error>().ok())
        .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound));
    Ok(())
}

async fn runtime(
    f: &Fixture,
    selection: Selection,
    environment: Uuid,
) -> anyhow::Result<Arc<Runtime>> {
    Ok(Runtime::checked(
        selection,
        PgPoolOptions::new()
            .max_connections(2)
            .acquire_timeout(Duration::from_secs(2)),
        f.endpoint.clone(),
        vec![(environment, ISSUER.into())],
        Limits {
            ordinary: 1,
            revocation: 1,
            snapshot: 1,
        },
    )
    .await?)
}

async fn seed_pending(
    store: &Store,
    selected: &Arc<Runtime>,
    environment: Uuid,
) -> anyhow::Result<String> {
    let owner = selected.admit(CapacityClass::Ordinary, Some(environment))?;
    let state = owner
        .store_scope(async {
            let now = crate::web::hosted::now().unwrap();
            let generation = super::super::generation(environment).unwrap();
            let mut flow = Flow::start(
                "browser",
                generation,
                Uuid::new_v4(),
                invitation(environment, now),
                None,
                now,
            );
            let auth = oauth::Authorization::begin(ISSUER, flow.domain, flow.deadline).unwrap();
            let state = auth.state.clone();
            flow.authorization = Some(auth);
            let mut tx = store.begin().await.unwrap();
            store.save(&mut tx, &flow).await.unwrap();
            tx.commit().await?;
            Ok::<_, sqlx::Error>(state)
        })
        .await??;
    owner.completion_for_test().await?;
    Ok(state)
}

async fn can_resume(
    store: &Store,
    runtime: &Arc<Runtime>,
    environment: Uuid,
    state: &str,
) -> anyhow::Result<bool> {
    let owner = runtime.admit(CapacityClass::Ordinary, Some(environment))?;
    let pending = owner
        .store_scope(pending_authorization(store, environment, state))
        .await?;
    owner.completion_for_test().await?;
    Ok(pending
        .map_err(|()| anyhow::anyhow!("hosted lookup failed"))?
        .is_some_and(|a| a.state == state))
}

async fn exercise(f: &Fixture) -> anyhow::Result<()> {
    setup_schema(&f.database, f.endpoint.get_username()).await?;
    let environment = Uuid::new_v4();
    let mut config = serde_json::json!({
        "database_url": f.endpoint.to_url_lossy().as_str(),
        "clients": {Uuid::new_v4().to_string(): "fixture-client"},
        "key": aegaeon_crypto::rand::random_base64url(32)
    });
    let file = PrivateFile::new(&config)?;
    config["key"] = aegaeon_crypto::rand::random_base64url(32).into();
    let replacement_file = PrivateFile::new(&config)?;
    let first = Store::from_file(&file.0, ISSUER, environment).await?;
    let second = Store::from_file(&file.0, ISSUER, environment).await?;
    let replaced_key = Store::from_file(&replacement_file.0, ISSUER, environment).await?;
    let current = runtime(f, f.selected, environment).await?;
    let before = async {
        let state = seed_pending(&first, &current, environment).await?;
        anyhow::ensure!(pending_authorization(&second, environment, &state)
            .await
            .is_err());
        anyhow::ensure!(can_resume(&second, &current, environment, &state).await?);
        anyhow::ensure!(can_resume(&replaced_key, &current, environment, &state)
            .await
            .is_err());
        Ok::<_, anyhow::Error>(state)
    }
    .await;
    current.close().await;
    first.pool.close().await;
    second.pool.close().await;
    replaced_key.pool.close().await;
    let state = before?;
    // Capture and restore the complete logical row as it existed in the old
    // generation, including its sealed bytes, handle, and OAuth state index.
    let backup: serde_json::Value =
        sqlx::query_scalar("DELETE FROM hosted_invitation.flow f RETURNING to_jsonb(f)")
            .fetch_one(&f.database)
            .await?;
    sqlx::query(
        "INSERT INTO hosted_invitation.flow SELECT * FROM jsonb_populate_record(NULL::hosted_invitation.flow,$1)",
    )
    .bind(backup)
    .execute(&f.database)
    .await?;
    wait_runtime_release(&f.database).await?;
    let successor = Selection::new(f.selected.deployment_id(), Uuid::new_v4())?;
    f.activate(Some(f.selected.generation()), successor.generation())
        .await?;
    anyhow::ensure!(runtime(f, f.selected, environment).await.is_err());
    let current = runtime(f, successor, environment).await?;
    let reopened = Store::from_file(&file.0, ISSUER, environment).await?;
    let after = async {
        // The same ciphertext and OAuth selector remain readable with the same
        // deployment key. Only the live admission's generation has changed.
        let mut tx = reopened.begin().await.unwrap();
        anyhow::ensure!(reopened
            .find(&mut tx, Find::OAuth(&state, false))
            .await
            .unwrap()
            .is_some());
        tx.commit().await?;
        anyhow::ensure!(!can_resume(&reopened, &current, environment, &state).await?);
        let fresh = seed_pending(&reopened, &current, environment).await?;
        anyhow::ensure!(can_resume(&reopened, &current, environment, &fresh).await?);
        Ok::<_, anyhow::Error>(())
    }
    .await;
    reopened.pool.close().await;
    current.close().await;
    after
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; actual hosted-store startup and generation activation"]
async fn pg_hosted_store_restarted_replicas_refuse_prior_generation_authorization(
) -> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let result = exercise(&fixture).await;
    fixture.finish().await?;
    result
}
