use super::*;
mod outcome;
mod runtime;
use crate::web::hosted::{cookies, flow::Step, hosted_page::MailLink};
use axum::http::{header, HeaderMap, HeaderValue};

async fn setup_schema(pool: &PgPool, role: &str) -> anyhow::Result<()> {
    let schema = include_str!("../../../../../../db/hosted-invitations/setup.sql");
    let ddl = schema
        .lines()
        .filter(|l| !l.starts_with('\\'))
        .collect::<Vec<_>>()
        .join("\n")
        .replace(
            ":\"serving_role\"",
            &crate::test_utils::postgres_cleanup::quote_database_identifier(role),
        );
    sqlx::raw_sql(&ddl).execute(pool).await?;
    Ok(())
}

fn replica(pool: PgPool, key: u8, environment: Uuid) -> Store {
    let (key, mac) = flow_keys(&[key; 32]).unwrap();
    Store {
        wake: Arc::new(tokio::sync::Notify::new()),
        pool,
        key,
        mac,
        clients: BTreeMap::new(),
        issuer: "https://issuer.example".into(),
        environment,
    }
}
fn invitation(environment: Uuid, now: i64) -> MailLink {
    let id = Uuid::new_v4();
    MailLink {
        issuer: "https://issuer.example".into(),
        environment_id: environment,
        domain_id: Uuid::new_v4(),
        invitation_id: id,
        object_id: id,
        template: "organization_invitation".into(),
        delivery_revision: 1,
        capability: aegaeon_crypto::rand::random_base64url(32),
        expires_at: now + 86400,
    }
}
fn generation() -> Generation {
    Generation {
        deployment: Uuid::new_v4(),
        generation: Uuid::new_v4(),
    }
}
#[tokio::test]
async fn identity_options_follow_the_anonymous_phase_and_each_purpose_policy() {
    use crate::organizations::invitations::enrollment::Purpose::{PasswordRecovery, Registration};

    let environment = Uuid::new_v4();
    let pool = PgPoolOptions::new()
        .connect_lazy("postgres://localhost/unused")
        .unwrap();
    let store = replica(pool, 1, environment);
    let clock = crate::web::hosted::now().unwrap();
    let mut flow = Flow::start(
        "binding",
        generation(),
        Uuid::new_v4(),
        invitation(environment, clock),
        None,
        clock,
    );
    flow.can_register = true;
    let view = flow.view(&store, clock);
    assert_eq!(view["canRegister"], true);
    assert_eq!(view["canRecover"], false);

    flow.can_recover = true;
    flow.authorization =
        Some(oauth::Authorization::begin(&store.issuer, flow.domain, flow.deadline).unwrap());
    let pending = flow.view(&store, clock);
    assert_eq!(pending["signInPending"], true);
    assert_eq!(pending["canRegister"], false);
    assert_eq!(pending["canRecover"], false);

    flow.authorization = None;
    flow.can_register = false;
    flow.expected_subject = Some(("registered subject".into(), clock));
    let resumed = flow.view(&store, clock);
    assert_eq!(resumed["signInPending"], false);
    assert_eq!(resumed["canRegister"], false);
    assert_eq!(resumed["canRecover"], true);
    flow.session = Some("bound session".into());
    assert!(!flow.allows_identity_request(PasswordRecovery));
    flow.session = None;
    flow.step = Step::IdentityWaiting;
    assert!(!flow.allows_identity_request(PasswordRecovery));
    assert!(!flow.allows_identity_request(Registration));
}

#[tokio::test]
async fn hosted_store_preserves_flow_keys_and_browser_mac_encoding() {
    let pool = PgPoolOptions::new()
        .connect_lazy("postgres://localhost/unused")
        .unwrap();
    let mut store = replica(pool, 1, Uuid::nil());
    let master = std::array::from_fn::<_, 32, _>(|i| i as u8);
    (store.key, store.mac) = flow_keys(&master).unwrap();
    assert_eq!(
        URL_SAFE_NO_PAD.encode(*store.key),
        "dkcxTToH-Q8uyFxVFUGMqFtab2zX24GiSHB5nAeQAEY"
    );
    assert_eq!(
        store.mac("state", r#"a"b/東京"#),
        "HlnWtM70pCi_XNdrudIQ1KxVAybAhwc6m3LhjTYV0Ug"
    );
    assert_eq!(
        hash(r#"a"b/東京"#),
        "fb7zLaoXSbjUStII0PoKDcM6F6Key7Sz6XslA8rFjpM"
    );
}

#[tokio::test]
async fn browser_and_flow_envelopes_bind_key_issuer_scope_and_record_identity() {
    let pool = PgPoolOptions::new()
        .connect_lazy("postgres://localhost/unused")
        .unwrap();
    let environment = Uuid::new_v4();
    let store = replica(pool.clone(), 1, environment);
    let other = replica(pool.clone(), 2, environment);
    let mut headers = HeaderMap::new();
    let cookie = cookies::new_browser(&store);
    let handle = Uuid::new_v4();
    let csrf = cookies::landing_csrf(&store, &cookie, Some(handle), 100);
    assert!(cookies::valid_landing(
        &store,
        &cookie,
        Some(handle),
        &csrf,
        1899
    ));
    assert!(!cookies::valid_landing(
        &store,
        &cookie,
        Some(handle),
        &csrf,
        1900
    ));
    assert!(!cookies::valid_landing(&store, &cookie, None, &csrf, 100));
    assert!(!cookies::valid_landing(
        &store,
        "other",
        Some(handle),
        &csrf,
        100
    ));
    headers.insert(
        header::COOKIE,
        HeaderValue::from_str(&format!("{}={cookie}", cookies::BROWSER)).unwrap(),
    );
    assert_eq!(
        cookies::browser(&store, &headers).as_deref(),
        Some(cookie.as_str())
    );
    assert!(cookies::browser(&other, &headers).is_none());
    let valid = |headers: &HeaderMap| {
        cookies::post_credentials(&store, &store.issuer, headers, None).is_ok()
    };
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    headers.insert(
        header::ORIGIN,
        HeaderValue::from_static("https://issuer.example"),
    );
    assert!(!valid(&headers));
    headers.insert("x-csrf-token", HeaderValue::from_str(&csrf).unwrap());
    assert!(valid(&headers));
    assert!(cookies::post_credentials(&store, &store.issuer, &headers, Some("")).is_err());
    let origin = headers.remove(header::ORIGIN).unwrap();
    assert!(!valid(&headers));
    headers.insert(
        header::ORIGIN,
        HeaderValue::from_static("https://foreign.example"),
    );
    assert!(!valid(&headers));
    headers.append(header::ORIGIN, origin.clone());
    assert!(!valid(&headers));
    headers.insert(header::ORIGIN, origin);
    headers.append("x-csrf-token", HeaderValue::from_str(&csrf).unwrap());
    assert!(!valid(&headers));
    headers.append(header::COOKIE, headers[header::COOKIE].clone());
    assert!(cookies::browser(&store, &headers).is_none());
    let flow = Flow::start(
        "binding",
        generation(),
        Uuid::new_v4(),
        invitation(environment, 1000),
        None,
        1000,
    );
    let bytes = store.seal("flow", flow.id, &flow).unwrap();
    assert_eq!(
        store
            .open::<Flow>("flow", flow.id, &bytes)
            .unwrap()
            .deadline,
        2800
    );
    assert!(store.open::<Flow>("cleanup", flow.id, &bytes).is_err());
    assert!(store.open::<Flow>("flow", Uuid::new_v4(), &bytes).is_err());
    assert!(other.open::<Flow>("flow", flow.id, &bytes).is_err());
    let mut complete = store.open::<Flow>("flow", flow.id, &bytes).unwrap();
    complete.clear(Step::Complete);
    complete.session = Some(hash("synthetic-session"));
    complete.session_subject = Some("subject".into());
    complete.session_until = 1200;
    complete.confirmation_until = Some(1150);
    let mut session = HeaderMap::new();
    session.insert(
        header::COOKIE,
        HeaderValue::from_str(&format!(
            "{}=synthetic-session",
            cookies::session(complete.id)
        ))
        .unwrap(),
    );
    assert!(complete
        .bound(&flow.generation, "binding", &session, 1149)
        .is_ok());
    assert_eq!(complete.view(&store, 1149)["step"], "complete");
    assert_eq!(complete.view(&store, 1150)["step"], "closed");
    assert!(complete
        .bound(&flow.generation, "binding", &session, 1200)
        .is_err());
    assert!(complete
        .bound(&generation(), "binding", &session, 1149)
        .is_err());
    assert!(complete
        .bound(&flow.generation, "binding", &HeaderMap::new(), 1149)
        .is_err());

    assert!(replica(pool, 1, Uuid::new_v4())
        .open::<Flow>("flow", flow.id, &bytes)
        .is_err());
}

#[tokio::test]
#[ignore = "requires a PostgreSQL admin in an isolated integration lane"]
async fn pg_hosted_store_replicas_preserve_pending_authorization_and_expire_abandoned_secrets(
) -> anyhow::Result<()> {
    use crate::test_utils::postgres_cleanup::{finish_database, quote_database_identifier};
    let options: sqlx::postgres::PgConnectOptions =
        std::env::var("AEGAEON_TEST_ADMIN_DATABASE_URL")?.parse()?;
    let db = format!("hosted_flow_{}", Uuid::new_v4().simple());
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(options.clone())
        .await?;
    sqlx::query(&format!(
        "CREATE DATABASE {}",
        quote_database_identifier(&db)
    ))
    .execute(&admin)
    .await?;
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect_lazy_with(options.database(&db));
    let result = async {
        setup_schema(&pool, pool.connect_options().get_username()).await?;
        let env = Uuid::new_v4();
        let a = replica(pool.clone(), 1, env);
        let b = replica(pool.clone(), 1, env);
        let now = crate::web::hosted::now().unwrap();
        let mut f = Flow::start(
            "browser",
            generation(),
            Uuid::new_v4(),
            invitation(env, now),
            None,
            now,
        );
        let auth = oauth::Authorization::begin(&a.issuer, f.domain, f.deadline).unwrap();
        let state = auth.state.clone();
        f.authorization = Some(auth);
        let mut tx = a.begin().await.unwrap();
        a.reserve(&mut tx).await.unwrap();
        a.save(&mut tx, &f).await.unwrap();
        tx.commit().await?;
        let mut tx = b.begin().await.unwrap();
        let resumed = b
            .find(&mut tx, Find::Invitation("browser", f.domain, f.invitation))
            .await
            .unwrap()
            .unwrap();
        anyhow::ensure!(resumed.handle == f.handle && resumed.deadline == f.deadline);
        anyhow::ensure!(b
            .find(&mut tx, Find::OAuth(&state, false))
            .await
            .unwrap()
            .is_some());
        anyhow::ensure!(b
            .find(&mut tx, Find::Invitation("other", f.domain, f.invitation))
            .await
            .unwrap()
            .is_none());
        tx.commit().await?;
        let sealed: Vec<u8> =
            sqlx::query_scalar("SELECT sealed FROM hosted_invitation.flow WHERE id=$1")
                .bind(f.id)
                .fetch_one(&pool)
                .await?;
        let secret = f.capability.as_ref().unwrap();
        anyhow::ensure!(!sealed.windows(secret.len()).any(|w| w == secret.as_bytes()));
        // Restore the exact encrypted row into the same keyed store. Possession
        // of the old handle and cookie cannot cross a runtime generation.
        sqlx::query("DELETE FROM hosted_invitation.flow WHERE id=$1")
            .bind(f.id)
            .execute(&pool)
            .await?;
        let mut tx = b.begin().await.unwrap();
        b.save(&mut tx, &resumed).await.unwrap();
        sqlx::query("UPDATE hosted_invitation.flow SET sealed=$2 WHERE id=$1")
            .bind(f.id)
            .bind(&sealed)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        let mut tx = a.begin().await.unwrap();
        let restored = a
            .find(&mut tx, Find::Handle(f.handle))
            .await
            .unwrap()
            .unwrap();
        let headers = HeaderMap::new();
        anyhow::ensure!(restored
            .bound(&f.generation, "browser", &headers, now)
            .is_ok());
        let successor = Generation {
            deployment: f.generation.deployment,
            generation: Uuid::new_v4(),
        };
        anyhow::ensure!(restored
            .bound(&successor, "browser", &headers, now)
            .is_err());
        let lost_key = replica(pool.clone(), 9, env);
        anyhow::ensure!(lost_key
            .find(&mut tx, Find::Handle(f.handle))
            .await
            .is_err());
        tx.commit().await?;
        let mut tx = a.begin().await.unwrap();
        let old_handle = f.handle;
        f.handle = Uuid::new_v4();
        f.authorization = None;
        f.deadline = now - 1;
        a.save(&mut tx, &f).await.unwrap();
        tx.commit().await?;
        b.maintain().await.unwrap();
        let mut tx = a.begin().await.unwrap();
        anyhow::ensure!(a
            .find(&mut tx, Find::Handle(old_handle))
            .await
            .unwrap()
            .is_none());
        anyhow::ensure!(a
            .find(&mut tx, Find::OAuth(&state, false))
            .await
            .unwrap()
            .is_none());
        let closed = a
            .find(&mut tx, Find::Handle(f.handle))
            .await
            .unwrap()
            .unwrap();
        anyhow::ensure!(closed.step == Step::Closed && closed.capability.is_none());
        tx.commit().await?;
        // Closure and the cleanup-only authority have one commit. Another
        // replica retains it across an issuer outage and removes it at expiry.
        let refresh = aegaeon_crypto::rand::random_base64url(32);
        let handle: oauth::Cleanup = serde_json::from_value(serde_json::json!({
            "issuer": a.issuer, "client_id": format!("aegaeon-hosted-invitation-{}", f.domain),
            "deadline": now + 120, "refresh": refresh
        }))?;
        let mut tx = a.begin().await.unwrap();
        a.cleanup(&mut tx, f.domain, &handle).await.unwrap();
        tx.rollback().await?;
        let queued =
            || sqlx::query_scalar::<_, i64>("SELECT count(*) FROM hosted_invitation.cleanup");
        anyhow::ensure!(queued().fetch_one(&pool).await? == 0);
        let mut tx = a.begin().await.unwrap();
        a.cleanup(&mut tx, f.domain, &handle).await.unwrap();
        tx.commit().await?;
        b.maintain().await.unwrap();
        let (id, sealed, retry_at): (Uuid, Vec<u8>, i64) =
            sqlx::query_as("SELECT id,sealed,retry_at FROM hosted_invitation.cleanup")
                .fetch_one(&pool)
                .await?;
        anyhow::ensure!(
            retry_at > now
                && !sealed
                    .windows(refresh.len())
                    .any(|w| w == refresh.as_bytes())
        );
        let (domain, decoded): (Uuid, oauth::Cleanup) = b.open("cleanup", id, &sealed).unwrap();
        anyhow::ensure!(domain == f.domain && decoded.deadline == handle.deadline);
        a.maintain().await.unwrap();
        anyhow::ensure!(queued().fetch_one(&pool).await? == 1);
        // The independent issuer deadline has now passed.
        b.maintain_at(handle.deadline).await.unwrap();
        anyhow::ensure!(queued().fetch_one(&pool).await? == 0);
        Ok::<(), anyhow::Error>(())
    }
    .await;
    finish_database(&admin, &pool, &db, Duration::from_secs(5)).await?;
    result
}
