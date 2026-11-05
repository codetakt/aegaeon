//! Distinct writer identity, reserved capacity and physical generation fencing.
use super::*;
use crate::organizations::request_work::{async_store, CapacityClass};

#[tokio::test]
#[ignore = "requires isolated PostgreSQL supplier"]
async fn pg_lifecycle_management_preserves_credentials_reservation_and_fence() -> anyhow::Result<()>
{
    let f = Fixture::new().await?;
    let writer = format!("life_writer_{}", Uuid::new_v4().simple());
    let password = Uuid::new_v4().simple().to_string();
    f.admin.execute(format!("CREATE ROLE {writer} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '{password}'").as_str()).await?;
    sqlx::raw_sql(&format!(
        "GRANT USAGE ON SCHEMA aegaeon_lifecycle TO {writer};
         GRANT SELECT ON aegaeon_lifecycle.current TO {writer};
         CREATE TABLE public.writer_probe(value integer);
         GRANT SELECT ON public.writer_probe TO {};
         GRANT SELECT,INSERT ON public.writer_probe TO {writer};",
        f.role
    ))
    .execute(&f.database)
    .await?;
    let endpoint = f.endpoint.clone().username(&writer).password(&password);
    let runtime = Runtime::checked_with_management(
        f.selected,
        PgPoolOptions::new()
            .max_connections(2)
            .acquire_timeout(Duration::from_millis(500)),
        f.endpoint.clone(),
        vec![(Uuid::new_v4(), "https://issuer.example/".into())],
        Limits {
            ordinary: 2,
            revocation: 1,
            snapshot: 1,
        },
        Some(endpoint.clone()),
    )
    .await?;
    let reader = runtime.pool().clone();
    let management = runtime.management_pool().unwrap().clone();
    let foreign = PgPoolOptions::new().connect_lazy_with(endpoint);
    let requested = management.clone();
    let expected = writer.clone();
    let (entered, started) = tokio::sync::oneshot::channel();
    let (release, waiting) = tokio::sync::oneshot::channel();
    let first = runtime.start(None, CapacityClass::Ordinary, move || async move {
        let owner = async_store::current_owner()?;
        assert!(matches!(owner.connection(&foreign).await, Err(sqlx::Error::Protocol(_))));
        close_pool(&foreign).await;
        let mut read = owner.connection(&reader).await?;
        assert!(matches!(sqlx::query("INSERT INTO public.writer_probe VALUES(0)").execute(read.as_mut()?).await,
            Err(sqlx::Error::Database(error)) if error.code().as_deref()==Some("42501")));
        read.release().await;
        let mut write = owner.connection(&requested).await?;
        assert_eq!(sqlx::query_scalar::<_,String>("SELECT current_user::text").fetch_one(write.as_mut()?).await?, expected);
        sqlx::query("INSERT INTO public.writer_probe VALUES(1)").execute(write.as_mut()?).await?;
        entered.send(()).unwrap();
        waiting.await.unwrap();
        write.release().await;
        Ok::<_,sqlx::Error>(())
    })?;
    tokio::time::timeout(Duration::from_secs(5), started).await??;
    let requested = management.clone();
    let expected = writer.clone();
    runtime
        .start(None, CapacityClass::Revocation, move || async move {
            let owner = async_store::current_owner()?;
            let mut write = owner.connection(&requested).await?;
            assert_eq!(
                sqlx::query_scalar::<_, String>("SELECT current_user::text")
                    .fetch_one(write.as_mut()?)
                    .await?,
                expected
            );
            sqlx::query("INSERT INTO public.writer_probe VALUES(2)")
                .execute(write.as_mut()?)
                .await?;
            write.release().await;
            Ok::<_, sqlx::Error>(())
        })?
        .result()
        .await??;
    release.send(()).unwrap();
    first.result().await??;
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM public.writer_probe")
            .fetch_one(&f.database)
            .await?,
        2
    );
    assert!(f
        .activate(Some(f.selected.generation), Uuid::new_v4())
        .await
        .is_err());
    // Kill every reader and writer session without closing the pools. Once the
    // DB is activated, replacement writer sessions must fail their own bind.
    sqlx::query("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=$1 AND usename=ANY($2)")
        .bind(&f.name).bind(vec![f.role.clone(),writer.clone()]).execute(&f.database).await?;
    wait_runtime_release(&f.database).await?;
    f.activate(Some(f.selected.generation), Uuid::new_v4())
        .await?;
    let requested = management.clone();
    runtime
        .start(None, CapacityClass::Ordinary, move || async move {
            let owner = async_store::current_owner()?;
            assert!(owner.connection(&requested).await.is_err());
            Ok::<_, sqlx::Error>(())
        })?
        .result()
        .await??;
    runtime.close().await;
    assert!(management.is_closed());
    wait_runtime_release(&f.database).await?;
    sqlx::query(&format!("DROP OWNED BY {writer}"))
        .execute(&f.database)
        .await?;
    sqlx::query(&format!("DROP ROLE {writer}"))
        .execute(&f.admin)
        .await?;
    f.finish().await
}
