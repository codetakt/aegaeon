use super::*;
use crate::organizations::{
    request_work::CapacityClass, witness::tests::caller_fixture::CallerFixture,
};
use std::time::Duration;

#[tokio::test]
#[ignore = "requires restricted PostgreSQL; actual management export must retain its enclosing witness"]
async fn pg_organizations_snapshot_http_epoch_retains_producer_and_cleanup() -> ManagementTestResult
{
    let (control, pool, name) = database().await?;
    let result: ManagementTestResult = async {
        let h = Harness::new(&pool).await?;
        grant(&h, &pool).await?;
        let witness = CallerFixture::new(h.environment).await?;
        let result = exercise(&h, &witness).await;
        let cleanup = witness
            .finish()
            .await
            .map_err(|error| -> Box<dyn std::error::Error> { error.into() });
        result.and(cleanup)
    }
    .await;
    finish(result, cleanup(control, pool, &name).await)
}

async fn exercise(h: &Harness, witness: &CallerFixture) -> ManagementTestResult {
    let work = witness.begin_class(CapacityClass::Snapshot).await?;
    let response = work
        .store_scope(h.app.clone().oneshot(h.read(&path(h))))
        .await??;
    assert_eq!(response.status(), StatusCode::OK);
    let mut completing = tokio::spawn(work.complete());
    let early = tokio::time::timeout(Duration::from_millis(150), &mut completing).await;
    let pending = witness.pending().await?;
    drop(response);
    let retained = early.is_err();
    let completed = match early {
        Ok(value) => value??,
        Err(_) => tokio::time::timeout(Duration::from_secs(5), completing).await???,
    };
    assert!(
        retained && pending == 1,
        "returning export headers cannot complete its durable admission"
    );
    assert_eq!(completed.pending, 0);

    // A nonempty complete export after clean cancellation remains usable.
    let work = witness.begin_class(CapacityClass::Snapshot).await?;
    let bytes = work
        .store_scope(async {
            let response = h.app.clone().oneshot(h.read(&path(h))).await?;
            assert_eq!(response.status(), StatusCode::OK);
            axum::body::to_bytes(response.into_body(), 2 * 1024 * 1024)
                .await
                .map_err(|error| -> Box<dyn std::error::Error> { error.into() })
        })
        .await??;
    assert!(std::str::from_utf8(&bytes)?.contains("\"record\":\"manifest\""));
    assert_eq!(work.complete().await?.pending, 0);

    // A foreign Environment and a foreign capacity class cannot inherit scope.
    for class in [CapacityClass::Snapshot, CapacityClass::Ordinary] {
        let work = witness.begin_class(class).await?;
        let requested = if class == CapacityClass::Snapshot {
            path(h).replace(&h.environment.to_string(), &Uuid::new_v4().to_string())
        } else {
            path(h)
        };
        let response = work
            .store_scope(h.app.clone().oneshot(h.read(&requested)))
            .await??;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        drop(response);
        assert_eq!(work.complete().await?.pending, 0);
    }
    Ok(())
}
