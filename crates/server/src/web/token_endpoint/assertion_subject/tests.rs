use super::{parse_client_id, run_lookup_parser, LookupError};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use std::{sync::mpsc, thread, time::Duration};

#[tokio::test(flavor = "current_thread")]
async fn lookup_parser_leaves_async_worker_available() {
    let async_worker = thread::current().id();
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let assertion = format!(
        "{}.{}.AA",
        URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256"}"#),
        URL_SAFE_NO_PAD.encode(r#"{"sub":"lookup-client"}"#),
    );
    let lookup = tokio::spawn(async move {
        run_lookup_parser(move || {
            assert_ne!(thread::current().id(), async_worker);
            started_tx.send(()).expect("signal parser start");
            // The timeout only bounds a broken implementation; success requires
            // another async task to run while this parser closure is blocked.
            release_rx
                .recv_timeout(Duration::from_secs(10))
                .expect("async task releases parser");
            parse_client_id(&assertion, Some("lookup-client"), 4096)
        })
        .await
    });
    started_rx.await.expect("parser started");
    tokio::spawn(async move {
        assert_eq!(thread::current().id(), async_worker);
        release_tx.send(()).expect("release parser");
    })
    .await
    .expect("unrelated async task completes");
    assert_eq!(
        lookup.await.expect("lookup task completes"),
        Ok(Some("lookup-client".into()))
    );
}

#[tokio::test(flavor = "current_thread")]
async fn lookup_parser_task_failure_is_internal() {
    assert_eq!(
        run_lookup_parser(|| panic!("local parser failure")).await,
        Err(LookupError::TaskFailed)
    );
    assert_eq!(
        run_lookup_parser(|| Err(LookupError::BackendPolicy)).await,
        Err(LookupError::BackendPolicy)
    );
}
