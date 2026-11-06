//! Startup diagnostics expose fixed categories while external errors stay generic.
use super::*;
use crate::organizations::witness::Error;
use std::{
    io::Write,
    sync::{Arc, Mutex},
};

const PRIVATE_SENTINEL: &str = "private-startup-diagnostic-sentinel";

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn failure_diagnostic(
    result: std::result::Result<Result<()>, Error>,
) -> (String, Vec<serde_json::Value>) {
    let capture = Capture::default();
    let writer = capture.clone();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .without_time()
        .with_max_level(tracing::Level::ERROR)
        .with_writer(move || writer.clone())
        .finish();
    let error = tracing::subscriber::with_default(subscriber, || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                // The lazy pool owns no physical connection; this test never
                // connects to a store or changes admission/pending state.
                let pool = PgPoolOptions::new()
                    .min_connections(0)
                    .connect_lazy_with(sqlx::postgres::PgConnectOptions::new());
                let error = startup_outcome(&pool, result).await.unwrap_err();
                assert!(pool.is_closed());
                format!("{error:#}")
            })
    });
    let log = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
    assert!(!log.contains(PRIVATE_SENTINEL));
    assert!(!error.contains(PRIVATE_SENTINEL));
    let records = log
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    (error, records)
}

#[test]
fn organization_startup_diagnostics_classify_without_source_errors() {
    let decode = serde_json::from_str::<u64>(&format!("\"{PRIVATE_SENTINEL}\"")).unwrap_err();
    let cases = [
        (Error::Refused, "boundary_refused"),
        (Error::Deadline, "deadline"),
        (
            Error::PrimaryIncarnationChanged,
            "primary_incarnation_changed",
        ),
        (Error::PrimaryProgressBehind, "primary_progress_behind"),
        (Error::TokenIncarnationChanged, "token_incarnation_changed"),
        (Error::StoreContinuityMismatch, "store_continuity_mismatch"),
        (Error::StoreRestartPending, "store_restart_pending"),
        (
            Error::Storage(sqlx::Error::Protocol(PRIVATE_SENTINEL.into())),
            "storage_unavailable",
        ),
        (Error::Decode(decode), "invalid_control_response"),
    ];
    for (error, expected) in cases {
        assert_eq!(error.reason_code(), expected);
        let (external, records) = failure_diagnostic(Err(error));
        assert_eq!(external, "Organizations owned startup failed");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["target"], "organization_startup");
        assert_eq!(records[0]["fields"]["stage"], "owned_startup");
        assert_eq!(records[0]["fields"]["reason_code"], expected);
    }
    let (external, records) = failure_diagnostic(Ok(Err(anyhow::anyhow!(PRIVATE_SENTINEL))));
    assert_eq!(external, "Organizations owned startup failed");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["fields"]["reason_code"], "runtime_build_failed");
}

#[test]
fn organization_successful_startup_preserves_open_pool() {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let pool = PgPoolOptions::new()
                .min_connections(0)
                .connect_lazy_with(sqlx::postgres::PgConnectOptions::new());
            assert_eq!(startup_outcome(&pool, Ok(Ok(42))).await.unwrap(), 42);
            assert!(!pool.is_closed());
            pool.close().await;
        });
}
