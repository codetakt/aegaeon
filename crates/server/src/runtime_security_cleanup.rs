//! Bounded cleanup of expired security decisions; live rows remain authoritative.
use crate::dcr_persistence::admitted_connection::AdmittedConnection;
use crate::metrics_support::{metric_or_local, OptionalCounterVec};
use sqlx::PgPool;
use std::{sync::LazyLock, time::Duration};

pub(crate) const BATCH_ROWS: u16 = 4096;
pub(crate) const PASS_BATCHES: u16 = 256;

#[derive(Clone, Copy)]
pub(crate) enum Kind {
    Budget,
    Replay,
    Nonce,
    Csrf,
    LogoutRelay,
    UpstreamAuth,
    StepUp,
    ManagementSession,
    BrowserSession,
    Par,
    AuthorizationCode,
    AuthorizationObservation,
    RequestObject,
    DeviceCode,
    JwksBindings,
    JwksFetch,
}

impl Kind {
    const fn label(self) -> &'static str {
        match self {
            Self::Budget => "budget",
            Self::Replay => "replay",
            Self::Nonce => "nonce",
            Self::Csrf => "csrf",
            Self::LogoutRelay => "logout_relay",
            Self::UpstreamAuth => "upstream_auth",
            Self::StepUp => "stepup",
            Self::ManagementSession => "management_session",
            Self::BrowserSession => "browser_session",
            Self::Par => "par",
            Self::AuthorizationCode => "authorization_code",
            Self::AuthorizationObservation => "authorization_observation",
            Self::RequestObject => "request_object",
            Self::DeviceCode => "device_code",
            Self::JwksBindings => "jwks_bindings",
            Self::JwksFetch => "jwks_fetch",
        }
    }

    const fn table(self) -> &'static str {
        match self {
            Self::Budget => "aegaeon.runtime_security_budgets",
            Self::Replay => "aegaeon.runtime_replay_entries",
            Self::Nonce => "aegaeon.runtime_dpop_nonces",
            Self::Csrf => "aegaeon.runtime_csrf_tokens",
            Self::LogoutRelay => "aegaeon.runtime_logout_relays",
            Self::UpstreamAuth => "aegaeon.runtime_upstream_auth",
            Self::StepUp => "aegaeon.runtime_stepup_challenges",
            Self::ManagementSession => "aegaeon.runtime_management_sessions",
            Self::BrowserSession => "aegaeon.runtime_browser_sessions",
            Self::Par => "aegaeon.runtime_par_requests",
            Self::AuthorizationCode => "aegaeon.runtime_authorization_codes",
            Self::AuthorizationObservation => "aegaeon.runtime_authorization_observations",
            Self::RequestObject => "aegaeon.runtime_request_object_jtis",
            Self::DeviceCode => "aegaeon.runtime_device_codes",
            Self::JwksBindings => "aegaeon.runtime_jwks_bindings",
            Self::JwksFetch => "aegaeon.runtime_jwks_fetches",
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Progress {
    pub(crate) removed: u64,
    /// Observed backlog, or exhaustion before an absence check could finish.
    pub(crate) more: bool,
}

fn counter(name: &str, help: &str, labels: &[&str]) -> OptionalCounterVec {
    OptionalCounterVec::new(metric_or_local(
        prometheus::register_int_counter_vec!(name, help, labels),
        name,
        || prometheus::IntCounterVec::new(prometheus::Opts::new(name, help), labels),
    ))
}

static ROWS: LazyLock<OptionalCounterVec> = LazyLock::new(|| {
    counter(
        "aegaeon_security_state_cleanup_rows_total",
        "Confirmed expired security rows removed",
        &["kind"],
    )
});
static PASSES: LazyLock<OptionalCounterVec> = LazyLock::new(|| {
    counter(
        "aegaeon_security_state_cleanup_passes_total",
        "Bounded security cleanup outcomes",
        &["kind", "outcome"],
    )
});

/// OIDC has dependent rows, so its bounded cleanup uses ordered statements.
pub(crate) fn record_oidc_cleanup(removed: u64, more: Option<bool>) {
    ROWS.with_label_values(&["oidc_session"]).inc_by(removed);
    let outcome = match more {
        Some(true) => "backlog",
        Some(false) => "drained",
        None => "error",
    };
    PASSES.with_label_values(&["oidc_session", outcome]).inc();
}

pub(crate) fn record_token_cleanup(removed: u64, more: Option<bool>) {
    ROWS.with_label_values(&["token_grant"]).inc_by(removed);
    let outcome = match more {
        Some(true) => "backlog",
        Some(false) => "drained",
        None => "error",
    };
    PASSES.with_label_values(&["token_grant", outcome]).inc();
}

pub(crate) async fn cleanup(
    pool: &PgPool,
    namespace: &str,
    kind: Kind,
    batches: u16,
) -> Result<Progress, String> {
    if !(1..=PASS_BATCHES).contains(&batches) {
        return Err("invalid security cleanup budget".into());
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    let mut connection = AdmittedConnection::acquire(pool).await.map_err(|_| {
        PASSES.with_label_values(&[kind.label(), "error"]).inc();
        "security cleanup database unavailable"
    })?;
    // Only the closed enum supplies this identifier; request data is always bound.
    let table = kind.table();
    let (expiry, now) = match kind {
        Kind::DeviceCode | Kind::JwksBindings | Kind::JwksFetch => (
            "expires_us",
            "floor(extract(epoch from statement_timestamp())*1000000)::bigint",
        ),
        _ => ("expires_at", "statement_timestamp()"),
    };
    let delete = format!(
        "DELETE FROM {table} WHERE ctid IN (
        SELECT ctid FROM {table} WHERE namespace=$1 AND {expiry} <= {now}
        ORDER BY {expiry} LIMIT $2 FOR UPDATE SKIP LOCKED)"
    );
    let remaining = format!(
        "SELECT EXISTS(SELECT FROM {table}
        WHERE namespace=$1 AND {expiry} <= {now})"
    );
    let mut removed = 0;
    let result = async {
        for _ in 0..batches {
            if tokio::time::Instant::now() >= deadline {
                return Ok(true);
            }
            crate::organizations::request_work::async_store::admit_current_commit()
                .map_err(|_| "security cleanup admission unavailable")?;
            let query_deadline = deadline.min(tokio::time::Instant::now() + Duration::from_secs(5));
            let count = tokio::time::timeout_at(query_deadline, async {
                sqlx::query(&delete)
                    .bind(namespace)
                    .bind(i64::from(BATCH_ROWS))
                    .execute(connection.as_mut()?)
                    .await
            })
            .await
            .map_err(|_| "security cleanup database deadline")?
            .map_err(|_| "security cleanup database unavailable")?
            .rows_affected();
            removed += count;
            if count < u64::from(BATCH_ROWS) {
                break;
            }
            tokio::task::yield_now().await;
        }
        if tokio::time::Instant::now() >= deadline {
            return Ok(true);
        }
        // SKIP LOCKED can leave expired rows even when a batch was short.
        let query_deadline = deadline.min(tokio::time::Instant::now() + Duration::from_secs(5));
        tokio::time::timeout_at(query_deadline, async {
            sqlx::query_scalar::<_, bool>(&remaining)
                .bind(namespace)
                .fetch_one(connection.as_mut()?)
                .await
        })
        .await
        .map_err(|_| "security cleanup observation deadline")?
        .map_err(|_| "security cleanup database unavailable")
    }
    .await;
    connection.release().await;
    ROWS.with_label_values(&[kind.label()]).inc_by(removed);
    let outcome = match &result {
        Ok(false) => "complete",
        Ok(true) => "backlog",
        Err(_) => "error",
    };
    PASSES.with_label_values(&[kind.label(), outcome]).inc();
    if matches!(result, Ok(true)) {
        tracing::warn!(target: "cleanup", kind = kind.label(), namespace, removed,
            "expired security state remains after bounded cleanup");
    }
    result
        .map(|more| Progress { removed, more })
        .map_err(str::to_owned)
}
