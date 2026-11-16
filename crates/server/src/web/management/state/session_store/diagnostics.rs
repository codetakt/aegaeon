use super::SessionStoreError;
use std::panic::Location;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const INTERVAL: Duration = Duration::from_secs(60);

#[derive(Clone, Copy)]
pub(super) enum Operation {
    Get,
    Create,
    Delete,
}

impl Operation {
    fn label(self) -> &'static str {
        match self {
            Self::Get => "get",
            Self::Create => "create",
            Self::Delete => "delete",
        }
    }
}

#[derive(Default)]
pub(in crate::web::management) struct Diagnostics {
    // Fixed operation slots shared by all store clones; no request-keyed map.
    operations: Mutex<[Window; 3]>,
}

#[derive(Default)]
struct Window {
    last_emission: Option<Instant>,
    started: Option<Instant>,
    unavailable: bool,
    failures: u64,
    recoveries: u64,
    first_request: String,
    latest_request: String,
    first_failure: Option<FailureDiagnostic>,
    latest_failure: Option<FailureDiagnostic>,
}

#[derive(Debug)]
struct Summary {
    unavailable: bool,
    failures: u64,
    recoveries: u64,
    suppressed: u64,
    elapsed: Duration,
    first_request: String,
    latest_request: String,
    first_failure: Option<FailureDiagnostic>,
    latest_failure: Option<FailureDiagnostic>,
}

#[derive(Clone, Copy, Debug)]
struct FailureDiagnostic {
    sqlstate: Option<[u8; 5]>,
    source: &'static Location<'static>,
}

impl FailureDiagnostic {
    #[track_caller]
    fn new(sqlstate: Option<&str>) -> Self {
        Self {
            sqlstate: sqlstate
                .and_then(|value| <[u8; 5]>::try_from(value.as_bytes()).ok())
                .filter(|value| {
                    value
                        .iter()
                        .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
                }),
            source: Location::caller(),
        }
    }

    fn sqlstate(&self) -> &str {
        self.sqlstate
            .as_ref()
            .and_then(|value| std::str::from_utf8(value).ok())
            .unwrap_or("none")
    }
}

fn correlation(request_id: &str) -> String {
    request_id
        .chars()
        .take(96)
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

impl Diagnostics {
    #[track_caller]
    pub(super) fn record<T>(
        &self,
        operation: Operation,
        request_id: &str,
        result: &Result<T, SessionStoreError>,
    ) {
        let diagnostic = match result {
            Err(error) => Some(FailureDiagnostic::new(error.sqlstate().as_deref())),
            Ok(_) => None,
        };
        let unavailable = match result {
            Err(error) if !error.is_unavailable() => {
                crate::metrics_integration::record_management_session_failure(
                    operation.label(),
                    "permanent",
                );
                tracing::error!(target: "management_session_store", operation = operation.label(),
                    source_file = file!(), source_line = line!(),
                    request_id = %correlation(request_id), sqlstate = diagnostic.as_ref().map_or("none", FailureDiagnostic::sqlstate),
                    "management session permanent storage failure");
                return;
            }
            Err(_) => {
                crate::metrics_integration::record_management_session_failure(
                    operation.label(),
                    "unavailable",
                );
                tracing::debug!(target: "management_session_store", operation = operation.label(),
                    source_file = file!(), source_line = line!(),
                    request_id = %correlation(request_id), sqlstate = diagnostic.as_ref().map_or("none", FailureDiagnostic::sqlstate),
                    "management session storage unavailable");
                true
            }
            Ok(_) => false,
        };
        if let Some(summary) = self.observe_at(
            operation,
            unavailable,
            request_id,
            diagnostic,
            Instant::now(),
        ) {
            emit(operation, &summary);
        }
    }

    #[cfg(test)]
    fn record_at(
        &self,
        operation: Operation,
        unavailable: bool,
        request_id: &str,
        now: Instant,
    ) -> Option<Summary> {
        self.observe_at(operation, unavailable, request_id, None, now)
    }

    fn observe_at(
        &self,
        operation: Operation,
        unavailable: bool,
        request_id: &str,
        diagnostic: Option<FailureDiagnostic>,
        now: Instant,
    ) -> Option<Summary> {
        let mut operations = self
            .operations
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let window = &mut operations[operation as usize];
        if unavailable || window.unavailable {
            window.started.get_or_insert(now);
            let request = correlation(request_id);
            if window.first_request.is_empty() {
                window.first_request = request.clone();
            }
            window.latest_request = request;
            if unavailable {
                window.failures += 1;
                if let Some(diagnostic) = diagnostic {
                    window.first_failure.get_or_insert(diagnostic);
                    window.latest_failure = Some(diagnostic);
                }
            } else {
                window.recoveries += 1;
            }
        }
        window.unavailable = unavailable;
        window.take_summary(now, unavailable)
    }

    /// Called by the existing periodic cleanup, including during idle recovery.
    pub(super) fn flush(&self) {
        for operation in [Operation::Get, Operation::Create, Operation::Delete] {
            let summary = self.flush_at(operation, Instant::now());
            if let Some(summary) = summary {
                emit(operation, &summary);
            }
        }
    }

    fn flush_at(&self, operation: Operation, now: Instant) -> Option<Summary> {
        let mut operations = self
            .operations
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        operations[operation as usize].take_summary(now, false)
    }
}

impl Window {
    fn take_summary(&mut self, now: Instant, current_failure: bool) -> Option<Summary> {
        let started = self.started?;
        if self
            .last_emission
            .is_some_and(|last| now.saturating_duration_since(last) < INTERVAL)
        {
            return None;
        }
        let summary = Summary {
            unavailable: self.unavailable,
            failures: self.failures,
            recoveries: self.recoveries,
            suppressed: self.failures.saturating_sub(u64::from(current_failure)),
            elapsed: now.saturating_duration_since(started),
            first_request: std::mem::take(&mut self.first_request),
            latest_request: std::mem::take(&mut self.latest_request),
            first_failure: self.first_failure.take().or(self.latest_failure),
            latest_failure: self.latest_failure,
        };
        self.started = None;
        self.failures = 0;
        self.recoveries = 0;
        self.last_emission = Some(now);
        Some(summary)
    }
}

fn emit(operation: Operation, summary: &Summary) {
    // Recovery shares the failure budget; successful traffic never refills it.
    if summary.unavailable {
        tracing::warn!(target: "management_session_store", operation = operation.label(),
            source_file = summary.latest_failure.map_or(file!(), |diagnostic| diagnostic.source.file()),
            source_line = summary.latest_failure.map_or(line!(), |diagnostic| diagnostic.source.line()),
            first_sqlstate = summary.first_failure.as_ref().map_or("none", FailureDiagnostic::sqlstate),
            latest_sqlstate = summary.latest_failure.as_ref().map_or("none", FailureDiagnostic::sqlstate),
            failures = summary.failures, recoveries = summary.recoveries, suppressed = summary.suppressed,
            interval_ms = summary.elapsed.as_millis() as u64,
            first_request_id = %summary.first_request, latest_request_id = %summary.latest_request,
            "management session storage outage summary");
    } else {
        tracing::info!(target: "management_session_store", operation = operation.label(),
            source_file = summary.latest_failure.map_or(file!(), |diagnostic| diagnostic.source.file()),
            source_line = summary.latest_failure.map_or(line!(), |diagnostic| diagnostic.source.line()),
            first_sqlstate = summary.first_failure.as_ref().map_or("none", FailureDiagnostic::sqlstate),
            latest_sqlstate = summary.latest_failure.as_ref().map_or("none", FailureDiagnostic::sqlstate),
            failures = summary.failures, recoveries = summary.recoveries, suppressed = summary.suppressed,
            interval_ms = summary.elapsed.as_millis() as u64,
            first_request_id = %summary.first_request, latest_request_id = %summary.latest_request,
            "management session storage recovery summary");
    }
}

#[cfg(test)]
mod tests;
