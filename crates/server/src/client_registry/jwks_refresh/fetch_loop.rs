use super::super::jwks_cache_control::CacheMetadata;
use super::super::jwks_circuit::circuit_on_failure_with_state;
use super::super::jwks_runtime_state::JwksRuntimeState;
use super::super::jwks_types::{CacheEntry, KidGuard};
use super::super::jwks_validators::{DateContext, JwksValidators};
use super::super::{maybe_log_event, metrics, JwksRuntimePolicy};
use super::cache_update::{record_successful_fetch_with_state, SuccessfulJwksFetch};
use super::failure::record_jwks_refresh_internal_failure_with_state;
use super::request::{execute_phase, is_supported_redirect, redirect_location, RequestError};
use super::retry::sleep_before_retry;
use super::validation::{admit_jwks_with_state, validate_refreshed_jwks_with_state};
use super::JwksRefreshOutcome;
use std::sync::Arc;

pub(super) struct RefreshLoop<'a> {
    pub(super) state: &'a JwksRuntimeState,
    pub(super) policy: &'a JwksRuntimePolicy,
    pub(super) uri: &'a str,
    pub(super) uri_hash: &'a str,
    pub(super) start: std::time::Instant,
    pub(super) client: reqwest::blocking::Client,
    pub(super) candidate: Option<CacheEntry>,
    pub(super) captured_guard: Option<Arc<KidGuard>>,
    pub(super) date_context: DateContext,
    pub(super) original_url: url::Url,
    pub(super) original_target: String,
    pub(super) max_body: usize,
    pub(super) retries: u32,
}

impl RefreshLoop<'_> {
    pub(super) fn run(mut self) -> Option<JwksRefreshOutcome> {
        let mut attempt = 0u32;
        let mut conditional = self
            .candidate
            .as_ref()
            .filter(|entry| {
                entry.effective_target.as_deref() == Some(self.original_target.as_str())
            })
            .and_then(|entry| entry.validators.conditional_headers());
        loop {
            let bound = match execute_phase(
                &self.client,
                &self.original_url,
                &self.original_target,
                conditional.as_ref(),
            ) {
                Ok(bound) => bound,
                Err(RequestError::Correspondence) => {
                    record_jwks_refresh_internal_failure_with_state(
                        self.state,
                        self.policy,
                        self.uri,
                        self.uri_hash,
                        "response_target",
                        self.start,
                    );
                    return None;
                }
                Err(RequestError::Transport) => {
                    if self.retry_transport(&mut attempt) {
                        continue;
                    }
                    return None;
                }
            };
            let status = bound.response.status();
            if conditional.is_some() && status == reqwest::StatusCode::NOT_MODIFIED {
                let metadata =
                    JwksValidators::from_headers(bound.response.headers(), self.date_context);
                if self
                    .candidate
                    .as_ref()
                    .is_some_and(|entry| metadata.identifies(&entry.validators))
                {
                    if let Some(mut entry) = self.candidate.take() {
                        metadata.update_selected(&mut entry.validators);
                        let validated = admit_jwks_with_state(
                            self.state,
                            self.policy,
                            self.uri,
                            self.uri_hash,
                            entry.jwks,
                            self.start,
                            self.captured_guard.as_deref(),
                        )?;
                        let metadata = entry
                            .metadata
                            .freshen(bound.response.headers(), self.date_context);
                        record_successful_fetch_with_state(SuccessfulJwksFetch {
                            state: self.state,
                            policy: self.policy,
                            uri: self.uri,
                            uri_hash: self.uri_hash,
                            start: self.start,
                            jwks: &validated.jwks,
                            guard: validated.guard,
                            validators: entry.validators,
                            effective_target: bound.target,
                            metadata,
                            timing: bound.timing,
                            eligible_200: true,
                            revalidated: true,
                        });
                        return Some(JwksRefreshOutcome::RevalidatedBody(validated.jwks));
                    }
                }
                // This transition is one-way, independent of the ordinary error budget.
                conditional = None;
                drop(bound);
                continue;
            }
            if conditional.is_some() && is_supported_redirect(status) {
                match redirect_location(&bound) {
                    Ok(Some(_)) => {
                        conditional = None;
                        drop(bound);
                        continue;
                    }
                    Ok(None) => {}
                    Err(_) => {
                        drop(bound);
                        if self.retry_transport(&mut attempt) {
                            continue;
                        }
                        return None;
                    }
                }
            }
            if !status.is_success() {
                let _ = crate::outbound_http::read_blocking_response_body_limited(
                    bound.response,
                    self.max_body,
                );
                if status.is_server_error() && sleep_before_retry(&mut attempt, self.retries) {
                    continue;
                }
                let reason = format!("http_{}", status.as_u16());
                metrics::record_jwks_http_status_failure(
                    self.policy,
                    self.uri_hash,
                    status.as_str(),
                    &reason,
                    self.start.elapsed(),
                );
                maybe_log_event(self.policy, "failure", self.uri, Some(status.as_str()));
                circuit_on_failure_with_state(self.state, self.policy, self.uri);
                return None;
            }
            let headers = bound.response.headers().clone();
            let bytes = match crate::outbound_http::read_blocking_response_body_limited(
                bound.response,
                self.max_body,
            ) {
                Ok(bytes) => bytes,
                Err(_) => {
                    circuit_on_failure_with_state(self.state, self.policy, self.uri);
                    return None;
                }
            };
            let validated = validate_refreshed_jwks_with_state(
                self.state,
                self.policy,
                self.uri,
                self.uri_hash,
                &bytes,
                self.start,
                self.captured_guard.as_deref(),
            )?;
            let validators = JwksValidators::from_headers(&headers, self.date_context);
            record_successful_fetch_with_state(SuccessfulJwksFetch {
                state: self.state,
                policy: self.policy,
                uri: self.uri,
                uri_hash: self.uri_hash,
                start: self.start,
                metadata: CacheMetadata::from_headers(&headers, self.date_context),
                timing: bound.timing,
                eligible_200: status == reqwest::StatusCode::OK && bound.follows == 0,
                revalidated: false,
                jwks: &validated.jwks,
                guard: validated.guard,
                validators,
                effective_target: bound.target,
            });
            return Some(JwksRefreshOutcome::AdmittedBody(validated.jwks));
        }
    }

    fn retry_transport(&self, attempt: &mut u32) -> bool {
        if sleep_before_retry(attempt, self.retries) {
            return true;
        }
        metrics::record_jwks_http_error(self.policy, self.uri_hash, "error", self.start.elapsed());
        maybe_log_event(self.policy, "error", self.uri, None);
        circuit_on_failure_with_state(self.state, self.policy, self.uri);
        false
    }
}
