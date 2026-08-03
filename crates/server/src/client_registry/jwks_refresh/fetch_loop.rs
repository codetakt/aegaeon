use super::super::jwks_circuit::circuit_on_failure_with_state;
use super::super::jwks_runtime_state::JwksRuntimeState;
use super::super::{maybe_log_event, metrics, JwksRuntimePolicy};
use super::cache_update::{
    record_not_modified_response_with_state, record_successful_fetch_with_state,
    SuccessfulJwksFetch,
};
use super::request::build_conditional_jwks_get;
use super::retry::sleep_before_retry;
use super::validation::validate_refreshed_jwks_with_state;

pub(super) struct RefreshLoop<'a> {
    pub(super) state: &'a JwksRuntimeState,
    pub(super) policy: &'a JwksRuntimePolicy,
    pub(super) uri: &'a str,
    pub(super) uri_hash: &'a str,
    pub(super) start: std::time::Instant,
    pub(super) client: reqwest::blocking::Client,
    pub(super) etag: Option<String>,
    pub(super) last_modified: Option<String>,
    pub(super) max_body: usize,
    pub(super) retries: u32,
}

impl RefreshLoop<'_> {
    pub(super) fn run(self) -> Option<()> {
        let mut attempt = 0u32;
        loop {
            let req = build_conditional_jwks_get(
                &self.client,
                self.uri,
                self.etag.as_deref(),
                self.last_modified.as_deref(),
            );
            match req.send() {
                Ok(resp) => {
                    if resp.status() == reqwest::StatusCode::NOT_MODIFIED {
                        record_not_modified_response_with_state(
                            self.state,
                            self.policy,
                            self.uri,
                            self.uri_hash,
                            resp.headers(),
                            self.start,
                        );
                        return Some(());
                    }

                    let status = resp.status();
                    if !status.is_success() {
                        let _ = crate::outbound_http::read_blocking_response_body_limited(
                            resp,
                            self.max_body,
                        );
                        if status.is_server_error()
                            && sleep_before_retry(&mut attempt, self.retries)
                        {
                            continue;
                        }
                        let reason_string = format!("http_{}", status.as_u16());
                        metrics::record_jwks_http_status_failure(
                            self.policy,
                            self.uri_hash,
                            status.as_str(),
                            reason_string.as_str(),
                            self.start.elapsed(),
                        );
                        maybe_log_event(self.policy, "failure", self.uri, Some(status.as_str()));
                        circuit_on_failure_with_state(self.state, self.policy, self.uri);
                        return None;
                    }

                    let headers_cloned = resp.headers().clone();
                    let bytes = match crate::outbound_http::read_blocking_response_body_limited(
                        resp,
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
                    )?;

                    record_successful_fetch_with_state(SuccessfulJwksFetch {
                        state: self.state,
                        policy: self.policy,
                        uri: self.uri,
                        uri_hash: self.uri_hash,
                        start: self.start,
                        headers: &headers_cloned,
                        jwks: &validated.jwks,
                        kid_fingerprints: validated.kid_fps,
                    });
                    return Some(());
                }
                Err(_) => {
                    if sleep_before_retry(&mut attempt, self.retries) {
                        continue;
                    }
                    metrics::record_jwks_http_error(
                        self.policy,
                        self.uri_hash,
                        "error",
                        self.start.elapsed(),
                    );
                    maybe_log_event(self.policy, "error", self.uri, None);
                    circuit_on_failure_with_state(self.state, self.policy, self.uri);
                    return None;
                }
            }
        }
    }
}
