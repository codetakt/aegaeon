//! Stable message transport. Adapter acknowledgement is not inbox delivery.
use super::*;
use crate::organizations::notification_retry::{RetryAfter, TransportOutcome};
use reqwest::header::{HeaderMap, CONTENT_LENGTH, RETRY_AFTER, TRANSFER_ENCODING};
use std::time::UNIX_EPOCH;
use uuid::Uuid;

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Observation {
    pub outcome: TransportOutcome,
    pub retry_after: Option<RetryAfter>,
}

impl Observation {
    fn uncertain() -> Self {
        Self {
            outcome: TransportOutcome::Uncertain,
            retry_after: None,
        }
    }
}

// The HTTP body takes ownership of this buffer. Its last reference erases the
// application-owned plaintext. HTTP/TLS implementation copies are not covered.
struct SecretBody(Zeroizing<Vec<u8>>);
impl AsRef<[u8]> for SecretBody {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

pub(crate) async fn send(
    client: &reqwest::Client,
    endpoint: &str,
    message: Uuid,
    plaintext: Zeroizing<Vec<u8>>,
    credential: &Credential,
    remaining: Duration,
) -> Observation {
    if message.is_nil() || plaintext.is_empty() || plaintext.len() > 8192 || remaining.is_zero() {
        return Observation::uncertain();
    }
    let Ok(authorization) = credential.authorization() else {
        return Observation::uncertain();
    };
    let deadline = remaining.min(Duration::from_secs(10));
    let body = axum::body::Bytes::from_owner(SecretBody(plaintext));
    // Header metadata survives a later body error or cancellation of the
    // bounded read. An uncertain acknowledgement cannot shorten Retry-After.
    let mut retry_after = None;
    let result = tokio::time::timeout(deadline, async {
        let mut response = client
            .post(endpoint)
            .header(AUTHORIZATION, authorization)
            .header("content-type", "application/json")
            .header("idempotency-key", message.to_string())
            .timeout(deadline)
            .body(body)
            .send()
            .await
            .map_err(|_| ())?;
        let status = response.status().as_u16();
        retry_after = parse_retry_after(response.headers());
        // Hyper treats 204 as bodyless even when its raw framing headers claim
        // otherwise. Do not let that normalization manufacture acceptance.
        if status == 204 && !empty_acknowledgement_headers(response.headers()) {
            return Err(());
        }
        if response
            .content_length()
            .is_some_and(|n| n > 1024 || (status == 204 && n != 0))
        {
            return Err(());
        }
        let mut size = 0usize;
        while let Some(chunk) = response.chunk().await.map_err(|_| ())? {
            size = size.checked_add(chunk.len()).ok_or(())?;
            if size > 1024 {
                return Err(());
            }
        }
        Ok(Observation {
            outcome: classify(status, size),
            retry_after,
        })
    })
    .await;
    match result {
        Ok(Ok(observation)) => observation,
        _ => Observation {
            outcome: TransportOutcome::Uncertain,
            retry_after,
        },
    }
}

pub(super) fn empty_acknowledgement_headers(headers: &HeaderMap) -> bool {
    if headers.contains_key(TRANSFER_ENCODING) {
        return false;
    }
    let mut lengths = headers.get_all(CONTENT_LENGTH).iter();
    let Some(length) = lengths.next() else {
        return true;
    };
    lengths.next().is_none()
        && length.to_str().is_ok_and(|value| {
            let value = value.trim_matches([' ', '\t']);
            !value.is_empty() && value.bytes().all(|byte| byte == b'0')
        })
}

fn classify(status: u16, size: usize) -> TransportOutcome {
    match status {
        204 if size == 0 => TransportOutcome::Accepted,
        429 | 500..=599 => TransportOutcome::Retryable,
        300..=399 | 400..=407 | 409..=428 | 430..=499 => TransportOutcome::Rejected,
        _ => TransportOutcome::Uncertain,
    }
}

fn parse_retry_after(headers: &HeaderMap) -> Option<RetryAfter> {
    let mut values = headers.get_all(RETRY_AFTER).iter();
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    let text = value.to_str().ok()?.trim_matches([' ', '\t']);
    if text.is_empty() {
        return None;
    }
    if text.bytes().all(|b| b.is_ascii_digit()) {
        // A syntactically valid delay larger than u64 cannot become a short
        // retry. Saturation makes the finite planner stop at original expiry.
        let delay = text.bytes().fold(0u64, |n, b| {
            n.saturating_mul(10).saturating_add(u64::from(b - b'0'))
        });
        return Some(RetryAfter::DelaySeconds(delay));
    }
    if text.len() > 128 {
        return None;
    }
    let date = httpdate::parse_http_date(text).ok()?;
    Some(RetryAfter::UnixSeconds(
        date.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs()),
    ))
}

#[cfg(test)]
mod tests;
