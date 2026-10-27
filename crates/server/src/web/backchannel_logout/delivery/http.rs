use super::*;
use crate::oidc::session::delivery::RetryAfter;
use reqwest::header::{HeaderMap, RETRY_AFTER};

pub(super) fn classify(status: u16, headers: &HeaderMap, now: SystemTime) -> Completion {
    match status {
        200 | 204 => Completion::Delivered,
        408 | 429 | 500 | 502 | 503 | 504 => match retry_after(headers, now) {
            Ok(retry_after) => Completion::Recoverable { retry_after },
            Err(()) => Completion::Terminal,
        },
        _ => Completion::Terminal,
    }
}

fn retry_after(headers: &HeaderMap, now: SystemTime) -> Result<Option<RetryAfter>, ()> {
    let mut values = headers.get_all(RETRY_AFTER).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(());
    }
    let text = value.to_str().map_err(|_| ())?.trim_matches([' ', '\t']);
    if text.is_empty() {
        return Err(());
    }
    if text.bytes().all(|b| b.is_ascii_digit()) {
        let delta = text.parse::<u64>().map_err(|_| ())?;
        return (delta <= i64::MAX as u64)
            .then_some(Some(RetryAfter::Delay(delta)))
            .ok_or(());
    }
    crate::client_registry::retry_after_http_date_seconds(value.clone(), now)
        .filter(|date| *date <= i64::MAX as u64)
        .map(|date| Some(RetryAfter::Date(date)))
        .ok_or(())
}

pub(super) fn request_timeout(
    cfg: &OidcConfig,
    permit: &Permit,
    now: std::time::Instant,
) -> Option<Duration> {
    let remaining = permit.send_deadline?.checked_duration_since(now)?;
    let timeout = Duration::from_secs(cfg.backchannel_logout_timeout_secs).min(remaining);
    (!timeout.is_zero()).then_some(timeout)
}

pub(super) fn client() -> Result<reqwest::Client, reqwest::Error> {
    let mut builder = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none());
    if !allow_http_loopback_backchannel_logout_for_tests() {
        builder = builder
            .dns_resolver(Arc::new(crate::ssrf::NonRoutableDnsResolver))
            .https_only(true);
    }
    builder.build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logout_delivery_retry_after_delta_is_independent_of_process_clock() {
        let mut headers = HeaderMap::new();
        headers.insert(RETRY_AFTER, reqwest::header::HeaderValue::from_static("20"));
        for now in [
            UNIX_EPOCH - Duration::from_secs(1),
            UNIX_EPOCH + Duration::from_secs(100),
            UNIX_EPOCH + Duration::from_millis(100_001),
        ] {
            assert!(matches!(
                retry_after(&headers, now),
                Ok(Some(RetryAfter::Delay(20)))
            ));
        }
    }
}
