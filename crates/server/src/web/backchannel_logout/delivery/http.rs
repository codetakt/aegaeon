use super::*;
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

fn retry_after(headers: &HeaderMap, now: SystemTime) -> Result<Option<u64>, ()> {
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
        let time = now.duration_since(UNIX_EPOCH).map_err(|_| ())?;
        let seconds = time
            .as_secs()
            .checked_add(u64::from(time.subsec_nanos() != 0))
            .ok_or(())?;
        return seconds
            .checked_add(delta)
            .filter(|n| *n <= i64::MAX as u64)
            .map(Some)
            .ok_or(());
    }
    crate::client_registry::retry_after_http_date_seconds(value.clone(), now)
        .map(Some)
        .ok_or(())
}

pub(super) fn request_timeout(
    cfg: &OidcConfig,
    permit: &Permit,
    now: SystemTime,
) -> Option<Duration> {
    let seconds = now.duration_since(UNIX_EPOCH).ok()?.as_secs();
    if seconds < permit.checked_at || seconds > i64::MAX as u64 {
        return None;
    }
    let end = UNIX_EPOCH.checked_add(Duration::from_secs(permit.deadline.min(permit.horizon)))?;
    let remaining = end.duration_since(now).ok()?;
    let mut timeout = Duration::from_secs(cfg.backchannel_logout_timeout_secs).min(remaining);
    if let Some(deadline) = permit.retention_deadline {
        timeout = timeout.min(deadline.checked_duration_since(std::time::Instant::now())?);
    }
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
    fn logout_delivery_fractional_retry_after_never_shortens_delta() {
        let mut headers = HeaderMap::new();
        headers.insert(RETRY_AFTER, reqwest::header::HeaderValue::from_static("20"));
        assert_eq!(
            retry_after(&headers, UNIX_EPOCH + Duration::from_secs(100)),
            Ok(Some(120))
        );
        assert_eq!(
            retry_after(&headers, UNIX_EPOCH + Duration::from_millis(100_001)),
            Ok(Some(121))
        );
    }
}
