use super::MAX_JWKS_CACHE_CONTROL_MAX_AGE_SECS;

pub(super) fn parse_cache_control(headers: &reqwest::header::HeaderMap) -> Option<u64> {
    use reqwest::header::CACHE_CONTROL;

    let val = headers.get(CACHE_CONTROL)?.to_str().ok()?;
    val.split(',').find_map(|part| {
        let (directive, value) = part.trim().split_once('=')?;
        directive.trim().eq_ignore_ascii_case("max-age").then(|| {
            value
                .trim()
                .parse::<u64>()
                .ok()
                .map(|secs| secs.min(MAX_JWKS_CACHE_CONTROL_MAX_AGE_SECS))
        })?
    })
}

pub(super) fn instant_after_secs(
    now: std::time::Instant,
    seconds: u64,
) -> Option<std::time::Instant> {
    now.checked_add(std::time::Duration::from_secs(seconds))
}
