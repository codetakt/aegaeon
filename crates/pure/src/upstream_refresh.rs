//! RP freshness policy; signature, expiration and future-iat checks remain separate.
//! This cannot distinguish replays within the configured clock-skew window.
pub fn issued_during_refresh(iat: i64, request_started_at: u64, leeway: u64) -> bool {
    match u64::try_from(iat) {
        Ok(issued_at) => issued_at >= request_started_at.saturating_sub(leeway),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::issued_during_refresh;

    #[test]
    fn refresh_iat_lower_bound_and_numeric_extremes() {
        assert!(issued_during_refresh(940, 1000, 60));
        assert!(!issued_during_refresh(939, 1000, 60));
        assert!(issued_during_refresh(1000, 1000, 0));
        assert!(!issued_during_refresh(999, 1000, 0));
        assert!(issued_during_refresh(0, 0, 0));
        assert!(!issued_during_refresh(-1, 0, u64::MAX));
        assert!(!issued_during_refresh(i64::MIN, 0, u64::MAX));
        assert!(issued_during_refresh(i64::MAX, i64::MAX as u64, 0));
        assert!(!issued_during_refresh(i64::MAX, u64::MAX, 0));
        assert!(issued_during_refresh(0, 1, u64::MAX));
    }
}
