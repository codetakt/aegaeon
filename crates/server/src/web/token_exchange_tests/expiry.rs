use super::*;

#[test]
fn token_exchange_expires_in_returns_none_for_expired_tokens() {
    let now = SystemTime::now();
    assert!(token_exchange_expires_in(now, now, 3600).is_none());
    assert!(token_exchange_expires_in(now - Duration::from_secs(1), now, 3600).is_none());
}

#[test]
fn token_exchange_expires_in_caps_to_3600_seconds() {
    let now = SystemTime::now();
    let subject_expires_at = now + Duration::from_secs(4000);
    assert_eq!(
        token_exchange_expires_in(subject_expires_at, now, 3600),
        Some(3600)
    );
}

#[test]
fn token_exchange_expires_in_caps_to_configured_access_ttl() {
    let now = SystemTime::now();
    let subject_expires_at = now + Duration::from_secs(4000);
    assert_eq!(
        token_exchange_expires_in(subject_expires_at, now, 123),
        Some(123)
    );
}

#[test]
fn token_exchange_expires_in_uses_remaining_when_smaller() {
    let now = SystemTime::now();
    let subject_expires_at = now + Duration::from_secs(10);
    assert_eq!(
        token_exchange_expires_in(subject_expires_at, now, 3600),
        Some(10)
    );
}

#[test]
fn access_token_expires_at_rejects_unrepresentable_expiry() {
    assert!(access_token_expires_at(UNIX_EPOCH, u64::MAX).is_err());
}
