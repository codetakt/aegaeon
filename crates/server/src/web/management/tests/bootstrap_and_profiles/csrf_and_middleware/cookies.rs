// ---------------------------------------------------------------
// P0: Session cookie tests
// ---------------------------------------------------------------

#[test]
fn session_cookie_contains_max_age() {
    let cookie = build_session_set_cookie("sid-123", false, 28800);
    assert!(cookie.contains("Max-Age=28800"));
    assert!(cookie.contains("HttpOnly"));
    assert!(cookie.contains("SameSite=Lax"));
    assert!(!cookie.contains("Secure"));
}

#[test]
fn session_cookie_secure_flag() {
    let cookie = build_session_set_cookie("sid-123", true, 3600);
    assert!(cookie.contains("Secure"));
    assert!(cookie.contains("Max-Age=3600"));
}

#[test]
fn session_clear_cookie_has_zero_max_age() {
    let cookie = build_session_clear_cookie(false);
    assert!(cookie.contains("Max-Age=0"));
}
