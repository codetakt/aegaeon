
// ---------------------------------------------------------------
// P1: Cookie builders
// ---------------------------------------------------------------

#[test]
fn build_csrf_set_cookie_insecure() {
    let cookie = build_csrf_set_cookie("tok123", false);
    assert!(cookie.contains("csrf_token=tok123"));
    assert!(cookie.split("; ").any(|attr| attr == "Path=/api/v1"));
    assert!(cookie.contains("SameSite=Lax"));
    assert!(!cookie.contains("Secure"));
}

#[test]
fn build_csrf_set_cookie_secure() {
    let cookie = build_csrf_set_cookie("tok123", true);
    assert!(cookie.contains("csrf_token=tok123"));
    assert!(cookie.contains("Secure"));
}

#[test]
fn build_session_clear_cookie_secure_flag() {
    let cookie = build_session_clear_cookie(true);
    assert!(cookie.contains("Secure"));
    assert!(cookie.contains("Max-Age=0"));
}

// ---------------------------------------------------------------
// P1: enforce_json_content_type
// ---------------------------------------------------------------

#[test]
fn enforce_json_content_type_accepts_json() -> TestResult {
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, "application/json".parse()?);
    assert!(enforce_json_content_type(&headers, "req-1").is_ok());
    Ok(())
}

#[test]
fn enforce_json_content_type_accepts_json_with_charset() -> TestResult {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        "application/json; charset=utf-8".parse()?,
    );
    assert!(enforce_json_content_type(&headers, "req-1").is_ok());
    Ok(())
}

#[test]
fn enforce_json_content_type_rejects_form() -> TestResult {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        "application/x-www-form-urlencoded".parse()?,
    );
    assert!(enforce_json_content_type(&headers, "req-1").is_err());
    Ok(())
}

#[test]
fn enforce_json_content_type_rejects_missing() {
    let headers = HeaderMap::new();
    assert!(enforce_json_content_type(&headers, "req-1").is_err());
}

#[test]
fn enforce_json_content_type_rejects_text_plain() -> TestResult {
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, "text/plain".parse()?);
    assert!(enforce_json_content_type(&headers, "req-1").is_err());
    Ok(())
}

#[test]
fn enforce_json_content_type_rejects_duplicate_header() -> TestResult {
    let mut headers = HeaderMap::new();
    headers.append(header::CONTENT_TYPE, "application/json".parse()?);
    headers.append(header::CONTENT_TYPE, "application/json".parse()?);
    assert!(enforce_json_content_type(&headers, "req-1").is_err());
    Ok(())
}

// ---------------------------------------------------------------
// P1: is_write_method
// ---------------------------------------------------------------

#[test]
fn is_write_method_identifies_write_methods() {
    assert!(is_write_method(&Method::POST));
    assert!(is_write_method(&Method::PUT));
    assert!(is_write_method(&Method::PATCH));
    assert!(is_write_method(&Method::DELETE));
}

#[test]
fn is_write_method_excludes_read_methods() {
    assert!(!is_write_method(&Method::GET));
    assert!(!is_write_method(&Method::HEAD));
    assert!(!is_write_method(&Method::OPTIONS));
}
