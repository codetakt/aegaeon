#[test]
fn oidc_config_does_not_read_startup_environment() {
    let source = include_str!("../../config.rs");

    assert!(!source.contains("std::env::var("));
    assert!(!source.contains("AEGAEON_OIDC_"));
    assert!(!source.contains("AWS_REGION"));
}
