use super::*;

#[test]
fn env_flag_invalid_value_returns_error_without_panic() -> TestResult {
    let _lock = env_lock()?;
    let _guard = EnvVarGuard::new("AEGAEON_MAIN_TEST_FLAG", Some("maybe"));

    let parsed = no_panic(
        std::panic::catch_unwind(|| env_flag("AEGAEON_MAIN_TEST_FLAG", false)),
        "env_flag must return an error instead of panicking",
    )?;

    assert!(parsed.is_err());
    Ok(())
}

#[test]
fn env_num_invalid_value_returns_error_without_panic() -> TestResult {
    let _lock = env_lock()?;
    let _guard = EnvVarGuard::new("AEGAEON_MAIN_TEST_NUM", Some("not-a-number"));

    let parsed = no_panic(
        std::panic::catch_unwind(|| env_num::<u64>("AEGAEON_MAIN_TEST_NUM", 7)),
        "env_num must return an error instead of panicking",
    )?;

    assert!(parsed.is_err());
    Ok(())
}

#[test]
fn optional_env_parser_trims_values_and_treats_empty_as_absent() -> TestResult {
    let _lock = env_lock()?;
    let key = "AEGAEON_MAIN_TEST_OPTIONAL_TRIMMED";
    let _guard = EnvVarGuard::new(key, Some("  redis://127.0.0.1/  "));

    let parsed = no_panic(
        std::panic::catch_unwind(|| env_optional_trimmed(key)),
        "optional env parser must return a value instead of panicking",
    )?;
    assert_eq!(parsed?, Some("redis://127.0.0.1/".to_string()));

    std::env::set_var(key, "   ");
    let parsed = no_panic(
        std::panic::catch_unwind(|| env_optional_trimmed(key)),
        "optional env parser must treat blank values as absent",
    )?;
    assert_eq!(parsed?, None);
    Ok(())
}

#[test]
fn security_optional_env_parser_rejects_empty_values() -> TestResult {
    let _lock = env_lock()?;
    let key = "AEGAEON_MAIN_TEST_SECRET";
    let _guard = EnvVarGuard::new(key, Some("   "));

    let parsed = no_panic(
        std::panic::catch_unwind(|| env_optional_non_empty(key)),
        "security optional env parser must reject blank values without panicking",
    )?;

    assert!(parsed.is_err());
    Ok(())
}

#[test]
fn runtime_issuer_host_parser_rejects_empty_configured_value() -> TestResult {
    let _lock = env_lock()?;
    let _removed = EnvVarGuard::new("BASE_URL", None);
    let _guard = EnvVarGuard::new("AEGAEON_RUNTIME_ISSUER_HOST", Some("   "));

    let parsed = no_panic(
        std::panic::catch_unwind(runtime_issuer_host_from_env),
        "runtime issuer host parser must reject blank configured values without panicking",
    )?;

    assert!(parsed.is_err());
    Ok(())
}

#[test]
fn runtime_issuer_host_parser_requires_configured_value() -> TestResult {
    let _lock = env_lock()?;
    let _removed = EnvVarGuard::new("BASE_URL", None);
    let _guard = EnvVarGuard::new("AEGAEON_RUNTIME_ISSUER_HOST", None);

    let parsed = no_panic(
        std::panic::catch_unwind(runtime_issuer_host_from_env),
        "runtime issuer host parser must return an error when absent without panicking",
    )?;

    assert!(parsed.is_err());
    Ok(())
}

#[test]
fn runtime_issuer_host_parser_normalizes_configured_host() -> TestResult {
    let _lock = env_lock()?;
    let _removed = EnvVarGuard::new("BASE_URL", None);
    let _guard = EnvVarGuard::new("AEGAEON_RUNTIME_ISSUER_HOST", Some("Auth.Example.com:443"));

    let parsed = no_panic(
        std::panic::catch_unwind(runtime_issuer_host_from_env),
        "runtime issuer host parser must normalize configured host without panicking",
    )?;

    assert_eq!(parsed?, "auth.example.com");
    Ok(())
}

#[test]
fn runtime_issuer_host_parser_rejects_removed_base_url() -> TestResult {
    let _lock = env_lock()?;
    let _issuer_host = EnvVarGuard::new("AEGAEON_RUNTIME_ISSUER_HOST", Some("auth.example.com"));
    let _removed = EnvVarGuard::new("BASE_URL", Some("https://auth.example.com"));

    let parsed = no_panic(
        std::panic::catch_unwind(runtime_issuer_host_from_env),
        "runtime issuer host parser must reject removed BASE_URL without panicking",
    )?;

    assert!(parsed.is_err());
    Ok(())
}

#[cfg(unix)]
#[test]
fn env_parsers_non_unicode_values_return_error_without_panic() -> TestResult {
    use std::os::unix::ffi::OsStringExt;

    let _lock = env_lock()?;
    let flag_key = "AEGAEON_MAIN_TEST_NON_UNICODE_FLAG";
    let num_key = "AEGAEON_MAIN_TEST_NON_UNICODE_NUM";
    let optional_key = "AEGAEON_DPOP_REDIS_URL";
    let secret_key = "AEGAEON_MAIN_TEST_NON_UNICODE_SECRET";
    let issuer_host_key = "AEGAEON_RUNTIME_ISSUER_HOST";
    let removed_base_url_key = "BASE_URL";
    let _flag_guard = EnvVarGuard::new(flag_key, None);
    let _num_guard = EnvVarGuard::new(num_key, None);
    let _optional_guard = EnvVarGuard::new(optional_key, None);
    let _secret_guard = EnvVarGuard::new(secret_key, None);
    let _issuer_host_guard = EnvVarGuard::new(issuer_host_key, None);
    let _removed_base_url_guard = EnvVarGuard::new(removed_base_url_key, None);
    std::env::set_var(flag_key, OsString::from_vec(vec![0x66, 0x80, 0x6f]));
    std::env::set_var(num_key, OsString::from_vec(vec![0x31, 0x80]));
    std::env::set_var(optional_key, OsString::from_vec(vec![0x72, 0x80]));
    std::env::set_var(secret_key, OsString::from_vec(vec![0x73, 0x80]));
    std::env::set_var(issuer_host_key, OsString::from_vec(vec![0x68, 0x80]));

    let flag = no_panic(
        std::panic::catch_unwind(|| env_flag(flag_key, false)),
        "env_flag must reject non-Unicode values without panicking",
    )?;
    let num = no_panic(
        std::panic::catch_unwind(|| env_num::<u64>(num_key, 7)),
        "env_num must reject non-Unicode values without panicking",
    )?;
    let optional = no_panic(
        std::panic::catch_unwind(|| env_optional_trimmed(optional_key)),
        "optional env parser must reject non-Unicode values without panicking",
    )?;
    let secret = no_panic(
        std::panic::catch_unwind(|| env_optional_non_empty(secret_key)),
        "security optional env parser must reject non-Unicode values without panicking",
    )?;
    let issuer_host = no_panic(
        std::panic::catch_unwind(runtime_issuer_host_from_env),
        "runtime issuer host parser must reject non-Unicode values without panicking",
    )?;

    assert!(flag.is_err());
    assert!(num.is_err());
    assert!(optional.is_err());
    assert!(secret.is_err());
    assert!(issuer_host.is_err());
    Ok(())
}
