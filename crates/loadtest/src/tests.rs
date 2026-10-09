use super::{
    cli::{parse_duration, Args},
    report::write_report,
    runner::{report_identity, run_load_test},
};
use aegaeon_loadtest::LoadTestConfig;
use anyhow::Result;
use clap::Parser;
use std::time::Duration;

#[tokio::test]
async fn zero_rounded_rate_is_retained_as_setup_failure_before_http() -> Result<()> {
    let config = LoadTestConfig {
        workers: 1,
        target_rps: 1e100,
        warmup_duration: Duration::ZERO,
        ..LoadTestConfig::default()
    };
    let results = run_load_test(config, "unused.json", None).await?;
    assert!(results.identity.is_none());
    assert!(!results.completion_errors.is_empty());
    assert_eq!(results.main_phase.http.attempts, 0);
    assert!(results.validate_complete().is_err());
    Ok(())
}

fn rejected_report_urls() -> [&'static str; 8] {
    [
        "https://user:synthetic-secret@issuer.example.test",
        "https://@issuer.example.test",
        "https://issuer.example.test?synthetic-secret",
        "https://issuer.example.test#synthetic-secret",
        "https://issuer.example.test/\nsynthetic-secret",
        "https://issuer.example.test/\0synthetic-secret",
        "https://issuer.example.test/\u{007f}synthetic-secret",
        "https://issuer.example.test/\u{0085}synthetic-secret",
    ]
}

fn rejected_url_config(value: &str, issuer: bool) -> LoadTestConfig {
    let mut config = LoadTestConfig::default();
    if issuer {
        config.discovery_expected_issuer = Some(value.into());
    } else {
        config.target_url = value.into();
    }
    config
}

#[test]
fn rejected_urls_cannot_reach_configuration_identity_serialization() {
    for value in rejected_report_urls() {
        for issuer in [false, true] {
            let config = rejected_url_config(value, issuer);
            assert!(config.validate().is_err());
            let error = report_identity(&config, "unused.json", None).unwrap_err();
            assert!(!error.to_string().contains("synthetic-secret"));
            assert!(!error.to_string().contains(value));
        }
    }
}

#[tokio::test]
async fn rejected_urls_leave_failed_reports_without_configuration_witness() {
    for value in rejected_report_urls() {
        for issuer in [false, true] {
            let config = rejected_url_config(value, issuer);
            let path = std::env::temp_dir().join(format!(
                "aegaeon-rejected-url-report-{}.json",
                uuid::Uuid::new_v4()
            ));
            let results = run_load_test(config, path.to_str().unwrap(), None)
                .await
                .unwrap();
            assert!(results.identity.is_none());
            assert!(!results.completion_errors.is_empty());
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .unwrap();
            write_report(&mut file, &results).unwrap();
            let raw = std::fs::read_to_string(&path).unwrap();
            std::fs::remove_file(&path).unwrap();
            assert!(!raw.contains("synthetic-secret"));
            assert!(!raw.contains("config_json"));
            assert!(!raw.contains("invalid issuer URL: "));
        }
    }
}

#[test]
fn safe_discovery_transport_and_exact_https_issuer_contract_are_preserved() {
    for target in [
        "http://127.0.0.1:18095",
        "https://issuer.example.test/tenant/",
    ] {
        let config = LoadTestConfig {
            target_url: target.into(),
            discovery_expected_issuer: Some("https://issuer.example.test/tenant".into()),
            ..LoadTestConfig::default()
        };
        assert!(config.validate().is_ok());
    }
    for issuer in [
        "http://issuer.example.test",
        "https://issuer.example.test/",
        "https://ISSUER.example.test",
    ] {
        assert!(rejected_url_config(issuer, true).validate().is_err());
    }
}

#[test]
fn warmup_accepts_legacy_seconds_and_driver_duration_syntax() {
    for (input, seconds) in [
        ("0", 0),
        ("1", 1),
        ("1s", 1),
        ("10s", 10),
        ("1m", 60),
        ("1h", 3600),
    ] {
        let args = Args::try_parse_from([
            "aegaeon-loadtest",
            "--report-file",
            "unused.json",
            "--warmup",
            input,
        ])
        .unwrap();
        assert_eq!(
            parse_duration(&args.warmup).unwrap(),
            Duration::from_secs(seconds)
        );
    }
    for input in ["bad", "5秒", "18446744073709551615h"] {
        let args = Args::try_parse_from([
            "aegaeon-loadtest",
            "--report-file",
            "unused.json",
            "--warmup",
            input,
        ])
        .unwrap();
        assert!(parse_duration(&args.warmup).is_err());
    }
}
#[test]
fn explicit_report_uuid_and_discovery_issuer_are_parsed_without_transport_override() {
    let id = "12345678-1234-4234-8234-123456789abc";
    let args = Args::try_parse_from([
        "aegaeon-loadtest",
        "--url",
        "http://127.0.0.1:18095",
        "--discovery-expected-issuer",
        "https://issuer.example.test",
        "--report-file",
        "fresh.json",
        "--report-id",
        id,
    ])
    .unwrap();
    assert_eq!(args.url, "http://127.0.0.1:18095");
    assert_eq!(
        args.discovery_expected_issuer.as_deref(),
        Some("https://issuer.example.test")
    );
    assert_eq!(args.report_id.unwrap().to_string(), id);
    assert!(Args::try_parse_from([
        "aegaeon-loadtest",
        "--report-file",
        "fresh.json",
        "--report-id",
        "malformed"
    ])
    .is_err());
}

#[test]
fn config_rejects_zero_and_nonfinite_execution_parameters() {
    let mut config = LoadTestConfig::default();
    assert!(config.validate().is_ok());
    for rps in [0.0, -1.0, f64::NAN, f64::INFINITY] {
        config.target_rps = rps;
        assert!(config.validate().is_err());
    }
    config.target_rps = 1.0;
    config.workers = 0;
    assert!(config.validate().is_err());
    assert!(parse_duration("18446744073709551615h").is_err());
    assert!(parse_duration("bad").is_err());
    assert!(parse_duration("5秒").is_err());
}
