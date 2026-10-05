use crate::profile::issuer_url;
use anyhow::{ensure, Result};

/// Validate transport URLs and exact discovery issuers with the workload URL contract.
pub fn validate_report_urls(
    target_url: &str,
    discovery_expected_issuer: Option<&str>,
) -> Result<()> {
    for value in std::iter::once(target_url).chain(discovery_expected_issuer) {
        ensure!(
            !value.chars().any(|c| c.is_control() || c.is_whitespace()),
            "URL inputs must not contain controls or whitespace"
        );
        ensure!(
            !value.split_once("://").is_some_and(|(_, suffix)| suffix
                .split(['/', '?', '#'])
                .next()
                .is_some_and(|authority| authority.contains('@'))),
            "URL inputs must not contain credentials"
        );
    }
    let target =
        reqwest::Url::parse(target_url).map_err(|_| anyhow::anyhow!("invalid target URL"))?;
    ensure!(
        ["http", "https"].contains(&target.scheme())
            && target.host_str().is_some()
            && target.username().is_empty()
            && target.password().is_none()
            && target.query().is_none()
            && target.fragment().is_none(),
        "invalid target URL components"
    );
    if let Some(issuer) = discovery_expected_issuer {
        let url = issuer_url(issuer)?;
        ensure!(
            url.as_str().trim_end_matches('/') == issuer,
            "discovery issuer must be a canonical HTTPS URL"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_report_urls;

    #[test]
    fn canonical_issuer_spellings_remain_valid() {
        for issuer in [
            "https://issuer.example.test",
            "https://issuer.example.test.",
            "https://issuer.example.test:0",
            "https://issuer.example.test:1",
            "https://issuer.example.test:444",
            "https://issuer.example.test:65535",
            "https://issuer.example.test/tenant",
            "https://issuer.example.test/caf%C3%A9",
            "https://issuer.example.test/caf%c3%a9",
            "https://xn--bcher-kva.example.test/tenant",
            "https://127.0.0.1",
            "https://[::1]",
            "https://[2001:db8::1]:444/tenant",
            "https://[::ffff:c000:201]",
        ] {
            assert!(
                validate_report_urls("http://localhost:8080", Some(issuer)).is_ok(),
                "canonical issuer rejected: {issuer}"
            );
        }
    }

    #[test]
    fn normalized_issuer_spellings_are_rejected_without_narrowing_transport() {
        for value in [
            "HTTPS://issuer.example.test",
            "https://ISSUER.example.test",
            "https://issuer.example.test:443",
            "https://issuer.example.test:",
            "https://issuer.example.test:00444",
            "https://[0:0:0:0:0:0:0:1]",
            "https://[2001:DB8::1]",
            "https://[::ffff:192.0.2.1]",
            "https://127.1",
            "https://0x7f000001",
            "https://0177.0.0.1",
            "https://issuer.example.test/a/../tenant",
            "https://issuer.example.test/a/./tenant",
            "https://issuer.example.test/a/%2e%2e/tenant",
            "https://issuer.example.test/%2e/tenant",
            "https://issuer.example.test/caf\u{00e9}",
            "https://b\u{00fc}cher.example.test/tenant",
            "https://%69ssuer.example.test/tenant",
            "https://issuer.example.test/tenant/",
        ] {
            assert!(
                validate_report_urls("http://127.0.0.1:8080", Some(value)).is_err(),
                "noncanonical issuer admitted: {value}"
            );
            assert!(
                validate_report_urls(value, None).is_ok(),
                "valid transport rejected: {value}"
            );
        }
    }

    #[test]
    fn malformed_or_secret_bearing_urls_are_rejected_for_both_roles() {
        for value in [
            "",
            "https://user:synthetic-secret@issuer.example.test",
            "https://@issuer.example.test",
            "https://issuer.example.test?synthetic-secret",
            "https://issuer.example.test#synthetic-secret",
            "https://issuer.example.test/\nsynthetic-secret",
            "https://issuer.example.test/\u{009f}synthetic-secret",
            "https://issuer.example.test/\u{00a0}synthetic-secret",
            "https://issuer.example.test/\u{2028}synthetic-secret",
            "https://issuer.example.test:65536",
            "https://issuer.example.test:not-a-port",
            "https://[invalid",
            "https://xn--.example.test",
            "https://iss|uer.example.test",
            "ftp://issuer.example.test",
        ] {
            assert!(
                validate_report_urls(value, None).is_err(),
                "target: {value}"
            );
            assert!(
                validate_report_urls("http://localhost:8080", Some(value)).is_err(),
                "issuer: {value}"
            );
        }
        assert!(
            validate_report_urls("http://localhost:8080", Some("http://issuer.example.test"))
                .is_err()
        );
    }
}
