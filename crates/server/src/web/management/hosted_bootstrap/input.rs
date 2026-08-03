use anyhow::{anyhow, bail, Context, Result};

use super::super::host_validation::{normalize_dns_label, validate_dns_name};
use super::super::{normalize_email, validate_bootstrap_owner_password};
use super::model::{HostedBootstrapInput, NormalizedHostedBootstrapInput};

pub(super) fn normalize_input(
    input: HostedBootstrapInput,
) -> Result<NormalizedHostedBootstrapInput> {
    let parsed = url::Url::parse(input.issuer_url.trim())
        .context("AEGAEON_HOSTED_BOOTSTRAP_ISSUER_URL must be a valid URL")?;
    if parsed.scheme() != "https" {
        bail!("hosted bootstrap issuer URL must use https");
    }
    if !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        bail!("hosted bootstrap issuer URL must not contain credentials, query, or fragment");
    }
    let issuer_host = parsed
        .host_str()
        .map(str::to_ascii_lowercase)
        .ok_or_else(|| anyhow!("hosted bootstrap issuer URL must include a host"))?;
    if crate::ssrf::validate_url_host_not_non_routable_literal(&parsed).is_err() {
        bail!("hosted bootstrap issuer URL must not target non-routable hosts");
    }
    if parsed.port().is_some() {
        bail!("hosted bootstrap issuer URL must not include a port");
    }
    if parsed.path() != "/" && !parsed.path().is_empty() {
        bail!("hosted bootstrap issuer URL must not include a path");
    }
    validate_dns_name(&issuer_host, "issuer host").map_err(|message| anyhow!(message))?;

    let owner_email = normalize_email(&input.owner_email)
        .ok_or_else(|| anyhow!("AEGAEON_HOSTED_BOOTSTRAP_OWNER_EMAIL is invalid"))?;
    validate_bootstrap_owner_password(&input.owner_password)
        .map_err(|message| anyhow!("owner password is invalid: {message}"))?;

    Ok(NormalizedHostedBootstrapInput {
        issuer_url: format!("https://{issuer_host}"),
        issuer_host,
        owner_email,
        owner_password: input.owner_password,
        team_name: non_empty(input.team_name, "team name")?,
        team_slug: normalize_label(input.team_slug, "team slug")?,
        tenant_name: non_empty(input.tenant_name, "tenant name")?,
        tenant_slug: normalize_label(input.tenant_slug, "tenant slug")?,
        tenant_region: normalize_label(input.tenant_region, "tenant region")?,
        environment_name: non_empty(input.environment_name, "environment name")?,
        environment_slug: normalize_label(input.environment_slug, "environment slug")?,
        kms_region: non_empty(input.kms_region, "KMS region")?,
        kms_key_id: non_empty(input.kms_key_id, "KMS key id")?,
        kms_kid: normalize_kid(input.kms_kid)?,
    })
}

fn non_empty(value: String, label: &'static str) -> Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        bail!("{label} must not be empty");
    }
    Ok(trimmed.to_string())
}

fn normalize_label(value: String, label: &'static str) -> Result<String> {
    normalize_dns_label(&value, label).map_err(|message| anyhow!(message))
}

fn normalize_kid(value: String) -> Result<String> {
    let kid = value.trim();
    if kid.is_empty() || kid.len() > 128 || !kid.is_ascii() || kid.chars().any(char::is_whitespace)
    {
        bail!("KMS runtime key kid must be non-empty ASCII without whitespace and <= 128 bytes");
    }
    Ok(kid.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_input(issuer_url: &str) -> HostedBootstrapInput {
        HostedBootstrapInput {
            issuer_url: issuer_url.to_string(),
            owner_email: " Owner@Example.COM ".to_string(),
            owner_password: "long-enough!".to_string(),
            team_name: " Aegaeon Hosted ".to_string(),
            team_slug: " Aegaeon-Hosted ".to_string(),
            tenant_name: " Primary Tenant ".to_string(),
            tenant_slug: " Primary ".to_string(),
            tenant_region: " AWS ".to_string(),
            environment_name: " Hosted Issuer ".to_string(),
            environment_slug: " Issuer ".to_string(),
            kms_region: " ap-northeast-1 ".to_string(),
            kms_key_id: " arn:aws:kms:ap-northeast-1:111122223333:key/example ".to_string(),
            kms_kid: " aegaeon-hosted-oidc-rs256 ".to_string(),
        }
    }

    #[test]
    fn normalize_input_canonicalizes_host_and_labels() {
        let normalized = normalize_input(valid_input(" https://Issuer.EXAMPLE.com/ "))
            .expect("valid hosted bootstrap input should normalize");

        assert_eq!(normalized.issuer_host, "issuer.example.com");
        assert_eq!(normalized.issuer_url, "https://issuer.example.com");
        assert_eq!(normalized.owner_email, "owner@example.com");
        assert_eq!(normalized.team_slug, "aegaeon-hosted");
        assert_eq!(normalized.tenant_slug, "primary");
        assert_eq!(normalized.tenant_region, "aws");
        assert_eq!(normalized.environment_slug, "issuer");
        assert_eq!(normalized.kms_region, "ap-northeast-1");
        assert_eq!(normalized.kms_kid, "aegaeon-hosted-oidc-rs256");
    }

    #[test]
    fn normalize_input_rejects_non_canonical_issuer_urls() {
        for issuer_url in [
            "http://issuer.example.com",
            "https://issuer.example.com:8443",
            "https://issuer.example.com/path",
            "https://user:pass@issuer.example.com",
            "https://issuer.example.com?x=1",
            "https://issuer.example.com#fragment",
            "https://localhost",
            "https://127.0.0.1",
            "https://[::1]",
            "https://[fc00::1]",
        ] {
            assert!(
                normalize_input(valid_input(issuer_url)).is_err(),
                "{issuer_url} should be rejected"
            );
        }
    }
}
