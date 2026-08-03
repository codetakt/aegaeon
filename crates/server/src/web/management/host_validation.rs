use std::net::IpAddr;

pub(in crate::web::management) fn normalize_dns_label(
    value: &str,
    label: &'static str,
) -> Result<String, String> {
    let normalized = value.trim().to_ascii_lowercase();
    validate_dns_label(&normalized, label)?;
    Ok(normalized)
}

pub(in crate::web::management) fn normalize_dns_name(
    value: &str,
    label: &'static str,
) -> Result<String, String> {
    let normalized = value.trim().to_ascii_lowercase();
    validate_dns_name(&normalized, label)?;
    Ok(normalized)
}

pub(in crate::web::management) fn validate_dns_name(
    value: &str,
    label: &'static str,
) -> Result<(), String> {
    let valid_len = !value.is_empty() && value.len() <= 253;
    let valid_labels = value.split('.').all(valid_dns_label);
    if !valid_len || !valid_labels {
        return Err(format!("{label} must contain DNS labels"));
    }
    if value == "localhost" || value.ends_with(".localhost") || value.parse::<IpAddr>().is_ok() {
        return Err(format!("{label} must be a DNS name"));
    }
    Ok(())
}

fn validate_dns_label(value: &str, label: &'static str) -> Result<(), String> {
    if valid_dns_label(value) {
        Ok(())
    } else {
        Err(format!("{label} must contain a DNS label"))
    }
}

fn valid_dns_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
}
