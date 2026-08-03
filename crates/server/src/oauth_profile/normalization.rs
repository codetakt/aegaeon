use crate::policy::SenderConstraint;

pub(crate) fn normalize_response_type(value: &str) -> String {
    let tokens = value
        .split_whitespace()
        .map(|v| v.trim().to_ascii_lowercase())
        .filter(|v| !v.is_empty())
        .collect::<Vec<_>>();
    tokens.join(" ")
}

pub(crate) fn merge_sender_constraints(
    base: SenderConstraint,
    profile: SenderConstraint,
) -> SenderConstraint {
    match (base, profile) {
        (SenderConstraint::Mtls, _) | (_, SenderConstraint::Mtls) => SenderConstraint::Mtls,
        (SenderConstraint::DPoP, _) | (_, SenderConstraint::DPoP) => SenderConstraint::DPoP,
        _ => SenderConstraint::None,
    }
}

pub(super) fn parse_sender_constraint(value: &str) -> Option<SenderConstraint> {
    match value.trim().to_ascii_lowercase().as_str() {
        "none" => Some(SenderConstraint::None),
        "dpop" => Some(SenderConstraint::DPoP),
        "mtls" => Some(SenderConstraint::Mtls),
        _ => None,
    }
}

pub(super) fn normalize_lower_list(values: Vec<String>) -> Vec<String> {
    let mut normalized = std::collections::BTreeSet::new();
    for value in values {
        let value = value.trim().to_ascii_lowercase();
        if !value.is_empty() {
            normalized.insert(value);
        }
    }
    normalized.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_sender_constraint_accepts_only_known_values() {
        assert_eq!(
            parse_sender_constraint(" none "),
            Some(SenderConstraint::None)
        );
        assert_eq!(
            parse_sender_constraint("DPOP"),
            Some(SenderConstraint::DPoP)
        );
        assert_eq!(
            parse_sender_constraint("mtls"),
            Some(SenderConstraint::Mtls)
        );
        assert_eq!(parse_sender_constraint("unknown"), None);
        assert_eq!(parse_sender_constraint(""), None);
    }
}
