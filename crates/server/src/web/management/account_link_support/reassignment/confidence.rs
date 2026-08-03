use crate::management::types::{AccountLinkConflictCandidate, AccountLinkLowConfidenceHandling};

pub(in crate::web::management) fn account_link_candidate_is_low_confidence(
    candidate: Option<&AccountLinkConflictCandidate>,
) -> bool {
    match candidate {
        Some(candidate) => !candidate
            .match_reasons
            .iter()
            .any(|reason| reason == "subject"),
        None => true,
    }
}

pub(in crate::web::management) fn resolve_account_link_low_confidence_handling(
    requires_explicit_override: bool,
    requested: Option<AccountLinkLowConfidenceHandling>,
) -> Result<Option<AccountLinkLowConfidenceHandling>, &'static str> {
    if !requires_explicit_override {
        return Ok(None);
    }

    match requested {
        Some(AccountLinkLowConfidenceHandling::AllowLowConfidence) => {
            Ok(Some(AccountLinkLowConfidenceHandling::AllowLowConfidence))
        }
        None => Err(
            "Low-confidence account link handling must be set to allow_low_confidence before reassignment",
        ),
    }
}

pub(in crate::web::management) fn account_link_low_confidence_handling_label(
    action: Option<AccountLinkLowConfidenceHandling>,
) -> &'static str {
    match action {
        Some(AccountLinkLowConfidenceHandling::AllowLowConfidence) => "allow_low_confidence",
        None => "unchanged",
    }
}
