use super::JwkError;
use std::collections::HashSet;

pub(super) fn validate_key_usage(
    key_use: Option<&str>,
    key_ops: Option<&[String]>,
) -> Result<(), JwkError> {
    let Some(operations) = key_ops else {
        return Ok(());
    };
    let mut seen = HashSet::new();
    for operation in operations {
        if !seen.insert(operation) {
            return Err(JwkError::DuplicateKeyOperation(operation.clone()));
        }
        let signature = matches!(operation.as_str(), "sign" | "verify");
        let encryption = matches!(
            operation.as_str(),
            "encrypt" | "decrypt" | "wrapKey" | "unwrapKey" | "deriveKey" | "deriveBits"
        );
        if (key_use == Some("sig") && encryption) || (key_use == Some("enc") && signature) {
            return Err(JwkError::InconsistentKeyUsage);
        }
    }
    Ok(())
}

/// Check exact JWK usage metadata for this library's signature-verification consumer.
///
/// Unknown uses and operations remain representable in a JWK, but cannot grant
/// verification. Present operations must include `verify`, may additionally
/// include `sign`, and must not contain duplicates or unrelated operations.
/// This restricted operation combination is a consumer policy, not a universal
/// RFC 7517 prohibition. Key type, material and algorithm checks are separate.
#[must_use]
pub fn verification_usage_allowed(key_use: Option<&str>, key_ops: Option<&[String]>) -> bool {
    if key_use.is_some_and(|value| value != "sig") {
        return false;
    }
    let Some(operations) = key_ops else {
        return true;
    };
    validate_key_usage(key_use, key_ops).is_ok()
        && operations.iter().any(|operation| operation == "verify")
        && operations
            .iter()
            .all(|operation| matches!(operation.as_str(), "sign" | "verify"))
}
