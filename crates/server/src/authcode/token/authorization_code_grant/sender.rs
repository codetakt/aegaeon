use super::error::{TokenGrantError, TokenGrantErrorCode};
use crate::authcode::types::{AuthorizationCode, CnfClaim, SenderBinding};

/// Check the code loaded with its original CAS payload before signing or descendants.
pub(super) fn validate_code_sender(
    code: &AuthorizationCode,
    cnf: Option<&CnfClaim>,
    sender: Option<&SenderBinding>,
) -> Result<(), TokenGrantError> {
    if let Some(expected) = &code.dpop_jkt {
        match sender {
            None => {
                return Err(TokenGrantError::described(
                    TokenGrantErrorCode::InvalidDpopProof,
                    "DPoP proof required for authorization code",
                ))
            }
            Some(SenderBinding::DPoP { jkt }) if jkt == expected.as_str() => {}
            Some(_) => {
                return Err(TokenGrantError::described(
                    TokenGrantErrorCode::InvalidGrant,
                    "authorization code DPoP key mismatch",
                ))
            }
        }
    }
    let consistent = match (sender, cnf) {
        (None, None) => true,
        (Some(SenderBinding::DPoP { jkt }), Some(CnfClaim::Jkt(confirmation))) => {
            jkt == confirmation
        }
        (Some(SenderBinding::Mtls { fingerprint }), Some(CnfClaim::X5tS256(confirmation))) => {
            crate::middleware::tls::mtls_fingerprint_to_x5t_s256(fingerprint).as_ref()
                == Some(confirmation)
        }
        _ => false,
    };
    if !consistent {
        return Err(TokenGrantError::described(
            TokenGrantErrorCode::InvalidGrant,
            "token confirmation disagrees with verified sender",
        ));
    }
    Ok(())
}
