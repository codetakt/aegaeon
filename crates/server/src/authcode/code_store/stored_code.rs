use super::{AuthCodeStorageError, AuthorizationCode};

/// One read binds the stored bytes to the fields used by grant validation.
/// Keep both private: re-encoding JSON is not a valid compare-and-consume input.
pub(in crate::authcode) struct StoredAuthorizationCode {
    code: AuthorizationCode,
    payload: String,
}

impl StoredAuthorizationCode {
    pub(super) fn decode(
        requested_code: &str,
        payload: String,
    ) -> Result<Option<Self>, AuthCodeStorageError> {
        let code: AuthorizationCode = serde_json::from_str(&payload)
            .map_err(|err| AuthCodeStorageError::Serialize(err.to_string()))?;
        if !code_is_redeemable(
            requested_code.as_bytes(),
            code.code.as_bytes(),
            code.used,
            code.is_expired(),
        ) {
            return Ok(None);
        }
        Ok(Some(Self { code, payload }))
    }

    pub(in crate::authcode) fn code(&self) -> &AuthorizationCode {
        &self.code
    }

    pub(in crate::authcode) fn into_parts(self) -> (AuthorizationCode, String) {
        (self.code, self.payload)
    }
}

fn code_is_redeemable(requested: &[u8], stored: &[u8], used: bool, expired: bool) -> bool {
    crate::util::constant_time_eq(requested, stored) && !used && !expired
}

#[cfg(kani)]
mod proofs {
    // Direct bounded check of the production read guard. This does not cover
    // serde, wall-clock expiry, storage durability, or the Redis commit.
    #[kani::proof]
    #[kani::unwind(66)]
    fn stored_code_read_guard() {
        let requested: [u8; 64] = kani::any();
        let stored: [u8; 64] = kani::any();
        let requested_len: usize = kani::any();
        let stored_len: usize = kani::any();
        kani::assume(requested_len <= 64 && stored_len <= 64);
        let requested = &requested[..requested_len];
        let stored = &stored[..stored_len];
        let used: bool = kani::any();
        let expired: bool = kani::any();
        let mut same_code = requested_len == stored_len;
        for index in 0..requested_len {
            if index >= stored_len || requested[index] != stored[index] {
                same_code = false;
            }
        }
        let accepted = super::code_is_redeemable(requested, stored, used, expired);
        if accepted {
            assert!(same_code);
            assert!(!used && !expired);
        }
        if same_code && !used && !expired {
            assert!(accepted);
        }
    }
}
