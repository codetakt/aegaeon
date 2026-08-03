use core::fmt;

const TOKEN_METHOD_NONE: u8 = 0;
const TOKEN_METHOD_CLIENT_SECRET_BASIC: u8 = 1;
const TOKEN_METHOD_CLIENT_SECRET_POST: u8 = 2;
const TOKEN_METHOD_PRIVATE_KEY_JWT: u8 = 3;
const TOKEN_METHOD_TLS_CLIENT_AUTH: u8 = 4;
const TOKEN_METHOD_SELF_SIGNED_TLS: u8 = 5;
const TOKEN_METHOD_OTHER: u8 = 6;

const POLICY_ERROR_MISSING_PKCE_PUBLIC: u8 = 0;
const POLICY_ERROR_MISSING_PKCE_CONFIDENTIAL: u8 = 1;
const POLICY_ERROR_MISSING_SENDER_CONSTRAINT: u8 = 2;
const POLICY_ERROR_UNSUPPORTED_SENDER_METHOD: u8 = 3;

#[cfg(all(not(kani), not(test), not(no_mbedtls)))]
const VALIDATION_RESULT_SUCCESS: u8 = 0;
#[cfg(all(not(kani), not(test), not(no_mbedtls)))]
const VALIDATION_RESULT_ERROR: u8 = 1;

const SENDER_METHOD_BIT_DPOP: u32 = 0x1;
const SENDER_METHOD_BIT_MTLS: u32 = 0x2;
const SENDER_METHOD_SUPPORTED_MASK: u32 = SENDER_METHOD_BIT_DPOP | SENDER_METHOD_BIT_MTLS;

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TokenMethodTag {
    None = TOKEN_METHOD_NONE,
    ClientSecretBasic = TOKEN_METHOD_CLIENT_SECRET_BASIC,
    ClientSecretPost = TOKEN_METHOD_CLIENT_SECRET_POST,
    PrivateKeyJwt = TOKEN_METHOD_PRIVATE_KEY_JWT,
    TlsClientAuth = TOKEN_METHOD_TLS_CLIENT_AUTH,
    SelfSignedTls = TOKEN_METHOD_SELF_SIGNED_TLS,
    Other = TOKEN_METHOD_OTHER,
}

impl TokenMethodTag {
    #[must_use]
    pub fn from_label(label: &str) -> Option<Self> {
        match label {
            "none" => Some(Self::None),
            "client_secret_basic" => Some(Self::ClientSecretBasic),
            "client_secret_post" => Some(Self::ClientSecretPost),
            "private_key_jwt" => Some(Self::PrivateKeyJwt),
            "tls_client_auth" => Some(Self::TlsClientAuth),
            "self_signed_tls_client_auth" => Some(Self::SelfSignedTls),
            _ => None,
        }
    }

    #[inline]
    #[cfg(all(not(kani), not(test), not(no_mbedtls)))]
    pub(crate) fn as_raw(self) -> u8 {
        self as u8
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolicyError {
    MissingPkcePublic = POLICY_ERROR_MISSING_PKCE_PUBLIC,
    MissingPkceConfidential = POLICY_ERROR_MISSING_PKCE_CONFIDENTIAL,
    MissingSenderConstraint = POLICY_ERROR_MISSING_SENDER_CONSTRAINT,
    UnsupportedSenderMethod = POLICY_ERROR_UNSUPPORTED_SENDER_METHOD,
}

impl PolicyError {
    #[must_use]
    pub fn metric_label(&self) -> &'static str {
        match self {
            PolicyError::MissingPkcePublic => "public_pkce_required",
            PolicyError::MissingPkceConfidential => "confidential_pkce_required",
            PolicyError::MissingSenderConstraint => "sender_required_missing",
            PolicyError::UnsupportedSenderMethod => "sender_method_not_allowed",
        }
    }

    #[must_use]
    pub fn description(&self) -> &'static str {
        match self {
            PolicyError::MissingPkcePublic => {
                "public clients must require PKCE (set pkce_required=true)"
            }
            PolicyError::MissingPkceConfidential => {
                "confidential clients must require PKCE (set pkce_required=true)"
            }
            PolicyError::MissingSenderConstraint => {
                "sender-constrained tokens must be declared when required"
            }
            PolicyError::UnsupportedSenderMethod => {
                "sender-constrained methods not allowed by policy"
            }
        }
    }
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.description())
    }
}

impl std::error::Error for PolicyError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SenderMethod {
    Dpop,
    Mtls,
}

impl SenderMethod {
    #[must_use]
    pub fn from_label(label: &str) -> Option<Self> {
        match label {
            "dpop" => Some(Self::Dpop),
            "mtls" => Some(Self::Mtls),
            _ => None,
        }
    }

    #[inline]
    fn bit(self) -> u32 {
        match self {
            SenderMethod::Dpop => SENDER_METHOD_BIT_DPOP,
            SenderMethod::Mtls => SENDER_METHOD_BIT_MTLS,
        }
    }
}

#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub struct SenderMethodsMask(u32);

impl SenderMethodsMask {
    pub const fn empty() -> Self {
        Self(0)
    }

    #[must_use]
    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    pub fn with(self, method: SenderMethod) -> Self {
        Self(self.0 | method.bit())
    }

    #[must_use]
    pub fn contains(self, method: SenderMethod) -> bool {
        (self.0 & method.bit()) != 0
    }

    pub fn union(self, other: SenderMethodsMask) -> Self {
        Self(self.0 | other.0)
    }

    #[must_use]
    pub fn bits(self) -> u32 {
        self.0
    }

    #[must_use]
    pub fn is_subset_of(self, other: SenderMethodsMask) -> bool {
        (self.0 & !other.0) == 0
    }

    #[must_use]
    pub fn is_supported(self) -> bool {
        (self.0 & !SENDER_METHOD_SUPPORTED_MASK) == 0
    }

    pub fn sanitize(self) -> Self {
        Self(self.0 & SENDER_METHOD_SUPPORTED_MASK)
    }
}

impl Default for SenderMethodsMask {
    fn default() -> Self {
        Self::empty()
    }
}

#[cfg(test)]
impl From<&[SenderMethod]> for SenderMethodsMask {
    fn from(methods: &[SenderMethod]) -> Self {
        methods
            .iter()
            .fold(SenderMethodsMask::empty(), |mask, method| {
                mask.with(*method)
            })
    }
}

#[cfg(all(not(kani), not(test), not(no_mbedtls)))]
#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct JoseDcrValidationResult {
    tag: u8,
    error: u8,
}

#[cfg(all(not(kani), not(test), not(no_mbedtls)))]
extern "C" {
    fn Jose_Dcr_validate_dcr_metadata_c(
        token_method: u8,
        pkce_declared: bool,
        pkce_value: bool,
        sender_flag_declared: bool,
        sender_flag_value: bool,
        sender_methods_declared: bool,
        sender_methods_mask_value: u32,
        require_pkce_public: bool,
        require_pkce_confidential: bool,
        require_sender: bool,
        allowed_sender_mask: u32,
    ) -> JoseDcrValidationResult;
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::fn_params_excessive_bools)]
/// Validate DCR operator policy flags against the declared client metadata.
///
/// # Errors
///
/// Returns [`PolicyError`] when PKCE or sender-constraint declarations violate
/// the configured policy gates. Unknown native error tags fail closed as
/// [`PolicyError::UnsupportedSenderMethod`].
pub fn validate_metadata(
    token_method: TokenMethodTag,
    pkce_declared: bool,
    pkce_value: bool,
    sender_flag_declared: bool,
    sender_flag_value: bool,
    sender_methods_declared: bool,
    sender_methods_mask: SenderMethodsMask,
    require_pkce_public: bool,
    require_pkce_confidential: bool,
    require_sender: bool,
    allowed_sender_mask: SenderMethodsMask,
) -> Result<(), PolicyError> {
    #[cfg(all(not(kani), not(test), not(no_mbedtls)))]
    unsafe {
        let result = Jose_Dcr_validate_dcr_metadata_c(
            token_method.as_raw(),
            pkce_declared,
            pkce_value,
            sender_flag_declared,
            sender_flag_value,
            sender_methods_declared,
            sender_methods_mask.bits(),
            require_pkce_public,
            require_pkce_confidential,
            require_sender,
            allowed_sender_mask.bits(),
        );
        map_result(result)
    }

    #[cfg(any(kani, test, no_mbedtls))]
    {
        validate_metadata_rust(
            token_method,
            pkce_declared,
            pkce_value,
            sender_flag_declared,
            sender_flag_value,
            sender_methods_declared,
            sender_methods_mask,
            require_pkce_public,
            require_pkce_confidential,
            require_sender,
            allowed_sender_mask,
        )
    }
}

#[cfg(any(kani, test, no_mbedtls))]
#[allow(clippy::too_many_arguments)]
#[allow(clippy::fn_params_excessive_bools)]
fn validate_metadata_rust(
    token_method: TokenMethodTag,
    pkce_declared: bool,
    pkce_value: bool,
    sender_flag_declared: bool,
    sender_flag_value: bool,
    sender_methods_declared: bool,
    sender_methods_mask: SenderMethodsMask,
    require_pkce_public: bool,
    require_pkce_confidential: bool,
    require_sender: bool,
    allowed_sender_mask: SenderMethodsMask,
) -> Result<(), PolicyError> {
    let pkce_true = pkce_declared && pkce_value;
    let sender_flag_true = sender_flag_declared && sender_flag_value;
    let allowed_mask = allowed_sender_mask.sanitize();
    let methods_mask = sender_methods_mask.sanitize();

    if require_pkce_public && token_method == TokenMethodTag::None && !pkce_true {
        return Err(PolicyError::MissingPkcePublic);
    }

    if require_pkce_confidential && token_method != TokenMethodTag::None && !pkce_true {
        return Err(PolicyError::MissingPkceConfidential);
    }

    if require_sender && !sender_flag_true {
        return Err(PolicyError::MissingSenderConstraint);
    }

    let sender_methods_ok = if sender_flag_true {
        if sender_methods_declared {
            methods_mask.is_supported() && methods_mask.is_subset_of(allowed_mask)
        } else {
            allowed_mask.is_empty()
        }
    } else {
        true
    };

    if !sender_methods_ok {
        return Err(PolicyError::UnsupportedSenderMethod);
    }

    Ok(())
}

#[cfg(all(not(kani), not(test), not(no_mbedtls)))]
fn map_result(result: JoseDcrValidationResult) -> Result<(), PolicyError> {
    match result.tag {
        VALIDATION_RESULT_SUCCESS => Ok(()),
        VALIDATION_RESULT_ERROR => match result.error {
            POLICY_ERROR_MISSING_PKCE_PUBLIC => Err(PolicyError::MissingPkcePublic),
            POLICY_ERROR_MISSING_PKCE_CONFIDENTIAL => Err(PolicyError::MissingPkceConfidential),
            POLICY_ERROR_MISSING_SENDER_CONSTRAINT => Err(PolicyError::MissingSenderConstraint),
            _ => Err(PolicyError::UnsupportedSenderMethod),
        },
        _ => Err(PolicyError::UnsupportedSenderMethod),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allowed_mask() -> SenderMethodsMask {
        SenderMethodsMask::from(&[SenderMethod::Dpop, SenderMethod::Mtls][..])
    }

    #[test]
    fn fallback_accepts_valid_metadata() {
        assert!(validate_metadata(
            TokenMethodTag::ClientSecretBasic,
            true,
            true,
            false,
            false,
            false,
            SenderMethodsMask::empty(),
            true,
            true,
            false,
            allowed_mask(),
        )
        .is_ok());
    }

    #[test]
    fn fallback_rejects_public_pkce_missing() {
        assert_eq!(
            validate_metadata(
                TokenMethodTag::None,
                true,
                false,
                false,
                false,
                false,
                SenderMethodsMask::empty(),
                true,
                false,
                false,
                allowed_mask(),
            ),
            Err(PolicyError::MissingPkcePublic)
        );
    }

    #[test]
    fn fallback_rejects_confidential_pkce_missing() {
        assert_eq!(
            validate_metadata(
                TokenMethodTag::ClientSecretBasic,
                true,
                false,
                false,
                false,
                false,
                SenderMethodsMask::empty(),
                false,
                true,
                false,
                allowed_mask(),
            ),
            Err(PolicyError::MissingPkceConfidential)
        );
    }

    #[test]
    fn fallback_rejects_missing_sender_flag() {
        assert_eq!(
            validate_metadata(
                TokenMethodTag::ClientSecretBasic,
                true,
                true,
                false,
                false,
                true,
                SenderMethodsMask::from(&[SenderMethod::Dpop][..]),
                false,
                false,
                true,
                allowed_mask(),
            ),
            Err(PolicyError::MissingSenderConstraint)
        );
    }

    #[test]
    fn fallback_rejects_disallowed_sender_method() {
        assert_eq!(
            validate_metadata(
                TokenMethodTag::ClientSecretBasic,
                true,
                true,
                true,
                true,
                true,
                SenderMethodsMask::from(&[SenderMethod::Mtls][..]),
                false,
                false,
                true,
                SenderMethodsMask::from(&[SenderMethod::Dpop][..]),
            ),
            Err(PolicyError::UnsupportedSenderMethod)
        );
    }
}
