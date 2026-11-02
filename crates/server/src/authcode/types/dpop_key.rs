//! Canonical RFC 7638 SHA-256 thumbprints used by RFC 9449 authorization binding.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};

/// An expected authorization key. This value never attests proof of possession.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct DpopKeyThumbprint(String);

impl DpopKeyThumbprint {
    /// Accept only the canonical unpadded base64url encoding of 32 bytes.
    pub fn parse(value: &str) -> Result<Self, &'static str> {
        let invalid = "dpop_jkt must be a canonical SHA-256 JWK thumbprint";
        if value.len() != 43 || !value.is_ascii() {
            return Err(invalid);
        }
        let bytes = URL_SAFE_NO_PAD.decode(value).map_err(|_| invalid)?;
        if bytes.len() != 32 || URL_SAFE_NO_PAD.encode(&bytes) != value {
            return Err(invalid);
        }
        Ok(Self(value.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for DpopKeyThumbprint {
    type Error = &'static str;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<DpopKeyThumbprint> for String {
    fn from(value: DpopKeyThumbprint) -> Self {
        value.0
    }
}

/// A missing stored expectation is obsolete/corrupt; explicit null is unbound.
pub(crate) fn required_expectation<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<DpopKeyThumbprint>, D::Error> {
    Option::<DpopKeyThumbprint>::deserialize(deserializer)
}

/// The v3 code/PAR envelope is mandatory even if the expectation is null.
pub(crate) fn storage_version<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<u8, D::Error> {
    let version = u8::deserialize(deserializer)?;
    if version != 3 {
        return Err(serde::de::Error::custom(
            "obsolete authorization binding storage version",
        ));
    }
    Ok(version)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_thumbprint_rejects_aliases_and_noncanonical_last_bits() {
        let valid = URL_SAFE_NO_PAD.encode([42_u8; 32]);
        assert_eq!(DpopKeyThumbprint::parse(&valid).unwrap().as_str(), valid);
        for invalid in [
            "".to_string(),
            valid[..42].to_string(),
            format!("{valid}A"),
            format!("{valid}="),
            format!(" {valid}"),
            format!("urn:ietf:params:oauth:jwk-thumbprint:sha-256:{valid}"),
            format!("{}p", &valid[..42]),
            "é".repeat(21) + "A",
        ] {
            assert!(DpopKeyThumbprint::parse(&invalid).is_err(), "{invalid}");
            assert!(
                serde_json::from_value::<DpopKeyThumbprint>(serde_json::json!(invalid)).is_err()
            );
        }
    }

    #[test]
    fn stored_expectation_requires_member_and_validates_present_value() {
        #[derive(Deserialize)]
        struct Record {
            #[serde(deserialize_with = "required_expectation")]
            key: Option<DpopKeyThumbprint>,
        }
        assert!(serde_json::from_str::<Record>("{}").is_err());
        assert!(serde_json::from_str::<Record>(r#"{"key":null}"#)
            .unwrap()
            .key
            .is_none());
        assert!(serde_json::from_str::<Record>(r#"{"key":"invalid"}"#).is_err());
    }
}
