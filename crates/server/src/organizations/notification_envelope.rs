//! Bounded internal notification JWE profile, separate from OIDC/JWT admission.
//!
//! Caller-supplied context and key configuration must come from current trusted
//! authority. Encryption alone authenticates neither an issuer nor eligibility.
//! This module does not load credentials, read a clock, or implement an outbox.

use aegaeon_crypto::{hash::sha256_digest, jwe, rand::fill_random};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::Serialize;
use uuid::Uuid;
use zeroize::Zeroizing;

mod keys;
pub use keys::{KeyVersion, PrivateDeliveryKey, PrivateKeyRing, PublicDeliveryKey};

/// Application payload limit, before base64 encoding. No compression is used.
pub const MAX_PAYLOAD_BYTES: usize = 8192;
const MAX_HEADER_BYTES: usize = 4096;
const MAX_WRAPPED_KEY_BYTES: usize = 1024;
const PROFILE: &str = "https://github.com/codetakt/aegaeon/spec/notification-envelope/v1";
const TYPE: &str = "application/aegaeon-notification+jwe";

const fn encoded_limit(bytes: usize) -> usize {
    bytes.div_ceil(3) * 4
}

/// Includes all five bounded base64url segments and four separators.
pub const MAX_ENVELOPE_BYTES: usize = encoded_limit(MAX_HEADER_BYTES)
    + encoded_limit(MAX_WRAPPED_KEY_BYTES)
    + encoded_limit(12)
    + encoded_limit(MAX_PAYLOAD_BYTES)
    + encoded_limit(16)
    + 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("invalid notification envelope input")]
    InvalidInput,
    #[error("invalid notification encryption key")]
    InvalidKey,
    #[error("notification encryption key unavailable")]
    KeyUnavailable,
    #[error("notification encryption failed")]
    SealFailed,
    #[error("notification envelope authentication failed")]
    OpenFailed,
}

/// No nil identifier stands in for an absent Environment, domain or Organization.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Scope {
    Installation,
    Environment {
        environment_id: Uuid,
    },
    Domain {
        environment_id: Uuid,
        domain_id: Uuid,
    },
    Organization {
        environment_id: Uuid,
        domain_id: Uuid,
        organization_id: Uuid,
    },
}

impl Scope {
    fn validate(&self) -> Result<(), Error> {
        let ids: &[Uuid] = match self {
            Self::Installation => &[],
            Self::Environment { environment_id } => &[*environment_id],
            Self::Domain {
                environment_id,
                domain_id,
            } => &[*environment_id, *domain_id],
            Self::Organization {
                environment_id,
                domain_id,
                organization_id,
            } => &[*environment_id, *domain_id, *organization_id],
        };
        if ids.iter().any(Uuid::is_nil) {
            return Err(Error::InvalidInput);
        }
        Ok(())
    }

    // Explicit containment, never an installation-wide wildcard for tenants.
    fn admits(&self, message: &Self) -> bool {
        match (self, message) {
            (Self::Installation, Self::Installation) => true,
            (
                Self::Environment { environment_id: a },
                Self::Environment { environment_id: b }
                | Self::Domain {
                    environment_id: b, ..
                }
                | Self::Organization {
                    environment_id: b, ..
                },
            ) => a == b,
            (
                Self::Domain {
                    environment_id: a,
                    domain_id: ad,
                },
                Self::Domain {
                    environment_id: b,
                    domain_id: bd,
                }
                | Self::Organization {
                    environment_id: b,
                    domain_id: bd,
                    ..
                },
            ) => a == b && ad == bd,
            (Self::Organization { .. }, Self::Organization { .. }) => self == message,
            _ => false,
        }
    }
}

/// Zero is a real revision in some purpose models; absence is a separate value.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum Revision {
    NotApplicable,
    Value(i64),
}

impl Revision {
    fn valid(&self) -> bool {
        matches!(self, Self::NotApplicable | Self::Value(0..))
    }
}

/// Expected facts supplied by the purpose handler, never reconstructed from mail.
///
/// Digests bind the exact destination, complete purpose-specific authority and
/// payload bytes. Handlers own those encodings and all current-authority checks.
/// Selected runtime generations are UUIDs; Organization generations are positive
/// counters. This type is intentionally not a deserializable authority object.
#[derive(Clone, Serialize)]
pub struct MessageContext {
    pub message_id: Uuid,
    pub deployment_id: Uuid,
    pub runtime_generation: Uuid,
    pub scope: Scope,
    pub organization_generation: Revision,
    pub purpose: String,
    pub template: String,
    pub template_version: u32,
    pub expires_at: i64,
    pub authority_revision: Revision,
    pub contact_revision: Revision,
    pub configuration_revision: Revision,
    pub authority_binding: [u8; 32],
    pub destination_binding: [u8; 32],
    pub payload_digest: [u8; 32],
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c))
}

impl MessageContext {
    fn validate(&self, now: i64) -> Result<(), Error> {
        self.scope.validate()?;
        let generation_valid = match self.scope {
            Scope::Organization { .. } => {
                matches!(self.organization_generation, Revision::Value(1..))
            }
            _ => self.organization_generation == Revision::NotApplicable,
        };
        if [self.message_id, self.deployment_id, self.runtime_generation]
            .iter()
            .any(Uuid::is_nil)
            || !generation_valid
            || !valid_id(&self.purpose)
            || !valid_id(&self.template)
            || self.template_version == 0
            || now < 0
            || self.expires_at <= now
            || !self.authority_revision.valid()
            || !self.contact_revision.valid()
            || !self.configuration_revision.valid()
        {
            return Err(Error::InvalidInput);
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct Binding<'a> {
    context: &'a MessageContext,
    spki_sha256: String,
}

#[derive(Serialize)]
struct Header<'a> {
    alg: &'static str,
    enc: &'static str,
    kid: &'a str,
    typ: &'static str,
    crit: [&'static str; 1],
    #[serde(rename = "https://github.com/codetakt/aegaeon/spec/notification-envelope/v1")]
    binding: Binding<'a>,
}

fn protected(
    context: &MessageContext,
    version: &str,
    fingerprint: &[u8; 32],
) -> Result<String, Error> {
    let bytes = serde_json::to_vec(&Header {
        alg: "RSA-OAEP-256",
        enc: "A256GCM",
        kid: version,
        typ: TYPE,
        crit: [PROFILE],
        binding: Binding {
            context,
            spki_sha256: URL_SAFE_NO_PAD.encode(fingerprint),
        },
    })
    .map_err(|_| Error::InvalidInput)?;
    if bytes.len() > MAX_HEADER_BYTES {
        return Err(Error::InvalidInput);
    }
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

impl PublicDeliveryKey {
    /// Seal exact logical bytes. Retries should reuse the persisted message.
    ///
    /// Borrowed plaintext remains caller-owned. The returned JWE is not a proof
    /// of issuance authority. Caller time/configuration must be current and trusted.
    pub fn seal(
        &self,
        context: &MessageContext,
        plaintext: &[u8],
        now: i64,
    ) -> Result<String, Error> {
        context.validate(now)?;
        self.version.admit(context, now, true)?;
        if plaintext.len() > MAX_PAYLOAD_BYTES || sha256_digest(plaintext) != context.payload_digest
        {
            return Err(Error::InvalidInput);
        }
        let header = protected(context, &self.version.id, &self.fingerprint)?;
        let mut cek = Zeroizing::new([0; 32]);
        let mut iv = [0; 12];
        fill_random(cek.as_mut()).map_err(|_| Error::SealFailed)?;
        fill_random(&mut iv).map_err(|_| Error::SealFailed)?;
        let wrapped =
            jwe::rsa_oaep_256_wrap(&self.spki, cek.as_ref()).map_err(|_| Error::SealFailed)?;
        let encrypted = jwe::encrypt_a256gcm(cek.as_ref(), &iv, plaintext, header.as_bytes())
            .map_err(|_| Error::SealFailed)?;
        let (ciphertext, tag) = encrypted.split_at(encrypted.len() - 16);
        Ok(format!(
            "{}.{}.{}.{}.{}",
            header,
            URL_SAFE_NO_PAD.encode(wrapped),
            URL_SAFE_NO_PAD.encode(iv),
            URL_SAFE_NO_PAD.encode(ciphertext),
            URL_SAFE_NO_PAD.encode(tag)
        ))
    }
}

fn decode(segment: &str, max: usize) -> Result<Vec<u8>, Error> {
    if segment.len() > encoded_limit(max) {
        return Err(Error::OpenFailed);
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|_| Error::OpenFailed)?;
    if bytes.len() > max {
        return Err(Error::OpenFailed);
    }
    Ok(bytes)
}

impl PrivateKeyRing {
    /// Open using one externally selected version and authoritative expected facts.
    ///
    /// This internal profile accepts only its exact header encoding, not arbitrary
    /// equivalent JSON. The original encoded protected header is RFC 7516 AAD.
    /// No header-provided URL, key or resolver is consulted. No fallback is tried.
    /// Plaintext is returned in an owned erasing buffer after authentication and
    /// digest comparison. Callers still enforce purpose/currentness and secret use.
    pub fn open(
        &self,
        version: &str,
        context: &MessageContext,
        envelope: &str,
        now: i64,
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        context.validate(now)?;
        let key = self.select(version, context, now)?;
        if envelope.len() > MAX_ENVELOPE_BYTES {
            return Err(Error::OpenFailed);
        }
        let mut segments = envelope.split('.');
        let [Some(header), Some(wrapped), Some(iv), Some(ciphertext), Some(tag)] = [
            segments.next(),
            segments.next(),
            segments.next(),
            segments.next(),
            segments.next(),
        ] else {
            return Err(Error::OpenFailed);
        };
        if segments.next().is_some() || header != protected(context, version, &key.fingerprint)? {
            return Err(Error::OpenFailed);
        }
        let wrapped = decode(wrapped, MAX_WRAPPED_KEY_BYTES)?;
        let iv = decode(iv, 12)?;
        let ciphertext = decode(ciphertext, MAX_PAYLOAD_BYTES)?;
        let tag = decode(tag, 16)?;
        if wrapped.len() < 256 || iv.len() != 12 || tag.len() != 16 {
            return Err(Error::OpenFailed);
        }
        let mut cek = Zeroizing::new(
            jwe::rsa_oaep_256_unwrap(&key.pkcs8, &wrapped).map_err(|_| Error::OpenFailed)?,
        );
        if cek.len() != 32 {
            return Err(Error::OpenFailed);
        }
        let plaintext = Zeroizing::new(
            jwe::decrypt_a256gcm(&mut cek, &iv, &ciphertext, &tag, header.as_bytes())
                .map_err(|_| Error::OpenFailed)?,
        );
        if sha256_digest(&plaintext) != context.payload_digest {
            return Err(Error::OpenFailed);
        }
        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests;
