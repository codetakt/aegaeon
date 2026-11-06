//! Secret primitives only. Hash possession is not authenticated acceptance.
use super::{AuthorityError, Scope};
use aegaeon_crypto::{hash::Sha256Hasher, rand::fill_random};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use uuid::Uuid;

pub use aegaeon_pure::organization_invitations::{
    challenge_deadline, invitation_deadline, is_live, Purpose, DEFAULT_INVITATION_SECONDS,
    IDENTITY_PROOF_SECONDS, RECIPIENT_CHALLENGE_SECONDS,
};

#[derive(Clone, Copy)]
pub struct Binding {
    pub scope: Scope,
    pub object_id: Uuid,
    pub delivery_revision: i64,
    pub purpose: Purpose,
}

impl Binding {
    fn validate(self) -> Result<(), AuthorityError> {
        self.scope.validate()?;
        super::model::require(!self.object_id.is_nil() && self.delivery_revision > 0)
    }
}

// Intentionally no Debug/Display/Clone/Serialize implementation.
pub struct Capability(String);

impl Capability {
    pub fn into_delivery(self) -> String {
        self.0
    }
}

#[derive(Debug, thiserror::Error)]
pub enum GenerationError {
    #[error("invalid invitation capability binding")]
    InvalidBinding,
    #[error("invitation random supplier unavailable")]
    Unavailable,
}

pub fn generate(binding: Binding) -> Result<(Capability, [u8; 32]), GenerationError> {
    binding
        .validate()
        .map_err(|_| GenerationError::InvalidBinding)?;
    let mut secret = [0u8; 32];
    fill_random(&mut secret).map_err(|_| GenerationError::Unavailable)?;
    Ok((
        Capability(URL_SAFE_NO_PAD.encode(secret)),
        hash(binding, &secret),
    ))
}

pub fn matches(binding: Binding, expected: &[u8; 32], presented: &str) -> bool {
    if binding.validate().is_err() || presented.len() != 43 {
        return false;
    }
    let mut secret = [0u8; 32];
    if URL_SAFE_NO_PAD.decode_slice(presented, &mut secret).ok() != Some(32)
        || URL_SAFE_NO_PAD.encode(secret) != presented
    {
        return false;
    }
    crate::util::constant_time_eq(&hash(binding, &secret), expected)
}

fn hash(binding: Binding, secret: &[u8; 32]) -> [u8; 32] {
    let mut context = Sha256Hasher::new();
    context.update(b"Aegaeon/organization-capability/v1\0");
    context.update(&[match binding.purpose {
        Purpose::Invitation => 1,
        Purpose::RecipientChallenge => 2,
        Purpose::IdentityRegistration => 3,
        Purpose::IdentityRecovery => 4,
    }]);
    context.update(binding.scope.environment_id.as_bytes());
    context.update(binding.scope.domain_id.as_bytes());
    context.update(binding.object_id.as_bytes());
    context.update(&binding.delivery_revision.to_be_bytes());
    context.update(secret);
    context.finalize()
}

#[cfg(test)]
mod tests;
