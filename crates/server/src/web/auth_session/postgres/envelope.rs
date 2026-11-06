//! Recoverable internal session identifiers for inventory, bound to their lookup digest.
const VERSION: u8 = 1;
const ENVELOPE_BYTES: usize = 1 + 12 + 36 + 16;

fn invalid() -> String {
    "invalid browser session envelope".into()
}

fn aad(namespace: &str, digest: &[u8]) -> Vec<u8> {
    let mut value = b"aegaeon/browser-session-id/v1".to_vec();
    value.extend_from_slice(&(namespace.len() as u64).to_be_bytes());
    value.extend_from_slice(namespace.as_bytes());
    value.extend_from_slice(digest);
    value
}

pub(super) fn seal(key: &[u8; 32], namespace: &str, sid: &str) -> Result<Vec<u8>, String> {
    if uuid::Uuid::parse_str(sid)
        .map_err(|_| invalid())?
        .to_string()
        != sid
    {
        return Err(invalid());
    }
    let digest = aegaeon_crypto::hash::sha256_digest(sid.as_bytes());
    let mut nonce = [0; 12];
    aegaeon_crypto::rand::fill_random(&mut nonce).map_err(|_| invalid())?;
    let context = aad(namespace, &digest);
    let key =
        aegaeon_crypto::hkdf::derive_sha256_32(key, &digest, &context).map_err(|_| invalid())?;
    let ciphertext =
        aegaeon_crypto::jwe::encrypt_a256gcm(key.as_ref(), &nonce, sid.as_bytes(), &context)
            .map_err(|_| invalid())?;
    let mut envelope = Vec::with_capacity(ENVELOPE_BYTES);
    envelope.push(VERSION);
    envelope.extend_from_slice(&nonce);
    envelope.extend_from_slice(&ciphertext);
    Ok(envelope)
}

pub(super) fn open(
    key: &[u8; 32],
    namespace: &str,
    digest: &[u8],
    envelope: &[u8],
) -> Result<String, String> {
    if digest.len() != 32 || envelope.len() != ENVELOPE_BYTES || envelope[0] != VERSION {
        return Err(invalid());
    }
    let context = aad(namespace, digest);
    let mut consumed_key =
        aegaeon_crypto::hkdf::derive_sha256_32(key, digest, &context).map_err(|_| invalid())?;
    let sid = aegaeon_crypto::jwe::decrypt_a256gcm(
        consumed_key.as_mut(),
        &envelope[1..13],
        &envelope[13..49],
        &envelope[49..],
        &context,
    )
    .map_err(|_| invalid())?;
    let sid = String::from_utf8(sid).map_err(|_| invalid())?;
    if uuid::Uuid::parse_str(&sid)
        .map_err(|_| invalid())?
        .to_string()
        != sid
        || !crate::util::constant_time_eq(
            &aegaeon_crypto::hash::sha256_digest(sid.as_bytes()),
            digest,
        )
    {
        return Err(invalid());
    }
    Ok(sid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn browser_session_envelope_is_bound_and_rejects_corruption() -> Result<(), String> {
        let key = aegaeon_crypto::hash::sha256_digest(uuid::Uuid::new_v4().as_bytes());
        let sid = uuid::Uuid::new_v4().to_string();
        let digest = aegaeon_crypto::hash::sha256_digest(sid.as_bytes());
        let value = seal(&key, "namespace", &sid)?;
        assert_eq!(value.len(), ENVELOPE_BYTES);
        assert_eq!(open(&key, "namespace", &digest, &value)?, sid);
        let mut wrong_key = key;
        wrong_key[0] ^= 1;
        assert!(open(&wrong_key, "namespace", &digest, &value).is_err());
        assert!(open(&key, "foreign", &digest, &value).is_err());
        let mut wrong_digest = digest;
        wrong_digest[0] ^= 1;
        assert!(open(&key, "namespace", &wrong_digest, &value).is_err());
        assert!(open(&key, "namespace", &digest, &value[..64]).is_err());
        for offset in [0, 1, 13, 49, 64] {
            let mut bad = value.clone();
            bad[offset] ^= 1;
            assert!(open(&key, "namespace", &digest, &bad).is_err());
        }
        assert!(seal(&key, "namespace", "not-a-session-id").is_err());
        Ok(())
    }
}
