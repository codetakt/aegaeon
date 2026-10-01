use super::*;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde_json::json;

pub(super) fn digest(token: &str) -> String {
    let mut hash = aegaeon_crypto::hash::Sha256Hasher::new();
    hash.update(token.as_bytes());
    URL_SAFE_NO_PAD.encode(hash.finalize())
}

pub(super) fn validate_candidate(
    candidate: &Candidate,
    identity: &Identity,
    binding: &Binding,
) -> Result<(), String> {
    let fail = || STORAGE_ERROR.to_string();
    if candidate.token_jti.trim().is_empty()
        || candidate.token_jti == identity.event_jti
        || candidate.iat.checked_add(300) != Some(candidate.exp)
        || candidate.exp > i64::MAX as u64
        || candidate.digest != digest(&candidate.token)
    {
        return Err(fail());
    }
    let parts: Vec<_> = candidate.token.split('.').collect();
    if parts.len() != 3 {
        return Err(fail());
    }
    let header: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).map_err(|_| fail())?)
            .map_err(|_| fail())?;
    if header["alg"] != "RS256"
        || header["typ"] != "logout+jwt"
        || header["kid"]
            .as_str()
            .is_none_or(|kid| kid.trim().is_empty())
    {
        return Err(fail());
    }
    let signature = URL_SAFE_NO_PAD.decode(parts[2]).map_err(|_| fail())?;
    if signature.is_empty() {
        return Err(fail());
    }
    let claims: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).map_err(|_| fail())?)
            .map_err(|_| fail())?;
    let mut expected = json!({"iss":binding.issuer,"aud":identity.client_id,
        "iat":candidate.iat,"exp":candidate.exp,"jti":candidate.token_jti,"sid":identity.sid,
        "events":{"http://schemas.openid.net/event/backchannel-logout":{}}});
    if !binding.session_required {
        expected["sub"] = json!(identity.subject);
    }
    if claims != expected {
        return Err(fail());
    }
    Ok(())
}

pub(super) fn validate_record(
    record: &Record,
    identity: &Identity,
    parent: &Parent,
    now: u64,
) -> Result<(), String> {
    if record.identity != *identity
        || record.attempts > 3
        || record.observed_at < parent.logged_out_at
        || now < record.observed_at
    {
        return Err(STORAGE_ERROR.to_string());
    }
    match (&record.candidate, &record.binding) {
        (Some(candidate), Some(binding)) => {
            validate_candidate(candidate, identity, binding)?;
            if candidate.iat < parent.logged_out_at
                || candidate.iat > record.observed_at
                || record.attempts == 0
            {
                return Err(STORAGE_ERROR.to_string());
            }
            let horizon = candidate.exp.min(parent.deadline);
            match &record.phase {
                Phase::InFlight { owner, deadline }
                    if owner.trim().is_empty()
                        || *deadline > horizon
                        || *deadline <= candidate.iat =>
                {
                    return Err(STORAGE_ERROR.to_string())
                }
                Phase::Retry { due }
                    if *due >= horizon || *due <= candidate.iat || record.attempts >= 3 =>
                {
                    return Err(STORAGE_ERROR.to_string())
                }
                _ => {}
            }
        }
        (None, None) if record.phase == Phase::Terminal && record.attempts == 0 => {}
        _ => return Err(STORAGE_ERROR.to_string()),
    }
    Ok(())
}

pub(super) fn validate_parent(
    parent: &Parent,
    identity: &Identity,
    now: u64,
) -> Result<(), String> {
    if identity.sid.trim().is_empty()
        || identity.event_jti.trim().is_empty()
        || identity.client_id.trim().is_empty()
        || identity.subject.trim().is_empty()
        || parent.user_id != identity.subject
        || parent.event_jti != identity.event_jti
        || parent.deadline <= parent.logged_out_at
        || parent.deadline - parent.logged_out_at > super::super::MAX_LOGOUT_SESSION_TTL_SECS
        || parent.deadline > i64::MAX as u64
        || now < parent.logged_out_at
        || now > i64::MAX as u64
    {
        return Err(STORAGE_ERROR.to_string());
    }
    Ok(())
}
