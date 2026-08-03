use super::super::now_epoch_secs;

use crate::oidc::{IdToken, IdTokenValidationContext};

pub(in crate::web) struct UpstreamIdTokenValidationInput<'a> {
    pub(in crate::web) client_id: &'a str,
    pub(in crate::web) issuer: &'a str,
    pub(in crate::web) expected_nonce: Option<&'a str>,
    pub(in crate::web) max_age: Option<i64>,
    pub(in crate::web) access_token: Option<&'a str>,
    pub(in crate::web) code: Option<&'a str>,
    pub(in crate::web) requested_acr: Option<&'a str>,
    pub(in crate::web) jwt_leeway_secs: u64,
}

pub(in crate::web) fn validate_upstream_id_token(
    id_token: &IdToken,
    input: &UpstreamIdTokenValidationInput<'_>,
) -> Result<(), String> {
    let mut ctx = IdTokenValidationContext::new(input.client_id, input.issuer);
    ctx.expected_nonce = input.expected_nonce;
    ctx.max_age = input.max_age;
    ctx.clock_skew = input.jwt_leeway_secs.cast_signed();
    if id_token.claims.at_hash.is_some() {
        let value = input
            .access_token
            .ok_or_else(|| "upstream access_token missing".to_string())?;
        ctx.access_token_for_hash = Some(value);
    }
    if id_token.claims.c_hash.is_some() {
        let value = input
            .code
            .ok_or_else(|| "upstream authorization code missing".to_string())?;
        ctx.code_for_hash = Some(value);
    }
    id_token
        .validate_with_context(&ctx)
        .map_err(|err| err.to_string())?;

    if let Some(auth_time) = id_token.claims.auth_time {
        let auth_time = u64::try_from(auth_time)
            .map_err(|_| "upstream id_token auth_time is invalid".to_string())?;
        let now_with_leeway = now_epoch_secs()?
            .checked_add(input.jwt_leeway_secs)
            .ok_or_else(|| "upstream id_token auth_time validation overflow".to_string())?;
        if auth_time > now_with_leeway {
            return Err("upstream id_token auth_time is in the future".to_string());
        }
    }

    if let Some(requested_acr) = input.requested_acr {
        match id_token.claims.acr.as_deref() {
            Some(value) if value == requested_acr => {}
            Some(_) => return Err("upstream id_token acr mismatch".to_string()),
            None => return Err("upstream id_token acr missing".to_string()),
        }
    }

    Ok(())
}
