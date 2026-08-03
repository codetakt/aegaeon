use super::{split_scopes, unix_epoch_secs_i64, TokenIssuer};
use crate::end_user_profiles::OidcProfileClaims;
use crate::oidc::{required_rs256, IdTokenBuilder, OidcConfig};
use crate::upstream::{
    filter_downstream_custom_claims, DownstreamClaimSurface, UpstreamClaimReleasePolicy,
};
use serde_json::json;
use std::time::SystemTime;

fn apply_local_profile_claims(
    mut builder: IdTokenBuilder,
    scope: Option<&str>,
    local_profile: Option<&OidcProfileClaims>,
    claim_release_policy: Option<&UpstreamClaimReleasePolicy>,
) -> IdTokenBuilder {
    let Some(local_profile) = local_profile else {
        return builder;
    };
    let scopes = split_scopes(scope);
    let profile_requested = scopes.iter().any(|value| value == "profile");
    let email_requested = scopes.iter().any(|value| value == "email");

    if email_requested {
        if let Some(email) = local_profile.email.as_ref() {
            builder = builder.claim("email".to_string(), json!(email));
        }
        if let Some(email_verified) = local_profile.email_verified {
            builder = builder.claim("email_verified".to_string(), json!(email_verified));
        }
    }

    if profile_requested {
        if let Some(display_name) = local_profile.display_name.as_ref() {
            builder = builder.claim("name".to_string(), json!(display_name));
        }
        if let Some(updated_at) = local_profile.updated_at_epoch_seconds {
            builder = builder.claim("updated_at".to_string(), json!(updated_at));
        }
        for (key, value) in filter_downstream_custom_claims(
            &local_profile.custom_claims,
            claim_release_policy,
            DownstreamClaimSurface::IdToken,
        ) {
            builder = builder.claim(key, value);
        }
    }

    builder
}

#[derive(Clone, Copy)]
pub(super) struct IdTokenBuildInput<'a> {
    pub(super) client_id: &'a str,
    pub(super) user_id: &'a str,
    pub(super) scope: Option<&'a str>,
    pub(super) local_profile: Option<&'a OidcProfileClaims>,
    pub(super) claim_release_policy: Option<&'a UpstreamClaimReleasePolicy>,
    pub(super) session_id: Option<&'a str>,
    pub(super) nonce: Option<&'a str>,
    pub(super) auth_time_epoch_secs: i64,
    pub(super) acr: Option<&'a str>,
    pub(super) access_token: &'a str,
    pub(super) code: &'a str,
}

impl TokenIssuer {
    pub(super) fn build_id_token(
        cfg: &OidcConfig,
        input: IdTokenBuildInput<'_>,
    ) -> Result<String, (String, Option<String>)> {
        let id_token = Self::build_unsigned_id_token(cfg, input)?;
        required_rs256::sign_required_id_token(&id_token.claims, &cfg.signing_key).map_err(|e| {
            (
                "server_error".to_string(),
                Some(format!("failed to sign id_token: {e}")),
            )
        })
    }

    pub(super) async fn build_id_token_async(
        cfg: &OidcConfig,
        input: IdTokenBuildInput<'_>,
    ) -> Result<String, (String, Option<String>)> {
        let id_token = Self::build_unsigned_id_token(cfg, input)?;
        required_rs256::sign_required_id_token_async(&id_token.claims, &cfg.signing_key)
            .await
            .map_err(|e| {
                (
                    "server_error".to_string(),
                    Some(format!("failed to sign id_token: {e}")),
                )
            })
    }

    fn build_unsigned_id_token(
        cfg: &OidcConfig,
        input: IdTokenBuildInput<'_>,
    ) -> Result<crate::oidc::IdToken, (String, Option<String>)> {
        let now = unix_epoch_secs_i64(SystemTime::now()).map_err(|()| {
            (
                "server_error".to_string(),
                Some("system clock error while issuing id_token".to_string()),
            )
        })?;

        if cfg.require_nonce && input.nonce.is_none() {
            return Err((
                "invalid_request".to_string(),
                Some("nonce is required when requesting the openid scope".to_string()),
            ));
        }

        let id_token_ttl = i64::try_from(cfg.id_token_ttl_secs).map_err(|_| {
            (
                "server_error".to_string(),
                Some("id_token TTL is outside representable time".to_string()),
            )
        })?;
        let id_token_exp = now.checked_add(id_token_ttl).ok_or_else(|| {
            (
                "server_error".to_string(),
                Some("id_token expiration is outside representable time".to_string()),
            )
        })?;

        let mut builder = IdTokenBuilder::try_new(
            cfg.issuer.clone(),
            input.user_id.to_string(),
            input.client_id.to_string(),
        )
        .map_err(|err| ("server_error".to_string(), Some(err.to_string())))?
        .expiration(id_token_exp);
        builder = builder.auth_time(input.auth_time_epoch_secs);
        if let Some(acr_value) = input.acr.filter(|value| !value.trim().is_empty()) {
            builder = builder.acr(acr_value.to_string());
        }

        if let Some(sid) = input.session_id {
            if sid.trim().is_empty() {
                return Err((
                    "server_error".to_string(),
                    Some("session_id must not be blank".to_string()),
                ));
            }
            builder = builder.session_id(sid.to_string());
        }

        if let Some(nonce_value) = input.nonce {
            if nonce_value.trim().is_empty() {
                return Err((
                    "invalid_request".to_string(),
                    Some("nonce must not be blank".to_string()),
                ));
            }
            builder = builder.nonce(nonce_value.to_string());
        }

        builder = apply_local_profile_claims(
            builder,
            input.scope,
            input.local_profile,
            input.claim_release_policy,
        );

        let builder =
            required_rs256::apply_required_hashes(builder, input.access_token, input.code)
                .map_err(|e| ("server_error".to_string(), Some(e.to_string())))?;

        Ok(builder.build())
    }
}
