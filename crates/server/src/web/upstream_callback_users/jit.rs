use axum::{http::StatusCode, response::Response};
use sqlx::{Postgres, Transaction};

use crate::oidc::IdToken;
use crate::upstream::{email_allowed_by_domain_allowlist, UpstreamAuthRequest};

use super::super::oauth_errors::json_error_with_iss;
use super::super::upstream_users::{
    load_upstream_email_matches, select_upstream_jit_reuse_candidate, upsert_upstream_end_user,
    UpstreamResolvedUser,
};
use super::account_link::upsert_upstream_account_link;
use super::audit::{record_upstream_account_link_audit, record_upstream_user_provision_audit};

#[derive(Clone, Copy)]
struct UpstreamCallbackEmail<'a> {
    value: Option<&'a str>,
    verified: bool,
}

fn upstream_default_subject(request: &UpstreamAuthRequest, id_token: &IdToken) -> String {
    format!("upstream:{}:{}", request.issuer, id_token.claims.sub)
}

fn upstream_callback_email(id_token: &IdToken) -> Option<String> {
    id_token
        .claims
        .additional_claims
        .get("email")
        .and_then(|value| value.as_str())
        .map(ToString::to_string)
}

fn upstream_callback_email_verified(id_token: &IdToken) -> bool {
    id_token
        .claims
        .additional_claims
        .get("email_verified")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
}

fn ensure_upstream_jit_verified_email(
    email: UpstreamCallbackEmail<'_>,
    issuer_base: &str,
) -> Result<(), Response> {
    if email.value.is_some() && email.verified {
        return Ok(());
    }
    Err(json_error_with_iss(
        StatusCode::FORBIDDEN,
        "access_denied",
        Some("upstream user email is missing or not verified by JIT provisioning policy"),
        issuer_base,
    ))
}

async fn select_or_provision_upstream_user(
    tx: &mut Transaction<'_, Postgres>,
    request: &UpstreamAuthRequest,
    environment_id: uuid::Uuid,
    default_subject: &str,
    email: UpstreamCallbackEmail<'_>,
    issuer_base: &str,
    request_id: &str,
) -> Result<UpstreamResolvedUser, Response> {
    if let Some(policy) = request.jit_provisioning_policy.as_ref() {
        if !policy.enabled {
            return Err(json_error_with_iss(
                StatusCode::FORBIDDEN,
                "access_denied",
                Some("upstream JIT provisioning is disabled"),
                issuer_base,
            ));
        }
        if policy.require_verified_email {
            ensure_upstream_jit_verified_email(email, issuer_base)?;
        }
        if !email_allowed_by_domain_allowlist(email.value, &policy.domain_allowlist) {
            return Err(json_error_with_iss(
                StatusCode::FORBIDDEN,
                "access_denied",
                Some("upstream user email is not allowed by JIT provisioning policy"),
                issuer_base,
            ));
        }
        let reuse_candidate = if let Some(email_value) = email.value {
            let matches = load_upstream_email_matches(tx, environment_id, email_value)
                .await
                .map_err(|_| {
                    json_error_with_iss(
                        StatusCode::BAD_GATEWAY,
                        "server_error",
                        Some("failed to load upstream email matches"),
                        issuer_base,
                    )
                })?;
            match select_upstream_jit_reuse_candidate(policy, default_subject, &matches) {
                Ok(candidate) => candidate,
                Err(message) => {
                    return Err(json_error_with_iss(
                        StatusCode::FORBIDDEN,
                        "access_denied",
                        Some(message),
                        issuer_base,
                    ));
                }
            }
        } else {
            None
        };
        if let Some(candidate) = reuse_candidate {
            return Ok(candidate);
        }
        record_upstream_user_provision_audit(
            tx,
            request,
            default_subject,
            "upstream.user.provision.authorized.v1",
            issuer_base,
            request_id,
        )
        .await?;
        return upsert_upstream_end_user(
            tx,
            environment_id,
            default_subject,
            email.value,
            policy.initial_status.clone(),
        )
        .await
        .map_err(|_| {
            json_error_with_iss(
                StatusCode::BAD_GATEWAY,
                "server_error",
                Some("failed to provision upstream user"),
                issuer_base,
            )
        });
    }
    Err(json_error_with_iss(
        StatusCode::FORBIDDEN,
        "access_denied",
        Some("upstream JIT provisioning policy is required"),
        issuer_base,
    ))
}

pub(super) async fn resolve_provisioned_upstream_callback_user(
    tx: &mut Transaction<'_, Postgres>,
    request: &UpstreamAuthRequest,
    id_token: &IdToken,
    upstream_sub_hash: &str,
    issuer_base: &str,
    request_id: &str,
) -> Result<(String, Option<uuid::Uuid>), Response> {
    let default_subject = upstream_default_subject(request, id_token);
    let context = request.managed_connection_context();
    let upstream_email = upstream_callback_email(id_token);
    let resolved_user = select_or_provision_upstream_user(
        tx,
        request,
        context.environment_id,
        &default_subject,
        UpstreamCallbackEmail {
            value: upstream_email.as_deref(),
            verified: upstream_callback_email_verified(id_token),
        },
        issuer_base,
        request_id,
    )
    .await?;
    if resolved_user.status == "SUSPENDED" {
        return Err(json_error_with_iss(
            StatusCode::FORBIDDEN,
            "access_denied",
            Some("upstream user is blocked by JIT provisioning policy"),
            issuer_base,
        ));
    }
    record_upstream_account_link_audit(
        tx,
        request,
        &resolved_user.subject,
        upstream_sub_hash,
        "upstream.account_link.upsert.authorized.v1",
        issuer_base,
        request_id,
    )
    .await?;
    upsert_upstream_account_link(
        tx,
        context.environment_id,
        context.connection_id,
        &request.issuer,
        upstream_sub_hash,
        resolved_user.end_user_id,
        issuer_base,
    )
    .await?;
    Ok((resolved_user.subject, Some(resolved_user.end_user_id)))
}

#[cfg(test)]
mod tests {
    use super::{ensure_upstream_jit_verified_email, UpstreamCallbackEmail};
    use axum::http::StatusCode;

    #[test]
    fn jit_verified_email_policy_accepts_verified_email() {
        assert!(ensure_upstream_jit_verified_email(
            UpstreamCallbackEmail {
                value: Some("user@example.com"),
                verified: true,
            },
            "https://issuer.example",
        )
        .is_ok());
    }

    #[test]
    fn jit_verified_email_policy_rejects_unverified_email() {
        let response = ensure_upstream_jit_verified_email(
            UpstreamCallbackEmail {
                value: Some("user@example.com"),
                verified: false,
            },
            "https://issuer.example",
        )
        .expect_err("unverified email must fail closed");

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn jit_verified_email_policy_rejects_missing_email() {
        let response = ensure_upstream_jit_verified_email(
            UpstreamCallbackEmail {
                value: None,
                verified: false,
            },
            "https://issuer.example",
        )
        .expect_err("missing email must fail closed");

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
}
