use super::{
    endpoint, now, transport, Authorization, Cleanup, Error, Grant, Recipient, CALLBACK,
    RECIPIENT_SCOPE, SOURCE_SCOPES,
};
use crate::web::AppState;
use serde_json::Value;
use uuid::Uuid;

pub(crate) enum Operation<'a> {
    Status,
    Challenge(&'a str),
    Preview,
    Accept(&'a str),
}
pub(crate) struct Reply {
    pub status: u16,
    pub body: Value,
    pub etag: Option<String>,
}

pub(crate) struct RedeemError {
    pub reason: Error,
    pub cleanup: Option<Cleanup>,
}
impl From<Error> for RedeemError {
    fn from(reason: Error) -> Self {
        Self {
            reason,
            cleanup: None,
        }
    }
}
fn text<'a>(json: &'a Value, field: &str) -> Result<&'a str, Error> {
    json.get(field)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty() && s.len() <= 32768)
        .ok_or(Error::Refused)
}
fn positive_lifetime(json: &Value) -> Result<i64, Error> {
    json.get("expires_in")
        .and_then(Value::as_i64)
        .filter(|s| *s > 0)
        .ok_or(Error::Refused)
}

pub(super) fn parent_deadline(
    json: &Value,
    access: &str,
    received: i64,
    upper: i64,
) -> Result<i64, Error> {
    let ttl = positive_lifetime(json)?;
    let bound = received.checked_add(ttl).ok_or(Error::Refused)?.min(upper);
    // The verified ID token binds these exact access-token bytes via at_hash.
    // Opaque access tokens carry no timestamp, so receipt time gives an upper
    // bound. The issuer checks the parent again on every exchange.
    let deadline = if access.contains('.') {
        let payload = crate::util::decode_compact_jwt_payload(access).ok_or(Error::Refused)?;
        let claims: Value = crate::util::deserialize_json_without_duplicate_object_keys(&payload)
            .map_err(|_| Error::Refused)?;
        let iat = claims["iat"].as_i64().ok_or(Error::Refused)?;
        let exp = claims["exp"].as_i64().ok_or(Error::Refused)?;
        if iat.checked_add(ttl) != Some(exp) || exp > upper {
            return Err(Error::Refused);
        }
        exp
    } else {
        bound
    };
    if deadline <= received {
        return Err(Error::Expired);
    }
    Ok(deadline)
}

pub(super) fn child_deadline(json: &Value, received: i64, upper: i64) -> Result<i64, Error> {
    let ttl = positive_lifetime(json)?;
    let deadline = json["expires_at"].as_i64().ok_or(Error::Refused)?;
    if ttl > 300
        || deadline > upper
        || deadline > received.checked_add(ttl).ok_or(Error::Refused)?
    {
        return Err(Error::Refused);
    }
    if deadline <= received {
        return Err(Error::Expired);
    }
    Ok(deadline)
}

pub(crate) async fn redeem(
    state: &AppState,
    auth: &Authorization,
    code: &str,
    secret: &str,
) -> Result<Grant, RedeemError> {
    let issued = now()?;
    if auth.issuer != state.issuer.as_str()
        || auth.deadline <= issued
        || code.is_empty()
        || code.len() > 4096
    {
        return Err(Error::Refused.into());
    }
    let url = endpoint(&auth.issuer, "/token")?;
    let client = auth.client_id();
    let cb = endpoint(&auth.issuer, CALLBACK)?;
    let fields = [
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", cb.as_str()),
        ("code_verifier", &auth.verifier),
    ];
    let response = transport::send(
        transport::form(&url, &client, secret, &fields)?,
        &url,
        Some((&auth.key, None)),
    )
    .await?;
    if response.status != 200 {
        return Err(if matches!(response.status, 408 | 429 | 500..=599)
            || matches!(
                response.json["error"].as_str(),
                Some("temporarily_unavailable" | "invalid_client" | "use_dpop_nonce")
            ) {
            Error::Unavailable
        } else {
            Error::Refused
        }
        .into());
    }
    let received = now()?;
    let tokens = response.json;
    let cleanup = Cleanup {
        issuer: auth.issuer.clone(),
        client_id: client.clone(),
        deadline: auth.deadline,
        refresh: text(&tokens, "refresh_token")?.into(),
    };
    let result = async {
        if !text(&tokens, "token_type")?.eq_ignore_ascii_case("DPoP")
            || text(&tokens, "scope")? != SOURCE_SCOPES
            || tokens.get("authorization_details").is_some()
        {
            return Err(Error::Refused);
        }
        let parent = text(&tokens, "access_token")?;
        let public_keys = state.oidc.config.as_ref().ok_or(Error::Unavailable)?.jwks();
        let claims = verified_id(
            &public_keys,
            state.cfg.jose_header_max_len,
            auth,
            code,
            parent,
            text(&tokens, "id_token")?,
        )?;
        let auth_time = claims.auth_time.ok_or(Error::Refused)?;
        let sid = claims.sid.filter(|v| !v.is_empty()).ok_or(Error::Refused)?;
        let (user_id, account) = account(state, &claims.sub).await?;
        Ok(Grant {
            subject: claims.sub,
            user_id,
            account,
            sid,
            auth_time,
            parent_expires_at: parent_deadline(&tokens, parent, received, auth.deadline)?,
            parent: parent.into(),
            key: auth.key.clone(),
            cleanup: cleanup.clone(),
        })
    }
    .await;
    result.map_err(|reason| RedeemError {
        reason,
        cleanup: Some(cleanup),
    })
}

pub(in crate::web) async fn account(
    state: &AppState,
    subject: &str,
) -> Result<(Uuid, String), Error> {
    let profile = crate::end_user_profiles::load_user_profile_for_subject(
        &state.db_pool,
        &state.issuer,
        subject,
    )
    .await
    .map_err(|_| Error::Unavailable)?
    .ok_or(Error::Refused)?;
    let id = Uuid::parse_str(&profile.user_id).map_err(|_| Error::Refused)?;
    let account = profile
        .email
        .or(profile.display_name)
        .filter(|s| !s.trim().is_empty())
        // The stable subject itself is also an accepted local login identifier.
        .unwrap_or(profile.subject);
    Ok((id, account))
}

pub(super) fn verified_id(
    jwks: &crate::jwk_types::Jwks,
    header_bound: usize,
    auth: &Authorization,
    code: &str,
    parent: &str,
    token: &str,
) -> Result<crate::oidc::IdTokenClaims, Error> {
    let header = crate::util::decode_compact_jwt_header_without_duplicate_keys_with_max_len(
        token,
        header_bound,
    )
    .map_err(|_| Error::Refused)?;
    if header.alg != jsonwebtoken::Algorithm::RS256 || header.typ.as_deref() != Some("JWT") {
        return Err(Error::Refused);
    }
    let kid = header.kid.ok_or(Error::Refused)?;
    let mut keys = jwks.keys.iter().filter(|k| {
        k.kid == kid
            && k.kty == "RSA"
            && k.use_.as_deref() == Some("sig")
            && k.alg.as_deref() == Some("RS256")
    });
    let key = keys.next().ok_or(Error::Refused)?;
    if keys.next().is_some() {
        return Err(Error::Refused);
    }
    let claims = crate::oidc::required_rs256::verify_required_id_token_claims(
        token,
        key.n.as_deref().ok_or(Error::Refused)?,
        key.e.as_deref().ok_or(Error::Refused)?,
    )
    .map_err(|_| Error::Refused)?;
    let id = crate::oidc::IdToken {
        claims,
        signing_alg: "RS256".into(),
    };
    id.validate_with_context(&crate::oidc::IdTokenValidationContext {
        client_id: &auth.client_id(),
        issuer: &auth.issuer,
        expected_nonce: Some(&auth.nonce),
        max_age: Some(300),
        access_token_for_hash: Some(parent),
        code_for_hash: Some(code),
        clock_skew: 0,
        current_time: Some(now()?),
    })
    .map_err(|_| Error::Refused)?;
    if id.claims.auth_time.is_none_or(|t| t < auth.started_at) || now()? >= auth.deadline {
        return Err(Error::Expired);
    }
    Ok(id.claims)
}

pub(crate) async fn exchange(
    issuer: &str,
    secret: &str,
    grant: &Grant,
) -> Result<Recipient, Error> {
    let issued = now()?;
    if issuer != grant.cleanup.issuer || issued >= grant.parent_expires_at {
        return Err(Error::Expired);
    }
    let url = endpoint(issuer, "/token")?;
    let audience = endpoint(issuer, "/organization-invitations")?;
    let fields = [
        (
            "grant_type",
            "urn:ietf:params:oauth:grant-type:token-exchange",
        ),
        ("subject_token", &grant.parent),
        (
            "subject_token_type",
            "urn:ietf:params:oauth:token-type:access_token",
        ),
        ("audience", &audience),
        ("scope", RECIPIENT_SCOPE),
    ];
    let response = transport::send(
        transport::form(&url, &grant.cleanup.client_id, secret, &fields)?,
        &url,
        Some((&grant.key, None)),
    )
    .await?;
    if matches!(response.status, 408 | 429 | 500..=599)
        || matches!(
            response.json["error"].as_str(),
            Some("temporarily_unavailable" | "invalid_client" | "use_dpop_nonce")
        )
    {
        return Err(Error::Unavailable);
    }
    if response.status != 200 {
        return Err(Error::Expired);
    }
    let token = response.json;
    if !text(&token, "token_type")?.eq_ignore_ascii_case("DPoP")
        || text(&token, "scope")? != RECIPIENT_SCOPE
        || text(&token, "issued_token_type")? != "urn:ietf:params:oauth:token-type:access_token"
        || token.get("authorization_details").is_some()
        || token.get("refresh_token").is_some()
    {
        return Err(Error::Refused);
    }
    Ok(Recipient {
        expires_at: child_deadline(&token, now()?, grant.parent_expires_at)?,
        access: text(&token, "access_token")?.into(),
    })
}

pub(crate) async fn revoke(issuer: &str, secret: &str, cleanup: &Cleanup) -> Result<(), Error> {
    if issuer != cleanup.issuer || super::domain_for_client(&cleanup.client_id).is_none() {
        return Err(Error::Refused);
    }
    let url = endpoint(issuer, "/revoke")?;
    let fields = [
        ("token", cleanup.refresh.as_str()),
        ("token_type_hint", "refresh_token"),
    ];
    let response = transport::send(
        transport::form(&url, &cleanup.client_id, secret, &fields)?,
        &url,
        None,
    )
    .await?;
    if response.status == 200 {
        Ok(())
    } else {
        Err(Error::Unavailable)
    }
}

pub(crate) async fn post(
    issuer: &str,
    grant: &Grant,
    recipient: &Recipient,
    domain: Uuid,
    invitation: Uuid,
    operation: Operation<'_>,
    body: &Value,
) -> Result<Reply, Error> {
    if issuer != grant.cleanup.issuer
        || super::domain_for_client(&grant.cleanup.client_id) != Some(domain)
        || invitation.is_nil()
    {
        return Err(Error::Refused);
    }
    if now()? >= recipient.expires_at {
        return Err(Error::Expired);
    }
    let action = match operation {
        Operation::Status => "challenge-status",
        Operation::Challenge(_) => "challenges",
        Operation::Preview => "preview",
        Operation::Accept(_) => "accept",
    };
    let url = endpoint(
        issuer,
        &format!("/organization-invitations/{domain}/{invitation}/{action}"),
    )?;
    let mut req = transport::json(&url, &recipient.access, body)?;
    match operation {
        Operation::Challenge(key) => {
            req = req.header("Idempotency-Key", key).header(
                "Accept",
                "application/vnd.aegaeon.invitation-challenge.v2+json",
            )
        }
        Operation::Accept(etag) => req = req.header("If-Match", etag),
        _ => {}
    }
    let response = transport::send(req, &url, Some((&grant.key, Some(&recipient.access)))).await?;
    Ok(Reply {
        status: response.status,
        body: response.json,
        etag: response.etag,
    })
}
