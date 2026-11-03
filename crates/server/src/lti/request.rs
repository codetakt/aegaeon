//! Exact form decoding shared by GET, POST and browser continuations.
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use super::LtiError;

pub const MAX_REQUEST_BYTES: usize = 16_384;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationRequest {
    pub client_id: String,
    pub redirect_uri: String,
    pub login_hint: String,
    pub lti_message_hint: String,
    pub nonce: String,
    pub state: Option<String>,
    pub scope: String,
    pub response_type: String,
    pub response_mode: String,
    pub prompt: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_age: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id_token_hint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    unsupported: Option<UnsupportedParameter>,
}

#[derive(Clone, Serialize, Deserialize)]
enum UnsupportedParameter {
    Request,
    RequestUri,
    Registration,
    ConflictingRequestObjects,
}

fn decode(raw: &str) -> Result<String, LtiError> {
    let bytes = raw.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => decoded.push(b' '),
            b'%' => {
                let digits = bytes.get(index + 1..index + 3).ok_or(LtiError::Invalid)?;
                let high = char::from(digits[0])
                    .to_digit(16)
                    .ok_or(LtiError::Invalid)?;
                let low = char::from(digits[1])
                    .to_digit(16)
                    .ok_or(LtiError::Invalid)?;
                decoded.push(u8::try_from(high * 16 + low).map_err(|_| LtiError::Invalid)?);
                index += 2;
            }
            byte => decoded.push(byte),
        }
        index += 1;
    }
    String::from_utf8(decoded).map_err(|_| LtiError::Invalid)
}

/// Decode without lossy UTF-8 replacement, trimming or duplicate-key precedence.
///
/// # Errors
/// Rejects malformed encoding, repeated names and oversized input.
pub fn form(raw: &str) -> Result<BTreeMap<String, String>, LtiError> {
    if raw.len() > MAX_REQUEST_BYTES {
        return Err(LtiError::Invalid);
    }
    let mut fields = BTreeMap::new();
    for pair in raw.split('&').filter(|pair| !pair.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let key = decode(key)?;
        let value = decode(value)?;
        if key.is_empty() || fields.len() >= 64 || fields.insert(key, value).is_some() {
            return Err(LtiError::Invalid);
        }
    }
    Ok(fields)
}

impl AuthorizationRequest {
    /// Parse the request; validate the trusted redirect before calling `validate`.
    ///
    /// # Errors
    /// Rejects malformed or incomplete requests.
    pub fn parse(raw: &str) -> Result<Self, LtiError> {
        let mut fields = form(raw)?;
        // Preserve absence for later protocol validation as an empty required
        // parameter; this does not create a default scope, grant or recipient.
        let mut take = |name: &str| {
            fields
                .remove(name)
                .map_or_else(String::new, std::convert::identity)
        };
        let request = Self {
            client_id: take("client_id"),
            redirect_uri: take("redirect_uri"),
            login_hint: take("login_hint"),
            lti_message_hint: take("lti_message_hint"),
            nonce: take("nonce"),
            scope: take("scope"),
            response_type: take("response_type"),
            response_mode: take("response_mode"),
            prompt: take("prompt"),
            state: fields.remove("state").filter(|value| !value.is_empty()),
            max_age: fields.remove("max_age"),
            id_token_hint: fields
                .remove("id_token_hint")
                .filter(|value| !value.is_empty()),
            unsupported: None,
        };
        if request.client_id.is_empty() || request.redirect_uri.is_empty() {
            return Err(LtiError::Invalid);
        }
        // RFC 6749 Appendix A.5: state is 1*VSCHAR. Refuse values HTML
        // parsing/form encoding could normalize; never reflect them as errors.
        if request.state.as_ref().is_some_and(|value| {
            value.is_empty()
                || value.len() > 4096
                || !value.bytes().all(|b| (0x20..=0x7e).contains(&b))
        }) {
            return Err(LtiError::Invalid);
        }
        let supplied = |name: &str| fields.get(name).is_some_and(|value| !value.is_empty());
        // Preserve the error kind until the caller has admitted the registered
        // redirect. Never decode or retrieve an unsupported Request Object.
        let unsupported = match (supplied("request"), supplied("request_uri")) {
            (true, true) => Some(UnsupportedParameter::ConflictingRequestObjects),
            (true, false) => Some(UnsupportedParameter::Request),
            (false, true) => Some(UnsupportedParameter::RequestUri),
            (false, false) if supplied("registration") => Some(UnsupportedParameter::Registration),
            (false, false) => None,
        };
        // claims is not supported by this profile. OIDC 5.5 recommends returning
        // the independently configured claims; it grants no disclosure permission.
        // acr_values is an optional preference. OIDC 15.1 permits minimal
        // support that does not fail; no unachieved ACR is added to the token.
        Ok(Self {
            unsupported,
            ..request
        })
    }

    fn authentication_age_limit(&self) -> Result<Option<u64>, &'static str> {
        self.max_age
            .as_deref()
            .filter(|value| !value.is_empty())
            .map(|value| {
                if value.len() > 20 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                    return Err("invalid_request");
                }
                value.parse().map_err(|_| "invalid_request")
            })
            .transpose()
    }

    /// Re-evaluate the actual authentication time at each publication boundary.
    /// max_age=0 requires active authentication, which prompt=none cannot perform.
    #[must_use]
    pub fn authentication_is_current(&self, authenticated_at: u64, now: i64) -> bool {
        let Some(age) = u64::try_from(now)
            .ok()
            .and_then(|now| now.checked_sub(authenticated_at))
        else {
            return false;
        };
        match self.authentication_age_limit() {
            Ok(None) => true,
            Ok(Some(limit)) => limit != 0 && age <= limit,
            Err(_) => false,
        }
    }

    /// Enforce the LTI profile, preserving opaque values exactly.
    ///
    /// # Errors
    /// Returns an OIDC error code; the caller must first admit its response URI.
    pub fn validate(&self) -> Result<(), &'static str> {
        if let Some(parameter) = &self.unsupported {
            return Err(match parameter {
                UnsupportedParameter::Request => "request_not_supported",
                UnsupportedParameter::RequestUri => "request_uri_not_supported",
                UnsupportedParameter::Registration => "registration_not_supported",
                UnsupportedParameter::ConflictingRequestObjects => "invalid_request",
            });
        }
        self.authentication_age_limit()?;
        // RFC 6749 sections 3.1 / 4.1.2.1: an empty value is omitted, and
        // missing required input is distinct from a supplied unsupported value.
        if self.response_type.is_empty() || self.scope.is_empty() {
            return Err("invalid_request");
        }
        if self.response_type != "id_token" {
            return Err("unsupported_response_type");
        }
        if self.scope != "openid" {
            return Err("invalid_scope");
        }
        if self.response_mode != "form_post"
            || self.prompt != "none"
            || self.login_hint.is_empty()
            || self.lti_message_hint.is_empty()
            || self.nonce.is_empty()
            || self.nonce.len() > 1024
            || self.state.as_ref().is_some_and(|value| value.len() > 4096)
        {
            return Err("invalid_request");
        }
        Ok(())
    }
}
