//! Versioned server-only continuation data. Old envelopes require a restart.
use super::{
    authorize_context::AuthorizeRequestContext, authorize_input::AdmittedAuthorizationInput,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AuthorizationSnapshot {
    version: u8,
    pub(super) input: AdmittedAuthorizationInput,
    request: Value,
    prompt: String,
    response_mode: String,
    #[serde(deserialize_with = "required_optional_string")]
    pub(super) par_continuation: Option<String>,
    pub(super) reauthenticated: bool,
    #[serde(deserialize_with = "required_optional_value")]
    pub(super) authentication_session: Option<Value>,
}

impl AuthorizationSnapshot {
    pub(super) fn encode(ctx: &AuthorizeRequestContext) -> Result<Value, serde_json::Error> {
        serde_json::to_value(Self {
            version: 2,
            input: ctx.input.clone(),
            request: serde_json::to_value(&ctx.req)?,
            prompt: ctx.prompt.to_string(),
            response_mode: format!("{:?}", ctx.response_mode),
            par_continuation: ctx.par_authorize_continuation.clone(),
            reauthenticated: ctx.reauthenticated,
            authentication_session: ctx.reauthentication_session.clone(),
        })
    }

    pub(super) fn matches_client(&self, client_id: &str) -> bool {
        self.request.get("client_id").and_then(Value::as_str) == Some(client_id)
    }

    pub(super) fn decode(value: &Value) -> Result<Self, ()> {
        let snapshot: Self = serde_json::from_value(value.clone()).map_err(|_| ())?;
        if snapshot.version != 2
            || snapshot.reauthenticated != snapshot.authentication_session.is_some()
        {
            return Err(());
        }
        let request: crate::authcode::types::AuthorizationRequest =
            serde_json::from_value(snapshot.request.clone()).map_err(|_| ())?;
        if serde_json::to_value(request).map_err(|_| ())? != snapshot.request
            || !matches!(snapshot.response_mode.as_str(), "Query" | "FormPost")
            || super::prompt::Prompt::parse(snapshot.prompt.clone()).is_err()
        {
            return Err(());
        }
        snapshot
            .input
            .raw(snapshot.par_continuation.as_deref())
            .map_err(|_| ())?;
        Ok(snapshot)
    }
}

fn required_optional_string<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    Option::<String>::deserialize(deserializer)
}

fn required_optional_value<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Value>, D::Error> {
    Option::<Value>::deserialize(deserializer)
}
