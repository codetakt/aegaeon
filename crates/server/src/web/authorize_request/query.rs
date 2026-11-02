use serde::Deserialize;

fn deserialize_string_vec<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrMany {
        One(String),
        Many(Vec<String>),
    }

    Option::<OneOrMany>::deserialize(deserializer).map(|value| match value {
        None => Vec::new(),
        Some(OneOrMany::One(value)) => vec![value],
        Some(OneOrMany::Many(values)) => values,
    })
}

#[derive(Deserialize, Default)]
pub(in crate::web) struct RawAuthzQuery {
    pub(in crate::web) dpop_jkt: Option<String>,
    pub(in crate::web) client_id: Option<String>,
    pub(in crate::web) response_type: Option<String>,
    pub(in crate::web) response_mode: Option<String>,
    pub(in crate::web) iss: Option<String>,
    pub(in crate::web) redirect_uri: Option<String>,
    #[serde(default, deserialize_with = "deserialize_string_vec")]
    pub(in crate::web) resource: Vec<String>,
    pub(in crate::web) authorization_details: Option<String>,
    pub(in crate::web) scope: Option<String>,
    pub(in crate::web) state: Option<String>,
    pub(in crate::web) nonce: Option<String>,
    pub(in crate::web) prompt: Option<String>,
    pub(in crate::web) max_age: Option<u64>,
    pub(in crate::web) acr_values: Option<String>,
    pub(in crate::web) code_challenge: Option<String>,
    pub(in crate::web) code_challenge_method: Option<String>,
    pub(in crate::web) request: Option<String>,
    pub(in crate::web) request_uri: Option<String>,
    pub(in crate::web) aeg_par_continue: Option<String>,
}

impl RawAuthzQuery {
    pub(in crate::web) fn recognizes_parameter(name: &str) -> bool {
        matches!(
            name,
            "dpop_jkt"
                | "client_id"
                | "response_type"
                | "response_mode"
                | "iss"
                | "redirect_uri"
                | "resource"
                | "authorization_details"
                | "scope"
                | "state"
                | "nonce"
                | "prompt"
                | "max_age"
                | "acr_values"
                | "code_challenge"
                | "code_challenge_method"
                | "request"
                | "request_uri"
                | "aeg_par_continue"
        )
    }

    pub(in crate::web) fn from_admitted(
        parameters: &crate::web::oidc_request_input::OidcParameters,
    ) -> Result<Self, crate::web::oidc_request_input::OidcInputError> {
        use crate::web::oidc_request_input::OidcInputError;
        let mut raw = Self::default();
        for (name, value) in parameters.as_pairs() {
            match name.as_str() {
                "dpop_jkt" => raw.dpop_jkt = Some(value.clone()),
                "client_id" => raw.client_id = Some(value.clone()),
                "response_type" => raw.response_type = Some(value.clone()),
                "response_mode" => raw.response_mode = Some(value.clone()),
                "iss" => raw.iss = Some(value.clone()),
                "redirect_uri" => raw.redirect_uri = Some(value.clone()),
                "resource" => raw.resource.push(value.clone()),
                "authorization_details" => raw.authorization_details = Some(value.clone()),
                "scope" => raw.scope = Some(value.clone()),
                "state" => raw.state = Some(value.clone()),
                "nonce" => raw.nonce = Some(value.clone()),
                "prompt" => raw.prompt = Some(value.clone()),
                "max_age" => {
                    raw.max_age = Some(
                        value
                            .parse()
                            .map_err(|_| OidcInputError::InvalidParameterValue)?,
                    )
                }
                "acr_values" => raw.acr_values = Some(value.clone()),
                "code_challenge" => raw.code_challenge = Some(value.clone()),
                "code_challenge_method" => raw.code_challenge_method = Some(value.clone()),
                "request" => raw.request = Some(value.clone()),
                "request_uri" => raw.request_uri = Some(value.clone()),
                "aeg_par_continue" => raw.aeg_par_continue = Some(value.clone()),
                _ => return Err(OidcInputError::InvalidParameterValue),
            }
        }
        Ok(raw)
    }
}
