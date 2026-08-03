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
