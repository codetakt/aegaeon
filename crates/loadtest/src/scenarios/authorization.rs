//! PKCE transactions, strict authorization callbacks and PAR setup.
use super::{
    wire::{apply_auth, one_header, ParSuccess},
    ScenarioExecutor,
};
use crate::{
    generator::PkcePair,
    profile::{scopes, ClientProfile, ParPolicy},
};
use anyhow::{ensure, Context, Result};
use reqwest::{
    header::{HeaderMap, LOCATION},
    StatusCode, Url,
};

pub(super) struct Transaction {
    pub(super) pkce: PkcePair,
    pub(super) state: String,
    pub(super) nonce: Option<String>,
    pub(super) scope: String,
    pub(super) resource: Option<String>,
    pub(super) params: Vec<(String, String)>,
}

pub(super) fn authorization_code(
    status: StatusCode,
    headers: &HeaderMap,
    redirect: &str,
    state: &str,
    issuer: &str,
) -> Result<String> {
    ensure!(
        status == StatusCode::FOUND,
        "positive authorization requires HTTP 302"
    );
    let location = one_header(headers, LOCATION.as_str())?;
    let actual = Url::parse(location).context("authorization Location must be absolute")?;
    let registered = Url::parse(redirect)?;
    ensure!(
        actual.scheme() == registered.scheme()
            && actual.host_str() == registered.host_str()
            && actual.port_or_known_default() == registered.port_or_known_default()
            && actual.username().is_empty()
            && actual.password().is_none()
            && actual.path() == registered.path()
            && actual.fragment().is_none(),
        "authorization destination differs from registration"
    );
    let query = location
        .split_once('?')
        .map(|(_, query)| query)
        .context("authorization response query is missing")?;
    let response_query = if let Some((_, static_query)) = redirect.split_once('?') {
        query
            .strip_prefix(static_query)
            .and_then(|suffix| suffix.strip_prefix('&'))
            .context("registered static query was changed or not retained first")?
    } else {
        query
    };
    ensure!(
        response_query.split('&').all(|pair| !pair.is_empty()),
        "empty authorization response query field"
    );
    let mut response_url = actual;
    response_url.set_query(Some(response_query));
    let remaining: Vec<(String, String)> = response_url
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    let unique = |name: &str| -> Result<Option<&str>> {
        let values: Vec<_> = remaining
            .iter()
            .filter(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
            .collect();
        ensure!(
            values.len() <= 1 && values.iter().all(|v| !v.is_empty()),
            "duplicate or empty authorization response parameter"
        );
        Ok(values.first().copied())
    };
    ensure!(
        unique("state")? == Some(state) && unique("iss")? == Some(issuer),
        "authorization state/issuer mismatch"
    );
    let code = unique("code")?;
    let error = unique("error")?;
    ensure!(
        code.is_some() != error.is_some(),
        "authorization must return exactly one code or error"
    );
    for (name, _) in &remaining {
        ensure!(
            [
                "code",
                "state",
                "iss",
                "error",
                "error_description",
                "error_uri"
            ]
            .contains(&name.as_str()),
            "unexpected authorization response parameter"
        );
    }
    unique("error_description")?;
    unique("error_uri")?;
    ensure!(error.is_none(), "authorization returned an OAuth error");
    ensure!(
        remaining.len() == 3,
        "positive authorization response has unexpected fields"
    );
    Ok(code.context("authorization code missing")?.to_owned())
}

impl ScenarioExecutor {
    pub(super) fn transaction(
        &mut self,
        scope: String,
        resource: Option<String>,
    ) -> Result<Transaction> {
        let profile = self.profile()?.clone();
        let state = self.generator.state();
        let pkce = self.generator.pkce_pair();
        let nonce = scopes(&scope)?
            .contains("openid")
            .then(|| self.generator.nonce());
        let mut params = vec![
            ("response_type".into(), "code".into()),
            ("response_mode".into(), "query".into()),
            ("prompt".into(), "none".into()),
            ("iss".into(), profile.supply.issuer.clone()),
            ("client_id".into(), profile.supply.client_id),
            ("redirect_uri".into(), profile.supply.redirect_uri),
            ("scope".into(), scope.clone()),
            ("state".into(), state.clone()),
            ("code_challenge".into(), pkce.challenge.clone()),
            ("code_challenge_method".into(), "S256".into()),
        ];
        if let Some(value) = &nonce {
            params.push(("nonce".into(), value.clone()));
        }
        if let Some(value) = &resource {
            params.push(("resource".into(), value.clone()));
        }
        Ok(Transaction {
            pkce,
            state,
            nonce,
            scope,
            resource,
            params,
        })
    }

    pub(super) async fn authorization_params(
        &mut self,
        profile: &ClientProfile,
        tx: &Transaction,
        force_par: bool,
    ) -> Result<Vec<(String, String)>> {
        let params = if force_par || profile.supply.par_policy == ParPolicy::Required {
            let mut params = tx.params.clone();
            let request = apply_auth(
                profile,
                self.client.post(format!("{}/par", self.base_url)),
                &mut params,
            )
            .form(&params);
            let response = self.send("POST", "/par", request).await?;
            ensure!(
                response.status == StatusCode::CREATED,
                "PAR must return HTTP 201"
            );
            let par: ParSuccess =
                serde_json::from_slice(&response.body).context("invalid PAR response")?;
            ensure!(
                !par.request_uri.trim().is_empty() && par.expires_in > 0,
                "empty or expired PAR response"
            );
            vec![
                ("client_id".into(), profile.supply.client_id.clone()),
                ("request_uri".into(), par.request_uri),
            ]
        } else {
            tx.params.clone()
        };
        Ok(params)
    }
}
