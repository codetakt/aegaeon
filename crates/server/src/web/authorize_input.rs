//! Owned browser input. No Debug: pairs can contain compact Request Objects.
use super::authorize_request::RawAuthzQuery;
use super::oidc_request_input::{
    admit_oidc_form, admit_oidc_query, OidcEndpoint, OidcInputError, OidcParameters,
};
use axum::{
    body::{to_bytes, Body},
    http::{Method, Request, Uri},
    response::Response,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Provenance {
    Query,
    Form,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AdmittedAuthorizationInput {
    provenance: Provenance,
    parameters: OidcParameters,
}

impl AdmittedAuthorizationInput {
    pub(super) fn query(uri: &Uri) -> Result<Self, OidcInputError> {
        Ok(Self {
            provenance: Provenance::Query,
            parameters: admit_oidc_query(OidcEndpoint::Authorize, uri)?,
        })
    }

    pub(super) fn raw(&self, continuation: Option<&str>) -> Result<RawAuthzQuery, OidcInputError> {
        self.parameters.validate_authorization()?;
        let mut raw = RawAuthzQuery::from_admitted(&self.parameters)?;
        if let Some(continuation) = continuation {
            if raw.request_uri.is_none() || continuation.is_empty() {
                return Err(OidcInputError::InvalidParameterValue);
            }
            // A resolver-issued continuation overrides, but never rewrites, submitted pairs.
            raw.aeg_par_continue = Some(continuation.to_string());
        }
        Ok(raw)
    }
}

pub(super) async fn admit(
    uri: &Uri,
    request: Request<Body>,
    issuer: &str,
) -> Result<AdmittedAuthorizationInput, Response> {
    if request.method() != Method::POST {
        return AdmittedAuthorizationInput::query(uri).map_err(|e| e.into_response(issuer));
    }
    if uri.query().is_some_and(|q| !q.is_empty()) {
        return Err(OidcInputError::InvalidParameterValue.into_response(issuer));
    }
    super::request_admission::enforce_content_type(
        request.headers(),
        "application/x-www-form-urlencoded",
        issuer,
    )?;
    let body = to_bytes(
        request.into_body(),
        super::request_admission::DEFAULT_QUERY_LIMITS.max_bytes(),
    )
    .await
    .map_err(|_| OidcInputError::ParametersTooLarge.into_response(issuer))?;
    let parameters =
        admit_oidc_form(OidcEndpoint::Authorize, &body).map_err(|e| e.into_response(issuer))?;
    Ok(AdmittedAuthorizationInput {
        provenance: Provenance::Form,
        parameters,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{header, HeaderValue};

    #[tokio::test]
    async fn authorization_post_input_preserves_decoded_values_and_provenance() {
        let uri = "/authorize".parse().expect("URI");
        let body = "client_id=client&client_id=&response_type=code&state=++exact%2B%26%3D&resource=https%3A%2F%2Fa.example&resource=https%3A%2F%2Fb.example&unknown=ignored&scope=openid";
        let request = Request::post("/authorize")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .expect("request");
        let input = admit(&uri, request, "https://issuer.example")
            .await
            .expect("admitted");
        let raw = input.raw(None).expect("lowered");
        assert_eq!(raw.client_id.as_deref(), Some("client"));
        assert_eq!(raw.state.as_deref(), Some("  exact+&="));
        assert_eq!(raw.resource, ["https://a.example", "https://b.example"]);
        let value = serde_json::to_value(input).expect("serialized");
        assert_eq!(value["provenance"], "form");
        let restored: AdmittedAuthorizationInput = serde_json::from_value(value).expect("restored");
        assert_eq!(
            restored.raw(None).expect("validated").state.as_deref(),
            Some("  exact+&=")
        );
    }

    #[tokio::test]
    async fn authorization_post_input_rejects_mixed_ambiguous_and_malformed_forms() {
        for (uri, content_type, body) in [
            (
                "/authorize?client_id=query",
                "application/x-www-form-urlencoded",
                "client_id=form",
            ),
            ("/authorize", "application/json", "client_id=form"),
            (
                "/authorize",
                "application/x-www-form-urlencoded",
                "client_id=a&client_id=b",
            ),
            (
                "/authorize",
                "application/x-www-form-urlencoded",
                "state=%GG",
            ),
            (
                "/authorize",
                "application/x-www-form-urlencoded",
                "unknown=%FF",
            ),
        ] {
            let request = Request::post(uri)
                .header(header::CONTENT_TYPE, content_type)
                .body(Body::from(body))
                .expect("request");
            let response = admit(
                &uri.parse().expect("URI"),
                request,
                "https://issuer.example",
            )
            .await
            .err()
            .expect("rejected");
            assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        }
        let mut request = Request::post("/authorize")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::empty())
            .expect("request");
        request.headers_mut().append(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        );
        assert!(admit(
            &"/authorize".parse().expect("URI"),
            request,
            "https://issuer.example"
        )
        .await
        .is_err());
        let request = Request::post("/authorize")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from("x".repeat(
                super::super::request_admission::DEFAULT_QUERY_LIMITS.max_bytes() + 1,
            )))
            .expect("request");
        assert!(admit(
            &"/authorize".parse().expect("URI"),
            request,
            "https://issuer.example"
        )
        .await
        .is_err());
    }
}
