use super::*;
use axum::{body::to_bytes, http::header, response::Response};
use std::collections::BTreeMap;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const ISSUER: &str = "https://issuer.example/path?x=%25&y=+";
const STATE: &str = "state\"\\\r\n\t\0é雪😀&<>'%+&quot;";
const CALLBACK: &str = "https://client.example/callback";

pub(crate) fn decode_form(html: &str) -> BTreeMap<String, String> {
    html.split("<input type=\"hidden\" name=\"")
        .skip(1)
        .map(|input| {
            let (name, rest) = input.split_once("\" value=\"").expect("hidden value");
            let (value, _) = rest.split_once("\">").expect("closed hidden value");
            let decoded = value
                .replace("&quot;", "\"")
                .replace("&#x27;", "'")
                .replace("&lt;", "<")
                .replace("&gt;", ">")
                .replace("&amp;", "&");
            (name.into(), decoded)
        })
        .collect()
}

async fn response_json(response: Response) -> TestResult<Value> {
    Ok(serde_json::from_slice(
        &to_bytes(response.into_body(), 65536).await?,
    )?)
}

fn examples() -> Vec<(String, String)> {
    let mut values: Vec<_> = (0u8..=127)
        .map(|byte| {
            let input = format!("before{}after", char::from(byte));
            let expected = if (32..=126).contains(&byte) && ![34, 92].contains(&byte) {
                input.clone()
            } else {
                "before?after".into()
            };
            (input, expected)
        })
        .collect();
    values.extend([
        ("é雪😀".into(), "???".into()),
        ("\"\\\r\n\t\0".into(), "??????".into()),
        (
            " !#$%&'()*+,-./:;<=>?@[]^_`{|}~&quot;".into(),
            " !#$%&'()*+,-./:;<=>?@[]^_`{|}~&quot;".into(),
        ),
    ]);
    values
}

#[tokio::test]
async fn error_fields_decode_consistently_across_public_transports() -> TestResult {
    for (input, expected) in examples() {
        let expected_code = if input == expected {
            input.as_str()
        } else {
            "server_error"
        };
        let body = json_body(&input, Some(&input));
        let decoded: Value = serde_json::from_slice(&serde_json::to_vec(&body)?)?;
        assert_eq!(decoded["error"], expected_code);
        assert_eq!(decoded["error_description"], expected);
        assert_eq!(json_body(expected_code, Some(&expected)), decoded);
        let uri = crate::util::append_error_and_state(
            CALLBACK,
            &input,
            Some(&input),
            Some(STATE),
            ISSUER,
        );
        let url = url::Url::parse(&uri)?;
        let query: BTreeMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(query.len(), 4);
        assert_eq!(query["error"], expected_code);
        assert_eq!(query["error_description"], expected);
        assert_eq!(query["state"], STATE);
        assert_eq!(query["iss"], ISSUER);
        let response = crate::form_post::authorization_error(
            CALLBACK,
            &input,
            Some(&input),
            Some(STATE),
            ISSUER,
        )
        .map_err(|_| "form response")?;
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        let html = String::from_utf8(to_bytes(response.into_body(), 65536).await?.to_vec())?;
        assert_eq!(decode_form(&html), query);
        let response = crate::util::bearer_invalid_token_response(&input);
        let challenge = response.headers()[header::WWW_AUTHENTICATE].to_str()?;
        let attribute = challenge
            .strip_prefix("Bearer error=\"invalid_token\", error_description=\"")
            .and_then(|value| value.strip_suffix('"'))
            .ok_or("challenge parameters")?;
        assert_eq!(attribute, expected);
        assert_eq!(
            response_json(response).await?["error_description"],
            expected
        );
        assert_eq!(
            response_json(crate::util::invalid_client_response("fixed", &input)).await?
                ["error_description"],
            expected
        );
    }
    Ok(())
}

#[tokio::test]
async fn empty_error_fields_are_omitted_without_altering_state_or_success_fields() -> TestResult {
    for detail in [None, Some("")] {
        assert_eq!(json_body("", detail), json!({"error":"server_error"}));
        let uri = crate::util::append_error_and_state(CALLBACK, "", detail, Some(STATE), ISSUER);
        let url = url::Url::parse(&uri)?;
        let query: BTreeMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(query.len(), 3);
        assert_eq!(query["error"], "server_error");
        let response =
            crate::form_post::authorization_error(CALLBACK, "", detail, Some(STATE), ISSUER)
                .map_err(|_| "form response")?;
        let html = String::from_utf8(to_bytes(response.into_body(), 65536).await?.to_vec())?;
        assert_eq!(decode_form(&html), query);
    }
    let response = crate::util::bearer_invalid_token_response("");
    assert_eq!(
        response.headers()[header::WWW_AUTHENTICATE],
        "Bearer error=\"invalid_token\""
    );
    assert_eq!(
        response_json(response).await?,
        json!({"error":"invalid_token"})
    );
    assert_eq!(
        response_json(crate::util::invalid_client_response("fixed", "")).await?,
        json!({"error":"invalid_client"})
    );
    let response = crate::form_post::authorization_success(CALLBACK, STATE, Some(STATE), ISSUER)
        .map_err(|_| "success form")?;
    let html = String::from_utf8(to_bytes(response.into_body(), 65536).await?.to_vec())?;
    let fields = decode_form(&html);
    assert_eq!(fields.len(), 3);
    assert_eq!(fields["code"], STATE);
    assert_eq!(fields["state"], STATE);
    Ok(())
}

#[test]
fn public_error_models_normalize_serialization_without_mutating_data() -> TestResult {
    for (input, expected) in examples()
        .into_iter()
        .chain([(String::new(), String::new())])
    {
        for detail in [None, Some(String::new()), Some(input.clone())] {
            let par = crate::par::ParError {
                error: input.clone(),
                error_description: detail.clone(),
            };
            let token = crate::authcode::TokenResponse::Error {
                error: input.clone(),
                error_description: detail.clone(),
            };
            let par_wire: Value = serde_json::from_slice(&serde_json::to_vec(&par)?)?;
            let token_wire: Value = serde_json::from_slice(&serde_json::to_vec(&token)?)?;
            assert_eq!(par_wire, token_wire);
            assert_eq!(
                par_wire["error"],
                if input == expected && !input.is_empty() {
                    &input
                } else {
                    "server_error"
                }
            );
            if detail.as_deref().is_some_and(|value| !value.is_empty()) {
                assert_eq!(par_wire["error_description"], expected);
            } else {
                assert!(par_wire.get("error_description").is_none());
            }
            assert_eq!(par.error, input);
            assert_eq!(par.error_description, detail);
            let crate::authcode::TokenResponse::Error {
                error,
                error_description,
            } = token
            else {
                unreachable!()
            };
            assert_eq!(error, input);
            assert_eq!(error_description, detail);
        }
    }
    Ok(())
}
