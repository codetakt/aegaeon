pub(super) fn build_conditional_jwks_get(
    client: &reqwest::blocking::Client,
    uri: &str,
    etag: Option<&str>,
    last_modified: Option<&str>,
) -> reqwest::blocking::RequestBuilder {
    let mut req = client.get(uri);
    if let Some(tag) = etag {
        req = req.header(reqwest::header::IF_NONE_MATCH, tag);
    }
    if let Some(last_modified) = last_modified {
        req = req.header(reqwest::header::IF_MODIFIED_SINCE, last_modified);
    }
    req
}
