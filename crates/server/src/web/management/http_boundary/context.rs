use axum::http::HeaderMap;

#[derive(Clone, Debug)]
pub(in crate::web::management) struct RequestContext {
    pub(in crate::web::management) request_id: String,
}

pub(in crate::web::management::http_boundary) fn request_id_from_headers(
    headers: &HeaderMap,
) -> String {
    crate::web::request_id::request_id_from_headers(headers)
}
