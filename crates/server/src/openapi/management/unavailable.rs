//! Shared management admission/store failure; operation-specific descriptions win.
use utoipa::openapi::{Content, Ref, RefOr, Response};
use utoipa::Modify;

pub(super) struct ManagementUnavailable;

impl Modify for ManagementUnavailable {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let mut response = Response::new("Request admission or required store unavailable");
        response.content.insert(
            "application/json".into(),
            Content::new(Some(Ref::from_schema_name("ErrorResponse"))),
        );
        for path in openapi.paths.paths.values_mut() {
            for operation in [
                &mut path.get,
                &mut path.put,
                &mut path.post,
                &mut path.delete,
                &mut path.options,
                &mut path.patch,
                &mut path.trace,
            ]
            .into_iter()
            .flatten()
            {
                operation
                    .responses
                    .responses
                    .entry("503".into())
                    .or_insert_with(|| response.clone().into());
            }
            if let Some(head) = &mut path.head {
                let unavailable =
                    head.responses
                        .responses
                        .entry("503".into())
                        .or_insert_with(|| {
                            Response::new("Request admission or required store unavailable").into()
                        });
                // A HEAD error preserves status and headers but has no response body.
                if let RefOr::T(response) = unavailable {
                    response.content.clear();
                }
            }
        }
    }
}
